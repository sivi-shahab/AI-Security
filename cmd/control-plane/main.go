package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/twmb/franz-go/pkg/kgo"
	"github.com/twmb/franz-go/pkg/sr"

	"aisec/internal/agents"
	"aisec/internal/audit"
	"aisec/internal/authz"
	"aisec/internal/catalog"
	"aisec/internal/events"
	"aisec/internal/identity"
	"aisec/internal/incident"
	"aisec/internal/ingest"
	"aisec/internal/lifecycle"
	"aisec/internal/policysvc"
	"aisec/internal/posture"
	"aisec/internal/privacy"
	"aisec/internal/server"
	"aisec/policy"
)

// Env: BUNDLE_SIGNING_KEY_FILE, DATABASE_URL, INCIDENT_KEK_FILE (32 raw bytes), KAFKA_BROKERS, SCHEMA_REGISTRY_URL,
// TENANT_ID, PUBLIC_URL, CATALOG_FEED_URL + CATALOG_FEED_PUBKEY_FILE (signed app catalog feed), OPENSEARCH_URL/USER/PASSWORD (policy simulation reads stored events), and identity (ADR-0002): OIDC_ISSUER, OIDC_AUDIENCE, OIDC_MFA_ACR (comma-separated acr
// values that mean MFA), BREAK_GLASS_SUBS (comma-separated token subs), SCIM_TOKEN_SHA256 (hex),
// MCP_GATEWAY_TOKEN_SHA256 (hex; the MCP gateway reporting tools/list, ticket 29).
func main() {
	// `control-plane audit anchor|verify ...`: run by the audit-anchor CronJob or via kubectl exec.
	if len(os.Args) > 1 && os.Args[1] == "audit" {
		os.Exit(audit.Main(context.Background(), os.Args[2:], os.Stdout))
	}
	log := privacy.NewLogger("control-plane")
	fail := func(msg string, err error) {
		log.Error(msg, "err", err)
		os.Exit(1)
	}
	ctx, cancel := context.WithCancel(context.Background())

	// No key, no bundle: sidecars must never be offered an unsigned policy.
	key, err := os.ReadFile(os.Getenv("BUNDLE_SIGNING_KEY_FILE"))
	if err != nil {
		fail("read bundle signing key", err)
	}

	// Incidents: Postgres (with the audit log), Kafka for decision events.
	auditLog, err := audit.Open(ctx, os.Getenv("DATABASE_URL"))
	if err != nil {
		fail("audit log", err)
	}
	db, err := pgxpool.New(ctx, os.Getenv("DATABASE_URL"))
	if err != nil {
		fail("database", err)
	}
	kek, err := os.ReadFile(os.Getenv("INCIDENT_KEK_FILE"))
	if err != nil {
		fail("read incident KEK", err)
	}
	incidents, err := incident.Open(ctx, db, auditLog, kek)
	if err != nil {
		fail("incident store", err)
	}
	rc, err := sr.NewClient(sr.URLs(os.Getenv("SCHEMA_REGISTRY_URL")))
	if err != nil {
		fail("schema registry client", err)
	}
	go func() {
		for t := time.NewTicker(time.Hour); ctx.Err() == nil; <-t.C {
			if n, err := incidents.PurgeExpired(ctx, time.Now()); err != nil {
				log.Error("purge expired evidence", "err", err)
			} else if n > 0 {
				log.Info("purged expired raw evidence", "count", n)
			}
		}
	}()

	// Policy lifecycle: releases from Postgres become the signed bundle on every replica.
	policies, err := lifecycle.Open(ctx, db, os.Getenv("TENANT_ID"), policy.Files)
	if err != nil {
		fail("policy store", err)
	}
	// The app catalog joins every release (ticket 16): open it before the first bundle is built.
	var feedKey []byte
	if f := os.Getenv("CATALOG_FEED_PUBKEY_FILE"); f != "" {
		if feedKey, err = os.ReadFile(f); err != nil {
			fail("catalog feed key", err)
		}
	}
	apps, err := catalog.Open(ctx, db, os.Getenv("TENANT_ID"), policies)
	if err != nil {
		fail("app catalog", err)
	}
	registry, err := agents.Open(ctx, db, os.Getenv("TENANT_ID"), policies)
	if err != nil {
		fail("agent registry", err)
	}
	bundles := &policysvc.Server{}
	releaser := &lifecycle.Releaser{Store: policies, Server: bundles, FS: policy.Files, SigningKey: string(key), Log: log, Poll: 15 * time.Second}
	if err := releaser.Sync(ctx); err != nil {
		fail("build policy bundle", err)
	}
	go releaser.Run(ctx)
	corpus, err := lifecycle.LoadCorpus(policy.Files)
	if err != nil {
		fail("simulation corpus", err)
	}
	search := &ingest.OpenSearch{URL: os.Getenv("OPENSEARCH_URL"), User: os.Getenv("OPENSEARCH_USER"), Password: os.Getenv("OPENSEARCH_PASSWORD"),
		HTTP: &http.Client{Timeout: time.Minute}}
	simulator := &lifecycle.Simulator{Store: policies, Source: search.Events, Corpus: corpus, MaxEvents: 100_000, Log: log}
	go func() {
		for t := time.NewTicker(time.Hour); ctx.Err() == nil; <-t.C {
			if n, err := registry.Reconcile(ctx); err != nil {
				log.Error("agent owner reconcile", "err", err)
			} else if n > 0 {
				log.Info("agents quarantined: no active owner", "count", n)
			}
			if err := apps.PurgeUsage(ctx, time.Now()); err != nil {
				log.Error("purge app usage", "err", err)
			}
			if url := os.Getenv("CATALOG_FEED_URL"); url != "" {
				if v, err := apps.PullFeed(ctx, &http.Client{Timeout: time.Minute}, url, feedKey); err != nil {
					log.Error("catalog feed pull", "err", err)
				} else if v > 0 {
					log.Info("catalog feed imported", "version", v)
				}
			}
			if expired, notified, err := policies.Sweep(ctx, time.Now()); err != nil {
				log.Error("exception sweep", "err", err)
			} else if expired+notified > 0 {
				log.Info("exception sweep", "expired", expired, "expiry_notices", notified)
			}
		}
	}()

	ids, err := identity.Open(ctx, db, os.Getenv("TENANT_ID"))
	if err != nil {
		fail("identity store", err)
	}
	verify, err := authz.KeycloakVerifier(ctx, os.Getenv("OIDC_ISSUER"), os.Getenv("OIDC_AUDIENCE"))
	if err != nil {
		fail("oidc issuer", err)
	}
	scimHash, err := hex.DecodeString(os.Getenv("SCIM_TOKEN_SHA256"))
	if err != nil || len(scimHash) != sha256.Size {
		fail("SCIM_TOKEN_SHA256 must be a hex SHA-256", err)
	}
	mcpHash, err := hex.DecodeString(os.Getenv("MCP_GATEWAY_TOKEN_SHA256"))
	if err != nil || len(mcpHash) != sha256.Size {
		fail("MCP_GATEWAY_TOKEN_SHA256 must be a hex SHA-256", err)
	}
	breakGlass := map[string]bool{}
	for _, sub := range strings.Split(os.Getenv("BREAK_GLASS_SUBS"), ",") {
		if sub = strings.TrimSpace(sub); sub != "" {
			breakGlass[sub] = true
		}
	}
	var breakGlassRequests atomic.Int64
	rt := authz.NewRouter(&authz.Authenticator{
		Verify:     verify,
		MFAACR:     strings.Split(os.Getenv("OIDC_MFA_ACR"), ","),
		BreakGlass: breakGlass,
		Bindings:   ids.Bindings,
		Audit: func(ctx context.Context, actor, action string, target map[string]any) error {
			if action == "breakglass.request" {
				breakGlassRequests.Add(1)
			}
			_, err := auditLog.Append(ctx, os.Getenv("TENANT_ID"), actor, action, target)
			return err
		},
		StepUpAge: 5 * time.Minute,
		Now:       time.Now,
	})
	metrics := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n, err := incidents.Overdue(r.Context(), time.Now())
		if err != nil {
			http.Error(w, "metrics unavailable", http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "text/plain; version=0.0.4")
		_, _ = fmt.Fprintf(w, "# TYPE incident_ack_overdue gauge\nincident_ack_overdue %d\n", n)
		_, _ = fmt.Fprintf(w, "# TYPE breakglass_requests_total counter\nbreakglass_requests_total %d\n", breakGlassRequests.Load())
		_, _ = fmt.Fprintf(w, "# TYPE policy_release_current gauge\npolicy_release_current %d\n", releaser.Current())
		if n, err := policies.ExpiringSoon(r.Context(), time.Now()); err == nil {
			_, _ = fmt.Fprintf(w, "# TYPE policy_exceptions_expiring gauge\npolicy_exceptions_expiring %d\n", n)
		}
	})
	// One consumer group feeds every control-plane module that learns from decision events.
	kc, err := kgo.NewClient(kgo.SeedBrokers(strings.Split(os.Getenv("KAFKA_BROKERS"), ",")...),
		kgo.ConsumerGroup(consumerGroup), kgo.ConsumeTopics(events.Topic), kgo.DisableAutoCommit())
	if err != nil {
		fail("kafka client", err)
	}
	go func() {
		if err := events.Consume(ctx, kc, &events.Decoder{SR: rc}, log, incidents.Handle, apps.Handle, registry.Handle); err != nil {
			fail("decision event consumer stopped", err)
		}
	}()

	routes(rt, deps{bundles: bundles, scim: ids.SCIMHandler(scimHash, os.Getenv("PUBLIC_URL")), metrics: metrics, mcpObserved: registry.ObservedHandler(mcpHash, time.Now), incidents: incidents, identity: ids,
		policies: policies, simulator: simulator, apps: apps, feedKey: feedKey,
		posture: posture.Sources{Search: search.Search, Apps: apps, Incidents: incidents, Policies: policies, Agents: registry},
		agents:  registry})
	server.Run("control-plane", rt.Mux)
	cancel()
	kc.Close()
}

// consumerGroup is the control-plane's group on the decision event topic (incidents, app usage, shadow agents).
const consumerGroup = "control-plane"
