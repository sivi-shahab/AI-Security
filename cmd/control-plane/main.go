package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/twmb/franz-go/pkg/kgo"
	"github.com/twmb/franz-go/pkg/sr"

	"aisec/internal/audit"
	"aisec/internal/events"
	"aisec/internal/incident"
	"aisec/internal/policysvc"
	"aisec/internal/privacy"
	"aisec/internal/server"
	"aisec/policy"
)

// Env: BUNDLE_SIGNING_KEY_FILE, DATABASE_URL, INCIDENT_KEK_FILE (32 raw bytes), KAFKA_BROKERS, SCHEMA_REGISTRY_URL,
// AUTH_MODE (only "trusted-proxy" admits API calls until SSO lands, see internal/incident/api.go).
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
	tarball, rev, err := policysvc.Build(ctx, policy.Files, string(key))
	if err != nil {
		fail("build policy bundle", err)
	}
	bundles := &policysvc.Server{}
	bundles.Publish(tarball, rev)
	log.Info("policy bundle published", "revision", rev)

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
	kc, err := kgo.NewClient(kgo.SeedBrokers(strings.Split(os.Getenv("KAFKA_BROKERS"), ",")...),
		kgo.ConsumerGroup(incident.Group), kgo.ConsumeTopics(events.Topic), kgo.DisableAutoCommit())
	if err != nil {
		fail("kafka client", err)
	}
	rc, err := sr.NewClient(sr.URLs(os.Getenv("SCHEMA_REGISTRY_URL")))
	if err != nil {
		fail("schema registry client", err)
	}
	go func() {
		if err := incident.Consume(ctx, kc, &events.Decoder{SR: rc}, incidents, log); err != nil {
			fail("incident consumer stopped", err)
		}
	}()
	go func() {
		for t := time.NewTicker(time.Hour); ctx.Err() == nil; <-t.C {
			if n, err := incidents.PurgeExpired(ctx, time.Now()); err != nil {
				log.Error("purge expired evidence", "err", err)
			} else if n > 0 {
				log.Info("purged expired raw evidence", "count", n)
			}
		}
	}()

	mux := http.NewServeMux()
	mux.Handle("GET /bundles/aisec.tar.gz", bundles)
	incident.Routes(mux, incidents, os.Getenv("AUTH_MODE"), time.Now)
	mux.HandleFunc("GET /metrics", func(w http.ResponseWriter, r *http.Request) {
		n, err := incidents.Overdue(r.Context(), time.Now())
		if err != nil {
			http.Error(w, "metrics unavailable", http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "text/plain; version=0.0.4")
		_, _ = fmt.Fprintf(w, "# TYPE incident_ack_overdue gauge\nincident_ack_overdue %d\n", n)
	})
	server.Run("control-plane", mux)
	cancel()
	kc.Close()
}
