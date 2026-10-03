package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"aisec/internal/events"
	"aisec/internal/mcpgw"
	"aisec/internal/privacy"
	"aisec/internal/server"
)

// Env: MCP_BASE_URL (public origin agents call), OIDC_ISSUER (Keycloak realm), MCP_SERVERS_FILE (JSON list of
// mcpgw.Server), STS_TOKEN_URL (default: the realm's token endpoint), STS_CLIENT_ID, STS_CLIENT_SECRET,
// OPA_URL (default http://127.0.0.1:8181, the sidecar), KAFKA_BROKERS, SCHEMA_REGISTRY_URL, TENANT_ID,
// TENANT_PEPPER, MCP_DEFAULT_RATE (tools/call per minute per agent and tool, default 60).
func main() {
	log := privacy.NewLogger("mcp-gateway")
	fail := func(msg string, err error) {
		log.Error(msg, "err", err)
		os.Exit(1)
	}
	ctx := context.Background()
	env := func(k, def string) string {
		if v := os.Getenv(k); v != "" {
			return v
		}
		return def
	}
	for _, k := range []string{"MCP_BASE_URL", "OIDC_ISSUER", "MCP_SERVERS_FILE", "STS_CLIENT_ID", "STS_CLIENT_SECRET", "TENANT_ID", "TENANT_PEPPER"} {
		if os.Getenv(k) == "" {
			fail("config", errors.New(k+" is required"))
		}
	}

	var list []mcpgw.Server
	b, err := os.ReadFile(os.Getenv("MCP_SERVERS_FILE"))
	if err == nil {
		err = json.Unmarshal(b, &list)
	}
	if err != nil {
		fail("MCP_SERVERS_FILE", err)
	}
	servers := map[string]mcpgw.Server{}
	for _, s := range list {
		if s.Name == "" || s.Upstream == "" || s.Audience == "" || s.AppID == "" || s.Sanction == "" || s.Region == "" {
			fail("MCP_SERVERS_FILE", errors.New("every server needs name, upstream, audience, app_id, sanction, region"))
		}
		servers[s.Name] = s
	}

	issuer := os.Getenv("OIDC_ISSUER")
	verify, err := mcpgw.NewVerifier(ctx, issuer)
	if err != nil {
		fail("OIDC discovery", err)
	}
	rate, err := strconv.Atoi(env("MCP_DEFAULT_RATE", "60"))
	if err != nil || rate < 1 {
		fail("MCP_DEFAULT_RATE", errors.New("positive integer"))
	}
	producer, err := events.NewProducer(ctx, strings.Split(os.Getenv("KAFKA_BROKERS"), ","), os.Getenv("SCHEMA_REGISTRY_URL"))
	if err != nil {
		fail("event producer", err)
	}
	defer producer.Close()

	opa := &mcpgw.OPA{URL: env("OPA_URL", "http://127.0.0.1:8181"), HTTP: &http.Client{Timeout: 2 * time.Second}}
	sts := &mcpgw.STS{URL: env("STS_TOKEN_URL", issuer+"/protocol/openid-connect/token"), ClientID: os.Getenv("STS_CLIENT_ID"),
		ClientSecret: os.Getenv("STS_CLIENT_SECRET"), HTTP: &http.Client{Timeout: 5 * time.Second}, Now: time.Now}
	gw := &mcpgw.Gateway{
		BaseURL: strings.TrimSuffix(os.Getenv("MCP_BASE_URL"), "/"), Issuer: issuer, Servers: servers,
		Verify: verify, Exchange: sts.Exchange, Agent: opa.Agent, Decide: opa.Decide,
		Emit: func(ctx context.Context, e events.Event) error {
			ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
			defer cancel()
			return producer.Publish(ctx, e)
		},
		// SSE streams stay open as long as the tool server keeps them: bound the wait for headers, not the body.
		Upstream: &http.Client{Transport: &http.Transport{Proxy: http.ProxyFromEnvironment, ResponseHeaderTimeout: 30 * time.Second}},
		Pepper:   []byte(os.Getenv("TENANT_PEPPER")), TenantID: os.Getenv("TENANT_ID"), DefaultRate: rate,
		Now: time.Now, Log: log,
	}
	mux := http.NewServeMux()
	gw.Routes(mux)
	server.Run("mcp-gateway", mux)
}
