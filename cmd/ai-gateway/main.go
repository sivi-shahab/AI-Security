package main

import (
	"context"
	"errors"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"

	"aisec/internal/aigw"
	"aisec/internal/events"
	"aisec/internal/mcpgw"
	"aisec/internal/privacy"
	"aisec/internal/server"
)

// Env: AIGW_CONFIG_FILE (aigw.Config: apps with gateway key hashes and limits, providers with vault key files),
// OPA_URL (default http://127.0.0.1:8181, the sidecar), KAFKA_BROKERS, SCHEMA_REGISTRY_URL, TENANT_ID,
// TENANT_PEPPER, REDIS_URL (rate limits and token quotas shared across replicas; without it, per replica).
func main() {
	log := privacy.NewLogger("ai-gateway")
	fail := func(msg string, err error) {
		log.Error(msg, "err", err)
		os.Exit(1)
	}
	ctx := context.Background()
	for _, k := range []string{"AIGW_CONFIG_FILE", "TENANT_ID", "TENANT_PEPPER"} {
		if os.Getenv(k) == "" {
			fail("config", errors.New(k+" is required"))
		}
	}
	raw, err := os.ReadFile(os.Getenv("AIGW_CONFIG_FILE"))
	if err != nil {
		fail("AIGW_CONFIG_FILE", err)
	}
	cfg, err := aigw.ParseConfig(raw)
	if err != nil {
		fail("AIGW_CONFIG_FILE", err)
	}
	providers := map[string]aigw.Provider{}
	for _, p := range cfg.Providers {
		providers[p.Name] = p
	}
	producer, err := events.NewProducer(ctx, strings.Split(os.Getenv("KAFKA_BROKERS"), ","), os.Getenv("SCHEMA_REGISTRY_URL"))
	if err != nil {
		fail("event producer", err)
	}
	defer producer.Close()
	count := aigw.MemoryCounter(time.Now)
	if u := os.Getenv("REDIS_URL"); u != "" {
		opt, err := redis.ParseURL(u)
		if err != nil {
			fail("REDIS_URL", err)
		}
		count = aigw.RedisCounter(redis.NewClient(opt))
	}
	opaURL := os.Getenv("OPA_URL")
	if opaURL == "" {
		opaURL = "http://127.0.0.1:8181"
	}
	opa := &mcpgw.OPA{URL: opaURL, HTTP: &http.Client{Timeout: 2 * time.Second}}
	gw := &aigw.Gateway{
		Apps: cfg.Apps, Providers: providers, Decide: opa.Decide, Key: (&aigw.KeyFiles{}).Key, Count: count,
		Emit: func(ctx context.Context, e events.Event) error {
			ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
			defer cancel()
			return producer.Publish(ctx, e)
		},
		// Models take their time: bound the wait for response headers, generously.
		Upstream: &http.Client{Transport: &http.Transport{Proxy: http.ProxyFromEnvironment, ResponseHeaderTimeout: 120 * time.Second}},
		Pepper:   []byte(os.Getenv("TENANT_PEPPER")), TenantID: os.Getenv("TENANT_ID"), Now: time.Now, Log: log,
	}
	mux := http.NewServeMux()
	gw.Routes(mux)
	server.Run("ai-gateway", mux)
}
