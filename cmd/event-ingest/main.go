package main

import (
	"context"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/twmb/franz-go/pkg/kgo"
	"github.com/twmb/franz-go/pkg/sr"

	"aisec/internal/events"
	"aisec/internal/ingest"
	"aisec/internal/privacy"
	"aisec/internal/server"
)

// Env: KAFKA_BROKERS (comma-separated), SCHEMA_REGISTRY_URL, OPENSEARCH_URL, OPENSEARCH_USER, OPENSEARCH_PASSWORD.
func main() {
	log := privacy.NewLogger("event-ingest")
	fail := func(msg string, err error) {
		log.Error(msg, "err", err)
		os.Exit(1)
	}
	ctx, cancel := context.WithCancel(context.Background())

	kc, err := kgo.NewClient(
		kgo.SeedBrokers(strings.Split(os.Getenv("KAFKA_BROKERS"), ",")...),
		kgo.ConsumerGroup(ingest.Group),
		kgo.ConsumeTopics(events.Topic),
		kgo.DisableAutoCommit(),
	)
	if err != nil {
		fail("kafka client", err)
	}
	rc, err := sr.NewClient(sr.URLs(os.Getenv("SCHEMA_REGISTRY_URL")))
	if err != nil {
		fail("schema registry client", err)
	}
	search := &ingest.OpenSearch{
		URL: os.Getenv("OPENSEARCH_URL"), User: os.Getenv("OPENSEARCH_USER"), Password: os.Getenv("OPENSEARCH_PASSWORD"),
		HTTP: &http.Client{Timeout: 30 * time.Second},
	}
	if err := search.Setup(ctx); err != nil {
		fail("opensearch setup", err)
	}

	metrics := ingest.NewMetrics()
	in := &ingest.Ingester{KC: kc, SR: rc, OS: search, Metrics: metrics, Log: log}
	go func() {
		// Any error here is one retrying cannot fix in-process: restart and redeliver from the last commit.
		if err := in.Run(ctx); err != nil {
			fail("ingest stopped", err)
		}
	}()

	mux := http.NewServeMux()
	mux.Handle("GET /metrics", metrics)
	server.Run("event-ingest", mux)
	cancel()
	kc.Close()
}
