package events

import (
	"strings"
	"testing"
	"time"

	"github.com/twmb/franz-go/pkg/kgo"
)

// Ticket 46: with no broker, Publish returns at once and the lost event is counted, not waited on.
func TestPublishKafkaDown(t *testing.T) {
	schema, err := Compile(SchemaV1)
	if err != nil {
		t.Fatal(err)
	}
	kc, err := kgo.NewClient(kgo.SeedBrokers("127.0.0.1:1"), kgo.DefaultProduceTopic(Topic),
		kgo.MaxBufferedRecords(1), kgo.RecordDeliveryTimeout(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	p := &Producer{kc: kc, schema: schema, header: []byte{0, 0, 0, 0, 1}}
	defer p.Close()

	e := Event{EventID: "00000000-0000-4000-8000-000000000001", TenantID: "00000000-0000-0000-0000-000000000001",
		TS: "2026-10-10T00:00:00Z", TraceID: strings.Repeat("a", 32), Channel: "ai_gateway", Direction: "request",
		PrincipalID: strings.Repeat("b", 64), AppID: "chatgpt", Action: "allow", ReasonCodes: []string{},
		PolicyVersion: "builtin-1", RiskVersion: "risk-1", Classes: []Class{}, ContentHash: strings.Repeat("c", 64)}
	start := time.Now()
	for range 3 {
		if err := p.Publish(e); err != nil {
			t.Fatal(err)
		}
	}
	if d := time.Since(start); d > 100*time.Millisecond {
		t.Errorf("Publish waited %v on a dead broker", d)
	}
	// Two refused at once (buffer of 1), the buffered one after the delivery timeout.
	deadline := time.Now().Add(10 * time.Second)
	for p.Dropped() < 3 && time.Now().Before(deadline) {
		time.Sleep(50 * time.Millisecond)
	}
	if p.Dropped() != 3 {
		t.Errorf("dropped %d, want 3", p.Dropped())
	}
	var b strings.Builder
	p.WriteMetrics(&b)
	if !strings.Contains(b.String(), "decision_events_dropped_total 3") {
		t.Errorf("metrics: %s", b.String())
	}
	bad := e
	bad.TenantID = ""
	if p.Publish(bad) == nil {
		t.Error("schema-invalid event accepted")
	}
}
