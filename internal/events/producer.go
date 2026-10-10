package events

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/santhosh-tekuri/jsonschema/v6"
	"github.com/twmb/franz-go/pkg/kgo"
	"github.com/twmb/franz-go/pkg/sr"
)

// Producer publishes decision events in the registry wire format (magic byte + schema id + JSON).
type Producer struct {
	kc     *kgo.Client
	schema *jsonschema.Schema
	header []byte

	dropped atomic.Int64
}

// Buffer while Kafka is unreachable: ~8 min at the ASM-2 peak of 20 RPS, a few tens of MB. Older records fail after
// the delivery timeout and newer ones are refused when the buffer is full; both count as dropped.
const (
	maxBuffered     = 10000
	deliveryTimeout = 30 * time.Second
)

// NewProducer registers SchemaV1 under Subject (idempotent: same schema, same id) and connects to Kafka with opts
// (KafkaOpts: brokers, TLS, SASL).
func NewProducer(ctx context.Context, registryURL string, opts ...kgo.Opt) (*Producer, error) {
	schema, err := Compile(SchemaV1)
	if err != nil {
		return nil, err
	}
	rc, err := sr.NewClient(sr.URLs(registryURL))
	if err != nil {
		return nil, err
	}
	ss, err := rc.CreateSchema(ctx, Subject, sr.Schema{Schema: SchemaV1, Type: sr.TypeJSON})
	if err != nil {
		return nil, fmt.Errorf("register %s: %w", Subject, err)
	}
	var serde sr.ConfluentHeader
	header, err := serde.AppendEncode(nil, ss.ID, nil)
	if err != nil {
		return nil, err
	}
	kc, err := kgo.NewClient(append([]kgo.Opt{kgo.DefaultProduceTopic(Topic),
		kgo.MaxBufferedRecords(maxBuffered), kgo.RecordDeliveryTimeout(deliveryTimeout)}, opts...)...)
	if err != nil {
		return nil, err
	}
	return &Producer{kc: kc, schema: schema, header: header}, nil
}

// Publish validates e and queues it, keyed by tenant (spec §10.1); trace_id travels in the event itself. It never
// waits on Kafka (ticket 46): an event bus outage must not stop the data plane. Delivery failures surface as
// decision_events_dropped_total, not as an error here; the returned error is only a schema rejection.
func (p *Producer) Publish(e Event) error {
	b, err := Marshal(e, p.schema)
	if err != nil {
		return err
	}
	rec := &kgo.Record{Key: []byte(e.TenantID), Value: append(append([]byte(nil), p.header...), b...)}
	// Not the request's context: it ends with the response, long before the record is delivered.
	p.kc.TryProduce(context.Background(), rec, func(_ *kgo.Record, err error) {
		if err != nil {
			p.dropped.Add(1)
		}
	})
	return nil
}

// Dropped is how many accepted events never reached Kafka.
func (p *Producer) Dropped() int64 { return p.dropped.Load() }

// WriteMetrics appends the producer's counters in Prometheus text format.
func (p *Producer) WriteMetrics(w io.Writer) {
	_, _ = fmt.Fprintf(w, "# TYPE decision_events_dropped_total counter\ndecision_events_dropped_total %d\n", p.Dropped())
}

// ServeMetrics is WriteMetrics as a handler, for a PEP without metrics of its own.
func (p *Producer) ServeMetrics(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4")
	p.WriteMetrics(w)
}

// Close delivers what is still buffered, for up to 5 s, then disconnects.
func (p *Producer) Close() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = p.kc.Flush(ctx)
	p.kc.Close()
}
