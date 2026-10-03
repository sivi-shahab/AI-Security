package events

import (
	"context"
	"fmt"

	"github.com/santhosh-tekuri/jsonschema/v6"
	"github.com/twmb/franz-go/pkg/kgo"
	"github.com/twmb/franz-go/pkg/sr"
)

// Producer publishes decision events in the registry wire format (magic byte + schema id + JSON).
type Producer struct {
	kc     *kgo.Client
	schema *jsonschema.Schema
	header []byte
}

// NewProducer registers SchemaV1 under Subject (idempotent: same schema, same id) and connects to Kafka.
func NewProducer(ctx context.Context, brokers []string, registryURL string, opts ...kgo.Opt) (*Producer, error) {
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
	kc, err := kgo.NewClient(append([]kgo.Opt{kgo.SeedBrokers(brokers...), kgo.DefaultProduceTopic(Topic)}, opts...)...)
	if err != nil {
		return nil, err
	}
	return &Producer{kc: kc, schema: schema, header: header}, nil
}

// Publish validates and writes e synchronously, keyed by tenant (spec §10.1). trace_id travels in the event itself.
func (p *Producer) Publish(ctx context.Context, e Event) error {
	b, err := Marshal(e, p.schema)
	if err != nil {
		return err
	}
	rec := &kgo.Record{Key: []byte(e.TenantID), Value: append(append([]byte(nil), p.header...), b...)}
	return p.kc.ProduceSync(ctx, rec).FirstErr()
}

func (p *Producer) Close() { p.kc.Close() }
