package events

import (
	"context"
	"fmt"

	"github.com/santhosh-tekuri/jsonschema/v6"
	"github.com/twmb/franz-go/pkg/sr"
)

// Rejections that are about the record, not the payload.
const (
	RejectWireFormat    = "wire_format"
	RejectUnknownSchema = "unknown_schema"
)

// Decoder turns a Kafka record value into a validated event payload. Every consumer of Topic uses it, so they all
// accept exactly the same events. Not safe for concurrent use: one per consumer loop.
type Decoder struct {
	SR      *sr.Client
	schemas map[int]*jsonschema.Schema // only versions registered under Subject
}

// Decode returns the JSON payload, or a rejection reason (see Reject*). err is only for an unreachable registry:
// the caller must retry, not reject, so a registry outage never drops valid events.
func (d *Decoder) Decode(ctx context.Context, value []byte) (payload []byte, reason string, err error) {
	var serde sr.ConfluentHeader
	id, payload, err := serde.DecodeID(value)
	if err != nil {
		return nil, RejectWireFormat, nil
	}
	schema, err := d.schema(ctx, id)
	if err != nil {
		return nil, "", err
	}
	if schema == nil {
		return nil, RejectUnknownSchema, nil
	}
	if reason := Check(payload, schema); reason != "" {
		return nil, reason, nil
	}
	return payload, "", nil
}

// schema returns the compiled schema for id, nil if id is not a version of Subject (a looser schema registered
// elsewhere must not let events through). Unknown ids trigger one refresh, so new versions need no restart.
func (d *Decoder) schema(ctx context.Context, id int) (*jsonschema.Schema, error) {
	if s, ok := d.schemas[id]; ok {
		return s, nil
	}
	versions, err := d.SR.Schemas(ctx, Subject)
	if err != nil {
		return nil, fmt.Errorf("schema registry: %w", err)
	}
	d.schemas = map[int]*jsonschema.Schema{}
	for _, v := range versions {
		s, err := Compile(v.Schema.Schema)
		if err != nil {
			return nil, fmt.Errorf("%s v%d: %w", Subject, v.Version, err)
		}
		d.schemas[v.ID] = s
	}
	return d.schemas[id], nil
}
