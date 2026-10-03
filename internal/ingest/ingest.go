// Package ingest is the event-ingest consumer: decision events from Kafka, validated against their registered
// schema and the raw-content check, indexed into daily OpenSearch indices (spec §5.1, §10.2).
package ingest

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"github.com/santhosh-tekuri/jsonschema/v6"
	"github.com/twmb/franz-go/pkg/kadm"
	"github.com/twmb/franz-go/pkg/kgo"
	"github.com/twmb/franz-go/pkg/sr"

	"aisec/internal/events"
)

const (
	Group = "event-ingest"
	// Rejections that are not about the payload itself.
	rejectWireFormat    = "wire_format"
	rejectUnknownSchema = "unknown_schema"
)

// Ingester consumes events.Topic. At-least-once: offsets are committed only after OpenSearch accepted the batch,
// and documents are indexed by event_id so redelivery overwrites instead of duplicating.
type Ingester struct {
	KC      *kgo.Client // consumer group Group on events.Topic, autocommit disabled
	SR      *sr.Client
	OS      *OpenSearch
	Metrics *Metrics
	Log     *slog.Logger

	schemas map[int]*jsonschema.Schema // only versions registered under events.Subject
}

// Run consumes until ctx is cancelled.
func (in *Ingester) Run(ctx context.Context) error {
	go in.trackLag(ctx)
	for {
		fetches := in.KC.PollRecords(ctx, 1000)
		if ctx.Err() != nil {
			return nil
		}
		fetches.EachError(func(t string, p int32, err error) { in.Log.Error("fetch", "topic", t, "partition", p, "err", err) })
		var docs []Doc
		var err error
		fetches.EachRecord(func(r *kgo.Record) {
			if err != nil {
				return
			}
			in.Metrics.Consumed.Add(1)
			var d Doc
			if d, err = in.accept(ctx, r); err == nil && d.ID != "" {
				docs = append(docs, d)
			}
		})
		if err != nil {
			return err // registry unreachable: crash and redeliver rather than reject good events
		}
		if err := in.index(ctx, docs); err != nil {
			return err
		}
		if err := in.KC.CommitUncommittedOffsets(ctx); err != nil {
			in.Log.Error("commit", "err", err)
		}
	}
}

// accept returns the document to index, or a zero Doc when the record is rejected (and counted).
func (in *Ingester) accept(ctx context.Context, r *kgo.Record) (Doc, error) {
	var serde sr.ConfluentHeader
	id, payload, err := serde.DecodeID(r.Value)
	if err != nil {
		in.reject(r, rejectWireFormat)
		return Doc{}, nil
	}
	schema, err := in.schema(ctx, id)
	if err != nil {
		return Doc{}, err
	}
	if schema == nil {
		in.reject(r, rejectUnknownSchema)
		return Doc{}, nil
	}
	if reason := events.Check(payload, schema); reason != "" {
		in.reject(r, reason)
		return Doc{}, nil
	}
	var meta struct {
		EventID string    `json:"event_id"`
		TS      time.Time `json:"ts"`
	}
	if err := json.Unmarshal(payload, &meta); err != nil {
		in.reject(r, events.RejectSchema)
		return Doc{}, nil
	}
	return Doc{Index: IndexFor(meta.TS), ID: meta.EventID, Body: payload, Received: r.Timestamp}, nil
}

// reject counts and logs where the record was; never its content.
func (in *Ingester) reject(r *kgo.Record, reason string) {
	in.Metrics.Rejected(reason)
	in.Log.Warn("event rejected", "reason", reason, "partition", r.Partition, "offset", r.Offset)
}

// schema returns the compiled schema for id, nil if id is not a version of events.Subject. Unknown ids trigger
// one refresh, so a newly registered version is picked up without a restart.
func (in *Ingester) schema(ctx context.Context, id int) (*jsonschema.Schema, error) {
	if s, ok := in.schemas[id]; ok {
		return s, nil
	}
	versions, err := in.SR.Schemas(ctx, events.Subject)
	if err != nil {
		return nil, fmt.Errorf("schema registry: %w", err)
	}
	in.schemas = map[int]*jsonschema.Schema{}
	for _, v := range versions {
		s, err := events.Compile(v.Schema.Schema)
		if err != nil {
			return nil, fmt.Errorf("%s v%d: %w", events.Subject, v.Version, err)
		}
		in.schemas[v.ID] = s
	}
	return in.schemas[id], nil
}

// index retries until OpenSearch takes the batch or ctx ends: nothing is committed before that.
func (in *Ingester) index(ctx context.Context, docs []Doc) error {
	for backoff := time.Second; len(docs) > 0; backoff = min(2*backoff, 30*time.Second) {
		failed, err := in.OS.Bulk(ctx, docs)
		if err == nil {
			in.Metrics.Indexed.Add(int64(len(docs) - failed))
			in.Metrics.IndexFailed.Add(int64(failed))
			now := time.Now()
			for _, d := range docs {
				in.Metrics.ObserveDelay(now.Sub(d.Received))
			}
			return nil
		}
		in.Log.Error("bulk index, retrying", "err", err, "docs", len(docs), "backoff", backoff)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(backoff):
		}
	}
	return nil
}

func (in *Ingester) trackLag(ctx context.Context) {
	adm := kadm.NewClient(in.KC)
	for t := time.NewTicker(10 * time.Second); ; {
		lags, err := adm.Lag(ctx, Group)
		if err == nil {
			for _, gl := range lags {
				for topic, parts := range gl.Lag {
					for p, l := range parts {
						in.Metrics.SetLag(topic, p, l.Lag)
					}
				}
			}
		} else if ctx.Err() == nil {
			in.Log.Error("consumer lag", "err", err)
		}
		select {
		case <-ctx.Done():
			t.Stop()
			return
		case <-t.C:
		}
	}
}
