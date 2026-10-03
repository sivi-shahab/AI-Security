package incident

import (
	"context"
	"encoding/json"
	"log/slog"
	"time"

	"github.com/twmb/franz-go/pkg/kgo"

	"aisec/internal/events"
)

// Group is the incident module's own consumer group on events.Topic (independent of event-ingest).
const Group = "incident"

// Consume folds decision events into incidents until ctx ends. Offsets are committed after each batch is stored;
// Ingest is idempotent per event_id, so redelivery is harmless. Rejected records are counted by event-ingest.
func Consume(ctx context.Context, kc *kgo.Client, dec *events.Decoder, s *Store, log *slog.Logger) error {
	for {
		fetches := kc.PollRecords(ctx, 500)
		if ctx.Err() != nil {
			return nil
		}
		fetches.EachError(func(t string, p int32, err error) { log.Error("fetch", "topic", t, "partition", p, "err", err) })
		var err error
		fetches.EachRecord(func(r *kgo.Record) {
			if err != nil {
				return
			}
			var payload []byte
			var reason string
			if payload, reason, err = dec.Decode(ctx, r.Value); err != nil || reason != "" {
				return
			}
			var e events.Event
			if json.Unmarshal(payload, &e) != nil {
				return
			}
			_, _, err = s.Ingest(ctx, e, payload, time.Now())
		})
		if err != nil {
			return err // registry or database down: restart and redeliver from the last commit
		}
		if err := kc.CommitUncommittedOffsets(ctx); err != nil {
			log.Error("commit", "err", err)
		}
	}
}
