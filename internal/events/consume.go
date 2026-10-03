package events

import (
	"context"
	"encoding/json"
	"log/slog"

	"github.com/twmb/franz-go/pkg/kgo"
)

// Handler processes one accepted decision event; payload is the validated JSON as received. Handlers must be
// idempotent per event_id: a batch is redelivered when any handler fails.
type Handler func(ctx context.Context, e Event, payload []byte) error

// Consume feeds every accepted event of the client's topics to each handler in order, and commits offsets after
// the whole batch is handled. Rejected records are skipped (event-ingest counts them). An error from the registry
// or a handler stops consumption: restart and redeliver from the last commit rather than lose events.
func Consume(ctx context.Context, kc *kgo.Client, dec *Decoder, log *slog.Logger, handlers ...Handler) error {
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
			var e Event
			if json.Unmarshal(payload, &e) != nil {
				return
			}
			for _, h := range handlers {
				if err = h(ctx, e, payload); err != nil {
					return
				}
			}
		})
		if err != nil {
			return err
		}
		if err := kc.CommitUncommittedOffsets(ctx); err != nil {
			log.Error("commit", "err", err)
		}
	}
}
