package catalog

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/twmb/franz-go/pkg/kgo"

	"aisec/internal/events"
)

// Group is the catalog's consumer group for APP_USAGE_DAILY.
const Group = "catalog-usage"

// Consume counts decision events into daily usage until ctx ends; offsets are committed after each batch.
func Consume(ctx context.Context, kc *kgo.Client, dec *events.Decoder, s *Store, log *slog.Logger) error {
	for {
		fetches := kc.PollRecords(ctx, 1000)
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
			if json.Unmarshal(payload, &e) == nil {
				err = s.Record(ctx, e)
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

// PullFeed fetches url and url+".sig" and imports the feed if it verifies and is newer. Feeds are pull-only
// (ADR-0001); an unchanged feed is not an error.
func (s *Store) PullFeed(ctx context.Context, client *http.Client, url string, pubPEM []byte) (int64, error) {
	get := func(u string) ([]byte, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		if err != nil {
			return nil, err
		}
		resp, err := client.Do(req)
		if err != nil {
			return nil, err
		}
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode != http.StatusOK {
			return nil, errors.New(u + ": " + resp.Status)
		}
		return io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	}
	raw, err := get(url)
	if err != nil {
		return 0, err
	}
	sig, err := get(url + ".sig")
	if err != nil {
		return 0, err
	}
	v, err := s.ImportSigned(ctx, "feed-pull", raw, string(sig), pubPEM)
	if errors.Is(err, ErrStale) {
		return 0, nil
	}
	return v, err
}

// PollEvery is how often the feed URL is checked.
const PollEvery = time.Hour
