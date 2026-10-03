package siem

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"sort"
	"sync"
	"time"
)

// DLQ stores what could not be delivered: the record (already sanitized), the sink and why. Operators replay it.
type DLQ func(ctx context.Context, sink string, rec Record, reason string) error

// Deliverer sends every record to every sink: Check first, then retries with exponential backoff, then the DLQ.
// Deliver returns an error only when even the DLQ write failed; then the caller must not advance its cursor.
type Deliverer struct {
	Sinks       []Sink
	DLQ         DLQ
	MaxAttempts int
	Backoff     time.Duration // first retry delay, doubled each time
	Log         *slog.Logger
	Metrics     *Metrics
}

func (d *Deliverer) Deliver(ctx context.Context, recs []Record) error {
	var ok []Record
	for _, r := range recs {
		if err := r.Check(); err != nil {
			for _, s := range d.Sinks {
				if err := d.dead(ctx, s.Name(), r, err.Error()); err != nil {
					return err
				}
			}
			continue
		}
		ok = append(ok, r)
	}
	if len(ok) == 0 {
		return nil
	}
	for _, s := range d.Sinks {
		err := d.send(ctx, s, ok)
		if err == nil {
			d.Metrics.add(&d.Metrics.sent, s.Name(), len(ok))
			continue
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		for _, r := range ok {
			if err := d.dead(ctx, s.Name(), r, err.Error()); err != nil {
				return err
			}
		}
	}
	return nil
}

func (d *Deliverer) send(ctx context.Context, s Sink, recs []Record) error {
	backoff := d.Backoff
	var err error
	for attempt := 1; attempt <= d.MaxAttempts; attempt++ {
		if err = s.Send(ctx, recs); err == nil {
			return nil
		}
		var perm *PermanentError
		if errors.As(err, &perm) || attempt == d.MaxAttempts {
			break
		}
		d.Metrics.add(&d.Metrics.retried, s.Name(), 1)
		d.Log.Warn("siem send failed, retrying", "sink", s.Name(), "attempt", attempt, "err", err)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(backoff):
		}
		backoff *= 2
	}
	return err
}

func (d *Deliverer) dead(ctx context.Context, sink string, r Record, reason string) error {
	d.Metrics.add(&d.Metrics.dead, sink, 1)
	d.Log.Error("siem record dead-lettered", "sink", sink, "id", r.ID, "reason", reason)
	if err := d.DLQ(ctx, sink, r, reason); err != nil {
		return fmt.Errorf("dead-letter %s: %w", r.ID, err)
	}
	return nil
}

// DLQMessage is what a DLQ stores.
func DLQMessage(sink string, r Record, reason string) []byte {
	b, _ := json.Marshal(map[string]any{"sink": sink, "reason": reason, "at": time.Now().UTC(), "record": r})
	return b
}

// Metrics is the Prometheus exposition for siem-export.
type Metrics struct {
	mu                  sync.Mutex
	sent, retried, dead map[string]int64
	AuditCursor         func() int64 // last exported audit seq
	AuditLag            func() int64 // audit entries not yet exported
}

func NewMetrics() *Metrics {
	return &Metrics{sent: map[string]int64{}, retried: map[string]int64{}, dead: map[string]int64{}}
}

func (m *Metrics) add(c *map[string]int64, sink string, n int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	(*c)[sink] += int64(n)
}

func (m *Metrics) Write(w io.Writer) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, c := range []struct {
		name string
		v    map[string]int64
	}{{"siem_records_sent_total", m.sent}, {"siem_send_retries_total", m.retried}, {"siem_records_dead_lettered_total", m.dead}} {
		_, _ = fmt.Fprintf(w, "# TYPE %s counter\n", c.name)
		keys := make([]string, 0, len(c.v))
		for k := range c.v {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			_, _ = fmt.Fprintf(w, "%s{sink=%q} %d\n", c.name, k, c.v[k])
		}
	}
	if m.AuditCursor != nil {
		_, _ = fmt.Fprintf(w, "# TYPE siem_audit_cursor gauge\nsiem_audit_cursor %d\n", m.AuditCursor())
		_, _ = fmt.Fprintf(w, "# TYPE siem_audit_lag gauge\nsiem_audit_lag %d\n", m.AuditLag())
	}
}
