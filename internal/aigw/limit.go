package aigw

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/redis/go-redis/v9"
)

// Counter adds n to a counter that expires ttl after it was created, and returns the new total (n = 0 reads it).
// Rate limits and token quotas are fixed windows built on it (FR-PSEC-9).
type Counter func(ctx context.Context, key string, n int64, ttl time.Duration) (int64, error)

// RedisCounter shares the windows between gateway replicas.
func RedisCounter(rdb *redis.Client) Counter {
	return func(ctx context.Context, key string, n int64, ttl time.Duration) (int64, error) {
		v, err := rdb.IncrBy(ctx, "aigw:"+key, n).Result()
		if err == nil && v == n && n > 0 {
			err = rdb.Expire(ctx, "aigw:"+key, ttl).Err() // first write of the window
		}
		return v, err
	}
}

// MemoryCounter is for tests and a single replica. ponytail: per process; use RedisCounter with more replicas.
func MemoryCounter(now func() time.Time) Counter {
	var mu sync.Mutex
	type entry struct {
		v   int64
		exp time.Time
	}
	m := map[string]entry{}
	return func(_ context.Context, key string, n int64, ttl time.Duration) (int64, error) {
		mu.Lock()
		defer mu.Unlock()
		t := now()
		e := m[key]
		if !e.exp.After(t) {
			e = entry{exp: t.Add(ttl)}
			for k, x := range m { // windows are short: sweep expired ones as we go
				if !x.exp.After(t) {
					delete(m, k)
				}
			}
		}
		e.v += n
		m[key] = e
		return e.v, nil
	}
}

// Degraded serves Primary (Redis) and, when it fails, Local (per replica) for Cooldown before Primary is tried
// again (ticket 48): a Redis outage costs one short timeout per Cooldown, not one per request, and limits stay
// enforced per replica instead of not at all.
type Degraded struct {
	Primary, Local Counter
	Cooldown       time.Duration
	Now            func() time.Time
	Log            *slog.Logger

	until    atomic.Int64 // unix nanos: Local only until then
	failures atomic.Int64
}

func (d *Degraded) Count(ctx context.Context, key string, n int64, ttl time.Duration) (int64, error) {
	now := d.Now()
	if now.UnixNano() < d.until.Load() {
		return d.Local(ctx, key, n, ttl)
	}
	v, err := d.Primary(ctx, key, n, ttl)
	if err == nil || ctx.Err() != nil { // the caller gave up: not the counter's fault
		return v, err
	}
	d.failures.Add(1)
	if old := d.until.Load(); d.until.CompareAndSwap(old, now.Add(d.Cooldown).UnixNano()) && old < now.UnixNano() {
		d.Log.Error("rate counter unavailable, limiting per replica", "err", err, "retry_in", d.Cooldown) // once per cooldown
	}
	return d.Local(ctx, key, n, ttl)
}

// WriteMetrics appends rate_counter_unavailable_total: shared counter calls that fell back to the replica's own.
func (d *Degraded) WriteMetrics(w io.Writer) {
	_, _ = fmt.Fprintf(w, "# TYPE aigw_rate_counter_unavailable_total counter\naigw_rate_counter_unavailable_total %d\n", d.failures.Load())
}
