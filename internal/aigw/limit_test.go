package aigw

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"
)

// Ticket 48: a failing shared counter is skipped for the cooldown, limits keep counting per replica.
func TestDegradedCounter(t *testing.T) {
	now := time.Date(2026, 10, 11, 9, 0, 0, 0, time.UTC)
	clock := func() time.Time { return now }
	down, calls := false, 0
	primary := func(ctx context.Context, key string, n int64, ttl time.Duration) (int64, error) {
		calls++
		if down {
			return 0, errors.New("dial tcp: i/o timeout")
		}
		return 100 + n, nil
	}
	d := &Degraded{Primary: primary, Local: MemoryCounter(clock), Cooldown: 5 * time.Second, Now: clock,
		Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	ctx := context.Background()

	if v, err := d.Count(ctx, "k", 1, time.Minute); err != nil || v != 101 {
		t.Fatalf("healthy: %d %v", v, err)
	}
	down = true
	for i := 1; i <= 3; i++ {
		if v, err := d.Count(ctx, "k", 1, time.Minute); err != nil || v != int64(i) {
			t.Fatalf("degraded call %d: %d %v", i, v, err)
		}
	}
	if calls != 2 {
		t.Errorf("primary called %d times, want 2 (one failure, then skipped)", calls)
	}
	now = now.Add(6 * time.Second)
	down = false
	if v, _ := d.Count(ctx, "k", 1, time.Minute); v != 101 || calls != 3 {
		t.Errorf("after cooldown: %d, %d calls", v, calls)
	}
	// A caller that gave up is not a counter outage.
	down = true
	cctx, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := d.Count(cctx, "k", 1, time.Minute); err == nil {
		t.Error("canceled caller got a value")
	}
	var b strings.Builder
	d.WriteMetrics(&b)
	if !strings.Contains(b.String(), "aigw_rate_counter_unavailable_total 1\n") {
		t.Errorf("metrics: %s", b.String())
	}
}
