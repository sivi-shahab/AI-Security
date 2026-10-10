package aigw

import (
	"context"
	"sync"
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
