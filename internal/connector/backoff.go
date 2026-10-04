package connector

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// Backoff retries throttled API calls: Retry-After when the service gives one, otherwise exponential from Base;
// never longer than Max per wait, at most Retries retries.
type Backoff struct {
	Retries int
	Base    time.Duration
	Max     time.Duration
	Sleep   func(ctx context.Context, d time.Duration) error // nil = real sleep
}

// DefaultBackoff suits SaaS APIs with per-minute quotas.
var DefaultBackoff = Backoff{Retries: 6, Base: time.Second, Max: 2 * time.Minute}

// StatusError is an answer the caller does not retry. Throttled: retries were exhausted.
type StatusError struct {
	Code      int
	Throttled bool
	What      string
}

func (e *StatusError) Error() string {
	if e.Throttled {
		return fmt.Sprintf("status %d, still throttled after retries: %s", e.Code, e.What)
	}
	return fmt.Sprintf("status %d: %s", e.Code, e.What)
}

// Do sends the request newReq builds (anew for every attempt) and returns the first answer below 300. retry
// decides which answers are throttling (nil: 429, 503, 504); it may read the body only if it says false.
func (b Backoff) Do(ctx context.Context, c *http.Client, newReq func() (*http.Request, error), retry func(*http.Response) bool) (*http.Response, error) {
	if retry == nil {
		retry = Throttled
	}
	for attempt := 0; ; attempt++ {
		req, err := newReq()
		if err != nil {
			return nil, err
		}
		resp, err := c.Do(req)
		if err != nil {
			return nil, err
		}
		what := req.Method + " " + req.URL.Scheme + "://" + req.URL.Host + req.URL.Path
		if !retry(resp) {
			if resp.StatusCode >= 300 {
				_ = resp.Body.Close()
				return nil, &StatusError{Code: resp.StatusCode, What: what}
			}
			return resp, nil
		}
		_ = resp.Body.Close()
		if attempt >= b.Retries {
			return nil, &StatusError{Code: resp.StatusCode, Throttled: true, What: what}
		}
		if err := b.sleep(ctx, b.wait(resp.Header.Get("Retry-After"), attempt)); err != nil {
			return nil, err
		}
	}
}

// Throttled: 429, 503, 504 (and Anthropic's 529).
func Throttled(r *http.Response) bool {
	switch r.StatusCode {
	case http.StatusTooManyRequests, http.StatusServiceUnavailable, http.StatusGatewayTimeout, 529:
		return true
	}
	return false
}

func (b Backoff) wait(retryAfter string, attempt int) time.Duration {
	d := b.Base << attempt
	if s, err := strconv.Atoi(strings.TrimSpace(retryAfter)); err == nil && s >= 0 {
		d = time.Duration(s) * time.Second
	} else if t, err := http.ParseTime(retryAfter); err == nil {
		d = time.Until(t)
	}
	return min(max(d, 0), b.Max)
}

func (b Backoff) sleep(ctx context.Context, d time.Duration) error {
	if b.Sleep != nil {
		return b.Sleep(ctx, d)
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}
