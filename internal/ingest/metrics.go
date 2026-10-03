package ingest

import (
	"fmt"
	"io"
	"net/http"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

// delayBuckets (seconds) for produce-to-indexed delay; the SLO is searchable <= 60 s p95 (+ refresh_interval).
var delayBuckets = []float64{1, 2, 5, 10, 30, 60, 120}

// Metrics is the Prometheus text exposition for ingest. Hand-written: a handful of series do not need client_golang.
type Metrics struct {
	Consumed, Indexed, IndexFailed atomic.Int64

	mu       sync.Mutex
	rejected map[string]int64
	lag      map[lagKey]int64
	delay    []int64 // cumulative per bucket, last = +Inf
	delaySum float64
}

func NewMetrics() *Metrics {
	return &Metrics{rejected: map[string]int64{}, lag: map[lagKey]int64{}, delay: make([]int64, len(delayBuckets)+1)}
}

type lagKey struct {
	topic     string
	partition int32
}

func (m *Metrics) Rejected(reason string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.rejected[reason]++
}

func (m *Metrics) SetLag(topic string, partition int32, lag int64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.lag[lagKey{topic, partition}] = lag
}

func (m *Metrics) ObserveDelay(d time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s := d.Seconds()
	m.delaySum += s
	for i, b := range delayBuckets {
		if s <= b {
			m.delay[i]++
		}
	}
	m.delay[len(delayBuckets)]++
}

func (m *Metrics) ServeHTTP(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4")
	m.write(w)
}

func (m *Metrics) write(w io.Writer) {
	m.mu.Lock()
	defer m.mu.Unlock()
	p := func(format string, a ...any) { _, _ = fmt.Fprintf(w, format+"\n", a...) }
	p("# TYPE events_consumed_total counter\nevents_consumed_total %d", m.Consumed.Load())
	p("# TYPE events_indexed_total counter\nevents_indexed_total %d", m.Indexed.Load())
	p("# TYPE events_index_failed_total counter\nevents_index_failed_total %d", m.IndexFailed.Load())
	p("# TYPE events_rejected_total counter")
	for _, r := range sortedKeys(m.rejected) {
		p("events_rejected_total{reason=%q} %d", r, m.rejected[r])
	}
	p("# TYPE kafka_consumer_lag gauge")
	keys := make([]lagKey, 0, len(m.lag))
	for k := range m.lag {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		return keys[i].topic < keys[j].topic || keys[i].topic == keys[j].topic && keys[i].partition < keys[j].partition
	})
	for _, k := range keys {
		p("kafka_consumer_lag{group=%q,topic=%q,partition=\"%d\"} %d", Group, k.topic, k.partition, m.lag[k])
	}
	p("# TYPE event_index_delay_seconds histogram")
	for i, b := range delayBuckets {
		p("event_index_delay_seconds_bucket{le=\"%g\"} %d", b, m.delay[i])
	}
	p("event_index_delay_seconds_bucket{le=\"+Inf\"} %d", m.delay[len(delayBuckets)])
	p("event_index_delay_seconds_sum %g", m.delaySum)
	p("event_index_delay_seconds_count %d", m.delay[len(delayBuckets)])
}

func sortedKeys(m map[string]int64) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
