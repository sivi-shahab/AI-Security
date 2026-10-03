package risk

import (
	"math"
	"math/rand/v2"
	"testing"
	"time"
)

var t0 = time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)

func near(a, b float64) bool { return math.Abs(a-b) < 1e-9 }

func TestHalfLifeWeighting(t *testing.T) {
	cases := []struct {
		name   string
		events []struct {
			score float64
			age   time.Duration // before t0
		}
		want float64
	}{
		{"empty", nil, 0},
		{"single", []struct {
			score float64
			age   time.Duration
		}{{80, 0}}, 80},
		// 100 is one half-life older than 40: weights 0.5 and 1 → (50+40)/1.5
		{"one half-life apart", []struct {
			score float64
			age   time.Duration
		}{{100, HalfLife}, {40, 0}}, 60},
		{"two half-lives apart", []struct {
			score float64
			age   time.Duration
		}{{100, 2 * HalfLife}, {0, 0}}, 20},
		{"same time is a plain mean", []struct {
			score float64
			age   time.Duration
		}{{10, time.Hour}, {20, time.Hour}, {90, time.Hour}}, 40},
	}
	for _, c := range cases {
		var a Agg
		for _, e := range c.events {
			a.Add(e.score, t0.Add(-e.age))
		}
		if !near(a.Value(), c.want) {
			t.Errorf("%s: %v, want %v", c.name, a.Value(), c.want)
		}
	}
}

// Late events must give the same answer as in-order ones, and the mean stays within [min, max] of the scores.
func TestOrderIndependentAndBounded(t *testing.T) {
	r := rand.New(rand.NewPCG(1, 2))
	type ev struct {
		s  float64
		at time.Time
	}
	for range 200 {
		evs := make([]ev, 1+r.IntN(30))
		for i := range evs {
			evs[i] = ev{float64(r.IntN(101)), t0.Add(-time.Duration(r.Int64N(int64(200 * 24 * time.Hour))))}
		}
		var inOrder, shuffled Agg
		sorted := append([]ev(nil), evs...)
		for i := range sorted { // insertion sort by time
			for j := i; j > 0 && sorted[j].at.Before(sorted[j-1].at); j-- {
				sorted[j], sorted[j-1] = sorted[j-1], sorted[j]
			}
		}
		lo, hi := 100.0, 0.0
		for _, e := range sorted {
			inOrder.Add(e.s, e.at)
			lo, hi = min(lo, e.s), max(hi, e.s)
		}
		r.Shuffle(len(evs), func(i, j int) { evs[i], evs[j] = evs[j], evs[i] })
		for _, e := range evs {
			shuffled.Add(e.s, e.at)
		}
		if math.Abs(inOrder.Value()-shuffled.Value()) > 1e-6 {
			t.Fatalf("order changed the mean: %v vs %v", inOrder.Value(), shuffled.Value())
		}
		if v := inOrder.Value(); v < lo-1e-9 || v > hi+1e-9 {
			t.Fatalf("mean %v outside [%v, %v]", v, lo, hi)
		}
	}
}
