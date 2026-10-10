package evalcorpus

import (
	"fmt"
	"io"
	"maps"
	"math"
	"slices"
	"sort"
	"strings"
	"time"

	"aisec/internal/detect"
)

// L2Answer is what the L2 model said about one text, and how long the call took.
type L2Answer struct {
	Entities  []detect.L2Entity
	Injection *detect.L2Injection
	Latency   time.Duration
}

// L2Scores are the §9.4 metrics for the L2 model on a holdout: alone, and merged with L1 as enforce mode would.
type L2Scores struct {
	NER         map[string]*Counts // L2 alone, span level, against the full gold (names and addresses included)
	Merged      map[string]*Counts // L1 + L2 (detect.WithL2)
	L1          map[string]*Counts // L1 alone against the same gold, for comparison
	NERECE      float64            // calibration of reported entity confidence (correct = same type, overlapping gold)
	NEREntities int
	Threshold   float64
	InjECE      float64           // calibration of the injection score over attacks and benign texts
	Injection   map[string][2]int // per technique: flagged, total
	FPR         float64           // benign flagged
	HardFPR     float64
	Benign      int
	Hards       int
	Latency     []time.Duration
	Calls       int
}

// ECE is the expected calibration error over equal-width bins: Σ |bin| / n · |accuracy − mean confidence|.
func ECE(conf []float64, correct []bool, bins int) float64 {
	type bin struct{ n, ok, c float64 }
	bs := make([]bin, bins)
	for i, c := range conf {
		k := min(int(c*float64(bins)), bins-1)
		bs[k].n++
		bs[k].c += c
		if correct[i] {
			bs[k].ok++
		}
	}
	var e float64
	for _, b := range bs {
		if b.n > 0 {
			e += b.n / float64(len(conf)) * math.Abs(b.ok/b.n-b.c/b.n)
		}
	}
	return e
}

// ScoreL2 scores the L2 answers. gold replaces the PII samples' entities (the derived full labels, PIIFull).
func ScoreL2(ss []Sample, gold map[string][]Entity, ask func(text string) L2Answer, threshold float64) L2Scores {
	s := L2Scores{NER: map[string]*Counts{}, Merged: map[string]*Counts{}, L1: map[string]*Counts{}, Injection: map[string][2]int{}, Threshold: threshold}
	var ec []float64
	var eok []bool
	var ic []float64
	var iok []bool
	var fp, hardFP int
	for _, x := range ss {
		a := ask(x.Text)
		s.Calls++
		s.Latency = append(s.Latency, a.Latency)
		ents := x.Entities
		if g, ok := gold[x.ID]; ok && x.Kind == "pii" {
			ents = g
		}
		if x.Kind == "pii" || x.Kind == "benign" {
			var ms []detect.Match
			for _, e := range a.Entities {
				ms = append(ms, detect.Match{Type: e.Type, Confidence: e.Confidence, Span: [2]int{e.Start, e.End}})
				ec = append(ec, e.Confidence)
				eok = append(eok, slices.ContainsFunc(ents, func(g Entity) bool { return g.Type == e.Type && e.Start < g.End && g.Start < e.End }))
			}
			l1 := detect.Scan(x.Text)
			tally(s.NER, ents, ms)
			tally(s.L1, ents, l1.Matches)
			tally(s.Merged, ents, detect.WithL2(l1, x.Text, a.Entities, nil).Matches)
		}
		if a.Injection == nil {
			continue
		}
		flagged := a.Injection.Score >= threshold
		switch x.Kind {
		case "injection":
			v := s.Injection[x.Technique]
			v[1]++
			if flagged {
				v[0]++
			}
			s.Injection[x.Technique] = v
			ic, iok = append(ic, a.Injection.Score), append(iok, true)
		case "benign":
			s.Benign++
			if x.Technique == "hard_negative" {
				s.Hards++
			}
			if flagged {
				fp++
				if x.Technique == "hard_negative" {
					hardFP++
				}
			}
			ic, iok = append(ic, a.Injection.Score), append(iok, false)
		}
	}
	s.NEREntities = len(ec)
	s.NERECE = ECE(ec, eok, 10)
	if len(ic) > 0 {
		// Calibration of P(attack): "correct" is the label being attack.
		s.InjECE = ECE(ic, iok, 10)
	}
	s.FPR, s.HardFPR = ratio(fp, s.Benign), ratio(hardFP, s.Hards)
	return s
}

func tally(into map[string]*Counts, gold []Entity, found []detect.Match) {
	sc := Scores{PII: into}
	sc.matchPII(gold, found)
}

// Percentile of the call latencies (p in 0..100).
func (s L2Scores) Percentile(p float64) time.Duration {
	ls := slices.Clone(s.Latency)
	if len(ls) == 0 {
		return 0
	}
	sort.Slice(ls, func(i, j int) bool { return ls[i] < ls[j] })
	return ls[min(len(ls)-1, int(math.Ceil(p/100*float64(len(ls))))-1)]
}

// Markdown writes the L2 report.
func (s L2Scores) Markdown(w io.Writer) error {
	var b strings.Builder
	p := func(f string, a ...any) { fmt.Fprintf(&b, f, a...) }
	p("### NER (span, gold termasuk nama dan alamat)\n\n| Kelas | L1 F1 | L2 P | L2 R | L2 F1 | L1+L2 P | L1+L2 R | L1+L2 F1 |\n|---|---:|---:|---:|---:|---:|---:|---:|\n")
	types := map[string]bool{}
	for _, m := range []map[string]*Counts{s.NER, s.Merged, s.L1} {
		for t := range m {
			types[t] = true
		}
	}
	get := func(m map[string]*Counts, t string) Counts {
		if c := m[t]; c != nil {
			return *c
		}
		return Counts{}
	}
	for _, t := range slices.Sorted(maps.Keys(types)) {
		l1, n, m := get(s.L1, t), get(s.NER, t), get(s.Merged, t)
		p("| %s | %.3f | %.3f | %.3f | %.3f | %.3f | %.3f | %.3f |\n", t, l1.F1(), n.Precision(), n.Recall(), n.F1(), m.Precision(), m.Recall(), m.F1())
	}
	p("\nECE confidence entitas L2: %.4f (%d entitas).\n\n", s.NERECE, s.NEREntities)
	if len(s.Injection) > 0 {
		p("### Prompt injection L2 (ambang %.2f)\n\n| Teknik | Terdeteksi | Total | Rate |\n|---|---:|---:|---:|\n", s.Threshold)
		for _, t := range slices.Sorted(maps.Keys(s.Injection)) {
			v := s.Injection[t]
			p("| %s | %d | %d | %.1f%% |\n", t, v[0], v[1], 100*ratio(v[0], v[1]))
		}
		p("\nFPR benign: %.2f%% dari %d; hard negative: %.1f%% dari %d. ECE skor injection: %.4f.\n\n", 100*s.FPR, s.Benign, 100*s.HardFPR, s.Hards, s.InjECE)
	}
	p("Latensi panggilan L2 (%d panggilan, klien → model-inference): p50 %.1f ms, p95 %.1f ms, p99 %.1f ms.\n", s.Calls,
		ms(s.Percentile(50)), ms(s.Percentile(95)), ms(s.Percentile(99)))
	_, err := io.WriteString(w, b.String())
	return err
}

func ms(d time.Duration) float64 { return float64(d.Microseconds()) / 1000 }
