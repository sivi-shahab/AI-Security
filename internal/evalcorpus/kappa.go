package evalcorpus

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"maps"
	"slices"
)

// Annotation is one annotator's label for one sample (docs/labeling-guideline.md): whether it is an attack, and
// which sensitive-data classes it contains.
type Annotation struct {
	ID     string   `json:"id"`
	Attack bool     `json:"attack"`
	PII    []string `json:"pii"`
}

func DecodeAnnotations(raw []byte) (map[string]Annotation, error) {
	m := map[string]Annotation{}
	sc := bufio.NewScanner(bytes.NewReader(raw))
	sc.Buffer(nil, 1<<20)
	for n := 1; sc.Scan(); n++ {
		var a Annotation
		if err := json.Unmarshal(sc.Bytes(), &a); err != nil {
			return nil, fmt.Errorf("line %d: %w", n, err)
		}
		m[a.ID] = a
	}
	return m, sc.Err()
}

// Kappa is Cohen's κ for two annotators on one binary question.
func Kappa(a, b []bool) float64 {
	n := float64(len(a))
	if n == 0 {
		return 0
	}
	var agree, ya, yb float64
	for i := range a {
		if a[i] == b[i] {
			agree++
		}
		if a[i] {
			ya++
		}
		if b[i] {
			yb++
		}
	}
	po, pe := agree/n, (ya/n)*(yb/n)+(1-ya/n)*(1-yb/n)
	if pe == 1 {
		return 1 // both annotators gave one answer to everything: perfect agreement, κ undefined
	}
	return (po - pe) / (1 - pe)
}

// Agreement is κ per question over the samples both annotators labelled.
type Agreement struct {
	Items int
	Kappa map[string]float64 // "attack", and each PII class either annotator used
	Min   float64
}

func Agree(a, b map[string]Annotation) Agreement {
	var ids []string
	for id := range a {
		if _, ok := b[id]; ok {
			ids = append(ids, id)
		}
	}
	slices.Sort(ids)
	classes := map[string]bool{}
	for _, id := range ids {
		for _, c := range append(slices.Clone(a[id].PII), b[id].PII...) {
			classes[c] = true
		}
	}
	ag := Agreement{Items: len(ids), Kappa: map[string]float64{}, Min: 1}
	question := func(name string, f func(Annotation) bool) {
		var x, y []bool
		for _, id := range ids {
			x, y = append(x, f(a[id])), append(y, f(b[id]))
		}
		k := Kappa(x, y)
		ag.Kappa[name] = k
		ag.Min = min(ag.Min, k)
	}
	question("attack", func(n Annotation) bool { return n.Attack })
	for _, c := range slices.Sorted(maps.Keys(classes)) {
		question(c, func(n Annotation) bool { return slices.Contains(n.PII, c) })
	}
	return ag
}
