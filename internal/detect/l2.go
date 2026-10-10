package detect

import (
	"slices"
	"strings"
)

// Views are the texts the L2 injection classifier reads besides the original: the normalized text (homoglyphs,
// zero-width characters gone) and every decoded layer (base64, hex, URL, Unicode tags), as L1 sees them (FR-PSEC-3).
// A model cannot read base64; it can read what the normaliser decoded.
func Views(text string) []string {
	var out []string
	var walk func(src string, depth int)
	walk = func(src string, depth int) {
		n := normalize(src)
		if n.s != src && strings.TrimSpace(n.s) != "" {
			out = append(out, n.s)
		}
		if n.tags != "" {
			out = append(out, n.tags)
		}
		if depth >= maxDepth {
			return
		}
		for _, e := range decodings(n.s) {
			out = append(out, e.text)
			walk(e.text, depth+1)
		}
	}
	walk(text, 0)
	return slices.Compact(out)
}

// L2Entity is an NER finding from the L2 model (ticket 09): byte offsets into the scanned text.
type L2Entity struct {
	Type       string  `json:"type"`
	Start      int     `json:"start"`
	End        int     `json:"end"`
	Confidence float64 `json:"confidence"`
}

// L2Injection is the classifier's verdict (ticket 10).
type L2Injection struct {
	Score float64  `json:"score"`
	Types []string `json:"types"`
}

// identity: the classes that share one 16-digit structure, so only context tells them apart (ticket 04 note).
var identity = []string{"PII_ID.NIK", "PII_ID.KK"}

// patternless: what only the model can find. For identifiers with a structure L1 has a validator; an NER-only
// "identifier" there was a false positive on the holdout (NPWP precision 0.997 → 0.708 when added), so it is not.
var patternless = []string{"PII.NAME", "PII.ADDRESS", "PHI.DIAGNOSIS"}

// WithL2 adds L2 findings to an L1 result. L1 stays authoritative for structured identifiers (checksums and
// validators beat a model), except NIK versus KK, which only context separates: there the NER's reading wins.
// Names, addresses and diagnoses, which L1 cannot see, are added. The injection score is the higher of L1 and L2,
// the attack types the union.
func WithL2(r Result, text string, ents []L2Entity, inj *L2Injection) Result {
	ms := slices.Clone(r.Matches)
	for _, e := range ents {
		if e.Start < 0 || e.End > len(text) || e.Start >= e.End {
			continue
		}
		hit := -1
		for i, m := range ms {
			if m.Span[0] < e.End && e.Start < m.Span[1] {
				hit = i
				break
			}
		}
		switch {
		case hit < 0 && slices.Contains(patternless, e.Type):
			ms = append(ms, Match{Type: e.Type, Confidence: e.Confidence, Span: [2]int{e.Start, e.End}, value: text[e.Start:e.End]})
		case slices.Contains(identity, e.Type) && slices.Contains(identity, ms[hit].Type):
			ms[hit].Type = e.Type
		}
	}
	out := aggregate(append(ms, r.Injection.Evidence...))
	out.Injection = r.Injection
	if inj != nil {
		if inj.Score > out.Injection.Score {
			out.Injection.Score = inj.Score
		}
		types := slices.Clone(out.Injection.Types)
		for _, t := range inj.Types {
			if !slices.Contains(types, "l2:"+t) {
				types = append(types, "l2:"+t)
			}
		}
		slices.Sort(types)
		out.Injection.Types = types
	}
	return out
}
