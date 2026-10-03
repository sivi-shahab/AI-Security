// Package detect is the deterministic L1 fast path (spec §9.1): normalize, decode up to three layers, then
// validated regex detectors for Indonesian PII, card numbers, bank accounts and secrets. No ML, no I/O.
package detect

import (
	"encoding/base64"
	"encoding/json"
	"math"
	"regexp"
	"sort"
	"strings"
)

// Threshold is the confidence a match needs to be reported (and to count toward sensitivity, FR-CLS-3).
const Threshold = 0.8

// Match is one finding (FR-CLS-2). Span is a UTF-8 byte range of the scanned text; the matched value itself is
// never exposed.
type Match struct {
	Type            string  `json:"type"`
	Confidence      float64 `json:"confidence"`
	Span            [2]int  `json:"span_offsets"`
	ValidatorPassed bool    `json:"validator_passed"`
	ContextScore    float64 `json:"context_score"`
	Encoding        string  `json:"encoding,omitempty"` // decode layers the match sat under, e.g. "base64/url"
	value           string
}

// Class is the per-type aggregate the PDP consumes (content.classes in the canonical input).
type Class struct {
	Type       string  `json:"type"`
	Count      int     `json:"count"` // distinct values
	Confidence float64 `json:"confidence"`
}

type Result struct {
	Sensitivity string  `json:"sensitivity"`
	Classes     []Class `json:"classes"`
	Matches     []Match `json:"matches"`
}

// Scan runs L1 over text.
func Scan(text string) Result {
	ms := scan(text, 0, "")
	sort.Slice(ms, func(i, j int) bool { return ms[i].Span[0] < ms[j].Span[0] })
	return aggregate(ms)
}

func scan(src string, depth int, enc string) []Match {
	n := normalize(src)
	var ms []Match
	add := func(found []Match, span func(Match) [2]int, layer string) {
		for _, m := range found {
			m.Span = span(m)
			if m.Encoding == "" { // matches from a deeper layer already carry their full path
				m.Encoding = strings.Trim(enc+"/"+layer, "/")
			}
			ms = append(ms, m)
		}
	}
	add(detectAll(n.s), func(m Match) [2]int { return n.span(m.Span[0], m.Span[1]) }, "")
	if depth >= maxDepth {
		return ms
	}
	for _, e := range decodings(n.s) {
		whole := n.span(e.start, e.end)
		add(scan(e.text, depth+1, strings.Trim(enc+"/"+e.kind, "/")), func(Match) [2]int { return whole }, "")
	}
	if n.tags != "" {
		add(scan(n.tags, depth+1, strings.Trim(enc+"/tags", "/")), func(Match) [2]int { return n.tagSpan }, "")
	}
	// ROT13 only changes letters, so only letter-keyed detectors (secrets) can newly fire.
	add(secrets(n.s, true), func(m Match) [2]int { return n.span(m.Span[0], m.Span[1]) }, "rot13")
	return ms
}

func detectAll(s string) []Match {
	ms := append(numbers(s), secrets(s, false)...)
	// A number inside a secret (key material, JWT, connection string) is part of the secret, not PII.
	out := ms[:0]
	for _, m := range ms {
		if insideSecret(m, ms) {
			continue
		}
		out = append(out, m)
	}
	return out
}

// insideSecret: m lies within a longer secret (a number in a key, a password in a connection string).
func insideSecret(m Match, ms []Match) bool {
	for _, o := range ms {
		if strings.HasPrefix(o.Type, "SECRET.") && o.Span[0] <= m.Span[0] && m.Span[1] <= o.Span[1] && o.Span[1]-o.Span[0] > m.Span[1]-m.Span[0] {
			return true
		}
	}
	return false
}

// --- numbers: NIK, KK, NPWP, mobile, PAN, bank account ---

var reNPWPFormat = regexp.MustCompile(`^\d{2}\.\d{3}\.\d{3}\.\d-\d{3}\.\d{3}$`)

var keywords = map[string][]string{
	"PII_ID.NIK":   {"nik", "ktp", "nomor induk kependudukan", "national id", "identity number"},
	"PII_ID.KK":    {"kk", "kartu keluarga", "family card"},
	"PII_ID.NPWP":  {"npwp", "tax id", "wajib pajak"},
	"PII_ID.PHONE": {"hp", "telp", "telepon", "phone", "ponsel", "whatsapp", "wa", "mobile"},
	"PCI.PAN":      {"kartu", "card", "visa", "mastercard", "kredit", "credit", "debit", "cc"},
	"FIN.ACCOUNT":  {"rekening", "rek", "norek", "account", "acct", "a/n"},
}

// notIdentifiers: words that label a number as a reference, not a person or card. Without positive context, a
// number next to one is dropped.
var notIdentifiers = []string{"ref", "referensi", "invoice", "inv", "order", "transaksi", "trx", "resi", "tracking", "id transaksi", "kode booking"}

// context returns 1 if any keyword for typ appears as a whole word within 48 bytes before or after [a, b).
func context(s string, a, b int, typ string) float64 {
	win := strings.ToLower(s[max(0, a-48):a] + " " + s[b:min(len(s), b+48)])
	for _, k := range keywords[typ] {
		if hasWord(win, k) {
			return 1
		}
	}
	return 0
}

func hasWord(s, w string) bool {
	for i := 0; ; {
		j := strings.Index(s[i:], w)
		if j < 0 {
			return false
		}
		j += i
		if (j == 0 || !alnum(s[j-1])) && (j+len(w) == len(s) || !alnum(s[j+len(w)])) {
			return true
		}
		i = j + 1
	}
}

func alnum(c byte) bool { return c >= 'a' && c <= 'z' || c >= '0' && c <= '9' }

func digit(c byte) bool { return c >= '0' && c <= '9' }

// digitGroups yields each run of digit groups joined by single space, dot or dash separators
// ("4111 1111 1111 1111", "01.855.081.4-412.000"). Hand-rolled: Go's regexp is the L1 latency bottleneck.
func digitGroups(s string, yield func(groups [][2]int)) {
	for i := 0; i < len(s); {
		if !digit(s[i]) {
			i++
			continue
		}
		var groups [][2]int
		for {
			j := i
			for j < len(s) && digit(s[j]) {
				j++
			}
			groups = append(groups, [2]int{i, j})
			if j+1 < len(s) && (s[j] == ' ' || s[j] == '.' || s[j] == '-') && digit(s[j+1]) {
				i = j + 1
				continue
			}
			i = j
			break
		}
		yield(groups)
	}
}

func numbers(s string) []Match {
	var out []Match
	digitGroups(s, func(groups [][2]int) {
		// Left to right, take the window of adjacent groups that validates with the highest confidence
		// (ties: the longer one). Keeps "NIK 3201… 0812…" as two findings.
		for i := 0; i < len(groups); {
			var best Match
			bestJ := -1
			digits := ""
			for j := i; j < len(groups); j++ {
				digits += s[groups[j][0]:groups[j][1]]
				if len(digits) > 19 {
					break
				}
				a, b := groups[i][0], groups[j][1]
				if a > 0 && s[a-1] == '+' {
					a--
				}
				if m, ok := classify(s, a, b, digits); ok && (m.Confidence >= best.Confidence) {
					best, bestJ = m, j
				}
			}
			if bestJ < 0 {
				i++
				continue
			}
			out = append(out, best)
			i = bestJ + 1
		}
	})
	return out
}

// classify picks the most likely type for one digit string at s[a:b].
func classify(s string, a, b int, d string) (Match, bool) {
	if len(d) < 10 { // shortest identifier we know: a 10-digit mobile or account number
		return Match{}, false
	}
	var best Match
	labelled := false
	win := strings.ToLower(s[max(0, a-24):a])
	for _, k := range notIdentifiers {
		labelled = labelled || hasWord(win, k)
	}
	try := func(typ string, ok bool, base, withCtx float64) {
		if !ok {
			return
		}
		c := context(s, a, b, typ)
		conf := base
		if c > 0 {
			conf = withCtx
		} else if labelled {
			return
		}
		if conf >= Threshold && conf > best.Confidence {
			best = Match{Type: typ, Confidence: conf, Span: [2]int{a, b}, ValidatorPassed: true, ContextScore: c, value: d}
		}
	}
	try("PII_ID.NIK", validNIK(d), 0.85, 0.99)
	try("PII_ID.KK", validKK(d), 0, 0.97)
	if reNPWPFormat.MatchString(s[a:b]) || len(d) == 16 {
		try("PII_ID.NPWP", validNPWP(d), 0.95, 0.99)
	} else {
		try("PII_ID.NPWP", validNPWP(d), 0, 0.95)
	}
	try("PCI.PAN", validPAN(d), 0.9, 0.99)
	if s[a] == '+' {
		try("PII_ID.PHONE", validMobile(d), 0.95, 0.99)
	} else {
		try("PII_ID.PHONE", validMobile(d), 0.9, 0.99)
	}
	if len(d) >= 10 && len(d) <= 16 {
		// A bank name alone is weak context (this is a bank: they are everywhere), but it pins the length.
		c := context(s, a, b, "FIN.ACCOUNT")
		conf := 0.85 * c
		n, pinned := nearestBank(strings.ToLower(s[max(0, a-48):a]))
		if pinned {
			conf = 0
			if n == len(d) {
				conf = 0.85 + 0.1*c
			}
		}
		if conf >= Threshold && conf > best.Confidence {
			best = Match{Type: "FIN.ACCOUNT", Confidence: conf, Span: [2]int{a, b}, ValidatorPassed: pinned, ContextScore: c, value: d}
		}
	}
	return best, best.Type != ""
}

// nearestBank: the account length of the bank named closest before a number.
func nearestBank(win string) (int, bool) {
	at, n := -1, 0
	for bank, l := range accountLengths {
		if i := strings.LastIndex(win, bank); i > at && hasWord(win[i:], bank) {
			at, n = i, l
		}
	}
	return n, at >= 0
}

// --- secrets (FR-CLS-1 Credentials / Secrets) ---

type secretRule struct {
	typ     string
	anchors []string // literals a match starts with; lower-case when fold
	fold    bool     // case-insensitive
	re      *regexp.Regexp
	conf    float64
	ok      func(value string) bool // nil = the pattern alone is enough
}

// Rules are anchored: strings.Index finds each anchor, then the ^-anchored regexp runs from there only.
// Unanchored, these patterns ran Go's NFA over the whole text and blew the 10 ms budget tenfold.
var secretRules = []secretRule{
	{"SECRET.AWS_KEY", []string{"AKIA", "ASIA"}, false, regexp.MustCompile(`^(?:AKIA|ASIA)[A-Z0-9]{16}\b`), 0.99, nil},
	{"SECRET.GITHUB_TOKEN", []string{"ghp_", "gho_", "ghu_", "ghs_", "ghr_", "github_pat_"}, false, regexp.MustCompile(`^(?:gh[pousr]_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{82})\b`), 0.99, nil},
	{"SECRET.GITLAB_TOKEN", []string{"glpat-"}, false, regexp.MustCompile(`^glpat-[A-Za-z0-9_-]{20,}`), 0.99, nil},
	{"SECRET.SLACK_TOKEN", []string{"xoxb-", "xoxa-", "xoxp-", "xoxr-", "xoxs-"}, false, regexp.MustCompile(`^xox[baprs]-[A-Za-z0-9-]{10,}`), 0.99, nil},
	{"SECRET.GOOGLE_API_KEY", []string{"AIza"}, false, regexp.MustCompile(`^AIza[0-9A-Za-z_-]{35}`), 0.99, nil},
	{"SECRET.LLM_API_KEY", []string{"sk-"}, false, regexp.MustCompile(`^sk-(?:ant-|proj-)?[A-Za-z0-9_-]{32,}`), 0.95, nil},
	{"SECRET.STRIPE_KEY", []string{"sk_live_", "rk_live_"}, false, regexp.MustCompile(`^[rs]k_live_[0-9A-Za-z]{24,}`), 0.99, nil},
	{"SECRET.PRIVATE_KEY", []string{"-----BEGIN "}, false, regexp.MustCompile(`^-----BEGIN (?:[A-Z]+ )?PRIVATE KEY-----`), 0.99, nil},
	{"SECRET.JWT", []string{"eyJ"}, false, regexp.MustCompile(`^eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}`), 0.95, jwtHeader},
	{"SECRET.CONNECTION_STRING", []string{"postgres", "mysql", "mongodb", "redis", "amqp", "mssql", "sqlserver", "oracle"}, false,
		regexp.MustCompile(`^(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|rediss?|amqps?|mssql|sqlserver|oracle)://[^\s:/@]+:[^\s@/]+@[^\s/]+`), 0.95, nil},
	{"SECRET.CONNECTION_STRING", []string{"server=", "data source=", "host="}, true,
		regexp.MustCompile(`(?i)^(?:server|data source|host)=[^;\n]+;(?:[^;\n]+;)*?\s*(?:password|pwd)=[^;\s]{4,}`), 0.95, nil},
	{"SECRET.PASSWORD", []string{"password", "passwd", "pwd", "kata sandi", "katasandi"}, true,
		regexp.MustCompile(`(?i)^(?:password|passwd|pwd|kata ?sandi)\s*[:=]\s*["']?([^\s"';]{6,})`), 0.85, password},
	{"SECRET.GENERIC", []string{"api_key", "api-key", "apikey", "secret", "client_secret", "client-secret", "access_token", "access-token", "auth_token", "auth-token"}, true,
		regexp.MustCompile(`(?i)^(?:api[_-]?key|secret[_-]?key|client[_-]?secret|access[_-]?token|auth[_-]?token|secret)\s*[:=]\s*["']?([A-Za-z0-9_\-+/=.]{16,})`), 0.85, highEntropy},
}

// maxSecret bounds the text an anchored rule may consume (a JWT can run to a few KB).
const maxSecret = 8 << 10

type anchor struct {
	lit  string // lower-case for fold rules
	rule int
}

// anchors[rot][c]: the anchors whose first byte (lower-cased for fold rules) is c, for plain text and for
// text to be read as ROT13. One pass over the text checks only those, instead of one strings.Index per anchor.
var anchors [2][256][]anchor

func init() {
	for i, r := range secretRules {
		for _, a := range r.anchors {
			for rot, lit := range []string{a, rot13(a)} {
				anchors[rot][lit[0]] = append(anchors[rot][lit[0]], anchor{lit, i})
				if r.fold && lit[0] >= 'a' && lit[0] <= 'z' {
					anchors[rot][lit[0]-32] = append(anchors[rot][lit[0]-32], anchor{lit, i})
				}
			}
		}
	}
}

// secrets finds secret rule matches in s; with rot, in ROT13(s) (same offsets: ROT13 maps byte to byte).
func secrets(s string, rot bool) []Match {
	var out []Match
	r := 0
	if rot {
		r = 1
	}
	for i := 0; i < len(s); i++ {
		for _, a := range anchors[r][s[i]] {
			rule := secretRules[a.rule]
			if len(s)-i < len(a.lit) || (i > 0 && word(s[i-1])) {
				continue
			}
			if head := s[i : i+len(a.lit)]; head != a.lit && (!rule.fold || asciiLower(head) != a.lit) {
				continue
			}
			text := s[i:min(len(s), i+maxSecret)]
			if rot {
				text = rot13(text)
			}
			loc := rule.re.FindStringSubmatchIndex(text)
			if loc == nil {
				continue
			}
			v := text[loc[0]:loc[1]]
			if len(loc) >= 4 && loc[2] >= 0 {
				v = text[loc[2]:loc[3]]
			}
			if rule.ok != nil && !rule.ok(v) {
				continue
			}
			out = append(out, Match{Type: rule.typ, Confidence: rule.conf, Span: [2]int{i + loc[0], i + loc[1]}, ValidatorPassed: rule.ok != nil, value: v})
		}
	}
	return out
}

func word(c byte) bool { return c == '_' || digit(c) || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' }

// asciiLower lower-cases ASCII only, so byte offsets stay valid for the original string.
func asciiLower(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + 32
		}
	}
	return string(b)
}

// jwtHeader: the first segment decodes to a JSON object with "alg".
func jwtHeader(tok string) bool {
	h, err := base64.RawURLEncoding.DecodeString(tok[:strings.IndexByte(tok, '.')])
	var v struct {
		Alg *string `json:"alg"`
	}
	return err == nil && json.Unmarshal(h, &v) == nil && v.Alg != nil
}

func notPlaceholder(v string) bool {
	l := strings.ToLower(v)
	if strings.Trim(l, "*x.•#") == "" || strings.ContainsAny(l, "<>{}$%") {
		return false
	}
	for _, p := range []string{"password", "changeme", "example", "redacted", "your", "dummy", "secret"} {
		if strings.Contains(l, p) {
			return false
		}
	}
	return true
}

// password: not a placeholder, and mixes at least two of lower, upper, digit, symbol (prose words do not).
func password(v string) bool {
	if !notPlaceholder(v) {
		return false
	}
	var kinds [4]bool
	for _, r := range v {
		switch {
		case r >= 'a' && r <= 'z':
			kinds[0] = true
		case r >= 'A' && r <= 'Z':
			kinds[1] = true
		case r >= '0' && r <= '9':
			kinds[2] = true
		default:
			kinds[3] = true
		}
	}
	n := 0
	for _, k := range kinds {
		if k {
			n++
		}
	}
	return n >= 2
}

// highEntropy: ≥ 3.5 bits/char Shannon entropy, which real keys clear and words or placeholders do not.
func highEntropy(v string) bool {
	if !notPlaceholder(v) {
		return false
	}
	freq := map[rune]float64{}
	for _, r := range v {
		freq[r]++
	}
	h := 0.0
	for _, f := range freq {
		p := f / float64(len(v))
		h -= p * math.Log2(p)
	}
	return h >= 3.5
}

// --- aggregation (FR-CLS-3) ---

var levels = []string{"public", "internal", "confidential", "restricted"}

// classLevel: secrets are restricted; personal and financial identifiers confidential.
func classLevel(typ string) int {
	if strings.HasPrefix(typ, "SECRET.") {
		return 3
	}
	return 2
}

// volumeRestricted: this many distinct personal/financial identifiers of one type make the content restricted.
const volumeRestricted = 10

// aggregate dedupes matches (same type and span, e.g. found both raw and decoded), counts distinct values per
// type, and derives sensitivity: the highest class level, raised by volume. No finding = internal (corporate
// content; "public" needs an external label, FR-CLS-6).
func aggregate(ms []Match) Result {
	seen := map[[3]any]bool{}
	out := ms[:0]
	values := map[string]map[string]bool{}
	conf := map[string]float64{}
	level := 1
	for _, m := range ms {
		k := [3]any{m.Type, m.Span[0], m.Span[1]}
		if seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, m)
		if values[m.Type] == nil {
			values[m.Type] = map[string]bool{}
		}
		values[m.Type][m.value] = true
		conf[m.Type] = max(conf[m.Type], m.Confidence)
		level = max(level, classLevel(m.Type))
	}
	classes := []Class{}
	for t, vs := range values {
		classes = append(classes, Class{Type: t, Count: len(vs), Confidence: conf[t]})
		if len(vs) >= volumeRestricted {
			level = 3
		}
	}
	sort.Slice(classes, func(i, j int) bool { return classes[i].Type < classes[j].Type })
	if out == nil {
		out = []Match{}
	}
	return Result{Sensitivity: levels[level], Classes: classes, Matches: out}
}

// Redact replaces the spans of matches whose type is in types (all matches if types is empty) with
// [REDACTED:<TYPE>] (spec §4.6). Overlapping spans are merged under the first type.
func Redact(text string, ms []Match, types ...string) string {
	want := map[string]bool{}
	for _, t := range types {
		want[t] = true
	}
	sel := []Match{}
	for _, m := range ms {
		if len(want) == 0 || want[m.Type] {
			sel = append(sel, m)
		}
	}
	sort.Slice(sel, func(i, j int) bool { return sel[i].Span[0] < sel[j].Span[0] })
	var b strings.Builder
	at := 0
	for _, m := range sel {
		if m.Span[1] <= at {
			continue
		}
		b.WriteString(text[at:max(at, m.Span[0])])
		b.WriteString("[REDACTED:" + m.Type + "]")
		at = m.Span[1]
	}
	b.WriteString(text[at:])
	return b.String()
}
