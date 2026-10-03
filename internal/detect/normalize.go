package detect

import (
	"encoding/base64"
	"encoding/hex"
	"net/url"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"
)

// normalized is the text detectors run on (spec FR-CLS-4, FR-PSEC-3): NFKC, invisible characters stripped,
// homoglyphs and non-ASCII digits folded to ASCII. Every output byte remembers the source byte range it came
// from, so a match found here maps back to a span of the original text.
type normalized struct {
	s        string
	from, to []int32
	tags     string // ASCII hidden in Unicode tag characters (U+E0020..E007E), decoded
	tagSpan  [2]int
}

func normalize(src string) normalized {
	var b strings.Builder
	b.Grow(len(src))
	from := make([]int32, 0, len(src))
	to := make([]int32, 0, len(src))
	var tags strings.Builder
	tagSpan := [2]int{-1, -1}

	var it norm.Iter
	it.InitString(norm.NFKC, src)
	for !it.Done() {
		start := it.Pos()
		seg := it.Next()
		end := it.Pos()
		for _, r := range string(seg) {
			switch {
			case r >= 0xE0000 && r <= 0xE007F:
				if r >= 0xE0020 && r <= 0xE007E {
					tags.WriteRune(r - 0xE0000)
				}
				if tagSpan[0] < 0 {
					tagSpan[0] = start
				}
				tagSpan[1] = end
				continue
			case invisible(r):
				continue
			}
			r = fold(r)
			n := b.Len()
			b.WriteRune(r)
			for range b.Len() - n {
				from = append(from, int32(start))
				to = append(to, int32(end))
			}
		}
	}
	return normalized{s: b.String(), from: from, to: to, tags: tags.String(), tagSpan: tagSpan}
}

// span maps [a, b) of the normalized text to the source byte range.
func (n normalized) span(a, b int) [2]int { return [2]int{int(n.from[a]), int(n.to[b-1])} }

func invisible(r rune) bool {
	switch {
	case r == 0x00AD, r == 0x180E, r == 0xFEFF,
		r >= 0x200B && r <= 0x200F, r >= 0x202A && r <= 0x202E,
		r >= 0x2060 && r <= 0x2064, r >= 0x2066 && r <= 0x2069,
		r >= 0xFE00 && r <= 0xFE0F, r >= 0xE0100 && r <= 0xE01EF:
		return true
	}
	return false
}

// homoglyphs: Cyrillic and Greek letters that render like Latin ones. NFKC leaves them alone.
var homoglyphs = map[rune]rune{
	'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c', 'у': 'y', 'х': 'x', 'і': 'i', 'ј': 'j', 'ѕ': 's', 'ԁ': 'd', 'ӏ': 'l', 'ԛ': 'q', 'ԝ': 'w',
	'А': 'A', 'В': 'B', 'Е': 'E', 'К': 'K', 'М': 'M', 'Н': 'H', 'О': 'O', 'Р': 'P', 'С': 'C', 'Т': 'T', 'Х': 'X', 'І': 'I', 'Ј': 'J', 'Ѕ': 'S',
	'α': 'a', 'ο': 'o', 'ρ': 'p', 'ι': 'i', 'κ': 'k', 'ν': 'v', 'τ': 't', 'υ': 'u', 'χ': 'x',
	'Α': 'A', 'Β': 'B', 'Ε': 'E', 'Ζ': 'Z', 'Η': 'H', 'Ι': 'I', 'Κ': 'K', 'Μ': 'M', 'Ν': 'N', 'Ο': 'O', 'Ρ': 'P', 'Τ': 'T', 'Υ': 'Y', 'Χ': 'X',
}

// digitZeros: the zero of each non-ASCII decimal digit block NFKC does not fold
// (Arabic-Indic, extended Arabic-Indic, Devanagari, Bengali, Thai).
var digitZeros = []rune{0x0660, 0x06F0, 0x0966, 0x09E6, 0x0E50}

func fold(r rune) rune {
	if r < utf8.RuneSelf {
		return r
	}
	if h, ok := homoglyphs[r]; ok {
		return h
	}
	for _, z := range digitZeros {
		if r >= z && r <= z+9 {
			return '0' + r - z
		}
	}
	return r
}

const maxDepth = 3 // decode layers (spec §9.1)

var reHex = regexp.MustCompile(`^(?:[0-9a-fA-F]{2})+$`)

// encoded is one decodable substring of the normalized text.
type encoded struct {
	start, end int
	kind, text string
}

func b64(c byte) bool {
	return c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '+' || c == '/' || c == '_' || c == '-'
}

func hexDigit(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F'
}

// decodings finds base64, hex and URL-encoded substrings that decode to mostly printable text. Scanned by hand,
// not by regexp, for the L1 latency budget.
func decodings(s string) []encoded {
	var out []encoded
	for i := 0; i < len(s); {
		if !b64(s[i]) {
			i++
			continue
		}
		j := i
		for j < len(s) && b64(s[j]) {
			j++
		}
		k := j
		for k < len(s) && k-j < 2 && s[k] == '=' {
			k++
		}
		if j-i >= 16 {
			if e, ok := decodeBlob(s[i:k]); ok {
				e.start, e.end = i, k
				out = append(out, e)
			}
		}
		i = k
	}
	for i := 0; i+2 < len(s); i++ {
		if s[i] != '%' || !hexDigit(s[i+1]) || !hexDigit(s[i+2]) {
			continue
		}
		a, b := i, i
		for a > 0 && !unicode.IsSpace(rune(s[a-1])) {
			a--
		}
		for b < len(s) && !unicode.IsSpace(rune(s[b])) {
			b++
		}
		if d, err := url.QueryUnescape(s[a:b]); err == nil {
			out = append(out, encoded{a, b, "url", d})
		}
		i = b
	}
	return out
}

func decodeBlob(blob string) (encoded, bool) {
	if reHex.MatchString(blob) {
		d, err := hex.DecodeString(blob)
		return encoded{kind: "hex", text: string(d)}, err == nil && printable(d)
	}
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if d, err := enc.DecodeString(blob); err == nil {
			return encoded{kind: "base64", text: string(d)}, printable(d)
		}
	}
	return encoded{}, false
}

// printable: valid UTF-8, at least 6 bytes, and ≥ 90% printable runes. Rejects the binary that random
// identifiers decode to.
func printable(b []byte) bool {
	if len(b) < 6 || !utf8.Valid(b) {
		return false
	}
	n, ok := 0, 0
	for _, r := range string(b) {
		n++
		if unicode.IsPrint(r) || unicode.IsSpace(r) {
			ok++
		}
	}
	return ok*10 >= n*9
}

func rot13(s string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z':
			return 'a' + (r-'a'+13)%26
		case r >= 'A' && r <= 'Z':
			return 'A' + (r-'A'+13)%26
		}
		return r
	}, s)
}
