package catalog

import (
	"bytes"
	"io"
	"slices"
	"strings"
)

func bytesReader(b []byte) io.Reader { return bytes.NewReader(b) }

// Signal weights (FR-DISC-3). Headers are listed as a fingerprint in FR-DISC-2 without a weight; they are as
// specific as an API signature in practice, so they get a bit less than one.
const (
	WeightDomain    = 0.9
	WeightAPI       = 0.8
	WeightHeader    = 0.7
	WeightPayload   = 0.6
	WeightUserAgent = 0.5
	ReviewBelow     = 0.6 // detections under this go to the review queue
)

// Signals is what a PEP or a log line shows about one request.
type Signals struct {
	Host        string   // domain / SNI
	Method      string   // "POST"
	Path        string   // "/v1/messages", or ".../models/x:generateContent"
	Headers     []string // header names present
	UserAgent   string
	PayloadKeys []string // top-level keys of the JSON body
}

// Detection is the best app for some signals. When several apps tie (an OpenAI-compatible endpoint is served by
// many vendors), AppID is empty, Candidates lists them and the detection goes to review.
type Detection struct {
	AppID       string   `json:"app_id,omitempty"`
	Candidates  []string `json:"candidates,omitempty"`
	Confidence  float64  `json:"confidence"`
	Signals     []string `json:"signals"` // which signals matched (for the best candidate)
	NeedsReview bool     `json:"needs_review"`
}

// Confidence combines independent signals: 1 − Π(1 − c_i).
func Confidence(cs ...float64) float64 {
	miss := 1.0
	for _, c := range cs {
		miss *= 1 - c
	}
	return 1 - miss
}

func domainMatches(host, domain string) bool {
	host, domain = strings.ToLower(strings.TrimSuffix(host, ".")), strings.ToLower(domain)
	return host == domain || strings.HasSuffix(host, "."+domain)
}

// endpointMatches understands "POST /v1/messages" (exact path) and "POST :generateContent" (path suffix).
func endpointMatches(method, path, endpoint string) bool {
	m, p, ok := strings.Cut(endpoint, " ")
	if !ok || !strings.EqualFold(m, method) {
		return false
	}
	if strings.HasPrefix(p, ":") {
		return strings.HasSuffix(path, p)
	}
	return path == p
}

// Match returns the most confident app for s, or ok=false when nothing matched.
func Match(apps []App, s Signals) (d Detection, ok bool) {
	var tied []string
	for _, a := range apps {
		var cs []float64
		var names []string
		add := func(name string, c float64) { cs, names = append(cs, c), append(names, name) }
		if slices.ContainsFunc(a.Domains, func(dom string) bool { return s.Host != "" && domainMatches(s.Host, dom) }) {
			add("domain", WeightDomain)
		}
		if slices.ContainsFunc(a.APIEndpoints, func(e string) bool { return endpointMatches(s.Method, s.Path, e) }) {
			add("api_signature", WeightAPI)
		}
		if slices.ContainsFunc(a.Headers, func(h string) bool {
			return slices.ContainsFunc(s.Headers, func(x string) bool { return strings.EqualFold(x, h) })
		}) {
			add("header", WeightHeader)
		}
		if len(a.PayloadKeys) > 0 && !slices.ContainsFunc(a.PayloadKeys, func(k string) bool { return !slices.Contains(s.PayloadKeys, k) }) {
			add("payload_shape", WeightPayload)
		}
		if slices.ContainsFunc(a.UserAgents, func(ua string) bool { return s.UserAgent != "" && strings.Contains(s.UserAgent, ua) }) {
			add("user_agent", WeightUserAgent)
		}
		if len(cs) == 0 {
			continue
		}
		switch c := Confidence(cs...); {
		case !ok || c > d.Confidence+1e-9:
			d, ok, tied = Detection{AppID: a.ID, Confidence: c, Signals: names}, true, []string{a.ID}
		case c > d.Confidence-1e-9:
			tied = append(tied, a.ID)
		}
	}
	if len(tied) > 1 {
		d.AppID, d.Candidates = "", tied
	}
	d.NeedsReview = ok && (d.Confidence < ReviewBelow || d.AppID == "")
	return d, ok
}
