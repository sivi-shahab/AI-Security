package mcpgw

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
)

// --- access tokens (MCP authorization: OAuth 2.1 bearer tokens, RFC 8707 audience) ---

// Token is what the gateway takes from a verified access token.
type Token struct {
	Identity   string // workload identity: azp / client_id (OIDC client), else sub (SPIFFE ID)
	ChainDepth int    // RFC 8693 act nesting: how many agents delegated to get here
}

var errAudience = errors.New("token audience is not this resource")

// Verifier checks signature (issuer JWKS, refreshed on rotation), issuer and expiry, then that the token was
// issued for resource (RFC 8707: aud is the MCP server's canonical URI) and is an access token, not an ID token.
func Verifier(v *oidc.IDTokenVerifier) func(ctx context.Context, raw, resource string) (Token, error) {
	return func(ctx context.Context, raw, resource string) (Token, error) {
		t, err := v.Verify(ctx, raw)
		if err != nil {
			return Token{}, err
		}
		if !slices.Contains(t.Audience, resource) {
			return Token{}, errAudience
		}
		var c struct {
			Typ      string          `json:"typ"`
			Azp      string          `json:"azp"`
			ClientID string          `json:"client_id"`
			Act      json.RawMessage `json:"act"`
		}
		if err := t.Claims(&c); err != nil {
			return Token{}, err
		}
		if c.Typ != "" && !strings.EqualFold(c.Typ, "Bearer") {
			return Token{}, fmt.Errorf("token typ %q is not an access token", c.Typ)
		}
		id := c.Azp
		if id == "" {
			id = c.ClientID
		}
		if id == "" {
			id = t.Subject
		}
		return Token{Identity: id, ChainDepth: actDepth(c.Act)}, nil
	}
}

// NewVerifier discovers issuer's keys (OIDC discovery) for Verifier.
func NewVerifier(ctx context.Context, issuer string) (func(ctx context.Context, raw, resource string) (Token, error), error) {
	p, err := oidc.NewProvider(ctx, issuer)
	if err != nil {
		return nil, err
	}
	return Verifier(p.Verifier(&oidc.Config{SkipClientIDCheck: true})), nil
}

func actDepth(raw json.RawMessage) int {
	n := 0
	for len(raw) > 0 && string(raw) != "null" && n < 64 {
		var a struct {
			Act json.RawMessage `json:"act"`
		}
		if json.Unmarshal(raw, &a) != nil {
			break
		}
		n++
		raw = a.Act
	}
	return n
}

// --- token exchange (RFC 8693): never pass the agent's token through ---

// STS swaps the agent's token for a short-lived token whose audience is the downstream tool server (spec
// FR-AGT-3/5). Results are cached per (subject token, audience) until shortly before they expire, so one agent's
// credential never serves another's request.
type STS struct {
	URL, ClientID, ClientSecret string
	HTTP                        *http.Client
	Now                         func() time.Time

	mu    sync.Mutex
	cache map[string]cached
}

type cached struct {
	token string
	until time.Time
}

// MaxTTL is FR-AGT-5's ceiling for downstream credentials.
const MaxTTL = 15 * time.Minute

const (
	grantTokenExchange = "urn:ietf:params:oauth:grant-type:token-exchange"
	typeAccessToken    = "urn:ietf:params:oauth:token-type:access_token"
)

func (s *STS) Exchange(ctx context.Context, subject, audience string) (string, error) {
	sum := sha256.Sum256([]byte(subject))
	key := hex.EncodeToString(sum[:]) + "|" + audience
	now := s.Now()
	s.mu.Lock()
	if c, ok := s.cache[key]; ok && now.Before(c.until) {
		s.mu.Unlock()
		return c.token, nil
	}
	s.mu.Unlock()

	form := url.Values{
		"grant_type":           {grantTokenExchange},
		"subject_token":        {subject},
		"subject_token_type":   {typeAccessToken},
		"requested_token_type": {typeAccessToken},
		"audience":             {audience},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.URL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(url.QueryEscape(s.ClientID), url.QueryEscape(s.ClientSecret)) // RFC 6749 §2.3.1
	resp, err := s.HTTP.Do(req)
	if err != nil {
		return "", fmt.Errorf("token exchange: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	var out struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
		ExpiresIn   int64  `json:"expires_in"`
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("token exchange: status %d", resp.StatusCode)
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", fmt.Errorf("token exchange: %w", err)
	}
	ttl := time.Duration(out.ExpiresIn) * time.Second
	switch {
	case out.AccessToken == "" || !strings.EqualFold(out.TokenType, "Bearer"):
		return "", errors.New("token exchange: no bearer access token")
	case out.AccessToken == subject:
		return "", errors.New("token exchange: STS returned the subject token")
	case ttl <= 0 || ttl > MaxTTL:
		// A longer-lived downstream token breaks FR-AGT-5; refuse rather than use it.
		return "", fmt.Errorf("token exchange: expires_in %ds outside (0, %d]", out.ExpiresIn, int(MaxTTL.Seconds()))
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cache == nil || len(s.cache) > 10000 {
		s.cache = map[string]cached{} // ponytail: drop-all eviction; an LRU if agents × servers outgrows it
	}
	s.cache[key] = cached{out.AccessToken, now.Add(ttl - min(30*time.Second, ttl/2))}
	return out.AccessToken, nil
}

// --- PDP: the OPA sidecar ---

// OPA asks the pod-local OPA sidecar (spec FR-POL-1) for registry lookups and decisions.
type OPA struct {
	URL  string // e.g. http://127.0.0.1:8181
	HTTP *http.Client
}

// RegistryAgent is the registry entry for an authenticated workload identity (policy aisec/mcp).
type RegistryAgent struct {
	ID     string `json:"agent_id"`
	Status string `json:"status"`
	Tools  []struct {
		Name   string         `json:"name"`
		Risk   string         `json:"risk"`
		Scopes map[string]any `json:"scopes"`
	} `json:"tools"`
}

// Decision is the PDP output (policy/aisec/schema output v1) the gateway acts on.
type Decision struct {
	Action      string `json:"action"`
	Obligations []struct {
		Type    string   `json:"type"`
		Classes []string `json:"classes"`
	} `json:"obligations"`
	ReasonCodes  []string `json:"reason_codes"`
	MatchedRules []string `json:"matched_rules"`
	Destination  struct {
		Sanction     string `json:"sanction"`
		Region       string `json:"region"`
		TrainsOnData *bool  `json:"trains_on_data"`
	} `json:"destination"`
	PolicyVersion string   `json:"policy_version"`
	RiskScore     int      `json:"risk_score"`
	RiskOverrides []string `json:"risk_overrides"`
	RiskVersion   string   `json:"risk_version"`
}

// Agent returns the registry entry for identity, or nil if the registry does not know it.
func (o *OPA) Agent(ctx context.Context, identity string) (*RegistryAgent, error) {
	var a *RegistryAgent
	return a, o.query(ctx, "aisec/mcp/agent", map[string]any{"identity": identity}, &a)
}

// Decide evaluates the canonical input. An undefined decision is an error: the caller fails closed.
func (o *OPA) Decide(ctx context.Context, input map[string]any) (Decision, error) {
	var d *Decision
	if err := o.query(ctx, "aisec/decision/result", input, &d); err != nil {
		return Decision{}, err
	}
	if d == nil || d.Action == "" {
		return Decision{}, errors.New("PDP returned no decision")
	}
	return *d, nil
}

func (o *OPA) query(ctx context.Context, path string, input any, out any) error {
	body, err := json.Marshal(map[string]any{"input": input})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, o.URL+"/v1/data/"+path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := o.HTTP.Do(req)
	if err != nil {
		return fmt.Errorf("PDP: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("PDP %s: status %d", path, resp.StatusCode)
	}
	var r struct {
		Result json.RawMessage `json:"result"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&r); err != nil {
		return fmt.Errorf("PDP %s: %w", path, err)
	}
	if len(r.Result) == 0 {
		return nil // undefined: out stays nil
	}
	return json.Unmarshal(r.Result, out)
}
