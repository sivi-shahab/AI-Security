package authz

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"
)

// Authenticated is the "permission" of routes any logged-in user may call (e.g. GET /me).
const Authenticated = "authenticated"

// Claims are what the API uses from a validated Keycloak access token (ADR-0002).
type Claims struct {
	Subject  string    `json:"sub"`
	Username string    `json:"preferred_username"`
	ACR      string    `json:"acr"`
	AuthTime time.Time `json:"-"` // from auth_time
}

// Authenticator turns a bearer token into a Caller. Every dependency is a func so tests can stub the IdP and stores.
type Authenticator struct {
	Verify     func(ctx context.Context, rawToken string) (Claims, error) // signature, iss, aud, exp
	MFAACR     []string                                                   // acr values that mean MFA was done
	BreakGlass map[string]bool                                            // token subs of break-glass accounts
	Bindings   func(ctx context.Context, username string) ([]Binding, error)
	Audit      func(ctx context.Context, actor, action string, target map[string]any) error
	StepUpAge  time.Duration // max age of the login for sensitive permissions
	Now        func() time.Time
}

// Route is one registered endpoint and the permission it needs.
type Route struct {
	Method, Pattern, Perm string // Perm "" = public (no user auth)
}

// Router registers routes only with a permission (or explicitly as public): there is no way to add an endpoint
// that skips authorization by accident.
type Router struct {
	Mux    *http.ServeMux
	Auth   *Authenticator
	routes []Route
}

func NewRouter(a *Authenticator) *Router { return &Router{Mux: http.NewServeMux(), Auth: a} }

// Routes lists every registered endpoint.
func (rt *Router) Routes() []Route { return slices.Clone(rt.routes) }

func (rt *Router) ServeHTTP(w http.ResponseWriter, r *http.Request) { rt.Mux.ServeHTTP(w, r) }

func (rt *Router) add(pattern, perm string, h http.Handler) {
	method, path, ok := strings.Cut(pattern, " ")
	if !ok {
		panic("authz: route " + pattern + " needs a method")
	}
	rt.routes = append(rt.routes, Route{Method: method, Pattern: path, Perm: perm})
	rt.Mux.Handle(pattern, h)
}

// Public registers an endpoint without user authentication (health, metrics, sidecar bundles, SCIM with its own
// token). Keep this list short; the route matrix test pins it.
func (rt *Router) Public(pattern string, h http.Handler) { rt.add(pattern, "", h) }

// Handle registers an endpoint that needs perm (or Authenticated). h runs only for an authorized caller.
func (rt *Router) Handle(pattern, perm string, h func(http.ResponseWriter, *http.Request, Caller)) {
	if perm == "" {
		panic("authz: route " + pattern + " needs a permission; use Public for unauthenticated routes")
	}
	rt.add(pattern, perm, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := rt.Auth.authorize(r, perm)
		if err != nil {
			writeDenial(w, err)
			return
		}
		h(w, r, c)
	}))
}

// Denial is why a request was refused, with the HTTP status to answer.
type Denial struct {
	Status int
	Reason string
	StepUp bool // ask the client to re-authenticate (RFC 9470)
}

func (d *Denial) Error() string { return d.Reason }

func writeDenial(w http.ResponseWriter, err error) {
	var d *Denial
	if !errors.As(err, &d) {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if d.Status == http.StatusUnauthorized {
		challenge := `Bearer error="invalid_token"`
		if d.StepUp {
			challenge = `Bearer error="insufficient_user_authentication", error_description="` + d.Reason + `"`
		}
		w.Header().Set("WWW-Authenticate", challenge)
	}
	http.Error(w, d.Reason, d.Status)
}

// Justification is read from the X-Justification header, or the justification query parameter.
func Justification(r *http.Request) string {
	if j := r.Header.Get("X-Justification"); j != "" {
		return j
	}
	return r.URL.Query().Get("justification")
}

// MinJustification is the shortest accepted justification for sensitive permissions.
const MinJustification = 10

// authorize authenticates r and checks perm. Sensitive permissions additionally need a login younger than
// StepUpAge and a justification; those attempts are audited whether granted or denied. Break-glass requests are
// audited always.
func (a *Authenticator) authorize(r *http.Request, perm string) (Caller, error) {
	ctx, now := r.Context(), a.Now()
	raw, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok || raw == "" {
		return Caller{}, &Denial{Status: http.StatusUnauthorized, Reason: "missing bearer token"}
	}
	claims, err := a.Verify(ctx, raw)
	if err != nil {
		return Caller{}, &Denial{Status: http.StatusUnauthorized, Reason: "invalid token"}
	}
	if !slices.Contains(a.MFAACR, claims.ACR) {
		return Caller{}, &Denial{Status: http.StatusUnauthorized, Reason: "multi-factor login required", StepUp: true}
	}
	c := Caller{ID: claims.Subject, Username: claims.Username, AuthTime: claims.AuthTime}
	if a.BreakGlass[claims.Subject] {
		c.BreakGlass = true
		c.Bindings = []Binding{{Role: "break_glass"}}
		if err := a.Audit(ctx, c.Username, "breakglass.request", map[string]any{"method": r.Method, "path": r.URL.Path, "perm": perm}); err != nil {
			return Caller{}, err // no audit record, no break-glass access
		}
	} else if c.Bindings, err = a.Bindings(ctx, claims.Username); err != nil {
		return Caller{}, fmt.Errorf("load bindings: %w", err)
	}

	if perm == Authenticated {
		return c, nil
	}
	allowed := c.Can(perm, Resource{}, now)
	if !Sensitive[perm] {
		if !allowed {
			return Caller{}, &Denial{Status: http.StatusForbidden, Reason: "missing permission " + perm}
		}
		return c, nil
	}
	// Sensitive: every attempt is audited, granted or denied, before anything else happens.
	target := map[string]any{"perm": perm, "method": r.Method, "path": r.URL.Path, "justification": Justification(r)}
	var denial *Denial
	switch {
	case !allowed:
		denial = &Denial{Status: http.StatusForbidden, Reason: "missing permission " + perm}
	case now.Sub(c.AuthTime) > a.StepUpAge:
		denial = &Denial{Status: http.StatusUnauthorized, Reason: fmt.Sprintf("%s needs a login within %s", perm, a.StepUpAge), StepUp: true}
	case len(strings.TrimSpace(Justification(r))) < MinJustification:
		denial = &Denial{Status: http.StatusForbidden, Reason: fmt.Sprintf("%s needs a justification of at least %d characters", perm, MinJustification)}
	}
	action := "access.sensitive"
	if denial != nil {
		action, target["denied"] = "access.sensitive.denied", denial.Reason
	}
	if err := a.Audit(ctx, c.Username, action, target); err != nil {
		return Caller{}, err
	}
	if denial != nil {
		return Caller{}, denial
	}
	return c, nil
}

// Check runs authentication and authorization for r against the registered route without calling its handler:
// 0 when the handler would run, else the denial status (404 if no route matches). For the route matrix test.
func (rt *Router) Check(r *http.Request) int {
	_, pattern := rt.Mux.Handler(r)
	if pattern == "" {
		return http.StatusNotFound
	}
	method, path, _ := strings.Cut(pattern, " ")
	i := slices.IndexFunc(rt.routes, func(x Route) bool { return x.Method == method && x.Pattern == path })
	if rt.routes[i].Perm == "" {
		return 0
	}
	if _, err := rt.Auth.authorize(r, rt.routes[i].Perm); err != nil {
		var d *Denial
		if errors.As(err, &d) {
			return d.Status
		}
		return http.StatusInternalServerError
	}
	return 0
}
