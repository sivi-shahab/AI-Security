package incident

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"
)

const (
	PermRead   = "incident.read"
	PermWrite  = "incident.write"
	PermUnmask = "evidence.unmask"
)

// Caller is the authenticated user and their permissions.
type Caller struct {
	ID    string
	Perms map[string]bool
}

// ponytail: until SSO/RBAC (ticket 06), identity comes from headers set by an authenticating proxy, and only when
// AUTH_MODE=trusted-proxy; every other mode rejects all requests. Replace with OIDC token validation there.
func callerFrom(r *http.Request, authMode string) (Caller, bool) {
	if authMode != "trusted-proxy" {
		return Caller{}, false
	}
	id := r.Header.Get("X-Aisec-User")
	if id == "" {
		return Caller{}, false
	}
	c := Caller{ID: id, Perms: map[string]bool{}}
	for _, p := range strings.Split(r.Header.Get("X-Aisec-Perms"), ",") {
		if p = strings.TrimSpace(p); p != "" {
			c.Perms[p] = true
		}
	}
	return c, true
}

// Routes mounts the §8.5 incident API.
func Routes(mux *http.ServeMux, s *Store, authMode string, now func() time.Time) {
	handle := func(pattern, perm string, h func(http.ResponseWriter, *http.Request, Caller) (any, error)) {
		mux.HandleFunc(pattern, func(w http.ResponseWriter, r *http.Request) {
			c, ok := callerFrom(r, authMode)
			if !ok {
				http.Error(w, "unauthenticated", http.StatusUnauthorized)
				return
			}
			if perm != "" && !c.Perms[perm] {
				http.Error(w, "missing permission "+perm, http.StatusForbidden)
				return
			}
			v, err := h(w, r, c)
			switch {
			case errors.Is(err, ErrNotFound):
				http.Error(w, err.Error(), http.StatusNotFound)
			case errors.Is(err, ErrForbidden):
				http.Error(w, err.Error(), http.StatusForbidden)
			case errors.Is(err, ErrInvalidTransition):
				http.Error(w, err.Error(), http.StatusConflict)
			case err != nil:
				http.Error(w, "internal error", http.StatusInternalServerError)
			case v != nil:
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(v)
			}
		})
	}

	handle("GET /incidents", PermRead, func(_ http.ResponseWriter, r *http.Request, _ Caller) (any, error) {
		return s.List(r.Context(), r.URL.Query().Get("severity"), r.URL.Query().Get("state"), 500)
	})
	handle("GET /incidents/{id}", PermRead, func(_ http.ResponseWriter, r *http.Request, _ Caller) (any, error) {
		id := r.PathValue("id")
		inc, err := s.Get(r.Context(), id)
		if err != nil {
			return nil, err
		}
		evs, err := s.Events(r.Context(), id)
		if err != nil {
			return nil, err
		}
		ev, err := s.Evidence(r.Context(), id)
		return map[string]any{"incident": inc, "events": evs, "evidence": ev}, err
	})
	handle("POST /incidents/{id}/transition", PermWrite, func(_ http.ResponseWriter, r *http.Request, c Caller) (any, error) {
		var body struct {
			To   State  `json:"to"`
			Note string `json:"note"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(nil, r.Body, 64<<10)).Decode(&body); err != nil {
			return nil, ErrInvalidTransition
		}
		return s.Transition(r.Context(), r.PathValue("id"), body.To, body.Note, c.ID, now())
	})
	handle("POST /incidents/{id}/severity", PermWrite, func(_ http.ResponseWriter, r *http.Request, c Caller) (any, error) {
		var body struct {
			Severity string `json:"severity"`
			Note     string `json:"note"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(nil, r.Body, 64<<10)).Decode(&body); err != nil {
			return nil, ErrInvalidTransition
		}
		return s.RaiseSeverity(r.Context(), r.PathValue("id"), body.Severity, body.Note, c.ID, now())
	})
	// No route-level permission: Unmask checks and audits it, so a denied attempt is recorded too.
	handle("GET /incidents/{id}/evidence/{eid}", "", func(w http.ResponseWriter, r *http.Request, c Caller) (any, error) {
		q := r.URL.Query()
		if q.Get("unmask") != "true" {
			if !c.Perms[PermRead] {
				return nil, ErrForbidden
			}
			metas, err := s.Evidence(r.Context(), r.PathValue("id"))
			for _, m := range metas {
				if m.ID == r.PathValue("eid") {
					return m, err
				}
			}
			if err == nil {
				err = ErrNotFound
			}
			return nil, err
		}
		raw, err := s.Unmask(r.Context(), c, r.PathValue("id"), r.PathValue("eid"), q.Get("justification"))
		if err != nil {
			return nil, err
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Cache-Control", "no-store")
		_, _ = w.Write(raw)
		return nil, nil
	})
}
