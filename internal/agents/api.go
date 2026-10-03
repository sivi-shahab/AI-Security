package agents

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"aisec/internal/authz"
)

var errScope = errors.New("outside your business unit")

// Routes mounts the registry API. Reads need agent.read; writes need agent.write *for the agent's business unit*
// (ABAC: an agent owner bound to unit "retail" cannot change a "treasury" agent, or move one there).
func Routes(rt *authz.Router, s *Store, now func() time.Time) {
	reply := func(w http.ResponseWriter, status int, v any, err error) {
		switch {
		case errors.Is(err, ErrNotFound):
			http.Error(w, err.Error(), http.StatusNotFound)
		case errors.Is(err, ErrInvalid):
			http.Error(w, err.Error(), http.StatusBadRequest)
		case errors.Is(err, errScope):
			http.Error(w, err.Error(), http.StatusForbidden)
		case err != nil:
			http.Error(w, "internal error", http.StatusInternalServerError)
		default:
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(status)
			_ = json.NewEncoder(w).Encode(v)
		}
	}
	decode := func(r *http.Request, v any) error {
		if err := json.NewDecoder(http.MaxBytesReader(nil, r.Body, 1<<20)).Decode(v); err != nil {
			return ErrInvalid
		}
		return nil
	}
	inUnit := func(c authz.Caller, units ...string) error {
		for _, u := range units {
			if !c.Can(authz.AgentWrite, authz.Resource{BusinessUnit: u}, now()) {
				return errScope
			}
		}
		return nil
	}

	rt.Handle("GET /agents", authz.AgentRead, func(w http.ResponseWriter, r *http.Request, _ authz.Caller) {
		as, err := s.List(r.Context(), r.URL.Query().Get("status"))
		reply(w, 200, as, err)
	})
	rt.Handle("GET /agents/summary", authz.DashboardRead, func(w http.ResponseWriter, r *http.Request, _ authz.Caller) {
		sum, err := s.Summarize(r.Context())
		reply(w, 200, sum, err)
	})
	rt.Handle("GET /agents/discovered", authz.AgentRead, func(w http.ResponseWriter, r *http.Request, _ authz.Caller) {
		ds, err := s.Discovered(r.Context(), r.URL.Query().Get("state"))
		reply(w, 200, ds, err)
	})
	rt.Handle("POST /agents/discovered/{id}/dismiss", authz.AgentWrite, func(w http.ResponseWriter, r *http.Request, c authz.Caller) {
		var b struct {
			Note string `json:"note"`
		}
		if err := decode(r, &b); err != nil {
			reply(w, 0, nil, err)
			return
		}
		reply(w, 200, map[string]any{"agent_id": r.PathValue("id"), "state": "dismissed"}, s.Dismiss(r.Context(), c.Username, r.PathValue("id"), b.Note))
	})
	rt.Handle("GET /agents/{id}", authz.AgentRead, func(w http.ResponseWriter, r *http.Request, _ authz.Caller) {
		a, err := s.Get(r.Context(), r.PathValue("id"))
		reply(w, 200, a, err)
	})
	rt.Handle("POST /agents", authz.AgentWrite, func(w http.ResponseWriter, r *http.Request, c authz.Caller) {
		var a Agent
		if err := decode(r, &a); err != nil {
			reply(w, 0, nil, err)
			return
		}
		if err := inUnit(c, a.BusinessUnit); err != nil {
			reply(w, 0, nil, err)
			return
		}
		a, err := s.Register(r.Context(), c.Username, a)
		reply(w, 201, a, err)
	})
	rt.Handle("PUT /agents/{id}", authz.AgentWrite, func(w http.ResponseWriter, r *http.Request, c authz.Caller) {
		var a Agent
		if err := decode(r, &a); err != nil {
			reply(w, 0, nil, err)
			return
		}
		a.ID = r.PathValue("id")
		cur, err := s.Get(r.Context(), a.ID)
		if err == nil {
			err = inUnit(c, cur.BusinessUnit, a.BusinessUnit)
		}
		if err == nil {
			a, err = s.Update(r.Context(), c.Username, a)
		}
		reply(w, 200, a, err)
	})
	rt.Handle("POST /agents/{id}/status", authz.AgentWrite, func(w http.ResponseWriter, r *http.Request, c authz.Caller) {
		var b struct {
			Status string `json:"status"`
			Reason string `json:"reason"`
		}
		if err := decode(r, &b); err != nil {
			reply(w, 0, nil, err)
			return
		}
		cur, err := s.Get(r.Context(), r.PathValue("id"))
		if err == nil {
			err = inUnit(c, cur.BusinessUnit)
		}
		var a Agent
		if err == nil {
			a, err = s.SetStatus(r.Context(), c.Username, cur.ID, b.Status, b.Reason)
		}
		reply(w, 200, a, err)
	})
}
