package incident

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"aisec/internal/authz"
)

// Routes mounts the §8.5 incident API. Raw evidence has its own route (…/raw) because it needs a different,
// sensitive permission than the metadata; the router enforces step-up re-auth and justification for it.
func Routes(rt *authz.Router, s *Store, now func() time.Time) {
	reply := func(w http.ResponseWriter, v any, err error) {
		switch {
		case errors.Is(err, ErrNotFound):
			http.Error(w, err.Error(), http.StatusNotFound)
		case errors.Is(err, ErrForbidden):
			http.Error(w, err.Error(), http.StatusForbidden)
		case errors.Is(err, ErrInvalidTransition):
			http.Error(w, err.Error(), http.StatusConflict)
		case err != nil:
			http.Error(w, "internal error", http.StatusInternalServerError)
		default:
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(v)
		}
	}
	decode := func(r *http.Request, v any) error {
		if err := json.NewDecoder(http.MaxBytesReader(nil, r.Body, 64<<10)).Decode(v); err != nil {
			return ErrInvalidTransition
		}
		return nil
	}

	rt.Handle("GET /incidents", authz.IncidentRead, func(w http.ResponseWriter, r *http.Request, _ authz.Caller) {
		v, err := s.List(r.Context(), r.URL.Query().Get("severity"), r.URL.Query().Get("state"), 500)
		reply(w, v, err)
	})
	rt.Handle("GET /incidents/{id}", authz.IncidentRead, func(w http.ResponseWriter, r *http.Request, _ authz.Caller) {
		id := r.PathValue("id")
		inc, err := s.Get(r.Context(), id)
		if err != nil {
			reply(w, nil, err)
			return
		}
		evs, err := s.Events(r.Context(), id)
		if err != nil {
			reply(w, nil, err)
			return
		}
		ev, err := s.Evidence(r.Context(), id)
		reply(w, map[string]any{"incident": inc, "events": evs, "evidence": ev}, err)
	})
	rt.Handle("POST /incidents/{id}/transition", authz.IncidentWrite, func(w http.ResponseWriter, r *http.Request, c authz.Caller) {
		var body struct {
			To   State  `json:"to"`
			Note string `json:"note"`
		}
		if err := decode(r, &body); err != nil {
			reply(w, nil, err)
			return
		}
		v, err := s.Transition(r.Context(), r.PathValue("id"), body.To, body.Note, c.Username, now())
		reply(w, v, err)
	})
	rt.Handle("POST /incidents/{id}/severity", authz.IncidentWrite, func(w http.ResponseWriter, r *http.Request, c authz.Caller) {
		var body struct {
			Severity string `json:"severity"`
			Note     string `json:"note"`
		}
		if err := decode(r, &body); err != nil {
			reply(w, nil, err)
			return
		}
		v, err := s.RaiseSeverity(r.Context(), r.PathValue("id"), body.Severity, body.Note, c.Username, now())
		reply(w, v, err)
	})
	rt.Handle("GET /incidents/{id}/evidence/{eid}", authz.IncidentRead, func(w http.ResponseWriter, r *http.Request, _ authz.Caller) {
		metas, err := s.Evidence(r.Context(), r.PathValue("id"))
		for _, m := range metas {
			if m.ID == r.PathValue("eid") {
				reply(w, m, err)
				return
			}
		}
		if err == nil {
			err = ErrNotFound
		}
		reply(w, nil, err)
	})
	rt.Handle("GET /incidents/{id}/evidence/{eid}/raw", authz.EvidenceUnmask, func(w http.ResponseWriter, r *http.Request, c authz.Caller) {
		raw, err := s.Unmask(r.Context(), c, r.PathValue("id"), r.PathValue("eid"), authz.Justification(r), now())
		if err != nil {
			reply(w, nil, err)
			return
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Cache-Control", "no-store")
		_, _ = w.Write(raw)
	})
}
