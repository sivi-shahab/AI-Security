package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"aisec/internal/detect"
	"aisec/internal/privacy"
	"aisec/internal/server"
	"aisec/internal/similarity"
	"aisec/internal/tuning"
)

// maxContent: spec §8.1 caps content at 256 KB.
const maxContent = 256 << 10

// scanText is POST /scan/text (spec §8.1) without policy evaluation yet: L1 findings less those the tenant tuning
// model judges false positives (ticket 38), registered confidential documents found (ticket 37), sensitivity, and the
// redacted snippet PEPs put in the decision event. Content is never logged or echoed back; matches carry offsets,
// not values.
func scanText(tuned *tuning.Live, similar *similarity.Live) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Content   string `json:"content"`
			Channel   string `json:"channel"`
			Direction string `json:"direction"`
			Context   struct {
				AppID string `json:"app_id"`
			} `json:"context"`
		}
		err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxContent+16<<10)).Decode(&req)
		var tooBig *http.MaxBytesError
		switch {
		case errors.As(err, &tooBig) || len(req.Content) > maxContent:
			http.Error(w, "content exceeds 256 KB", http.StatusRequestEntityTooLarge)
			return
		case err != nil:
			http.Error(w, "invalid JSON", http.StatusBadRequest)
			return
		}
		var res struct {
			detect.Result
			Similar []similarity.Hit `json:"similar,omitempty"`
			Tuning  *tuning.Report   `json:"tuning,omitempty"`
			Snippet string           `json:"snippet"`
		}
		res.Result, res.Tuning = tuned.Apply(req.Content, detect.Scan(req.Content), req.Channel, req.Direction, req.Context.AppID)
		res.Similar = similar.Index().Match(req.Content)
		similarity.Apply(&res.Result, res.Similar)
		res.Snippet = detect.Snippet(req.Content, res.Matches)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(res)
	}
}

// Env: MTLS_DIR, MTLS_ALLOW (internal/server, ticket 40). Optional (without it only L1 runs): DATABASE_URL (read access to similarity.docs and tuning.models), TENANT_ID,
// TENANT_PEPPER.
func main() {
	var similar *similarity.Live
	var tuned *tuning.Live
	if url := os.Getenv("DATABASE_URL"); url != "" {
		log := privacy.NewLogger("detection-svc")
		ctx := context.Background()
		db, err := pgxpool.New(ctx, url)
		if err == nil {
			similar, err = similarity.Watch(ctx, db, os.Getenv("TENANT_ID"), []byte(os.Getenv("TENANT_PEPPER")), time.Minute, log)
		}
		if err == nil {
			tuned, err = tuning.Watch(ctx, db, os.Getenv("TENANT_ID"), []byte(os.Getenv("TENANT_PEPPER")), time.Minute, log)
		}
		if err != nil {
			log.Error("similarity index or tuning models", "err", err)
			os.Exit(1)
		}
	}
	// Scanning is for PEP workloads only (ticket 40): on the mTLS listener, never on the probe port.
	server.RunMTLS("detection-svc", http.NewServeMux(), workloadRoutes(tuned, similar))
}

func workloadRoutes(tuned *tuning.Live, similar *similarity.Live) *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /scan/text", scanText(tuned, similar))
	return mux
}
