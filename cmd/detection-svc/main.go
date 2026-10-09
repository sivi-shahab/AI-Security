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
)

// maxContent: spec §8.1 caps content at 256 KB.
const maxContent = 256 << 10

// scanText is POST /scan/text (spec §8.1) without policy evaluation yet: L1 findings, registered confidential
// documents found (ticket 37) and sensitivity. Content is never logged or echoed back; matches carry offsets, not
// values.
func scanText(similar *similarity.Live) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Content   string `json:"content"`
			Channel   string `json:"channel"`
			Direction string `json:"direction"`
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
		res := struct {
			detect.Result
			Similar []similarity.Hit `json:"similar,omitempty"`
		}{Result: detect.Scan(req.Content)}
		res.Similar = similar.Index().Match(req.Content)
		similarity.Apply(&res.Result, res.Similar)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(res)
	}
}

// Env (optional; without it only L1 runs): DATABASE_URL (read access to similarity.docs), TENANT_ID, TENANT_PEPPER.
func main() {
	var similar *similarity.Live
	if url := os.Getenv("DATABASE_URL"); url != "" {
		log := privacy.NewLogger("detection-svc")
		ctx := context.Background()
		db, err := pgxpool.New(ctx, url)
		if err == nil {
			similar, err = similarity.Watch(ctx, db, os.Getenv("TENANT_ID"), []byte(os.Getenv("TENANT_PEPPER")), time.Minute, log)
		}
		if err != nil {
			log.Error("similarity index", "err", err)
			os.Exit(1)
		}
	}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /scan/text", scanText(similar))
	server.Run("detection-svc", mux)
}
