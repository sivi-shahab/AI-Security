package main

import (
	"encoding/json"
	"errors"
	"net/http"

	"aisec/internal/detect"
	"aisec/internal/server"
)

// maxContent: spec §8.1 caps content at 256 KB.
const maxContent = 256 << 10

// scanText is POST /scan/text (spec §8.1) without policy evaluation yet: L1 findings and sensitivity only.
// Content is never logged or echoed back; matches carry offsets, not values.
func scanText(w http.ResponseWriter, r *http.Request) {
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
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(detect.Scan(req.Content))
}

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /scan/text", scanText)
	server.Run("detection-svc", mux)
}
