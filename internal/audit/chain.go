// Package audit is the append-only audit log (spec FR-COMP-4): every entry is chained with
// hash = SHA-256(prev_hash ‖ canonical_json(entry)), and the chain head is anchored daily to WORM storage.
package audit

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// Genesis is prev_hash of the first entry.
var Genesis = strings.Repeat("0", 64)

// Entry is one audit record. PrevHash and Hash are not part of the hashed content.
type Entry struct {
	Seq      int64
	TenantID string
	TS       time.Time
	Actor    string
	Action   string
	Target   map[string]any
	PrevHash string
	Hash     string
}

// Canonical is the hashed form: JSON with sorted keys, no HTML escaping, ts in UTC RFC 3339 (µs, as Postgres
// stores it). Target must already be in its decoded-JSON shape (float64 numbers): Append normalizes it, and that
// is also what reading jsonb back yields, so the same bytes come out at write and verify time.
func Canonical(e Entry) []byte {
	target := e.Target
	if target == nil {
		target = map[string]any{}
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	// encoding/json sorts map keys and cannot fail on these types.
	_ = enc.Encode(map[string]any{
		"seq":       e.Seq,
		"tenant_id": e.TenantID,
		"ts":        e.TS.UTC().Format(time.RFC3339Nano),
		"actor":     e.Actor,
		"action":    e.Action,
		"target":    target,
	})
	return bytes.TrimSuffix(buf.Bytes(), []byte("\n"))
}

// Hash returns hex SHA-256(prevHash ‖ Canonical(e)), prevHash being the hex string.
func Hash(prevHash string, e Entry) string {
	h := sha256.New()
	h.Write([]byte(prevHash))
	h.Write(Canonical(e))
	return hex.EncodeToString(h.Sum(nil))
}

// BrokenError names the first entry at which the chain no longer verifies.
type BrokenError struct {
	Seq    int64
	Reason string
}

func (e *BrokenError) Error() string {
	return fmt.Sprintf("audit chain broken at seq %d: %s", e.Seq, e.Reason)
}

// Verify checks entries (ascending seq) continue the chain from (prevSeq, prevHash): no gaps, every prev_hash
// links, every hash matches its content. Rewriting a whole tail is only caught by the daily anchor.
func Verify(prevSeq int64, prevHash string, entries []Entry) error {
	for _, e := range entries {
		switch {
		case e.Seq != prevSeq+1:
			return &BrokenError{prevSeq + 1, fmt.Sprintf("missing (next present is %d)", e.Seq)}
		case e.PrevHash != prevHash:
			return &BrokenError{e.Seq, "prev_hash does not match previous entry"}
		case e.Hash != Hash(prevHash, e):
			return &BrokenError{e.Seq, "content does not match hash"}
		}
		prevSeq, prevHash = e.Seq, e.Hash
	}
	return nil
}
