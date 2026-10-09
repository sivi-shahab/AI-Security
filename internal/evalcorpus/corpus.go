// Package evalcorpus is the frozen evaluation corpus for the detectors (ticket 04, spec §9.3–9.4): synthetic
// Indonesian PII in bank document templates, prompt-injection attacks labelled by technique and language,
// enterprise-like benign prompts for false-positive rates, and a public open-licensed injection set. Each version is
// a directory of JSON-lines files plus MANIFEST.json (source, licence, version, sha256 per file); a version never
// changes once frozen, a new one gets a new directory.
package evalcorpus

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// Sample is one labelled text. Entity offsets are UTF-8 byte offsets into Text.
type Sample struct {
	ID         string   `json:"id"`
	Kind       string   `json:"kind"` // pii | injection | benign
	Lang       string   `json:"lang"` // id, en, jv, su, mixed, und
	Text       string   `json:"text"`
	Entities   []Entity `json:"entities"`
	Attack     bool     `json:"attack"`
	Technique  string   `json:"technique,omitempty"` // injection technique, or hard_negative for tricky benign text
	Template   string   `json:"template,omitempty"`
	Provenance string   `json:"provenance"`
}

type Entity struct {
	Type  string `json:"type"` // detector class, e.g. PII_ID.NIK
	Start int    `json:"start"`
	End   int    `json:"end"`
}

// Manifest describes a frozen version.
type Manifest struct {
	Version string `json:"version"`
	Frozen  string `json:"frozen"` // date
	Note    string `json:"note"`
	Files   []File `json:"files"`
}

type File struct {
	Name     string `json:"name"`
	Kind     string `json:"kind"`
	Samples  int    `json:"samples"`
	SHA256   string `json:"sha256"`
	Source   string `json:"source"`
	License  string `json:"license"`
	Upstream string `json:"upstream,omitempty"` // dataset revision for public sources
	Seed     uint64 `json:"seed,omitempty"`     // generator seed for synthetic files
}

// Encode writes samples as JSON lines.
func Encode(ss []Sample) []byte {
	var b bytes.Buffer
	for _, s := range ss {
		j, _ := json.Marshal(s)
		b.Write(j)
		b.WriteByte('\n')
	}
	return b.Bytes()
}

// Decode reads JSON lines.
func Decode(raw []byte) ([]Sample, error) {
	var ss []Sample
	sc := bufio.NewScanner(bytes.NewReader(raw))
	sc.Buffer(nil, 1<<20)
	for n := 1; sc.Scan(); n++ {
		var s Sample
		if err := json.Unmarshal(sc.Bytes(), &s); err != nil {
			return nil, fmt.Errorf("line %d: %w", n, err)
		}
		ss = append(ss, s)
	}
	return ss, sc.Err()
}

func Hash(raw []byte) string {
	h := sha256.Sum256(raw)
	return hex.EncodeToString(h[:])
}

// Load reads a version directory and verifies every file against the manifest: a frozen set that changed is an
// error, not a new baseline.
func Load(dir string) (Manifest, []Sample, error) {
	var m Manifest
	raw, err := os.ReadFile(filepath.Join(dir, "MANIFEST.json"))
	if err != nil {
		return m, nil, err
	}
	if err := json.Unmarshal(raw, &m); err != nil {
		return m, nil, err
	}
	var all []Sample
	for _, f := range m.Files {
		raw, err := os.ReadFile(filepath.Join(dir, f.Name))
		if err != nil {
			return m, nil, err
		}
		if h := Hash(raw); h != f.SHA256 {
			return m, nil, fmt.Errorf("%s: sha256 %s, manifest %s: frozen eval set modified", f.Name, h, f.SHA256)
		}
		ss, err := Decode(raw)
		if err != nil {
			return m, nil, fmt.Errorf("%s: %w", f.Name, err)
		}
		if len(ss) != f.Samples {
			return m, nil, fmt.Errorf("%s: %d samples, manifest %d", f.Name, len(ss), f.Samples)
		}
		all = append(all, ss...)
	}
	return m, all, nil
}
