// Package policysvc is the Policy Service: it builds and signs the OPA bundle every PEP sidecar pulls and
// serves it with ETag + long-polling (spec FR-POL-1).
package policysvc

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/fs"
	"net/http"
	"path"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/open-policy-agent/opa/v1/bundle"
	"github.com/open-policy-agent/opa/v1/rego"
	"github.com/open-policy-agent/opa/v1/storage/inmem"

	"aisec/internal/privacy"
)

const (
	// KeyID and Alg must match the sidecar's `keys` entry (deploy/base/opa-config.yaml).
	KeyID = "aisec-policy"
	Alg   = "ES256"
	// ContentType tells OPA the server supports long-polling.
	ContentType = "application/vnd.openpolicyagent.bundles"
	maxWait     = 5 * time.Minute
)

// Build bundles every non-test module and data.json in fsys, injects the forbidden log fields for decision-log
// masking (data.system.log.forbidden), refuses rule sets with errors, and signs with a PEM EC P-256 key.
func Build(ctx context.Context, fsys fs.FS, signingKeyPEM string) (tarball []byte, revision string, err error) {
	b := bundle.Bundle{Data: map[string]any{}}
	opts := []func(*rego.Rego){}
	h := sha256.New()
	err = fs.WalkDir(fsys, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		raw, err := fs.ReadFile(fsys, p)
		if err != nil {
			return err
		}
		switch {
		case strings.HasSuffix(p, "_test.rego"), !strings.HasSuffix(p, ".rego") && path.Base(p) != "data.json":
			return nil
		case strings.HasSuffix(p, ".rego"):
			b.Modules = append(b.Modules, bundle.ModuleFile{URL: "/" + p, Path: "/" + p, Raw: raw})
			opts = append(opts, rego.Module(p, string(raw)))
		default:
			var v any
			if err := json.Unmarshal(raw, &v); err != nil {
				return fmt.Errorf("%s: %w", p, err)
			}
			setPath(b.Data, strings.Split(path.Dir(p), "/"), v)
		}
		_, _ = fmt.Fprintf(h, "%s\x00%s\x00", p, raw) // hash.Hash writes never fail
		return nil
	})
	if err != nil {
		return nil, "", err
	}
	forbidden := privacy.Forbidden()
	setPath(b.Data, []string{"system", "log", "forbidden"}, forbidden)
	_, _ = fmt.Fprintf(h, "forbidden\x00%v", forbidden)
	revision = hex.EncodeToString(h.Sum(nil))[:16]

	if err := checkRules(ctx, b.Data, opts); err != nil {
		return nil, "", err
	}

	b.Manifest = bundle.Manifest{Revision: revision, Roots: &[]string{"aisec", "system"}}
	if err := b.GenerateSignature(bundle.NewSigningConfig(signingKeyPEM, Alg, ""), KeyID, false); err != nil {
		return nil, "", fmt.Errorf("sign bundle: %w", err)
	}
	var buf bytes.Buffer
	if err := bundle.NewWriter(&buf).Write(b); err != nil {
		return nil, "", err
	}
	return buf.Bytes(), revision, nil
}

// checkRules fails on any decision rule_errors or risk config_errors: a typo must never become a rule that silently
// never matches, nor weights that push a score out of 0-100.
func checkRules(ctx context.Context, data map[string]any, opts []func(*rego.Rego)) error {
	opts = append(opts, rego.Query("data.aisec.decision.rule_errors | data.aisec.risk.config_errors"), rego.Store(inmem.NewFromObject(data)))
	rs, err := rego.New(opts...).Eval(ctx)
	if err != nil {
		return fmt.Errorf("evaluate rule_errors: %w", err)
	}
	if len(rs) != 1 || len(rs[0].Expressions) != 1 {
		return fmt.Errorf("rule_errors undefined: are aisec/decision.rego and aisec/risk/risk.rego in the bundle?")
	}
	if errs, _ := rs[0].Expressions[0].Value.([]any); len(errs) > 0 {
		return fmt.Errorf("rule set invalid: %v", errs)
	}
	return nil
}

func setPath(m map[string]any, keys []string, v any) {
	for _, k := range keys[:len(keys)-1] {
		next, ok := m[k].(map[string]any)
		if !ok {
			next = map[string]any{}
			m[k] = next
		}
		m = next
	}
	m[keys[len(keys)-1]] = v
}

// Server serves the current bundle. A request whose If-None-Match equals the current ETag and carries
// `Prefer: wait=N` is held until Publish or N seconds pass (OPA long-polling), then gets 304.
type Server struct {
	mu      sync.Mutex
	body    []byte
	etag    string
	changed chan struct{}
}

// Publish swaps in a new bundle and wakes every waiting poller.
func (s *Server) Publish(body []byte, revision string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.body, s.etag = body, strconv.Quote(revision)
	if s.changed != nil {
		close(s.changed)
	}
	s.changed = make(chan struct{})
}

// preferWait reads N from OPA's `Prefer: modes=snapshot,delta;wait=N`; 0 when absent.
func preferWait(prefer string) time.Duration {
	for _, part := range strings.Split(prefer, ";") {
		if n, ok := strings.CutPrefix(strings.TrimSpace(part), "wait="); ok {
			secs, _ := strconv.Atoi(n)
			return time.Duration(secs) * time.Second
		}
	}
	return 0
}

func (s *Server) current() ([]byte, string, chan struct{}) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.body, s.etag, s.changed
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", ContentType)
	body, etag, changed := s.current()
	if body == nil {
		http.Error(w, "no bundle", http.StatusServiceUnavailable)
		return
	}
	if r.Header.Get("If-None-Match") == etag {
		timer := time.NewTimer(min(preferWait(r.Header.Get("Prefer")), maxWait))
		defer timer.Stop()
		select {
		case <-changed:
			body, etag, _ = s.current()
		case <-timer.C:
		case <-r.Context().Done():
			return
		}
	}
	w.Header().Set("ETag", etag)
	if r.Header.Get("If-None-Match") == etag {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	_, _ = w.Write(body)
}
