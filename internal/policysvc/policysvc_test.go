package policysvc

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"io"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/open-policy-agent/opa/v1/bundle"
	"github.com/open-policy-agent/opa/v1/tester"

	"aisec/policy"
)

// Runs every policy/**/*_test.rego (precedence, templates, residency matrix, log masking) under go test.
func TestRegoPolicies(t *testing.T) {
	modules, store, err := tester.Load([]string{"../../policy"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	// The 80-combination residency matrix outlives the default 5s per test under -race.
	ch, err := tester.NewRunner().SetStore(store).SetModules(modules).SetTimeout(time.Minute).RunTests(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	var results []*tester.Result
	for r := range ch {
		results = append(results, r)
	}
	t.Logf("%d rego tests", len(results))
	if len(results) == 0 {
		t.Fatal("no rego tests found")
	}
	for _, r := range results {
		if r.Fail || r.Error != nil {
			t.Errorf("%s.%s: fail=%v err=%v\n%s", r.Package, r.Name, r.Fail, r.Error, r.Output)
		}
	}
}

func keyPair(t *testing.T) (priv, pub string) {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, _ := x509.MarshalECPrivateKey(k)
	pubDer, _ := x509.MarshalPKIXPublicKey(&k.PublicKey)
	return string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})),
		string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDer}))
}

func read(tarball []byte, pub string) (bundle.Bundle, error) {
	vc := bundle.NewVerificationConfig(map[string]*bundle.KeyConfig{KeyID: {Key: pub, Algorithm: Alg}}, KeyID, "", nil)
	return bundle.NewReader(bytes.NewReader(tarball)).WithBundleVerificationConfig(vc).Read()
}

func TestBuildSignsVerifiableBundle(t *testing.T) {
	priv, pub := keyPair(t)
	tarball, rev, err := Build(context.Background(), policy.Files, priv)
	if err != nil {
		t.Fatal(err)
	}
	b, err := read(tarball, pub)
	if err != nil {
		t.Fatalf("verify with the signing key's public half: %v", err)
	}
	if b.Manifest.Revision != rev {
		t.Errorf("revision %q, want %q", b.Manifest.Revision, rev)
	}
	for _, m := range b.Modules {
		if strings.HasSuffix(m.Path, "_test.rego") {
			t.Errorf("test module shipped: %s", m.Path)
		}
	}
	forbidden, _ := b.Data["system"].(map[string]any)["log"].(map[string]any)["forbidden"].([]any)
	if !slices.Contains(forbidden, any("prompt")) {
		t.Errorf("data.system.log.forbidden = %v, want the privacy field list", forbidden)
	}

	_, otherPub := keyPair(t)
	if _, err := read(tarball, otherPub); err == nil {
		t.Error("bundle verified with an unrelated key")
	}
}

func TestBuildRefusesInvalidRules(t *testing.T) {
	priv, _ := keyPair(t)
	fsys := fstest.MapFS{}
	_ = fs.WalkDir(policy.Files, ".", func(p string, d fs.DirEntry, _ error) error {
		if !d.IsDir() {
			raw, _ := fs.ReadFile(policy.Files, p)
			fsys[p] = &fstest.MapFile{Data: raw}
		}
		return nil
	})
	fsys["aisec/rules/data.json"] = &fstest.MapFile{Data: []byte(
		`{"version": "bad", "items": [{"id": "x", "when": [{"field": "channel", "op": "regex", "value": "."}], "action": "block", "reason": "X"}]}`)}
	if _, _, err := Build(context.Background(), fsys, priv); err == nil || !strings.Contains(err.Error(), "unknown op regex") {
		t.Fatalf("err = %v, want rule_errors refusal", err)
	}
}

func get(t *testing.T, url string, hdr map[string]string) (*http.Response, string) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodGet, url, nil)
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	return resp, string(body)
}

func TestServerETagAndLongPoll(t *testing.T) {
	s := &Server{}
	ts := httptest.NewServer(s)
	defer ts.Close()

	if resp, _ := get(t, ts.URL, nil); resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("before publish: %d", resp.StatusCode)
	}
	s.Publish([]byte("v1"), "r1")
	resp, body := get(t, ts.URL, nil)
	if resp.StatusCode != 200 || body != "v1" || resp.Header.Get("ETag") != `"r1"` || resp.Header.Get("Content-Type") != ContentType {
		t.Fatalf("first fetch: %d %q %v", resp.StatusCode, body, resp.Header)
	}
	if resp, _ := get(t, ts.URL, map[string]string{"If-None-Match": `"r1"`}); resp.StatusCode != http.StatusNotModified {
		t.Fatalf("unchanged without wait: %d", resp.StatusCode)
	}

	done := make(chan string)
	go func() {
		_, body := get(t, ts.URL, map[string]string{"If-None-Match": `"r1"`, "Prefer": "modes=snapshot,delta;wait=30"}) // exactly what OPA 1.21 sends
		done <- body
	}()
	time.Sleep(100 * time.Millisecond)
	s.Publish([]byte("v2"), "r2")
	select {
	case body := <-done:
		if body != "v2" {
			t.Fatalf("long-poll got %q, want v2", body)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("long-poll not woken by Publish")
	}
}
