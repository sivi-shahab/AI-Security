package ingest

import (
	"context"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// Ticket 41 AC: the services' OpenSearch client refuses plaintext and anonymous configs, verifies the cluster
// certificate against OPENSEARCH_CA_FILE and authenticates.
func TestOpenSearchFromEnv(t *testing.T) {
	env := func(m map[string]string) func(string) string { return func(k string) string { return m[k] } }
	for name, m := range map[string]map[string]string{
		"http":          {"OPENSEARCH_URL": "http://os:9200", "OPENSEARCH_USER": "u", "OPENSEARCH_PASSWORD": "p"},
		"no password":   {"OPENSEARCH_URL": "https://os:9200", "OPENSEARCH_USER": "u"},
		"plaintext=1":   {"OPENSEARCH_URL": "http://os:9200", "OPENSEARCH_PLAINTEXT": "1"},
		"missing CA":    {"OPENSEARCH_URL": "https://os:9200", "OPENSEARCH_USER": "u", "OPENSEARCH_PASSWORD": "p", "OPENSEARCH_CA_FILE": "/nope"},
		"no URL at all": {},
	} {
		if _, err := OpenSearchFromEnv(env(m), time.Second); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := OpenSearchFromEnv(env(map[string]string{"OPENSEARCH_URL": "http://localhost:9200", "OPENSEARCH_PLAINTEXT": "true"}), time.Second); err != nil {
		t.Errorf("local opt-out: %v", err)
	}

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if u, p, ok := r.BasicAuth(); !ok || u != "event-ingest" || p != "s3cret" {
			w.WriteHeader(401)
		}
	}))
	defer srv.Close()
	ca := filepath.Join(t.TempDir(), "ca.pem")
	_ = os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}), 0o600)
	m := map[string]string{"OPENSEARCH_URL": srv.URL, "OPENSEARCH_USER": "event-ingest", "OPENSEARCH_PASSWORD": "s3cret", "OPENSEARCH_CA_FILE": ca}
	o, err := OpenSearchFromEnv(env(m), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if code, _, err := o.do(context.Background(), http.MethodGet, "/", nil, "application/json"); err != nil || code != 200 {
		t.Errorf("with CA and credentials: %d %v", code, err)
	}
	// Without the CA (system roots only) the self-signed cluster is not trusted.
	delete(m, "OPENSEARCH_CA_FILE")
	o, _ = OpenSearchFromEnv(env(m), time.Second)
	if _, _, err := o.do(context.Background(), http.MethodGet, "/", nil, "application/json"); err == nil {
		t.Error("untrusted certificate accepted")
	}
}
