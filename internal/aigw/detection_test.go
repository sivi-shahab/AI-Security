package aigw

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// TestDetectionShadow (ticket 49 AC): gateway traffic yields an L2 shadow report in the decision event (classes counted,
// never offsets or text); with detection-svc slow or down the app gets its answer within the L1 budget, the event
// says why L2 is missing, and detection_fallback_total counts it.
func TestDetectionShadow(t *testing.T) {
	reply := []byte(`{"id":"msg_1","type":"message","role":"assistant","content":[{"type":"text","text":"Baik."}],"stop_reason":"end_turn","usage":{"input_tokens":5,"output_tokens":2}}`)
	ask := func(e *env) (result, time.Duration) {
		start := time.Now()
		r := e.do("anthropic", "v1/messages", keyChat, map[string]any{"model": "m", "max_tokens": 50, "messages": []any{map[string]any{"role": "user", "content": "Tolong cek saldo nasabah"}}})
		return r, time.Since(start)
	}
	// waitL2 returns the request event once its L2 report arrived (the event waits for L2, the app does not).
	waitL2 := func(e *env) *eventL2 {
		for range 200 {
			for _, ev := range e.events.all() {
				if ev.Direction == "request" && ev.L2 != nil {
					return &eventL2{ev.L2.Status, ev.L2.Model, len(ev.L2.Classes), ev.L2.InjectionScore}
				}
			}
			time.Sleep(10 * time.Millisecond)
		}
		t.Fatal("no request event with an L2 report")
		return nil
	}
	metric := func(e *env) string {
		m := httptest.NewRecorder()
		e.gw.serveMetrics(m, nil)
		return m.Body.String()
	}

	t.Run("ok", func(t *testing.T) {
		// The handler also runs for the response scan, after the test reads got: guard it.
		var mu sync.Mutex
		var got map[string]any
		ds := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var body map[string]any
			_ = json.NewDecoder(r.Body).Decode(&body)
			mu.Lock()
			if got == nil {
				got = body
			}
			mu.Unlock()
			_, _ = w.Write([]byte(`{"l2":{"model":"l2-1+abc","mode":"shadow","status":"ok","latency_ms":12,
				"entities":[{"type":"PII_ID.NIK","start":0,"end":16,"confidence":0.7},{"type":"PII_ID.NIK","start":20,"end":36,"confidence":0.9},{"type":"bogus","start":1,"end":2,"confidence":1}],
				"injection":{"score":0.2,"types":[]}}}`))
		}))
		defer ds.Close()
		e := newEnv(t)
		e.ups["anthropic"].reply = reply
		e.gw.Detection = &Detection{URL: ds.URL, HTTP: ds.Client(), Timeout: 150 * time.Millisecond}
		if r, _ := ask(e); r.status != 200 {
			t.Fatalf("%d %s", r.status, r.raw)
		}
		l2 := waitL2(e)
		if l2.status != "ok" || l2.model != "l2-1+abc" || l2.classes != 1 || l2.injection == nil || *l2.injection != 0.2 {
			t.Errorf("L2 %+v", l2)
		}
		mu.Lock()
		defer mu.Unlock()
		if got["channel"] != "ai_gateway" || got["context"].(map[string]any)["trust"] == nil {
			t.Errorf("scan request %v", got)
		}
		if strings.Contains(metric(e), "detection_fallback_total") {
			t.Error("fallback counted on a good answer")
		}
	})

	for name, h := range map[string]http.HandlerFunc{
		"timeout": func(w http.ResponseWriter, r *http.Request) {
			select {
			case <-r.Context().Done():
			case <-time.After(2 * time.Second):
			}
		},
		"error": func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusServiceUnavailable) },
	} {
		t.Run(name, func(t *testing.T) {
			ds := httptest.NewServer(h)
			defer ds.Close()
			e := newEnv(t)
			e.ups["anthropic"].reply = reply
			e.gw.Detection = &Detection{URL: ds.URL, HTTP: ds.Client(), Timeout: time.Second}
			r, took := ask(e)
			// L2 is off the request path: the app never waits for it, however slow detection-svc is.
			if r.status != 200 || took > 500*time.Millisecond {
				t.Errorf("%d in %v", r.status, took)
			}
			if l2 := waitL2(e); l2.status != name {
				t.Errorf("L2 %+v", l2)
			}
			if !strings.Contains(metric(e), `aigw_detection_fallback_total{app="chat-assistant"}`) {
				t.Errorf("metrics:\n%s", metric(e))
			}
		})
	}
}

type eventL2 struct {
	status, model string
	classes       int
	injection     *float64
}
