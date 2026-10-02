package privacy

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"
)

const secret = "NIK 3171234567890001"

func TestForbiddenFieldsNeverLogged(t *testing.T) {
	var buf bytes.Buffer
	log := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{ReplaceAttr: ReplaceAttr}))

	for key := range forbidden {
		log.Info("top", key, secret)
		log.Info("upper", strings.ToUpper(key), secret)
		log.Info("group", slog.Group("req", key, secret))
		log.With(key, secret).Info("with")
	}
	log.Info("ok", "decision_id", "d-1")

	out := buf.String()
	if strings.Contains(out, secret) {
		t.Fatalf("raw content leaked into log:\n%s", out)
	}
	if !strings.Contains(out, `"decision_id":"d-1"`) {
		t.Fatalf("allowed field was dropped:\n%s", out)
	}
	if len(forbidden) < 5 {
		t.Fatalf("forbidden list not loaded: %v", forbidden)
	}
}
