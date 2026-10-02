// Package privacy keeps raw content out of logs (spec §10.2, §12.3).
package privacy

import (
	_ "embed"
	"log/slog"
	"os"
	"strings"
)

//go:embed forbidden_fields.txt
var forbiddenFile string

var forbidden = func() map[string]bool {
	m := map[string]bool{}
	for _, l := range strings.Split(forbiddenFile, "\n") {
		if l = strings.TrimSpace(l); l != "" && !strings.HasPrefix(l, "#") {
			m[strings.ToLower(l)] = true
		}
	}
	return m
}()

// ReplaceAttr drops forbidden fields at any nesting level. Use it in every slog handler.
func ReplaceAttr(_ []string, a slog.Attr) slog.Attr {
	if forbidden[strings.ToLower(a.Key)] {
		return slog.Attr{}
	}
	return a
}

// NewLogger returns the JSON logger every service uses.
func NewLogger(service string) *slog.Logger {
	h := slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{ReplaceAttr: ReplaceAttr})
	return slog.New(h).With("service", service)
}
