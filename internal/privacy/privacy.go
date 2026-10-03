// Package privacy keeps raw content out of logs (spec §10.2, §12.3).
package privacy

import (
	_ "embed"
	"log/slog"
	"maps"
	"os"
	"slices"
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

// IsForbidden reports whether a field name may never carry data into logs or events (case-insensitive).
func IsForbidden(field string) bool { return forbidden[strings.ToLower(field)] }

// Forbidden lists the field names (lowercase) that must never reach a log. OPA decision-log masking uses it too.
func Forbidden() []string {
	return slices.Sorted(maps.Keys(forbidden))
}

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
