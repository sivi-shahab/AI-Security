// Package toolscope is the parameter-scope format of an allow-listed tool (spec FR-AGT-4): the registry validates
// it on write, the MCP gateway enforces it on every tools/call.
//
//	{"amount": {"max": 25000000}, "currency": {"in": ["IDR"]}, "payee.account": {"in": ["1234567890"]},
//	 "rate_per_minute": 30}
//
// A key names an argument (dots descend into objects) and holds {max, min, in}; rate_per_minute caps calls of
// the tool per agent. A constrained argument that is missing, or of the wrong kind, is a violation: fail closed.
package toolscope

import (
	"errors"
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
)

const RateKey = "rate_per_minute"

// Validate rejects scopes the gateway could not enforce.
func Validate(scopes map[string]any) error {
	for k, v := range scopes {
		if k == RateKey {
			if n, ok := v.(float64); !ok || n < 1 || n != math.Trunc(n) {
				return fmt.Errorf("%s must be a positive integer", RateKey)
			}
			continue
		}
		c, ok := v.(map[string]any)
		if !ok || len(c) == 0 || k == "" {
			return fmt.Errorf("scope %q must be an object with max, min or in", k)
		}
		for op, x := range c {
			switch op {
			case "max", "min":
				if _, ok := x.(float64); !ok {
					return fmt.Errorf("scope %q: %s must be a number", k, op)
				}
			case "in":
				xs, ok := x.([]any)
				if !ok || len(xs) == 0 {
					return fmt.Errorf("scope %q: in must be a non-empty list", k)
				}
				for _, e := range xs {
					if !scalar(e) {
						return fmt.Errorf("scope %q: in holds strings, numbers or booleans only", k)
					}
				}
			default:
				return fmt.Errorf("scope %q: unknown constraint %q", k, op)
			}
		}
	}
	return nil
}

// Violations lists the constrained arguments args breaks, sorted. Scopes are assumed valid (Validate); anything
// else counts as a violation.
func Violations(scopes, args map[string]any) []string {
	var out []string
	for k, v := range scopes {
		if k == RateKey {
			continue
		}
		c, _ := v.(map[string]any)
		if c == nil || !satisfies(lookup(args, k), c) {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}

// RatePerMinute is the tool's call cap, or def when unset.
func RatePerMinute(scopes map[string]any, def int) int {
	if n, ok := scopes[RateKey].(float64); ok && n >= 1 {
		return int(n)
	}
	return def
}

var errMissing = errors.New("missing")

func lookup(args map[string]any, path string) any {
	var cur any = args
	for _, p := range strings.Split(path, ".") {
		m, ok := cur.(map[string]any)
		if !ok {
			return errMissing
		}
		if cur, ok = m[p]; !ok {
			return errMissing
		}
	}
	return cur
}

func satisfies(x any, c map[string]any) bool {
	if x == errMissing || x == nil {
		return false
	}
	for op, want := range c {
		switch op {
		case "max", "min":
			n, ok := number(x)
			w, wok := want.(float64)
			if !ok || !wok || op == "max" && n > w || op == "min" && n < w {
				return false
			}
		case "in":
			xs, _ := want.([]any)
			if !scalar(x) || !contains(xs, x) {
				return false
			}
		default:
			return false
		}
	}
	return true
}

// number accepts JSON numbers and numeric strings ("25000000"); NaN and ±Inf never satisfy a bound.
func number(x any) (float64, bool) {
	var n float64
	switch v := x.(type) {
	case float64:
		n = v
	case string:
		f, err := strconv.ParseFloat(strings.TrimSpace(v), 64)
		if err != nil {
			return 0, false
		}
		n = f
	default:
		return 0, false
	}
	return n, !math.IsNaN(n) && !math.IsInf(n, 0)
}

func scalar(x any) bool {
	switch x.(type) {
	case string, float64, bool:
		return true
	}
	return false
}

func contains(xs []any, x any) bool {
	for _, e := range xs {
		if scalar(e) && e == x {
			return true
		}
	}
	return false
}
