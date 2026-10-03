package toolscope

import (
	"encoding/json"
	"slices"
	"testing"
)

func obj(t *testing.T, s string) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal([]byte(s), &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func TestValidate(t *testing.T) {
	for s, ok := range map[string]bool{
		`{}`: true,
		`{"amount": {"max": 25000000, "min": 1}, "currency": {"in": ["IDR"]}, "rate_per_minute": 30}`: true,
		`{"payee.account": {"in": ["123", 456, true]}}`:                                               true,
		`{"amount_max": 25000000}`:        false,
		`{"amount": {}}`:                  false,
		`{"amount": {"max": "25000000"}}`: false,
		`{"amount": {"lt": 5}}`:           false,
		`{"to": {"in": []}}`:              false,
		`{"to": {"in": [{"a": 1}]}}`:      false,
		`{"rate_per_minute": 0}`:          false,
		`{"rate_per_minute": 1.5}`:        false,
	} {
		if err := Validate(obj(t, s)); (err == nil) != ok {
			t.Errorf("%s: err %v, want ok=%v", s, err, ok)
		}
	}
}

func TestViolations(t *testing.T) {
	scopes := obj(t, `{"amount": {"max": 25000000, "min": 1}, "currency": {"in": ["IDR"]}, "payee.account": {"in": ["1234567890"]}, "rate_per_minute": 30}`)
	for args, want := range map[string][]string{
		`{"amount": 25000000, "currency": "IDR", "payee": {"account": "1234567890"}}`: nil,
		`{"amount": "1000", "currency": "IDR", "payee": {"account": "1234567890"}}`:   nil,
		`{"amount": 25000001, "currency": "IDR", "payee": {"account": "1234567890"}}`: {"amount"},
		`{"amount": 0, "currency": "USD", "payee": {"account": "9999999999"}}`:        {"amount", "currency", "payee.account"},
		`{"currency": "IDR", "payee": {"account": "1234567890"}}`:                     {"amount"},
		`{"amount": "1e9", "currency": "IDR", "payee": {"account": "1234567890"}}`:    {"amount"},
		`{"amount": "NaN", "currency": "IDR", "payee": {"account": "1234567890"}}`:    {"amount"},
		`{"amount": [1], "currency": ["IDR"], "payee": "1234567890"}`:                 {"amount", "currency", "payee.account"},
		`{"amount": null, "currency": "IDR", "payee": {"account": "1234567890"}}`:     {"amount"},
		`{"amount": 10, "currency": "IDR", "payee": {"account": 1234567890}}`:         {"payee.account"},
	} {
		if got := Violations(scopes, obj(t, args)); !slices.Equal(got, want) {
			t.Errorf("%s: %v, want %v", args, got, want)
		}
	}
	if RatePerMinute(scopes, 60) != 30 || RatePerMinute(nil, 60) != 60 {
		t.Error("rate")
	}
}
