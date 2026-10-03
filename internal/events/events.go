// Package events is the decision_event contract between PEPs and the event pipeline (spec §5.1, §10.2):
// the versioned JSON Schema, the raw-content check both sides run, and the producer PEPs use.
package events

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"github.com/santhosh-tekuri/jsonschema/v6"

	"aisec/internal/privacy"
)

const (
	Topic = "aisec.decision_event.v1"
	// Subject follows the registry's TopicNameStrategy.
	Subject = Topic + "-value"
)

//go:embed decision_event.v1.json
var SchemaV1 string

// Event is decision_event v1. Field names and rules live in decision_event.v1.json; keep the two in step.
type Event struct {
	EventID       string   `json:"event_id"`
	TenantID      string   `json:"tenant_id"`
	TS            string   `json:"ts"` // RFC 3339
	TraceID       string   `json:"trace_id"`
	Channel       string   `json:"channel"`
	Direction     string   `json:"direction"`
	PrincipalID   string   `json:"principal_id"` // HMAC, never the raw identity
	AppID         string   `json:"app_id"`
	AgentID       string   `json:"agent_id,omitempty"`
	Action        string   `json:"action"`
	ReasonCodes   []string `json:"reason_codes"`
	MatchedRules  []string `json:"matched_rules,omitempty"`
	PolicyVersion string   `json:"policy_version"`
	RiskScore     int      `json:"risk_score"`
	RiskOverrides []string `json:"risk_overrides,omitempty"`
	RiskVersion   string   `json:"risk_version"`
	Classes       []Class  `json:"classes"`
	ContentHash   string   `json:"content_hash"`
	Snippet       string   `json:"snippet,omitempty"`
}

type Class struct {
	Type       string  `json:"type"`
	Count      int     `json:"count"`
	Confidence float64 `json:"confidence,omitempty"`
}

// Compile parses a registered JSON Schema.
func Compile(schema string) (*jsonschema.Schema, error) {
	doc, err := jsonschema.UnmarshalJSON(strings.NewReader(schema))
	if err != nil {
		return nil, err
	}
	c := jsonschema.NewCompiler()
	c.AssertFormat()
	if err := c.AddResource("schema.json", doc); err != nil {
		return nil, err
	}
	return c.Compile("schema.json")
}

// Long digit runs in a snippet are unredacted identifiers: NIK has 16 digits, a PAN 13-19 (spaces/dashes allowed).
var digitRun = regexp.MustCompile(`\d(?:[ -]?\d){11,}`)

// Rejection reasons, used as the events_rejected_total label.
const (
	RejectNotJSON    = "not_json"
	RejectRawContent = "raw_content"
	RejectUnredacted = "unredacted_snippet"
	RejectSchema     = "schema"
)

// Check returns "" when payload is a valid event, else the rejection reason. Raw content is checked before the
// schema so it is counted as raw_content, not hidden among generic schema failures.
func Check(payload []byte, schema *jsonschema.Schema) string {
	v, err := jsonschema.UnmarshalJSON(bytes.NewReader(payload))
	if err != nil {
		return RejectNotJSON
	}
	if hasForbiddenField(v) {
		return RejectRawContent
	}
	if m, ok := v.(map[string]any); ok {
		if s, ok := m["snippet"].(string); ok && digitRun.MatchString(s) {
			return RejectUnredacted
		}
	}
	if schema.Validate(v) != nil {
		return RejectSchema
	}
	return ""
}

func hasForbiddenField(v any) bool {
	switch v := v.(type) {
	case map[string]any:
		for k, child := range v {
			if privacy.IsForbidden(k) || hasForbiddenField(child) {
				return true
			}
		}
	case []any:
		for _, child := range v {
			if hasForbiddenField(child) {
				return true
			}
		}
	}
	return false
}

// Marshal validates e against the embedded schema so a PEP can never emit an event the pipeline would reject.
func Marshal(e Event, schema *jsonschema.Schema) ([]byte, error) {
	b, err := json.Marshal(e)
	if err != nil {
		return nil, err
	}
	if reason := Check(b, schema); reason != "" {
		return nil, fmt.Errorf("decision_event rejected: %s", reason)
	}
	return b, nil
}
