# METADATA
# title: AI-SPM policy decision point
# description: |
#   Generic engine: rules are data (data.aisec.rules.items), evaluated against the canonical input
#   (data.aisec.schema.input). The strictest matching action wins (DEC-2) and obligations are merged.
#   Rule shape: {id, when: [{field, op, value}], action, obligations?, reason, mode?: enforce|monitor}.
package aisec.decision

import rego.v1

import data.aisec.agent
import data.aisec.cond
import data.aisec.dest
import data.aisec.risk

# DEC-2 precedence, strictest last.
rank := {
	"allow": 0,
	"warn": 1,
	"redact": 2,
	"tokenize": 3,
	"require_approval": 4,
	"quarantine": 5,
	"block": 6,
}

valid_input if json.match_schema(input, data.aisec.schema.input)[0]

# Malformed input fails closed: a PEP bug must show up as blocks, never as silent allows.
result := {
	"action": "block",
	"obligations": [],
	"reason_codes": ["INPUT_SCHEMA_INVALID"],
	"matched_rules": [],
	"monitor_rules": [],
	"exempted_rules": [],
	"destination": object.get(input, "destination", {}),
	"policy_id": "aisec.decision",
	"policy_version": data.aisec.rules.version,
	# A malformed input is a PEP bug, not user risk: alert on INPUT_SCHEMA_INVALID, do not page the SOC.
	"risk_score": 0,
	"risk_overrides": [],
	"risk_version": data.aisec.risk.config.version,
} if not valid_input

result := {
	"action": action,
	"obligations": sort_objects(obligations),
	"reason_codes": sort({r.reason | some r in enforced}),
	"matched_rules": sort({r.id | some r in enforced}),
	"monitor_rules": sort({r.id | some r in monitored}),
	"exempted_rules": sort({r.id | some r in exempted}),
	"destination": dest.destination,
	"policy_id": "aisec.decision",
	"policy_version": data.aisec.rules.version,
	"risk_score": risk.score,
	"risk_overrides": risk.applied,
	"risk_version": data.aisec.risk.config.version,
} if valid_input

matched contains rule if {
	some rule in data.aisec.rules.items
	every c in rule.when {
		cond.holds(c.op, value(c.field), c.value)
	}
}

enforced contains r if {
	some r in matched
	object.get(r, "mode", "enforce") == "enforce"
	not r in exempted
}

# FR-POL-7: an approved exception lifts the listed rules for its scope until expires_at (RFC 3339). Exempted rules
# are reported in the result, never silently dropped. Every scope key must match; an empty scope matches nothing.
exempted contains r if {
	some r in matched
	object.get(r, "mode", "enforce") == "enforce"
	some ex in data.aisec.exceptions.items
	r.id in ex.rules
	time.now_ns() < time.parse_rfc3339_ns(ex.expires_at)
	count(ex.scope) > 0
	every k, v in ex.scope {
		in_scope(k, v)
	}
}

# FR-AGT-6: an approval granted by a human (claimed once by the MCP gateway for exactly this call) lifts the
# require_approval rules of this decision only; stricter rules still apply.
exempted contains r if {
	some r in matched
	r.action == "require_approval"
	input.agent.approval_granted == true
}

in_scope("principal_id", v) if input.principal.id == v

in_scope("group", v) if v in object.get(input.principal, "groups", [])

in_scope("app_id", v) if dest.destination.app_id == v

in_scope("agent_id", v) if input.agent.agent_id == v

monitored contains r if {
	some r in matched
	r.mode == "monitor"
}

top := max({rank[r.action] | some r in enforced} | {0})

action := a if {
	some a, n in rank
	n == top
}

obligations contains o if {
	some r in enforced
	some o in object.get(r, "obligations", [])
}

sort_objects(s) := [o | some k in sort([json.marshal(x) | some x in s]); o := json.unmarshal(k)]

# risk_score is computed by aisec.risk, never supplied by the PEP.
value("risk_score") := risk.score

# destination.* comes from the catalog-corrected destination (aisec.dest).
value(field) := object.get(dest.destination, array.slice(path, 1, count(path)), null) if {
	field != "risk_score"
	path := split(field, ".")
	path[0] == "destination"
}

# agent.* comes from the registry-corrected agent (aisec.agent).
value(field) := object.get(agent.agent, array.slice(path, 1, count(path)), null) if {
	path := split(field, ".")
	path[0] == "agent"
}

value(field) := object.get(input, split(field, "."), null) if {
	field != "risk_score"
	not startswith(field, "destination.")
	not startswith(field, "agent.")
}

# Rule-set validation. The bundle builder refuses to publish while this is non-empty, so a typo in a
# rule can never turn into a rule that silently never matches.
rule_errors contains sprintf("duplicate id %s", [id]) if {
	some id in {r.id | some r in data.aisec.rules.items}
	count([r | some r in data.aisec.rules.items; r.id == id]) > 1
}

rule_errors contains sprintf("%v: unknown action %v", [r.id, r.action]) if {
	some r in data.aisec.rules.items
	not r.action in object.keys(rank)
}

rule_errors contains sprintf("%v: unknown op %v", [r.id, c.op]) if {
	some r in data.aisec.rules.items
	some c in r.when
	not c.op in cond.ops
}

rule_errors contains sprintf("%v: empty when", [r.id]) if {
	some r in data.aisec.rules.items
	count(object.get(r, "when", [])) == 0
}

rule_errors contains sprintf("%v: missing reason", [r.id]) if {
	some r in data.aisec.rules.items
	not r.reason
}

rule_errors contains sprintf("%v: unknown mode %v", [r.id, r.mode]) if {
	some r in data.aisec.rules.items
	not r.mode in {"enforce", "monitor"}
	r.mode
}
