# METADATA
# title: AI-SPM policy decision point
# description: |
#   Generic engine: rules are data (data.aisec.rules.items), evaluated against the canonical input
#   (data.aisec.schema.input). The strictest matching action wins (DEC-2) and obligations are merged.
#   Rule shape: {id, when: [{field, op, value}], action, obligations?, reason, mode?: enforce|monitor}.
package aisec.decision

import rego.v1

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

ops := {"eq", "neq", "in", "not_in", "gte", "lte", "class_any"}

valid_input if json.match_schema(input, data.aisec.schema.input)[0]

# Malformed input fails closed: a PEP bug must show up as blocks, never as silent allows.
result := {
	"action": "block",
	"obligations": [],
	"reason_codes": ["INPUT_SCHEMA_INVALID"],
	"matched_rules": [],
	"monitor_rules": [],
	"policy_id": "aisec.decision",
	"policy_version": data.aisec.rules.version,
} if not valid_input

result := {
	"action": action,
	"obligations": sort_objects(obligations),
	"reason_codes": sort({r.reason | some r in enforced}),
	"matched_rules": sort({r.id | some r in enforced}),
	"monitor_rules": sort({r.id | some r in monitored}),
	"policy_id": "aisec.decision",
	"policy_version": data.aisec.rules.version,
} if valid_input

matched contains rule if {
	some rule in data.aisec.rules.items
	every c in rule.when {
		holds(c.op, c.field, c.value)
	}
}

enforced contains r if {
	some r in matched
	object.get(r, "mode", "enforce") == "enforce"
}

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

value(field) := object.get(input, split(field, "."), null)

# The op is the first argument so OPA's rule index picks one clause instead of trying all seven.
holds("eq", field, v) if value(field) == v

# Missing fields count as "not equal": e.g. an unknown region is offshore.
holds("neq", field, v) if value(field) != v

holds("in", field, v) if value(field) in v

holds("not_in", field, v) if not value(field) in v

holds("gte", field, v) if {
	x := value(field)
	is_number(x)
	x >= v
}

holds("lte", field, v) if {
	x := value(field)
	is_number(x)
	x <= v
}

holds("class_any", _, v) if {
	some cls in object.get(input, ["content", "classes"], [])
	some pattern in v
	glob.match(pattern, ["."], cls.type)
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
	not c.op in ops
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
