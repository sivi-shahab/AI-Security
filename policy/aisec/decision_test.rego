package aisec.decision_test

import rego.v1

import data.aisec.decision

base := {
	"channel": "ai_gateway",
	"direction": "request",
	"principal": {"type": "user", "id": "u-hmac-1"},
	"destination": {"app_id": "copilot", "sanction": "sanctioned", "region": "ID"},
	"content": {"sensitivity": "internal", "classes": []},
}

with_patch(patch) := object.union(base, patch)

decide(inp) := r if {
	r := decision.result with input as inp
}

rule(id, action) := {"id": id, "when": [{"field": "channel", "op": "eq", "value": "ai_gateway"}], "action": action, "reason": upper(id)}

# --- engine -------------------------------------------------------------------------------------

test_no_match_allows if {
	r := decide(base)
	r.action == "allow"
	r.matched_rules == []
	r.policy_version == "builtin-1"
}

test_output_matches_schema if {
	json.match_schema(decide(base), data.aisec.schema.output)[0]
	json.match_schema(decide({"bogus": true}), data.aisec.schema.output)[0]
}

test_strictest_action_wins_for_every_pair if {
	order := ["allow", "warn", "redact", "tokenize", "require_approval", "quarantine", "block"]
	every i, weaker in order {
		every stronger in array.slice(order, i + 1, count(order)) {
			r := decision.result with input as base
				with data.aisec.rules.items as [rule("a", weaker), rule("b", stronger)]
			r.action == stronger
		}
	}
}

test_obligations_and_reasons_are_merged if {
	rules := [
		object.union(rule("a", "redact"), {"obligations": [{"type": "redact", "classes": ["PCI.PAN"]}]}),
		object.union(rule("b", "redact"), {"obligations": [{"type": "log_evidence"}, {"type": "redact", "classes": ["PCI.PAN"]}]}),
	]
	r := decision.result with input as base with data.aisec.rules.items as rules
	r.action == "redact"
	r.obligations == [{"classes": ["PCI.PAN"], "type": "redact"}, {"type": "log_evidence"}]
	r.reason_codes == ["A", "B"]
	r.matched_rules == ["a", "b"]
}

test_monitor_rules_never_change_action if {
	rules := [object.union(rule("m", "block"), {"mode": "monitor"}), rule("w", "warn")]
	r := decision.result with input as base with data.aisec.rules.items as rules
	r.action == "warn"
	r.monitor_rules == ["m"]
	r.matched_rules == ["w"]
}

test_invalid_input_fails_closed if {
	every bad in [
		{},
		object.union(base, {"prompt": "raw text must never be sent"}),
		object.remove(base, ["destination"]),
		with_patch({"content": {"sensitivity": "secret", "classes": []}}),
		with_patch({"content": {"sensitivity": "internal", "classes": [{"type": "nik", "count": 1, "confidence": 1}]}}),
	] {
		r := decide(bad)
		r.action == "block"
		r.reason_codes == ["INPUT_SCHEMA_INVALID"]
	}
}

ops_input := with_patch({"content": {"sensitivity": "internal", "injection_score": 0.5, "classes": [{"type": "PII_ID.NIK", "count": 2, "confidence": 0.9}]}})

cond(c) if {
	decision.result.matched_rules == ["x"] with input as ops_input
		with data.aisec.rules.items as [{"id": "x", "when": [c], "action": "warn", "reason": "X"}]
}

test_ops if {
	cond({"field": "content.sensitivity", "op": "eq", "value": "internal"})
	not cond({"field": "content.sensitivity", "op": "eq", "value": "public"})
	cond({"field": "destination.region", "op": "neq", "value": "US"})
	cond({"field": "destination.missing", "op": "neq", "value": "ID"})
	cond({"field": "destination.sanction", "op": "in", "value": ["sanctioned"]})
	cond({"field": "destination.sanction", "op": "not_in", "value": ["blocked"]})
	not cond({"field": "destination.sanction", "op": "not_in", "value": ["sanctioned"]})
	cond({"field": "content.injection_score", "op": "gte", "value": 0.5})
	not cond({"field": "content.injection_score", "op": "gte", "value": 0.51})
	cond({"field": "content.injection_score", "op": "lte", "value": 0.5})
	not cond({"field": "risk_score", "op": "gte", "value": 0})
	cond({"field": "content.classes", "op": "class_any", "value": ["PII_ID.*"]})
	cond({"field": "content.classes", "op": "class_any", "value": ["PII_ID.NIK"]})
	not cond({"field": "content.classes", "op": "class_any", "value": ["PII.*"]})
	not cond({"field": "content.classes", "op": "class_any", "value": ["SECRET.*"]})
}

test_builtin_rules_are_valid if {
	count(decision.rule_errors) == 0
}

test_invalid_rules_are_reported if {
	bad := [
		rule("dup", "block"),
		rule("dup", "warn"),
		rule("act", "nuke"),
		{"id": "op", "when": [{"field": "channel", "op": "regex", "value": "."}], "action": "block", "reason": "R"},
		{"id": "empty", "when": [], "action": "block", "reason": "R"},
		{"id": "noreason", "when": [{"field": "channel", "op": "eq", "value": "x"}], "action": "block"},
		object.union(rule("mode", "warn"), {"mode": "shadow"}),
	]
	errs := decision.rule_errors with data.aisec.rules.items as bad
	errs == {
		"duplicate id dup",
		"act: unknown action nuke",
		"op: unknown op regex",
		"empty: empty when",
		"noreason: missing reason",
		"mode: unknown mode shadow",
	}
}

# --- FR-POL-8 templates ---------------------------------------------------------------------------

cls(t) := [{"type": t, "count": 1, "confidence": 0.99}]

test_tpl_pii_id_to_unsanctioned if {
	every s in ["unsanctioned", "blocked", "under_review"] {
		r := decide(with_patch({"destination": {"app_id": "x", "sanction": s, "region": "ID"}, "content": {"sensitivity": "confidential", "classes": cls("PII_ID.NIK")}}))
		r.action == "block"
		"tpl.pii-id-to-unsanctioned" in r.matched_rules
	}
	decide(with_patch({"content": {"sensitivity": "confidential", "classes": cls("PII_ID.NIK")}})).action == "allow"
	decide(with_patch({"direction": "response", "destination": {"app_id": "x", "sanction": "unsanctioned", "region": "ID"}, "content": {"sensitivity": "confidential", "classes": cls("PII_ID.NIK")}})).action == "allow"
}

test_tpl_secret_to_any_ai if {
	r := decide(with_patch({"content": {"sensitivity": "restricted", "classes": cls("SECRET.AWS_KEY")}}))
	r.action == "block"
	"SECRET_TO_AI" in r.reason_codes
	decide(with_patch({"direction": "tool_call", "content": {"sensitivity": "internal", "classes": cls("SECRET.JWT")}})).action == "block"
}

test_tpl_pci_pan_redact if {
	every d in ["request", "response", "tool_result"] {
		r := decide(with_patch({"direction": d, "content": {"sensitivity": "confidential", "classes": cls("PCI.PAN")}}))
		r.action == "redact"
		{"type": "redact", "classes": ["PCI.PAN"]} in r.obligations
	}
}

test_tpl_restricted_to_sanctioned if {
	r := decide(with_patch({"content": {"sensitivity": "restricted", "classes": []}}))
	r.action == "redact"
	r.obligations == [{"classes": ["*"], "type": "redact"}, {"type": "log_evidence"}]
}

test_tpl_injection_high if {
	every d in ["request", "response", "tool_result"] {
		decide(with_patch({"direction": d, "content": {"sensitivity": "public", "classes": [], "injection_score": 0.9}})).action == "block"
	}
	decide(with_patch({"content": {"sensitivity": "public", "classes": [], "injection_score": 0.89}})).action == "allow"
}

# --- ADR-0001 residency: every sensitivity x region x sanction ---------------------------------------

expected_residency(sens, region, sanction) := "block" if {
	region != "ID"
	true in {sens == "restricted", sanction != "sanctioned"}
} else := "redact" if {
	region != "ID"
	sens == "confidential"
} else := "redact" if {
	# onshore: only the restricted-to-sanctioned template applies
	sens == "restricted"
	sanction == "sanctioned"
} else := "allow"

test_residency_matrix if {
	combos := {[sens, region, sanction] |
		some sens in ["public", "internal", "confidential", "restricted"]
		some region in ["ID", "SG", "US", "unknown"]
		some sanction in ["sanctioned", "tolerated", "unsanctioned", "blocked", "under_review"]
	}
	count(combos) == 80
	mismatches := {[c, got, want] |
		some c in combos
		got := decide(with_patch({
			"destination": {"app_id": "x", "sanction": c[2], "region": c[1]},
			"content": {"sensitivity": c[0], "classes": []},
		})).action
		want := expected_residency(c[0], c[1], c[2])
		got != want
	}
	print("residency mismatches:", mismatches)
	count(mismatches) == 0
}

test_residency_does_not_apply_to_inbound if {
	every d in ["response", "tool_result"] {
		decide(with_patch({"direction": d, "destination": {"app_id": "x", "sanction": "unsanctioned", "region": "US"}, "content": {"sensitivity": "restricted", "classes": []}})).action == "allow"
	}
}
