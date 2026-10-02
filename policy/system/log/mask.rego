# METADATA
# description: |
#   FR-POL-9 decision-log masking. Drops any forbidden content field (same list as service logs,
#   internal/privacy/forbidden_fields.txt, injected by the bundle builder as data.system.log.forbidden)
#   wherever a PEP put it in the input. The canonical schema already rejects such fields; this keeps
#   them out of the log even when that happens.
package system.log

import rego.v1

mask contains ptr if {
	walk(input.input, [path, _])
	count(path) > 0
	lower(sprintf("%v", [path[count(path) - 1]])) in {lower(f) | some f in data.system.log.forbidden}
	ptr := concat("/", array.concat(["", "input"], [sprintf("%v", [p]) | some p in path]))
}
