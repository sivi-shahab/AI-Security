# METADATA
# description: |
#   Registry lookup for the MCP gateway (ticket 28): the agent whose workload identity (FR-AGT-2) the gateway
#   authenticated, with its tool allow-list and scopes. Undefined for an identity the registry does not know.
package aisec.mcp

import rego.v1

agent := object.union(entry, {"agent_id": id}) if {
	some id, entry in data.aisec.agents.items
	entry.identity == input.identity
}
