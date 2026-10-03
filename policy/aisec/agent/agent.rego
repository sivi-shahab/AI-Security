# METADATA
# description: |
#   The agent the PDP decides on. The agent registry (data.aisec.agents, ticket 27) is the source of truth:
#   registered means "in the registry and active"; whatever the PEP claims about registration does not count.
#   Unknown agents are "unregistered", quarantined/suspended ones keep that status for the rules to act on.
#   The registry's tool allow-list decides tool_allowed and its tool risk replaces the PEP's (FR-AGT-4): an
#   agent outside the registry has no allow-list, so it may call no tool.
package aisec.agent

import rego.v1

entry := data.aisec.agents.items[input.agent.agent_id]

status := entry.status if entry

else := "unregistered"

registered := status == "active"

tool := t if {
	some t in entry.tools
	t.name == input.agent.tool
}

tool_allowed if tool

else := false

risk_tier := entry.risk_tier if entry

else := "unknown"

registry := {"registered": registered, "status": status, "risk_tier": risk_tier, "tool_allowed": tool_allowed}

agent := object.union(object.union(input.agent, registry), {"tool_risk": tool.risk}) if {
	input.agent
	tool
} else := object.union(input.agent, registry) if input.agent

else := {}
