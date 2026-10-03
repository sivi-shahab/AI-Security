# METADATA
# description: |
#   The agent the PDP decides on. The agent registry (data.aisec.agents, ticket 27) is the source of truth:
#   registered means "in the registry and active"; whatever the PEP claims about registration does not count.
#   Unknown agents are "unregistered", quarantined/suspended ones keep that status for the rules to act on.
package aisec.agent

import rego.v1

entry := data.aisec.agents.items[input.agent.agent_id]

status := entry.status if entry

else := "unregistered"

registered := status == "active"

agent := object.union(input.agent, {"registered": registered, "status": status, "risk_tier": object.get(entry, "risk_tier", "unknown")}) if input.agent

else := {}
