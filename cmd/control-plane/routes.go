package main

import (
	"net/http"
	"time"

	"aisec/internal/agents"
	"aisec/internal/authz"
	"aisec/internal/catalog"
	"aisec/internal/identity"
	"aisec/internal/incident"
	"aisec/internal/lifecycle"
	"aisec/internal/posture"
)

// deps are the handlers and stores routes need. Nil stores are fine for the route matrix test: it never calls a
// handler, only the router's authentication and authorization.
type deps struct {
	bundles, scim, metrics http.Handler
	mcpObserved            http.Handler // MCP gateway reports tools/list (own token)
	incidents              *incident.Store
	identity               *identity.Store
	policies               *lifecycle.Store
	simulator              *lifecycle.Simulator
	apps                   *catalog.Store
	feedKey                []byte
	posture                posture.Sources
	agents                 *agents.Store
}

// routes is the complete admin API. Everything not listed as Public needs a permission (deny by default);
// routes_test.go checks every route against every role.
func routes(rt *authz.Router, d deps) {
	// GET /healthz is added by server.Run.
	rt.Public("GET /metrics", d.metrics)
	rt.Public("GET /bundles/aisec.tar.gz", d.bundles) // sidecars; bundle is signed (ticket 11)
	for _, m := range []string{"GET", "POST", "PUT", "PATCH", "DELETE"} {
		rt.Public(m+" /scim/v2/", d.scim) // IdP provisioning client, own bearer token
	}
	rt.Public("POST /mcp/tools/observed", d.mcpObserved) // MCP gateway, own bearer token (ticket 29)
	incident.Routes(rt, d.incidents, time.Now)
	identity.Routes(rt, d.identity)
	lifecycle.Routes(rt, d.policies, d.simulator, time.Now)
	catalog.Routes(rt, d.apps, d.feedKey, time.Now)
	posture.Routes(rt, d.posture, time.Now)
	agents.Routes(rt, d.agents, time.Now)
}
