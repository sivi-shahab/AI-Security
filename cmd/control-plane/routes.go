package main

import (
	"net/http"
	"time"

	"aisec/internal/authz"
	"aisec/internal/identity"
	"aisec/internal/incident"
	"aisec/internal/lifecycle"
)

// deps are the handlers and stores routes need. Nil stores are fine for the route matrix test: it never calls a
// handler, only the router's authentication and authorization.
type deps struct {
	bundles, scim, metrics http.Handler
	incidents              *incident.Store
	identity               *identity.Store
	policies               *lifecycle.Store
	simulator              *lifecycle.Simulator
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
	incident.Routes(rt, d.incidents, time.Now)
	identity.Routes(rt, d.identity)
	lifecycle.Routes(rt, d.policies, d.simulator, time.Now)
}
