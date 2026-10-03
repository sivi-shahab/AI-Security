// Package authz is who may do what in the admin API (spec §2, §10.1): built-in roles for the §2 personas, ABAC
// attributes, and the HTTP middleware every route goes through (deny by default).
package authz

import (
	"slices"
	"strings"
	"time"
)

// Permissions. Sensitive ones need a fresh login (step-up) and a justification, and every use is audited.
const (
	DashboardRead    = "dashboard.read"
	IncidentRead     = "incident.read"
	IncidentWrite    = "incident.write"
	EvidenceUnmask   = "evidence.unmask"
	PolicyRead       = "policy.read"
	PolicyWrite      = "policy.write"
	PolicyPublish    = "policy.publish"
	ConfigRead       = "config.read"
	ConfigWrite      = "config.write"
	ComplianceRead   = "compliance.read"
	ComplianceWrite  = "compliance.write"
	AuditRead        = "audit.read"
	AppRead          = "app.read"
	FeedbackWrite    = "feedback.write"
	AgentRead        = "agent.read"
	AgentWrite       = "agent.write"
	AgentKillGlobal  = "agent.kill.global"
	SelfService      = "self.request"
	IdentityRead     = "identity.read"
	IdentityAdmin    = "identity.admin" // bind roles to users/groups
	BreakGlassAccess = "breakglass"     // marker: every request audited
)

// Sensitive permissions (spec §10.1).
var Sensitive = map[string]bool{EvidenceUnmask: true, PolicyPublish: true, AgentKillGlobal: true, IdentityAdmin: true}

// Roles maps each §2 persona to its default permissions. "Scoped" personas (app owner, agent owner) are limited
// to their resources by ABAC attributes on the binding, not by separate permissions.
var Roles = map[string][]string{
	"ciso":           {DashboardRead, ComplianceRead, IncidentRead},
	"soc_analyst":    {DashboardRead, IncidentRead, IncidentWrite, AgentRead},
	"security_admin": {DashboardRead, ConfigRead, ConfigWrite, AgentRead, IdentityRead, IdentityAdmin},
	// DLP analysts author policy; publishing goes through 4-eyes approval (ticket 12), not this role alone.
	"dlp_analyst":     {DashboardRead, PolicyRead, PolicyWrite},
	"policy_approver": {PolicyRead, PolicyPublish},
	"dpo":             {DashboardRead, ComplianceRead, ComplianceWrite, IncidentRead, EvidenceUnmask, AuditRead},
	"app_owner":       {AppRead, FeedbackWrite},
	"agent_owner":     {AgentRead, AgentWrite},
	"auditor":         {DashboardRead, ComplianceRead, AuditRead, IncidentRead, PolicyRead, ConfigRead, IdentityRead},
	"end_user":        {SelfService},
	// Emergency access when the bank IdP is down: everything, every request audited and alerted.
	"break_glass": {
		DashboardRead, IncidentRead, IncidentWrite, PolicyRead, ConfigRead, ConfigWrite, ComplianceRead, AuditRead,
		AgentRead, AgentWrite, AgentKillGlobal, IdentityRead, IdentityAdmin, BreakGlassAccess,
	},
}

// Attrs are ABAC attributes. On a binding they limit the caller; on a resource they describe it. "*" or empty in a
// binding list means unrestricted; empty on a resource means the attribute does not apply.
type Attrs struct {
	BusinessUnits []string `json:"business_units,omitempty"`
	Regions       []string `json:"regions,omitempty"`
	// Clearance is the highest content sensitivity the caller may see (public < internal < confidential < restricted).
	Clearance string `json:"clearance,omitempty"`
}

// Resource is what a request touches, for ABAC.
type Resource struct {
	BusinessUnit, Region, Sensitivity string
}

var sensitivityOrder = []string{"public", "internal", "confidential", "restricted"}

func allows(list []string, v string) bool {
	return v == "" || len(list) == 0 || slices.Contains(list, "*") || slices.Contains(list, v)
}

// Covers reports whether a binding with attributes a may act on r.
func (a Attrs) Covers(r Resource) bool {
	if !allows(a.BusinessUnits, r.BusinessUnit) || !allows(a.Regions, r.Region) {
		return false
	}
	if r.Sensitivity == "" || a.Clearance == "" {
		return true
	}
	return slices.Index(sensitivityOrder, r.Sensitivity) <= slices.Index(sensitivityOrder, a.Clearance) &&
		slices.Index(sensitivityOrder, r.Sensitivity) >= 0
}

// Binding gives a role, limited by Attrs, until Expires (zero = no expiry; auditors are time-boxed).
type Binding struct {
	Role    string    `json:"role"`
	Attrs   Attrs     `json:"attrs"`
	Expires time.Time `json:"expires_at,omitzero"`
}

// Caller is the authenticated user with the bindings in force for this request.
type Caller struct {
	ID         string // token sub
	Username   string
	Bindings   []Binding
	AuthTime   time.Time
	BreakGlass bool
}

// Can reports whether some unexpired binding grants perm and covers r. Deny by default.
func (c Caller) Can(perm string, r Resource, now time.Time) bool {
	for _, b := range c.Bindings {
		if !b.Expires.IsZero() && !now.Before(b.Expires) {
			continue
		}
		if slices.Contains(Roles[b.Role], perm) && b.Attrs.Covers(r) {
			return true
		}
	}
	return false
}

// Perms lists every permission the caller holds through an unexpired binding (for UI hints, not decisions).
func (c Caller) Perms(now time.Time) []string {
	var out []string
	for _, b := range c.Bindings {
		if b.Expires.IsZero() || now.Before(b.Expires) {
			out = append(out, Roles[b.Role]...)
		}
	}
	slices.Sort(out)
	return slices.Compact(out)
}

// ValidRole reports whether name is a built-in role.
func ValidRole(name string) bool { _, ok := Roles[strings.TrimSpace(name)]; return ok }
