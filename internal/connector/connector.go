// Package connector is the Connector SDK contract (spec §4.3 FR-DATA-1): what a data-at-rest source (M365,
// Google Drive, S3, …) must offer for discovery, classification and oversharing analysis. Connectors are
// stateless; the scanner (internal/datascan) keeps cursors and checkpoints in Postgres.
//
// Spec name → method: list_containers → Containers, list_items(cursor, since) → Items (the cursor is the change
// feed position; "" = from the beginning), get_item(id, range) → Get, get_acl → ACL, apply_remediation → Remediate.
package connector

import (
	"context"
	"encoding/json"
	"errors"
	"time"
)

// ErrNotSupported: the connector does not offer this (e.g. remediation before ticket 33).
var ErrNotSupported = errors.New("not supported by this connector")

// Container is a unit with its own change feed: a SharePoint document library, a OneDrive, a bucket.
type Container struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Kind string `json:"kind"` // e.g. sharepoint | onedrive
}

// Item is a file (or folder) as the change feed reports it.
type Item struct {
	ID          string
	ContainerID string
	Name        string
	Path        string
	ContentTag  string // changes when, and only when, the content changes (Graph cTag, S3 ETag)
	Size        int64
	MimeType    string // when the source says (e.g. Google-native documents, exported rather than downloaded)
	Modified    time.Time
	Folder      bool
	Deleted     bool
}

// Grant is one way an item is shared.
type Grant struct {
	Kind     string `json:"kind"` // user | group | anyone_link | org_link | specific_link
	Ref      string `json:"ref"`  // UPN/e-mail or group name; "" for anyone links
	Role     string `json:"role"` // read | write | owner
	External bool   `json:"external"`
}

// Page is one page of the change feed. While !Done, Next continues this pass; when Done, Next is where the
// next incremental pass starts.
type Page struct {
	Items []Item
	Next  string
	Done  bool
}

type Connector interface {
	Containers(ctx context.Context) ([]Container, error)
	Items(ctx context.Context, c Container, cursor string) (Page, error)
	Get(ctx context.Context, it Item, maxBytes int64) ([]byte, error)
	ACL(ctx context.Context, it Item) ([]Grant, error)
	// Labels are the item's external sensitivity labels (Purview label ids; FR-CLS-6). nil when none.
	Labels(ctx context.Context, it Item) ([]string, error)
	// Remediate applies a (FR-DATA-6), or with dryRun only says what it would do. The returned Change lists the
	// steps (the same steps for the same state, so a plan can be compared before executing) and, when the source
	// can restore it, the data Undo needs.
	Remediate(ctx context.Context, it Item, a Action, dryRun bool) (Change, error)
	// Undo reverses a remediation from its Change.Undo; with dryRun only plans it.
	Undo(ctx context.Context, it Item, undo json.RawMessage, dryRun bool) (Change, error)
}

// Remediation kinds.
const (
	RevokeAnyoneLinks = "revoke_anyone_links" // anonymous sharing links
	RemoveGrants      = "remove_grants"       // the listed grantees (broad groups, external users or domains)
	ApplyLabel        = "apply_label"         // an external sensitivity label
	Quarantine        = "quarantine"          // move to a quarantine location and strip sharing
)

// Action is one remediation.
type Action struct {
	Kind   string   `json:"kind"`
	Grants []string `json:"grants,omitempty"` // remove_grants: grantee refs as Grant.Ref reports them
	Label  string   `json:"label,omitempty"`  // apply_label: external label id
}

// Change is what a remediation would do (dry run) or did. Undo is nil when the source cannot restore it
// (e.g. a deleted anonymous link cannot come back with the same URL).
type Change struct {
	Steps []string        `json:"steps"`
	Undo  json.RawMessage `json:"undo,omitempty"`
}

// ErrNothingToDo: the item already is as the action would leave it.
var ErrNothingToDo = errors.New("nothing to remediate")

// OAuthGrant is one user authorizing a third-party app on the bank's tenant (Google token audit, Entra consent):
// the feed for AI apps that reach bank data through OAuth rather than the network (FR-AGT-1 shadow agents).
type OAuthGrant struct {
	ClientID string
	AppName  string
	Scopes   []string
	User     string // e-mail; hashed before storage
	At       time.Time
}
