// Package catalog is the AI app catalog (spec §4.1 FR-DISC, §8.4): a signed, versioned feed of apps with their
// fingerprints and risk attributes, local overrides (sanction, owner, review date, corrections) that need no
// redeploy, daily usage per app, and the catalog document every policy release carries to the PDP.
package catalog

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
)

// App is one catalog entry as the feed (or a local addition) describes it. ID is what PEPs send as
// destination.app_id.
type App struct {
	ID                   string   `json:"id"`
	Vendor               string   `json:"vendor"`
	Name                 string   `json:"name"`
	Category             string   `json:"category"`
	Domains              []string `json:"domains"`
	APIEndpoints         []string `json:"api_endpoints"` // "POST /v1/messages", "POST :generateContent"
	Headers              []string `json:"headers"`       // header names distinctive for the app's SDK
	UserAgents           []string `json:"user_agents"`   // SDK user-agent substrings
	PayloadKeys          []string `json:"payload_keys"`  // top-level JSON keys of a request body
	DataRetentionPolicy  *string  `json:"data_retention_policy"`
	TrainsOnCustomerData *bool    `json:"trains_on_customer_data"`
	HostingRegion        string   `json:"hosting_region"` // ISO 3166-1 alpha-2, or "unknown"
	OJKApprovalRef       *string  `json:"ojk_approval_ref"`
	Certifications       []string `json:"certifications"`
	RiskTier             *int     `json:"risk_tier"`
}

// Feed is a catalog version. Versions only go up: an older or equal feed is refused (no rollback by replay).
type Feed struct {
	Version     int64  `json:"version"`
	PublishedAt string `json:"published_at"`
	Apps        []App  `json:"apps"`
}

var (
	Categories = []string{"chat", "code", "image", "agent", "embedding", "meeting", "plugin/extension"}
	Sanctions  = []string{"sanctioned", "tolerated", "unsanctioned", "blocked", "under_review"}
	idRe       = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)
	regionRe   = regexp.MustCompile(`^([A-Z]{2}|unknown)$`)
)

var ErrInvalid = errors.New("invalid")

// Validate checks one app definition.
func (a App) Validate() error {
	switch {
	case !idRe.MatchString(a.ID):
		return fmt.Errorf("%w: app id %q (lowercase letters, digits, dashes)", ErrInvalid, a.ID)
	case a.Name == "" || a.Vendor == "":
		return fmt.Errorf("%w: app %s needs name and vendor", ErrInvalid, a.ID)
	case !slices.Contains(Categories, a.Category):
		return fmt.Errorf("%w: app %s category %q", ErrInvalid, a.ID, a.Category)
	case !regionRe.MatchString(a.HostingRegion):
		return fmt.Errorf("%w: app %s hosting_region %q", ErrInvalid, a.ID, a.HostingRegion)
	}
	return nil
}

// ParseFeed decodes and validates a feed: known fields only, valid apps, unique ids.
func ParseFeed(raw []byte) (Feed, error) {
	var f Feed
	dec := json.NewDecoder(bytesReader(raw))
	if err := dec.Decode(&f); err != nil {
		return Feed{}, fmt.Errorf("%w: feed: %v", ErrInvalid, err)
	}
	if f.Version < 1 || len(f.Apps) == 0 {
		return Feed{}, fmt.Errorf("%w: feed needs a version >= 1 and apps", ErrInvalid)
	}
	seen := map[string]bool{}
	for _, a := range f.Apps {
		if err := a.Validate(); err != nil {
			return Feed{}, err
		}
		if seen[a.ID] {
			return Feed{}, fmt.Errorf("%w: duplicate app id %s", ErrInvalid, a.ID)
		}
		seen[a.ID] = true
	}
	return f, nil
}

// ErrSignature marks a feed whose signature does not verify: it is never imported.
var ErrSignature = errors.New("catalog feed signature invalid")

// VerifyFeed checks a detached signature (base64 ASN.1 ECDSA over SHA-256 of the exact feed bytes) against the
// catalog publisher's public key (PEM), then parses the feed. External feeds are pull-only and verified
// (ADR-0001).
func VerifyFeed(raw []byte, sigB64 string, pubPEM []byte) (Feed, error) {
	b, _ := pem.Decode(pubPEM)
	if b == nil {
		return Feed{}, fmt.Errorf("%w: no catalog feed key configured (CATALOG_FEED_PUBKEY_FILE)", ErrInvalid)
	}
	k, err := x509.ParsePKIXPublicKey(b.Bytes)
	if err != nil {
		return Feed{}, err
	}
	pub, ok := k.(*ecdsa.PublicKey)
	if !ok {
		return Feed{}, errors.New("catalog feed key: want ECDSA")
	}
	sig, err := base64.StdEncoding.DecodeString(strings.TrimSpace(sigB64))
	sum := sha256.Sum256(raw)
	if err != nil || !ecdsa.VerifyASN1(pub, sum[:], sig) {
		return Feed{}, ErrSignature
	}
	return ParseFeed(raw)
}

// seedFeed ships inside the control-plane image, which CI signs with cosign and admission verifies (ticket 05):
// that signature is its provenance, so it is imported without a feed signature.
//
//go:embed seed.json
var seedFeed []byte

// SeedApps is the embedded seed catalog, for tools that run without the control plane (ticket 03 baseline).
func SeedApps() []App {
	f, err := ParseFeed(seedFeed)
	if err != nil {
		panic(err) // the seed is validated by tests and at control-plane start
	}
	return f.Apps
}
