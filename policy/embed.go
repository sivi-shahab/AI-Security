// Package policy embeds the Rego modules and data documents the Policy Service bundles.
package policy

import "embed"

// Files holds every module, test and data.json under aisec/ and system/. The bundle builder skips tests.
//
//go:embed aisec system
var Files embed.FS
