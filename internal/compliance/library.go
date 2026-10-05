// Package compliance is the compliance module (spec §4.11 FR-COMP-1..3, §14): a versioned framework library,
// platform controls mapped to framework requirements, evidence collected automatically from the running
// platform, control status history, exports per audit period, and the AI register (OJK, ISO/IEC 42001).
//
// Mappings carry the desk research behind them; only a sign-off by the compliance team against the official
// text makes one verified. Nothing is ever deleted: a new framework version adds rows next to the old.
package compliance

import (
	"context"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

//go:embed schema.sql
var schemaSQL string

//go:embed library
var library embed.FS

var (
	ErrNotFound = errors.New("not found")
	ErrInvalid  = errors.New("invalid")
)

// Framework is one version of a framework: requirement ids and short titles (no licensed text).
type Framework struct {
	ID           string        `json:"id"`
	Name         string        `json:"name"`
	Version      string        `json:"version"`
	Source       string        `json:"source"`
	Note         string        `json:"note,omitempty"`
	Requirements []Requirement `json:"requirements"`
}

type Requirement struct {
	ID    string `json:"id"`
	Title string `json:"title"`
}

// Research is the desk check of a mapping against the official text (ticket 34): supported, weak, wrong (kept
// out) or unverifiable. It is not a sign-off.
type Research struct {
	Verdict string `json:"verdict"`
	Source  string `json:"source"`
	Note    string `json:"note,omitempty"`
}

// Mapping links a platform control to a requirement of one framework version.
type Mapping struct {
	Control     string   `json:"control"`
	Framework   string   `json:"framework"`
	Version     string   `json:"framework_version"`
	Requirement string   `json:"requirement"`
	Research    Research `json:"research"`
}

// Library is the embedded library: frameworks and the mapping set.
type Library struct {
	Frameworks []Framework
	Mappings   []Mapping
}

// LoadLibrary reads library/frameworks/*.json and library/mappings.json, and checks that every mapping names a
// known control, framework version and requirement, and that every control maps to at least one requirement
// (FR-COMP-2).
func LoadLibrary(fsys fs.FS) (Library, error) {
	var lib Library
	files, err := fs.Glob(fsys, "library/frameworks/*.json")
	if err != nil {
		return lib, err
	}
	for _, f := range files {
		b, err := fs.ReadFile(fsys, f)
		if err != nil {
			return lib, err
		}
		var fw Framework
		if err := json.Unmarshal(b, &fw); err != nil || fw.ID == "" || fw.Version == "" || len(fw.Requirements) == 0 {
			return lib, fmt.Errorf("%s: %w (id, version and requirements needed)", f, err)
		}
		lib.Frameworks = append(lib.Frameworks, fw)
	}
	b, err := fs.ReadFile(fsys, "library/mappings.json")
	if err != nil {
		return lib, err
	}
	var m struct {
		Mappings []Mapping `json:"mappings"`
	}
	if err := json.Unmarshal(b, &m); err != nil {
		return lib, fmt.Errorf("mappings.json: %w", err)
	}
	lib.Mappings = m.Mappings
	reqs := map[string]bool{}
	for _, fw := range lib.Frameworks {
		for _, r := range fw.Requirements {
			reqs[fw.ID+"@"+fw.Version+"#"+r.ID] = true
		}
	}
	mapped := map[string]bool{}
	for _, mp := range lib.Mappings {
		if _, ok := controlByID[mp.Control]; !ok {
			return lib, fmt.Errorf("mapping to unknown control %s", mp.Control)
		}
		if !reqs[mp.Framework+"@"+mp.Version+"#"+mp.Requirement] {
			return lib, fmt.Errorf("mapping %s → %s %s %s: no such requirement", mp.Control, mp.Framework, mp.Version, mp.Requirement)
		}
		switch mp.Research.Verdict {
		case "supported", "weak", "unverifiable":
		default:
			return lib, fmt.Errorf("mapping %s → %s: research verdict %q (wrong mappings are left out)", mp.Control, mp.Requirement, mp.Research.Verdict)
		}
		mapped[mp.Control] = true
	}
	for _, c := range Controls {
		if !mapped[c.ID] {
			return lib, fmt.Errorf("control %s maps to no requirement (FR-COMP-2)", c.ID)
		}
	}
	return lib, nil
}

// Store is the compliance store.
type Store struct {
	DB     *pgxpool.Pool
	Tenant string
}

// Open applies the schema and imports the embedded library: framework versions and mappings not yet stored are
// added; stored ones are never touched (a changed document under an existing version is an error).
func Open(ctx context.Context, db *pgxpool.Pool, tenant string, now time.Time) (*Store, error) {
	if _, err := db.Exec(ctx, schemaSQL); err != nil {
		return nil, fmt.Errorf("apply compliance schema: %w", err)
	}
	lib, err := LoadLibrary(library)
	if err != nil {
		return nil, err
	}
	s := &Store{DB: db, Tenant: tenant}
	return s, s.Import(ctx, lib, now)
}

// Import adds framework versions and mappings that are new.
func (s *Store) Import(ctx context.Context, lib Library, now time.Time) error {
	return pgx.BeginFunc(ctx, s.DB, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, "LOCK TABLE compliance.frameworks IN EXCLUSIVE MODE"); err != nil { // replicas start together
			return err
		}
		for _, fw := range lib.Frameworks {
			doc, _ := json.Marshal(fw)
			sum := sha256.Sum256(doc)
			var existing string
			err := tx.QueryRow(ctx, "SELECT sha256 FROM compliance.frameworks WHERE framework = $1 AND version = $2", fw.ID, fw.Version).Scan(&existing)
			switch {
			case errors.Is(err, pgx.ErrNoRows):
				if _, err := tx.Exec(ctx, "INSERT INTO compliance.frameworks (framework, version, doc, sha256, imported_at) VALUES ($1, $2, $3, $4, $5)",
					fw.ID, fw.Version, doc, hex.EncodeToString(sum[:]), now); err != nil {
					return err
				}
			case err != nil:
				return err
			case existing != hex.EncodeToString(sum[:]):
				return fmt.Errorf("framework %s %s changed without a new version: publish it as a new version", fw.ID, fw.Version)
			}
		}
		for _, m := range lib.Mappings {
			research, _ := json.Marshal(m.Research)
			if _, err := tx.Exec(ctx, `INSERT INTO compliance.mappings (framework, version, control_id, requirement, research) VALUES ($1, $2, $3, $4, $5)
				ON CONFLICT DO NOTHING`, m.Framework, m.Version, m.Control, m.Requirement, research); err != nil {
				return err
			}
		}
		return nil
	})
}

// FrameworkVersion is a stored version.
type FrameworkVersion struct {
	Framework  Framework `json:"framework"`
	SHA256     string    `json:"sha256"`
	ImportedAt time.Time `json:"imported_at"`
}

func (s *Store) Frameworks(ctx context.Context) ([]FrameworkVersion, error) {
	rows, err := s.DB.Query(ctx, "SELECT doc, sha256, imported_at FROM compliance.frameworks ORDER BY framework, imported_at")
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (FrameworkVersion, error) {
		var v FrameworkVersion
		err := r.Scan(&v.Framework, &v.SHA256, &v.ImportedAt)
		return v, err
	})
}

// MappingState is a mapping with its latest sign-off.
type MappingState struct {
	Mapping
	Verification *Verification `json:"verification,omitempty"`
}

type Verification struct {
	Status     string    `json:"status"`
	Source     string    `json:"source"`
	Note       *string   `json:"note,omitempty"`
	VerifiedBy string    `json:"verified_by"`
	VerifiedAt time.Time `json:"verified_at"`
}

// Mappings of one framework version ("" = all), each with its latest sign-off as of asOf.
func (s *Store) Mappings(ctx context.Context, framework, version string, asOf time.Time) ([]MappingState, error) {
	return mappings(ctx, s.DB, framework, version, asOf.Add(time.Nanosecond))
}

type querier interface {
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
}

// mappings with the latest sign-off made before `before`.
func mappings(ctx context.Context, q querier, framework, version string, before time.Time) ([]MappingState, error) {
	rows, err := q.Query(ctx, `SELECT m.control_id, m.framework, m.version, m.requirement, m.research,
		v.status, v.source, v.note, v.verified_by, v.verified_at
		FROM compliance.mappings m LEFT JOIN LATERAL (
			SELECT * FROM compliance.verifications v WHERE v.framework = m.framework AND v.version = m.version AND v.control_id = m.control_id
			AND v.requirement = m.requirement AND v.verified_at < $3 ORDER BY v.verified_at DESC, v.id DESC LIMIT 1) v ON true
		WHERE ($1 = '' OR m.framework = $1) AND ($2 = '' OR m.version = $2)
		ORDER BY m.framework, m.version, m.requirement, m.control_id`, framework, version, before)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (MappingState, error) {
		var m MappingState
		var status, source, by, note *string
		var at *time.Time
		err := r.Scan(&m.Control, &m.Framework, &m.Version, &m.Requirement, &m.Research, &status, &source, &note, &by, &at)
		if status != nil {
			m.Verification = &Verification{Status: *status, Source: *source, Note: note, VerifiedBy: *by, VerifiedAt: *at}
		}
		return m, err
	})
}

// Verify records the compliance team's sign-off (or rejection) of a mapping against the official text.
func (s *Store) Verify(ctx context.Context, actor string, m Mapping, status, source, note string, now time.Time) error {
	if status != "verified" && status != "rejected" || strings.TrimSpace(source) == "" {
		return fmt.Errorf("%w: status verified|rejected and the official source (URL, pasal/ayat, clause) are required", ErrInvalid)
	}
	return pgx.BeginFunc(ctx, s.DB, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `INSERT INTO compliance.verifications (framework, version, control_id, requirement, status, source, note, verified_by, verified_at)
			SELECT framework, version, control_id, requirement, $5, $6, $7, $8, $9 FROM compliance.mappings
			WHERE framework = $1 AND version = $2 AND control_id = $3 AND requirement = $4`,
			m.Framework, m.Version, m.Control, m.Requirement, status, source, nullable(note), actor, now)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return ErrNotFound
		}
		return auditTx(ctx, tx, s.Tenant, actor, "compliance.mapping."+status, map[string]any{"framework": m.Framework, "version": m.Version,
			"control_id": m.Control, "requirement": m.Requirement, "source": source})
	})
}

func nullable(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

func canonicalSHA(v any) string {
	b, _ := json.Marshal(v) // maps marshal with sorted keys
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
