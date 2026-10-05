package compliance

import (
	"bytes"
	"context"
	"encoding/csv"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// Report is the export for one audit period (FR-COMP-3).
type Report struct {
	From        time.Time         `json:"from"`
	To          time.Time         `json:"to"`
	GeneratedAt time.Time         `json:"generated_at"`
	GeneratedBy string            `json:"generated_by"`
	Frameworks  []ReportFramework `json:"frameworks"`
	Controls    []ReportControl   `json:"controls"`
	SHA256      string            `json:"sha256,omitempty"` // of the report with this field empty
}

// ReportFramework is the framework version in effect at the end of the period (the latest imported by then),
// and any other version that took effect during it.
type ReportFramework struct {
	Framework     string              `json:"framework"`
	Version       string              `json:"version"`
	Name          string              `json:"name"`
	Source        string              `json:"source"`
	ImportedAt    time.Time           `json:"imported_at"`
	Note          string              `json:"note,omitempty"`
	OtherVersions []string            `json:"versions_also_in_period,omitempty"`
	Requirements  []ReportRequirement `json:"requirements"`
	VerifiedShare string              `json:"mappings_verified"` // "n/m" signed off by the compliance team at period end
}

type ReportRequirement struct {
	ID       string          `json:"id"`
	Title    string          `json:"title"`
	Controls []ReportMapping `json:"controls"`
}

type ReportMapping struct {
	Control      string        `json:"control_id"`
	Research     Research      `json:"research"`
	Verification *Verification `json:"verification,omitempty"`
	StatusAtEnd  string        `json:"control_status_at_end"`
}

// ReportControl is a control's status over the period and the evidence behind it.
type ReportControl struct {
	Control
	StatusAtStart string           `json:"status_at_start"`
	StatusAtEnd   string           `json:"status_at_end"`
	Transitions   []Transition     `json:"transitions"`
	Evidence      EvidenceSummary  `json:"evidence"`
	Attachments   []map[string]any `json:"attachments"`
}

type Transition struct {
	At         time.Time `json:"at"`
	Status     string    `json:"status"`
	Reasons    []string  `json:"reasons"`
	EvidenceID int64     `json:"evidence_id"`
}

type EvidenceSummary struct {
	Automatic  int64            `json:"automatic"`
	ByStatus   map[string]int64 `json:"by_status"`
	FirstID    *int64           `json:"first_id,omitempty"`
	LastID     *int64           `json:"last_id,omitempty"`
	LastSHA256 *string          `json:"last_sha256,omitempty"`
}

// statusAt is a control's status at t: the last change at or before t ("unknown" before any).
func statusAt(ctx context.Context, tx pgx.Tx, control string, t time.Time) (string, error) {
	var st string
	err := tx.QueryRow(ctx, "SELECT status FROM compliance.control_status WHERE control_id = $1 AND at <= $2 ORDER BY at DESC, id DESC LIMIT 1", control, t).Scan(&st)
	if errors.Is(err, pgx.ErrNoRows) {
		return "unknown", nil
	}
	return st, err
}

// Export builds the report for [from, to) from history only: an export of a past period is the same whatever
// changed since (new framework versions, re-verifications after `to` excluded). It is audited with its hash.
func (s *Store) Export(ctx context.Context, actor string, from, to, now time.Time) (Report, error) {
	if !from.Before(to) || to.After(now) {
		return Report{}, fmt.Errorf("%w: from must be before to, and to not in the future", ErrInvalid)
	}
	r := Report{From: from, To: to, GeneratedAt: now, GeneratedBy: actor}
	err := pgx.BeginTxFunc(ctx, s.DB, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly}, func(tx pgx.Tx) error {
		end := map[string]string{}
		for _, c := range Controls {
			rc := ReportControl{Control: c, Transitions: []Transition{}, Attachments: []map[string]any{}, Evidence: EvidenceSummary{ByStatus: map[string]int64{}}}
			var err error
			if rc.StatusAtStart, err = statusAt(ctx, tx, c.ID, from); err != nil {
				return err
			}
			if rc.StatusAtEnd, err = statusAt(ctx, tx, c.ID, to.Add(-time.Nanosecond)); err != nil {
				return err
			}
			end[c.ID] = rc.StatusAtEnd
			rows, err := tx.Query(ctx, "SELECT at, status, reasons, evidence_id FROM compliance.control_status WHERE control_id = $1 AND at >= $2 AND at < $3 ORDER BY at, id", c.ID, from, to)
			if err != nil {
				return err
			}
			if rc.Transitions, err = pgx.CollectRows(rows, pgx.RowToStructByPos[Transition]); err != nil {
				return err
			}
			if rc.Transitions == nil {
				rc.Transitions = []Transition{}
			}
			rows, err = tx.Query(ctx, `SELECT kind, status, count(*), min(id), max(id) FROM compliance.evidence
				WHERE control_id = $1 AND collected_at >= $2 AND collected_at < $3 GROUP BY kind, status`, c.ID, from, to)
			if err != nil {
				return err
			}
			for rows.Next() {
				var kind, status string
				var n, lo, hi int64
				if err := rows.Scan(&kind, &status, &n, &lo, &hi); err != nil {
					return err
				}
				if kind != "automatic" {
					continue
				}
				rc.Evidence.Automatic += n
				rc.Evidence.ByStatus[status] += n
				if rc.Evidence.FirstID == nil || lo < *rc.Evidence.FirstID {
					rc.Evidence.FirstID = &lo
				}
				if rc.Evidence.LastID == nil || hi > *rc.Evidence.LastID {
					rc.Evidence.LastID = &hi
				}
			}
			if rows.Err() != nil {
				return rows.Err()
			}
			if rc.Evidence.LastID != nil {
				var sha string
				if err := tx.QueryRow(ctx, "SELECT sha256 FROM compliance.evidence WHERE id = $1", *rc.Evidence.LastID).Scan(&sha); err != nil {
					return err
				}
				rc.Evidence.LastSHA256 = &sha
			}
			rows, err = tx.Query(ctx, `SELECT jsonb_build_object('evidence_id', id, 'status', status, 'sha256', sha256, 'note', summary->>'note',
				'by', collected_by, 'at', collected_at) FROM compliance.evidence WHERE control_id = $1 AND kind = 'attachment' AND collected_at >= $2 AND collected_at < $3 ORDER BY id`,
				c.ID, from, to)
			if err != nil {
				return err
			}
			if rc.Attachments, err = pgx.CollectRows(rows, pgx.RowTo[map[string]any]); err != nil {
				return err
			}
			if rc.Attachments == nil {
				rc.Attachments = []map[string]any{}
			}
			r.Controls = append(r.Controls, rc)
		}

		// Framework versions in effect: the latest imported before the end of the period; if none was, the first.
		rows, err := tx.Query(ctx, "SELECT doc, imported_at FROM compliance.frameworks ORDER BY framework, imported_at")
		if err != nil {
			return err
		}
		type fv struct {
			fw Framework
			at time.Time
		}
		var all []fv
		for rows.Next() {
			var v fv
			if err := rows.Scan(&v.fw, &v.at); err != nil {
				return err
			}
			all = append(all, v)
		}
		if rows.Err() != nil {
			return rows.Err()
		}
		var fvs []fv
		for _, v := range all { // ordered by framework, then import time
			switch n := len(fvs); {
			case n == 0 || fvs[n-1].fw.ID != v.fw.ID:
				fvs = append(fvs, v)
			case v.at.Before(to):
				fvs[n-1] = v
			}
		}
		for _, v := range fvs {
			rf := ReportFramework{Framework: v.fw.ID, Version: v.fw.Version, Name: v.fw.Name, Source: v.fw.Source, ImportedAt: v.at, Note: v.fw.Note}
			if !v.at.Before(to) {
				rf.Note = strings.TrimSpace(rf.Note + " Imported after the period ended; shown because no version was in effect during it.")
			}
			others, err := tx.Query(ctx, "SELECT version FROM compliance.frameworks WHERE framework = $1 AND version <> $2 AND imported_at >= $3 AND imported_at < $4 ORDER BY imported_at",
				v.fw.ID, v.fw.Version, from, to)
			if err != nil {
				return err
			}
			if rf.OtherVersions, err = pgx.CollectRows(others, pgx.RowTo[string]); err != nil {
				return err
			}
			ms, err := mappings(ctx, tx, v.fw.ID, v.fw.Version, to)
			if err != nil {
				return err
			}
			byReq := map[string][]ReportMapping{}
			verified := 0
			for _, m := range ms {
				byReq[m.Requirement] = append(byReq[m.Requirement], ReportMapping{Control: m.Control, Research: m.Research, Verification: m.Verification, StatusAtEnd: end[m.Control]})
				if m.Verification != nil && m.Verification.Status == "verified" {
					verified++
				}
			}
			rf.VerifiedShare = fmt.Sprintf("%d/%d", verified, len(ms))
			for _, req := range v.fw.Requirements {
				if ms := byReq[req.ID]; len(ms) > 0 {
					rf.Requirements = append(rf.Requirements, ReportRequirement{ID: req.ID, Title: req.Title, Controls: ms})
				}
			}
			r.Frameworks = append(r.Frameworks, rf)
		}
		return nil
	})
	if err != nil {
		return Report{}, err
	}
	r.SHA256 = canonicalSHA(r)
	err = pgx.BeginFunc(ctx, s.DB, func(tx pgx.Tx) error {
		return auditTx(ctx, tx, s.Tenant, actor, "compliance.report.export", map[string]any{"from": from, "to": to, "sha256": r.SHA256})
	})
	return r, err
}

// CSV renders the report as one row per framework requirement and control.
func (r Report) CSV() ([]byte, error) {
	var b bytes.Buffer
	w := csv.NewWriter(&b)
	_ = w.Write([]string{"period_from", "period_to", "framework", "version", "requirement", "title", "control_id", "research_verdict",
		"verification", "verified_by", "control_status_at_end", "report_sha256"})
	for _, f := range r.Frameworks {
		for _, req := range f.Requirements {
			for _, m := range req.Controls {
				ver, by := "unverified", ""
				if m.Verification != nil {
					ver, by = m.Verification.Status, m.Verification.VerifiedBy
				}
				_ = w.Write([]string{r.From.Format(time.RFC3339), r.To.Format(time.RFC3339), f.Framework, f.Version, req.ID, req.Title, m.Control,
					m.Research.Verdict, ver, by, m.StatusAtEnd, r.SHA256})
			}
		}
	}
	w.Flush()
	return b.Bytes(), w.Error()
}
