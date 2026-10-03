package audit

import (
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

//go:embed schema.sql
var schemaSQL string

// appendLock serializes appends: the chain is one sequence, so writers must take turns.
// ponytail: one global lock, fine for admin/audit write rates; shard the chain per tenant if it ever bottlenecks.
const appendLock = 0x61756469 // "audi"

// Store is the Postgres-backed log (schema audit).
type Store struct{ db *pgxpool.Pool }

// Open connects and applies schema.sql (idempotent).
func Open(ctx context.Context, url string) (*Store, error) {
	db, err := pgxpool.New(ctx, url)
	if err != nil {
		return nil, err
	}
	if _, err := db.Exec(ctx, schemaSQL); err != nil {
		db.Close()
		return nil, fmt.Errorf("apply audit schema: %w", err)
	}
	return &Store{db}, nil
}

func (s *Store) Close() { s.db.Close() }

// Append writes the next entry in its own transaction.
func (s *Store) Append(ctx context.Context, tenantID, actor, action string, target map[string]any) (e Entry, err error) {
	err = pgx.BeginFunc(ctx, s.db, func(tx pgx.Tx) error {
		e, err = AppendTx(ctx, tx, tenantID, actor, action, target)
		return err
	})
	return e, err
}

// AppendTx writes the next entry inside the caller's transaction, so the audited change and its record commit or
// roll back together. ts comes from the database clock under the lock, so ts never decreases with seq.
func AppendTx(ctx context.Context, tx pgx.Tx, tenantID, actor, action string, target map[string]any) (Entry, error) {
	raw, err := json.Marshal(target)
	if err != nil {
		return Entry{}, err
	}
	e := Entry{TenantID: tenantID, Actor: actor, Action: action}
	if err := json.Unmarshal(raw, &e.Target); err != nil { // same shape jsonb reads back as
		return Entry{}, err
	}
	if _, err := tx.Exec(ctx, "SELECT pg_advisory_xact_lock($1)", appendLock); err != nil {
		return Entry{}, err
	}
	e.PrevHash = Genesis
	err = tx.QueryRow(ctx, "SELECT seq, hash FROM audit.audit_log ORDER BY seq DESC LIMIT 1").Scan(&e.Seq, &e.PrevHash)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return Entry{}, err
	}
	e.Seq++
	if err := tx.QueryRow(ctx, "SELECT date_trunc('microseconds', clock_timestamp())").Scan(&e.TS); err != nil {
		return Entry{}, err
	}
	e.TS = e.TS.UTC()
	e.Hash = Hash(e.PrevHash, e)
	_, err = tx.Exec(ctx, `INSERT INTO audit.audit_log (seq, tenant_id, ts, actor, action, target, prev_hash, hash)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`, e.Seq, e.TenantID, e.TS, e.Actor, e.Action, e.Target, e.PrevHash, e.Hash)
	return e, err
}

const cols = "seq, tenant_id::text, ts, actor, action, target, prev_hash, hash"

func scan(rows pgx.Rows) ([]Entry, error) {
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (Entry, error) {
		var e Entry
		err := r.Scan(&e.Seq, &e.TenantID, &e.TS, &e.Actor, &e.Action, &e.Target, &e.PrevHash, &e.Hash)
		e.TS = e.TS.UTC()
		return e, err
	})
}

// Range returns every entry from the first with ts >= from to the last with ts < to, by seq (so deleted rows
// show up as gaps), plus the predecessor's seq and hash to verify from.
func (s *Store) Range(ctx context.Context, from, to time.Time) (prevSeq int64, prevHash string, entries []Entry, err error) {
	var lo, hi *int64
	err = s.db.QueryRow(ctx, `SELECT (SELECT min(seq) FROM audit.audit_log WHERE ts >= $1),
		(SELECT max(seq) FROM audit.audit_log WHERE ts < $2)`, from, to).Scan(&lo, &hi)
	if err != nil || lo == nil || hi == nil || *lo > *hi {
		return 0, Genesis, nil, err
	}
	rows, err := s.db.Query(ctx, "SELECT "+cols+" FROM audit.audit_log WHERE seq BETWEEN $1 AND $2 ORDER BY seq", *lo-1, *hi)
	if err != nil {
		return 0, "", nil, err
	}
	all, err := scan(rows)
	if err != nil {
		return 0, "", nil, err
	}
	prevSeq, prevHash = *lo-1, Genesis
	if len(all) > 0 && all[0].Seq == *lo-1 {
		prevHash, all = all[0].Hash, all[1:]
	} else if *lo > 1 {
		return 0, "", nil, &BrokenError{*lo - 1, "missing"}
	}
	return prevSeq, prevHash, all, nil
}

// Head returns the last entry with ts < t (seq 0 and Genesis if none): the chain state an anchor records.
func (s *Store) Head(ctx context.Context, t time.Time) (seq int64, hash string, err error) {
	err = s.db.QueryRow(ctx, "SELECT seq, hash FROM audit.audit_log WHERE ts < $1 ORDER BY seq DESC LIMIT 1", t).Scan(&seq, &hash)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, Genesis, nil
	}
	return seq, hash, err
}

// At returns the entry hash stored at seq.
func (s *Store) At(ctx context.Context, seq int64) (string, error) {
	var hash string
	err := s.db.QueryRow(ctx, "SELECT hash FROM audit.audit_log WHERE seq = $1", seq).Scan(&hash)
	return hash, err
}
