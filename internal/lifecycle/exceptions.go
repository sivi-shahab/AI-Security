package lifecycle

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// scopeKeys are what an exception can be limited to (FR-POL-7); decision.rego matches them against the input.
var scopeKeys = []string{"principal_id", "group", "app_id", "agent_id"}

// Exception is the API view.
type Exception struct {
	ID          string            `json:"id"`
	Rules       []string          `json:"rules"`
	Scope       map[string]string `json:"scope"`
	Reason      string            `json:"reason"`
	RequestedBy string            `json:"requested_by"`
	Approver    *string           `json:"approver,omitempty"`
	State       string            `json:"state"`
	ExpiresAt   time.Time         `json:"expires_at"`
	CreatedAt   time.Time         `json:"created_at"`
	ApprovedAt  *time.Time        `json:"approved_at,omitempty"`
	NotifiedAt  *time.Time        `json:"notified_at,omitempty"`
}

// RequestException records a pending exception. expires_at is mandatory, in the future and at most
// MaxExceptionAge away; every rule must exist in the current release; the scope must name something.
func (s *Store) RequestException(ctx context.Context, actor string, e Exception, now time.Time) (string, error) {
	switch {
	case e.ExpiresAt.IsZero():
		return "", fmt.Errorf("%w: expires_at is required", ErrInvalid)
	case !e.ExpiresAt.After(now):
		return "", fmt.Errorf("%w: expires_at is in the past", ErrInvalid)
	case e.ExpiresAt.Sub(now) > MaxExceptionAge:
		return "", fmt.Errorf("%w: expires_at is more than %d days away", ErrInvalid, int(MaxExceptionAge.Hours()/24))
	case len(e.Rules) == 0 || strings.TrimSpace(e.Reason) == "" || len(e.Scope) == 0:
		return "", fmt.Errorf("%w: rules, reason and scope are required", ErrInvalid)
	}
	for k, v := range e.Scope {
		if !slices.Contains(scopeKeys, k) || strings.TrimSpace(v) == "" {
			return "", fmt.Errorf("%w: scope key %q (allowed: %v)", ErrInvalid, k, scopeKeys)
		}
	}
	latest, err := s.Latest(ctx)
	if err != nil {
		return "", err
	}
	known := map[string]bool{}
	items, _ := latest.Rules["items"].([]any)
	for _, r := range items {
		if id, ok := r.(map[string]any)["id"].(string); ok {
			known[id] = true
		}
	}
	for _, r := range e.Rules {
		if !known[r] {
			return "", fmt.Errorf("%w: rule %q is not in the active release", ErrInvalid, r)
		}
	}
	var id string
	err = s.change(ctx, actor, "policy.exception.request", func(tx pgx.Tx) (map[string]any, error) {
		err := tx.QueryRow(ctx, `INSERT INTO policy.exceptions (rules, scope, reason, requested_by, state, expires_at)
			VALUES ($1, $2, $3, $4, 'pending', $5) RETURNING id::text`, e.Rules, e.Scope, e.Reason, actor, e.ExpiresAt).Scan(&id)
		return map[string]any{"exception": id, "rules": e.Rules, "scope": e.Scope, "expires_at": e.ExpiresAt, "reason": e.Reason}, err
	})
	return id, err
}

func (s *Store) exceptionChange(ctx context.Context, actor, action, id string, from, to string, check func(Exception) error) (int64, error) {
	var n int64
	err := s.change(ctx, actor, action, func(tx pgx.Tx) (map[string]any, error) {
		rows, err := tx.Query(ctx, "SELECT "+exceptionCols+" FROM policy.exceptions WHERE id::text = $1 FOR UPDATE", id)
		if err != nil {
			return nil, err
		}
		e, err := pgx.CollectExactlyOneRow(rows, pgx.RowToStructByPos[Exception])
		if err != nil {
			return nil, notFound(err)
		}
		if e.State != from {
			return nil, fmt.Errorf("%w: exception is %s, needs %s", ErrState, e.State, from)
		}
		if check != nil {
			if err := check(e); err != nil {
				return nil, err
			}
		}
		_, err = tx.Exec(ctx, `UPDATE policy.exceptions SET state = $2,
			approver = CASE WHEN $2 = 'active' THEN $3 ELSE approver END,
			approved_at = CASE WHEN $2 = 'active' THEN now() ELSE approved_at END WHERE id = $1`, e.ID, to, actor)
		if err != nil {
			return nil, err
		}
		n, err = s.release(ctx, tx, actor, fmt.Sprintf("%s exception %s", action, id))
		return map[string]any{"exception": id, "from": from, "to": to, "requested_by": e.RequestedBy, "release": n}, err
	})
	return n, err
}

// ApproveException activates it (4-eyes: approver ≠ requester) and cuts a release.
func (s *Store) ApproveException(ctx context.Context, actor, id string, now time.Time) (int64, error) {
	return s.exceptionChange(ctx, actor, "policy.exception.approve", id, "pending", "active", func(e Exception) error {
		if strings.EqualFold(e.RequestedBy, actor) {
			return ErrFourEyes
		}
		if !e.ExpiresAt.After(now) {
			return fmt.Errorf("%w: exception already expired", ErrState)
		}
		return nil
	})
}

// RevokeException ends an active exception early and cuts a release.
func (s *Store) RevokeException(ctx context.Context, actor, id string) (int64, error) {
	return s.exceptionChange(ctx, actor, "policy.exception.revoke", id, "active", "revoked", nil)
}

const exceptionCols = "id::text, rules, scope, reason, requested_by, approver, state, expires_at, created_at, approved_at, notified_at"

func (s *Store) Exceptions(ctx context.Context) ([]Exception, error) {
	rows, err := s.db.Query(ctx, "SELECT "+exceptionCols+" FROM policy.exceptions ORDER BY created_at DESC")
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowToStructByPos[Exception])
}

// Sweep marks expired exceptions (and cuts a release without them) and sends the expiry notice once per exception
// 7 days ahead. Notice = audit entry policy.exception.expiring, which the SIEM forwards (ticket 19) and the
// metric counts. Safe on every replica: each row is claimed by one UPDATE.
func (s *Store) Sweep(ctx context.Context, now time.Time) (expired, notified int, err error) {
	err = s.change(ctx, "system", "policy.exception.expire", func(tx pgx.Tx) (map[string]any, error) {
		rows, err := tx.Query(ctx, `UPDATE policy.exceptions SET state = 'expired'
			WHERE state = 'active' AND expires_at <= $1 RETURNING id::text`, now)
		if err != nil {
			return nil, err
		}
		ids, err := pgx.CollectRows(rows, pgx.RowTo[string])
		if err != nil || len(ids) == 0 {
			return nil, err
		}
		expired = len(ids)
		n, err := s.release(ctx, tx, "system", fmt.Sprintf("expire %d exception(s)", len(ids)))
		return map[string]any{"exceptions": ids, "release": n}, err
	})
	if err != nil {
		return 0, 0, err
	}
	rows, err := s.db.Query(ctx, `UPDATE policy.exceptions SET notified_at = $1
		WHERE state = 'active' AND notified_at IS NULL AND expires_at <= $2 RETURNING `+exceptionCols, now, now.Add(ExpiryNotice))
	if err != nil {
		return expired, 0, err
	}
	soon, err := pgx.CollectRows(rows, pgx.RowToStructByPos[Exception])
	if err != nil {
		return expired, 0, err
	}
	for _, e := range soon {
		err := s.change(ctx, "system", "policy.exception.expiring", func(pgx.Tx) (map[string]any, error) {
			return map[string]any{"exception": e.ID, "requested_by": e.RequestedBy, "approver": e.Approver, "expires_at": e.ExpiresAt, "rules": e.Rules}, nil
		})
		if err != nil {
			return expired, notified, err
		}
		notified++
	}
	return expired, notified, nil
}

// ActiveExceptions counts exceptions in force.
func (s *Store) ActiveExceptions(ctx context.Context, now time.Time) (n int, err error) {
	err = s.db.QueryRow(ctx, "SELECT count(*) FROM policy.exceptions WHERE state = 'active' AND expires_at > $1", now).Scan(&n)
	return n, err
}

// ExpiringSoon counts active exceptions within the notice window (gauge for alerting).
func (s *Store) ExpiringSoon(ctx context.Context, now time.Time) (n int, err error) {
	err = s.db.QueryRow(ctx, "SELECT count(*) FROM policy.exceptions WHERE state = 'active' AND expires_at <= $1", now.Add(ExpiryNotice)).Scan(&n)
	return n, err
}
