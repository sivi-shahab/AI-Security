// Package tenantdb is PostgreSQL row level security per tenant (ADR-0001 U11, ADR-0003, ticket 42). Tables holding a
// tenant's data carry a policy that shows and accepts only the rows of the tenant in app.tenant_id; Pool pins that
// setting on every connection of a process, Isolate puts a table under the policy.
package tenantdb

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Setting is the session setting the policies read. Unset, current_setting(…, true) is NULL and no row matches.
const Setting = "app.tenant_id"

// Pool opens a pool whose every connection belongs to tenant: app.tenant_id is a startup parameter, so no query
// path can forget it. A role that bypasses RLS (superuser, BYPASSRLS) is refused, since the policies would not
// apply to it, unless DATABASE_ALLOW_BYPASSRLS=true (local development only).
// ponytail: one tenant per process (ADR-0001: one deployment per bank); a process serving several tenants would
// set_config(app.tenant_id, …, true) per transaction instead.
func Pool(ctx context.Context, url, tenant string) (*pgxpool.Pool, error) {
	if _, err := uuid.Parse(tenant); err != nil {
		return nil, fmt.Errorf("tenant id %q: %w", tenant, err)
	}
	cfg, err := pgxpool.ParseConfig(url)
	if err != nil {
		return nil, err
	}
	cfg.ConnConfig.RuntimeParams[Setting] = tenant
	db, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, err
	}
	var bypass bool
	if err := db.QueryRow(ctx, "SELECT rolsuper OR rolbypassrls FROM pg_roles WHERE rolname = current_user").Scan(&bypass); err != nil {
		db.Close()
		return nil, fmt.Errorf("check database role: %w", err)
	}
	if bypass && os.Getenv("DATABASE_ALLOW_BYPASSRLS") != "true" {
		db.Close()
		return nil, fmt.Errorf("database role bypasses row level security (superuser or BYPASSRLS): use the application role")
	}
	return db, nil
}

// Policy is the tenant condition of a table with a tenant_id column.
const Policy = "tenant_id = current_setting('" + Setting + "', true)::uuid"

// Isolate puts tables with a tenant_id column under the tenant policy, for reads and writes, the table owner
// included (FORCE). Idempotent; it changes nothing on a table already isolated, so restarts take no table locks.
func Isolate(ctx context.Context, db *pgxpool.Pool, tables ...string) error {
	for _, t := range tables {
		if err := isolate(ctx, db, t, Policy); err != nil {
			return err
		}
	}
	return nil
}

// IsolateChild puts a table without tenant_id under the tenant of its parent row: fk must name a row of parent
// (by id) that the parent's own policy lets the session see.
func IsolateChild(ctx context.Context, db *pgxpool.Pool, table, fk, parent string) error {
	return isolate(ctx, db, table, fmt.Sprintf("%s IN (SELECT id FROM %s)", fk, parent))
}

func isolate(ctx context.Context, db *pgxpool.Pool, table, cond string) error {
	schema, name, ok := strings.Cut(table, ".")
	if !ok {
		return fmt.Errorf("table %q: want schema.table", table)
	}
	return pgx.BeginFunc(ctx, db, func(tx pgx.Tx) error {
		// Replicas starting together apply the same DDL: one at a time.
		if _, err := tx.Exec(ctx, "SELECT pg_advisory_xact_lock(hashtextextended('tenantdb.isolate', 0))"); err != nil {
			return err
		}
		var enabled, forced, policy bool
		err := tx.QueryRow(ctx, `SELECT c.relrowsecurity, c.relforcerowsecurity,
			  EXISTS (SELECT 1 FROM pg_policies p WHERE p.schemaname = $1 AND p.tablename = $2 AND p.policyname = 'tenant')
			FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = $1 AND c.relname = $2`, schema, name).
			Scan(&enabled, &forced, &policy)
		if err != nil {
			return fmt.Errorf("isolate %s: %w", table, err)
		}
		id := pgx.Identifier{schema, name}.Sanitize()
		if !policy {
			if _, err := tx.Exec(ctx, fmt.Sprintf("CREATE POLICY tenant ON %s USING (%s) WITH CHECK (%s)", id, cond, cond)); err != nil {
				return fmt.Errorf("isolate %s: %w", table, err)
			}
		}
		if !enabled || !forced {
			if _, err := tx.Exec(ctx, fmt.Sprintf("ALTER TABLE %s ENABLE ROW LEVEL SECURITY, FORCE ROW LEVEL SECURITY", id)); err != nil {
				return fmt.Errorf("isolate %s: %w", table, err)
			}
		}
		return nil
	})
}
