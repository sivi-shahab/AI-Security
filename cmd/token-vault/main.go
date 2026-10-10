package main

import (
	"context"
	"errors"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"aisec/internal/audit"
	"aisec/internal/privacy"
	"aisec/internal/server"
	"aisec/internal/tokvault"
)

// Env: DATABASE_URL, TENANT_ID, VAULT_KEK_FILE (32 raw bytes, from Vault/HSM), VAULT_CLIENT_TOKEN_SHA256 (hex; the
// AI gateway's VAULT_TOKEN). Run two replicas: one is active (holds the lock, ready), the other waits.
func main() {
	log := privacy.NewLogger("token-vault")
	fail := func(msg string, err error) {
		log.Error(msg, "err", err)
		os.Exit(1)
	}
	for _, k := range []string{"DATABASE_URL", "TENANT_ID", "VAULT_KEK_FILE", "VAULT_CLIENT_TOKEN_SHA256"} {
		if os.Getenv(k) == "" {
			fail("config", errors.New(k+" is required"))
		}
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, os.Interrupt)
	defer stop()
	db, err := pgxpool.New(ctx, os.Getenv("DATABASE_URL"))
	if err != nil {
		fail("database", err)
	}
	auditLog, err := audit.Open(ctx, os.Getenv("DATABASE_URL"))
	if err != nil {
		fail("audit log", err)
	}
	kek, err := os.ReadFile(os.Getenv("VAULT_KEK_FILE"))
	if err != nil {
		fail("read vault KEK", err)
	}
	v, err := tokvault.Open(ctx, db, auditLog, os.Getenv("TENANT_ID"), kek)
	if err != nil {
		fail("open vault", err)
	}
	leader := &tokvault.Leader{}
	go leader.Run(ctx, os.Getenv("DATABASE_URL"), 2*time.Second, log)
	go func() { // expired registrations go, on the active replica
		for range time.Tick(10 * time.Minute) {
			if leader.Active() {
				if n, err := v.Purge(ctx); err != nil {
					log.Error("purge", "err", err)
				} else if n > 0 {
					log.Info("purged expired tokens", "count", n)
				}
			}
		}
	}()
	mux := http.NewServeMux()
	v.Routes(mux, leader, os.Getenv("VAULT_CLIENT_TOKEN_SHA256"))
	server.Run("token-vault", mux)
}
