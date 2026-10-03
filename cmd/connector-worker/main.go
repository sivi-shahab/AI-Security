package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"aisec/internal/connector/m365"
	"aisec/internal/datascan"
	"aisec/internal/extract"
	"aisec/internal/privacy"
	"aisec/internal/server"
)

// Env: DATABASE_URL, TENANT_PEPPER, M365_TENANT_ID, M365_CLIENT_ID, M365_CLIENT_SECRET (Entra app: Sites.Read.All,
// Files.Read.All, User.Read.All), M365_DOMAINS (comma-separated tenant e-mail domains), M365_LABELS (JSON: Purview
// label id → public|internal|confidential|restricted), TIKA_URL (sandboxed Tika for PDF/legacy Office; optional),
// SCAN_INTERVAL (Go duration, default 1h).
func main() {
	log := privacy.NewLogger("connector-worker")
	fail := func(msg string, err error) {
		log.Error(msg, "err", err)
		os.Exit(1)
	}
	for _, k := range []string{"DATABASE_URL", "TENANT_PEPPER", "M365_TENANT_ID", "M365_CLIENT_ID", "M365_CLIENT_SECRET", "M365_DOMAINS"} {
		if os.Getenv(k) == "" {
			fail("config", errors.New(k+" is required"))
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	db, err := pgxpool.New(ctx, os.Getenv("DATABASE_URL"))
	if err != nil {
		fail("database", err)
	}
	if err := datascan.Open(ctx, db); err != nil {
		fail("data schema", err)
	}
	labels := map[string]string{}
	if v := os.Getenv("M365_LABELS"); v != "" {
		if err := json.Unmarshal([]byte(v), &labels); err != nil {
			fail("M365_LABELS", err)
		}
	}
	interval := time.Hour
	if v := os.Getenv("SCAN_INTERVAL"); v != "" {
		if interval, err = time.ParseDuration(v); err != nil || interval <= 0 {
			fail("SCAN_INTERVAL", errors.New("positive Go duration"))
		}
	}
	var tika *extract.Tika
	if u := os.Getenv("TIKA_URL"); u != "" {
		tika = &extract.Tika{URL: u, HTTP: &http.Client{Timeout: 2 * time.Minute}}
	}
	sc := &datascan.Scanner{DB: db, Source: "m365", Pepper: []byte(os.Getenv("TENANT_PEPPER")), Labels: labels, Tika: tika, Log: log,
		Conn: m365.New(os.Getenv("M365_TENANT_ID"), os.Getenv("M365_CLIENT_ID"), os.Getenv("M365_CLIENT_SECRET"), strings.Split(os.Getenv("M365_DOMAINS"), ","))}
	sc.Defaults()
	go func() {
		for t := time.NewTicker(interval); ctx.Err() == nil; <-t.C {
			start := time.Now()
			st, err := sc.Run(ctx)
			log.Info("scan pass", "source", sc.Source, "containers", st.Containers, "items", st.Items, "content_read", st.ContentRead,
				"acl_read", st.ACLRead, "unchanged", st.Unchanged, "deleted", st.Deleted, "errors", st.Errors, "took", time.Since(start).String())
			if err != nil {
				log.Error("scan pass", "err", err)
			}
		}
	}()
	server.Run("connector-worker", http.NewServeMux())
	cancel()
	db.Close()
}
