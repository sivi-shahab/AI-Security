package main

import (
	"context"
	"net/http"
	"os"

	"aisec/internal/policysvc"
	"aisec/internal/privacy"
	"aisec/internal/server"
	"aisec/policy"
)

func main() {
	log := privacy.NewLogger("control-plane")
	// No key, no bundle: sidecars must never be offered an unsigned policy.
	key, err := os.ReadFile(os.Getenv("BUNDLE_SIGNING_KEY_FILE"))
	if err != nil {
		log.Error("read bundle signing key", "err", err)
		os.Exit(1)
	}
	tarball, rev, err := policysvc.Build(context.Background(), policy.Files, string(key))
	if err != nil {
		log.Error("build policy bundle", "err", err)
		os.Exit(1)
	}
	bundles := &policysvc.Server{}
	bundles.Publish(tarball, rev)
	log.Info("policy bundle published", "revision", rev)

	mux := http.NewServeMux()
	mux.Handle("GET /bundles/aisec.tar.gz", bundles)
	server.Run("control-plane", mux)
}
