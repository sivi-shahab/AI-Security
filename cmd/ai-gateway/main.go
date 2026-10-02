package main

import (
	"net/http"

	"aisec/internal/server"
)

func main() {
	server.Run("ai-gateway", http.NewServeMux())
}
