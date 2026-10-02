package main

import (
	"net/http"

	"aisec/internal/server"
)

func main() {
	server.Run("control-plane", http.NewServeMux())
}
