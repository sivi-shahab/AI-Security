package main

import (
	"net/http"

	"aisec/internal/server"
)

func main() {
	server.Run("detection-svc", http.NewServeMux())
}
