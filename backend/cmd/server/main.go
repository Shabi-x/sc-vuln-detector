package main

import (
	"log"
	"os"

	"sc-vuln-detector/backend/internal/httpserver"
)

func main() {
	addr := os.Getenv("ADDR")
	if addr == "" {
		addr = ":8080"
	}

	srv := httpserver.New()
	log.Printf("server listening on %s", addr)
	if err := srv.Run(addr); err != nil {
		log.Fatal(err)
	}
}
