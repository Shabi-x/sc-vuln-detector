package main

import (
	"log"
	"os"

	"sc-vuln-detector/backend/internal/db"
	"sc-vuln-detector/backend/internal/httpserver"
	"sc-vuln-detector/backend/internal/store"
)

func main() {
	addr := os.Getenv("ADDR")
	if addr == "" {
		addr = ":8080"
	}

	gdb, err := db.Open(db.LoadConfigFromEnv())
	if err != nil {
		log.Fatal(err)
	}
	if err := store.AutoMigrate(gdb); err != nil {
		log.Fatal(err)
	}
	if err := store.SeedPresetPrompts(gdb); err != nil {
		log.Fatal(err)
	}

	srv := httpserver.New(gdb)
	log.Printf("server listening on %s", addr)
	if err := srv.Run(addr); err != nil {
		log.Fatal(err)
	}
}
