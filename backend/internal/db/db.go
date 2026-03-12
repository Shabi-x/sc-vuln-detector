package db

import (
	"fmt"
	"os"
	"path/filepath"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

type Config struct {
	Path string
}

func LoadConfigFromEnv() Config {
	path := os.Getenv("DB_PATH")
	if path == "" {
		path = "data/app.db"
	}
	return Config{Path: path}
}

func Open(cfg Config) (*gorm.DB, error) {
	if cfg.Path == "" {
		return nil, fmt.Errorf("db path is empty")
	}

	dir := filepath.Dir(cfg.Path)
	if dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return nil, fmt.Errorf("mkdir db dir: %w", err)
		}
	}

	gdb, err := gorm.Open(sqlite.Open(cfg.Path), &gorm.Config{})
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}

	return gdb, nil
}

