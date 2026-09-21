// Package database provides the SQLite-backed persistence layer.
package database

import (
	"database/sql"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	_ "modernc.org/sqlite"
)

// DB wraps the sql.DB connection.
type DB struct {
	*sql.DB
}

// New opens (or creates) the SQLite database and runs migrations.
func New(path string) (*DB, error) {
	location := path
	if path == "" {
		return nil, fmt.Errorf("DB_PATH must name a database file (not an empty temporary database)")
	}
	if path != ":memory:" && !strings.HasPrefix(path, "file:") {
		var err error
		location, err = filepath.Abs(path)
		if err != nil {
			return nil, fmt.Errorf("resolve DB_PATH: %w", err)
		}
		parent := filepath.Dir(location)
		if err := os.MkdirAll(parent, 0700); err != nil {
			return nil, fmt.Errorf("prepare database parent directory %q: %w", parent, err)
		}
		if info, err := os.Stat(location); err == nil && !info.Mode().IsRegular() {
			return nil, fmt.Errorf("DB_PATH %q is not a regular file; mount a directory and append a database filename", location)
		} else if err != nil && !os.IsNotExist(err) {
			return nil, fmt.Errorf("inspect DB_PATH %q: %w", location, err)
		}
		file, err := os.OpenFile(location, os.O_CREATE|os.O_RDWR, 0600)
		if err != nil {
			return nil, fmt.Errorf("open database file %q: %w", location, err)
		}
		if err := file.Close(); err != nil {
			return nil, fmt.Errorf("close database file %q: %w", location, err)
		}
	}
	dsn := location
	if path != ":memory:" && !strings.HasPrefix(path, "file:") {
		uriPath := filepath.ToSlash(location)
		if !strings.HasPrefix(uriPath, "/") {
			uriPath = "/" + uriPath
		}
		dsn = (&url.URL{Scheme: "file", Path: uriPath}).String()
	}
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open db: %w", err)
	}
	db.SetMaxOpenConns(1)
	if err := db.Ping(); err != nil {
		db.Close()
		return nil, fmt.Errorf("open SQLite database (DB_PATH; parent must allow database, -wal and -shm files): %w", err)
	}

	if _, err := db.Exec("PRAGMA journal_mode = WAL;"); err != nil {
		db.Close()
		return nil, fmt.Errorf("enable SQLite WAL (check DB_PATH parent directory write access and local-filesystem locking): %w", err)
	}
	if _, err := db.Exec("PRAGMA busy_timeout = 5000;"); err != nil {
		db.Close()
		return nil, fmt.Errorf("set busy timeout: %w", err)
	}
	if _, err := db.Exec("PRAGMA foreign_keys = ON;"); err != nil {
		db.Close()
		return nil, fmt.Errorf("enable foreign keys: %w", err)
	}

	if err := migrate(db); err != nil {
		db.Close()
		return nil, fmt.Errorf("migrate: %w", err)
	}

	if err := migrateRelayRevocations(db); err != nil {
		db.Close()
		return nil, fmt.Errorf("migrate relay revocations: %w", err)
	}

	if err := migrateRooms(db); err != nil {
		db.Close()
		return nil, fmt.Errorf("migrate rooms: %w", err)
	}

	if err := migratePathTelemetry(db); err != nil {
		db.Close()
		return nil, fmt.Errorf("migrate path telemetry: %w", err)
	}

	if err := migrateConnectionMetrics(db); err != nil {
		db.Close()
		return nil, fmt.Errorf("migrate connection metrics: %w", err)
	}

	return &DB{db}, nil
}

// ForeignKeysEnabled reports whether SQLite foreign key enforcement is active.
func (db *DB) ForeignKeysEnabled() (bool, error) {
	var enabled int
	if err := db.QueryRow(`PRAGMA foreign_keys`).Scan(&enabled); err != nil {
		return false, err
	}
	return enabled == 1, nil
}
