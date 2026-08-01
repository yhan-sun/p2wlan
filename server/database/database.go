// Package database provides the SQLite-backed persistence layer.
package database

import (
	"database/sql"
	"fmt"

	_ "modernc.org/sqlite"
)

// DB wraps the sql.DB connection.
type DB struct {
	*sql.DB
}

// New opens (or creates) the SQLite database and runs migrations.
func New(path string) (*DB, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open db: %w", err)
	}
	db.SetMaxOpenConns(1)

	if _, err := db.Exec("PRAGMA journal_mode = WAL;"); err != nil {
		db.Close()
		return nil, fmt.Errorf("enable wal mode: %w", err)
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
