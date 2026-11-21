package main

import (
	"database/sql"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestBackupDatabaseCreatesReadableSnapshot(t *testing.T) {
	root := t.TempDir()
	source := filepath.Join(root, "source.db")
	snapshot := filepath.Join(root, "backup", "database.sqlite")

	db, err := openDatabase(source)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("CREATE TABLE entries (value TEXT NOT NULL)"); err != nil {
		db.Close()
		t.Fatal(err)
	}
	if _, err := db.Exec("INSERT INTO entries(value) VALUES ('consistent')"); err != nil {
		db.Close()
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	if err := backupDatabase(source, snapshot); err != nil {
		t.Fatal(err)
	}
	if err := verifyDatabase(snapshot); err != nil {
		t.Fatal(err)
	}

	check, err := sql.Open("sqlite", dsn(snapshot))
	if err != nil {
		t.Fatal(err)
	}
	defer check.Close()
	var value string
	if err := check.QueryRow("SELECT value FROM entries").Scan(&value); err != nil {
		t.Fatal(err)
	}
	if value != "consistent" {
		t.Fatalf("snapshot value = %q, want consistent", value)
	}
	info, err := os.Stat(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" {
		if got := info.Mode().Perm(); got != 0o600 {
			t.Fatalf("snapshot permissions = %o, want 600", got)
		}
	}
}

func TestFilesystemPathRejectsNonFileDatabaseNames(t *testing.T) {
	for _, path := range []string{"", ":memory:", "file:memory.db"} {
		if _, err := filesystemPath(path); err == nil {
			t.Fatalf("filesystemPath(%q) unexpectedly succeeded", path)
		}
	}
}

func TestSchemaIdentitySurvivesLiveDataWritesAndDetectsMigrations(t *testing.T) {
	path := filepath.Join(t.TempDir(), "live.db")
	db, err := openDatabase(path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	exec := func(statement string) {
		t.Helper()
		if _, err := db.Exec(statement); err != nil {
			t.Fatal(err)
		}
	}
	identity := func() string {
		t.Helper()
		id, err := schemaID(path)
		if err != nil || len(id) != 64 {
			t.Fatalf("schema identity %q, error %v", id, err)
		}
		return id
	}
	exec("PRAGMA journal_mode = WAL")
	exec("CREATE TABLE devices (id INTEGER PRIMARY KEY)")
	previous := identity()
	exec("INSERT INTO devices VALUES (1)")
	if identity() != previous {
		t.Fatal("a data write changed the schema identity")
	}
	for _, statement := range []string{"PRAGMA user_version = 2", "PRAGMA application_id = 17", "ALTER TABLE devices ADD COLUMN name TEXT"} {
		exec(statement)
		current := identity()
		if current == previous {
			t.Fatalf("missed migration %q", statement)
		}
		previous = current
	}
}
