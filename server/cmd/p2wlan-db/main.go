// Command p2wlan-db provides the database operation used by the server
// manager. VACUUM INTO creates a consistent SQLite snapshot while the
// control-plane database remains online.
package main

import (
	"crypto/sha256"
	"database/sql"
	"errors"
	"flag"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	_ "modernc.org/sqlite"
)

func main() {
	source := flag.String("source", "", "SQLite database to snapshot")
	output := flag.String("output", "", "snapshot file to create")
	verify := flag.String("verify", "", "SQLite database snapshot to verify")
	schema := flag.String("schema-id", "", "read the SQLite schema identity for release recovery")
	flag.Parse()

	var err error
	switch {
	case *schema != "" && *source == "" && *output == "" && *verify == "":
		var identity string
		identity, err = schemaID(*schema)
		if err == nil {
			fmt.Println(identity)
		}
	case *verify != "" && *source == "" && *output == "" && *schema == "":
		err = verifyDatabase(*verify)
	case *source != "" && *output != "" && *verify == "" && *schema == "":
		err = backupDatabase(*source, *output)
	default:
		err = errors.New("use --source FILE --output FILE, --verify FILE or --schema-id FILE")
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "p2wlan-db: %v\n", err)
		os.Exit(1)
	}
}

// Read all compatibility fields from one SQLite read transaction, including WAL.
func schemaID(path string) (string, error) {
	absolute, err := filesystemPath(path)
	if err != nil {
		return "", err
	}
	db, err := sql.Open("sqlite", dsn(absolute)+"?mode=ro")
	if err != nil {
		return "", err
	}
	defer db.Close()
	tx, err := db.Begin()
	if err != nil {
		return "", err
	}
	defer tx.Rollback()
	var version, application int64
	if err := tx.QueryRow("PRAGMA user_version").Scan(&version); err != nil {
		return "", err
	}
	if err := tx.QueryRow("PRAGMA application_id").Scan(&application); err != nil {
		return "", err
	}
	rows, err := tx.Query("SELECT type, name, tbl_name, coalesce(sql,'') FROM sqlite_schema ORDER BY type, name")
	if err != nil {
		return "", err
	}
	defer rows.Close()
	hash := sha256.New()
	fmt.Fprintf(hash, "%d %d\n", version, application)
	for rows.Next() {
		var kind, name, table, definition string
		if err := rows.Scan(&kind, &name, &table, &definition); err != nil {
			return "", err
		}
		fmt.Fprintf(hash, "%q %q %q %q\n", kind, name, table, definition)
	}
	if err := rows.Err(); err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", hash.Sum(nil)), nil
}

func filesystemPath(path string) (string, error) {
	if path == "" || strings.HasPrefix(path, "file:") || path == ":memory:" {
		return "", fmt.Errorf("database path must be a filesystem file")
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return "", fmt.Errorf("resolve database path: %w", err)
	}
	info, err := os.Stat(absolute)
	if err != nil {
		return "", fmt.Errorf("stat database %q: %w", absolute, err)
	}
	if !info.Mode().IsRegular() {
		return "", fmt.Errorf("database path %q is not a regular file", absolute)
	}
	return absolute, nil
}

func dsn(path string) string {
	slashed := filepath.ToSlash(path)
	if !strings.HasPrefix(slashed, "/") {
		slashed = "/" + slashed
	}
	return (&url.URL{Scheme: "file", Path: slashed}).String()
}

func openDatabase(path string) (*sql.DB, error) {
	db, err := sql.Open("sqlite", dsn(path))
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}
	db.SetMaxOpenConns(1)
	if _, err := db.Exec("PRAGMA busy_timeout = 5000"); err != nil {
		db.Close()
		return nil, fmt.Errorf("set busy timeout: %w", err)
	}
	return db, nil
}

func backupDatabase(source, output string) error {
	sourcePath, err := filesystemPath(source)
	if err != nil {
		return err
	}
	outputPath, err := filepath.Abs(output)
	if err != nil {
		return fmt.Errorf("resolve output path: %w", err)
	}
	if sourcePath == outputPath {
		return errors.New("source and output must be different files")
	}
	if _, err := os.Stat(outputPath); err == nil {
		return fmt.Errorf("output already exists: %s", outputPath)
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("inspect output: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(outputPath), 0700); err != nil {
		return fmt.Errorf("prepare output directory: %w", err)
	}

	db, err := openDatabase(sourcePath)
	if err != nil {
		return err
	}
	defer db.Close()
	quoted := strings.ReplaceAll(outputPath, "'", "''")
	if _, err := db.Exec("VACUUM INTO '" + quoted + "'"); err != nil {
		return fmt.Errorf("create consistent SQLite snapshot: %w", err)
	}
	if err := os.Chmod(outputPath, 0600); err != nil {
		return fmt.Errorf("protect snapshot: %w", err)
	}
	return verifyDatabase(outputPath)
}

func verifyDatabase(path string) error {
	absolute, err := filesystemPath(path)
	if err != nil {
		return err
	}
	db, err := openDatabase(absolute)
	if err != nil {
		return err
	}
	defer db.Close()

	var integrity string
	if err := db.QueryRow("PRAGMA integrity_check").Scan(&integrity); err != nil {
		return fmt.Errorf("run integrity_check: %w", err)
	}
	if integrity != "ok" {
		return fmt.Errorf("SQLite integrity_check returned %q", integrity)
	}
	var userVersion int
	if err := db.QueryRow("PRAGMA user_version").Scan(&userVersion); err != nil {
		return fmt.Errorf("read user_version: %w", err)
	}
	fmt.Printf("integrity_check=%s\nuser_version=%d\n", integrity, userVersion)
	return nil
}
