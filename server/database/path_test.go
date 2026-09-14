package database

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestDatabaseNestedPathAndPersistence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "new data", "子目录", "control.db")
	db, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec("CREATE TABLE path_test(v TEXT)"); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec("INSERT INTO path_test VALUES ('retained')"); err != nil {
		t.Fatal(err)
	}
	if err = db.Close(); err != nil {
		t.Fatal(err)
	}
	db, err = New(path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var value string
	if err = db.QueryRow("SELECT v FROM path_test").Scan(&value); err != nil || value != "retained" {
		t.Fatalf("persistence: %q %v", value, err)
	}
}

func TestDatabasePathErrorsAreActionable(t *testing.T) {
	root := t.TempDir()
	if _, err := New(root); err == nil || !strings.Contains(err.Error(), "not a regular file") {
		t.Fatalf("directory: %v", err)
	}
	f := filepath.Join(root, "file")
	if err := os.WriteFile(f, []byte("do not overwrite"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := New(filepath.Join(f, "db")); err == nil || !strings.Contains(err.Error(), "parent directory") {
		t.Fatalf("parent file: %v", err)
	}
	if _, err := New(""); err == nil {
		t.Fatal("empty path must fail")
	}
	data, _ := os.ReadFile(f)
	if string(data) != "do not overwrite" {
		t.Fatal("existing file was changed")
	}
}

func TestDatabaseMemoryURIStillWorks(t *testing.T) {
	for _, p := range []string{":memory:", "file::memory:?cache=shared"} {
		db, err := New(p)
		if err != nil {
			t.Fatal(err)
		}
		db.Close()
	}
}

func TestDatabaseLiteralFilenameIsNotAConnectionQuery(t *testing.T) {
	names := []string{"data #1.db"}
	if runtime.GOOS != "windows" {
		names = append(names, "data?draft#1.db")
	}
	for _, name := range names {
		path := filepath.Join(t.TempDir(), name)
		db, err := New(path)
		if err != nil {
			t.Fatal(err)
		}
		var seq int
		var schema, actual string
		err = db.QueryRow("PRAGMA database_list").Scan(&seq, &schema, &actual)
		db.Close()
		if err != nil || filepath.Clean(actual) != filepath.Clean(path) {
			t.Fatalf("database filename changed: got %q want %q err=%v", actual, path, err)
		}
	}
}
