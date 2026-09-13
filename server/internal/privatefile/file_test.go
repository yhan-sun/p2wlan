package privatefile

import (
	"os"
	"path/filepath"
	"testing"
)

func TestPrivateFileBeforeWriteAndAfterRename(t *testing.T) {
	directory := t.TempDir()
	file, err := CreateTemp(directory)
	if err != nil {
		t.Fatal(err)
	}
	name := file.Name()
	defer file.Close()
	if err := Verify(name); err != nil {
		t.Fatalf("empty file must already be private: %v", err)
	}
	if _, err := file.WriteString("private fixture"); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	final := filepath.Join(directory, "stored.json.gz")
	if err := os.Rename(name, final); err != nil {
		t.Fatal(err)
	}
	if err := Verify(final); err != nil {
		t.Fatalf("renamed file lost privacy: %v", err)
	}
}

func TestWriteNewNeverOverwritesExistingSecret(t *testing.T) {
	name := filepath.Join(t.TempDir(), "secret.env")
	if err := WriteNew(name, []byte("original")); err != nil {
		t.Fatal(err)
	}
	if err := WriteNew(name, []byte("replacement")); !os.IsExist(err) {
		t.Fatalf("expected exists: %v", err)
	}
	content, err := os.ReadFile(name)
	if err != nil || string(content) != "original" {
		t.Fatalf("existing secret changed: %q %v", content, err)
	}
	if err := Verify(name); err != nil {
		t.Fatal(err)
	}
}
