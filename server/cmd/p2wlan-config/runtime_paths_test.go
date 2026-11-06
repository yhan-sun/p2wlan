package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNativeRuntimeDirectoriesDoNotChangeGenerationDestination(t *testing.T) {
	for _, tc := range []struct {
		name       string
		config, db bool
	}{
		{name: "defaults"},
		{name: "config-only", config: true},
		{name: "data-only", db: true},
		{name: "config-and-data", config: true, db: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			parent := t.TempDir()
			out := filepath.Join(parent, "staged-config")
			finalConfig := filepath.Join(parent, "installed-config")
			finalData := filepath.Join(parent, "installed-data")
			o := options{output: out, mode: "native", endpoint: "tls://localhost:18081", dev: true, controlPort: 18080, metricsPort: 18082}
			wantConfig, wantData := out, filepath.Join(out, "data")
			if tc.config {
				o.configDir, wantConfig = finalConfig, finalConfig
			}
			if tc.db {
				o.dataDir, wantData = finalData, finalData
			}
			if err := generate(o); err != nil {
				t.Fatal(err)
			}
			control := envFile(t, filepath.Join(out, "control.env"))
			relay := envFile(t, filepath.Join(out, "relay.env"))
			for key, want := range map[string]string{
				"DB_PATH":        filepath.ToSlash(wantData) + "/p2pnet.db",
				"LOG_UPLOAD_DIR": filepath.ToSlash(wantData) + "/log-uploads",
			} {
				if got := control[key]; got != want {
					t.Errorf("%s=%q; want %q", key, got, want)
				}
			}
			for key, want := range map[string]string{
				"RELAY_TLS_CERT": filepath.ToSlash(wantConfig) + "/tls.crt",
				"RELAY_TLS_KEY":  filepath.ToSlash(wantConfig) + "/tls.key",
			} {
				if got := relay[key]; got != want {
					t.Errorf("%s=%q; want %q", key, got, want)
				}
			}
			for _, name := range []string{"data", "control.env", "relay.env", "tls.crt", "tls.key"} {
				if _, err := os.Stat(filepath.Join(out, name)); err != nil {
					t.Errorf("staged %s is missing: %v", name, err)
				}
			}
			for _, path := range []string{finalConfig, finalData} {
				if _, err := os.Stat(path); !os.IsNotExist(err) {
					t.Errorf("generator created an external runtime directory: %s (%v)", path, err)
				}
			}
		})
	}
}

func TestDockerRejectsNativeRuntimeDirectories(t *testing.T) {
	for _, field := range []string{"config-dir", "data-dir"} {
		t.Run(field, func(t *testing.T) {
			parent := t.TempDir()
			out := filepath.Join(parent, "config")
			o := options{output: out, mode: "docker", endpoint: "tls://localhost:18081", dev: true, controlPort: 18080, metricsPort: 18082}
			if field == "config-dir" {
				o.configDir = filepath.Join(parent, "installed-config")
			} else {
				o.dataDir = filepath.Join(parent, "installed-data")
			}
			if err := generate(o); err == nil || !strings.Contains(err.Error(), "only supported in native mode") {
				t.Fatalf("docker accepted a native runtime directory: %v", err)
			}
			if _, err := os.Stat(out); !os.IsNotExist(err) {
				t.Fatalf("invalid configuration left staged files: %v", err)
			}
		})
	}
}

func TestRejectUnsafeExplicitRuntimeDirectoriesBeforeWritingFiles(t *testing.T) {
	parent := t.TempDir()
	for _, field := range []string{"config-dir", "data-dir"} {
		for _, suffix := range []string{"relative", "with space", "tab\there", "newline\nhere", "quote\"here", "quote'here", "$value", "%value", "null\x00here"} {
			t.Run(field+"/"+suffix, func(t *testing.T) {
				out := filepath.Join(t.TempDir(), "config")
				path := filepath.Join(parent, suffix)
				if suffix == "relative" {
					path = suffix
				}
				o := options{output: out, mode: "native", endpoint: "tls://localhost:18081", dev: true, controlPort: 18080, metricsPort: 18082}
				if field == "config-dir" {
					o.configDir = path
				} else {
					o.dataDir = path
				}
				if err := generate(o); err == nil {
					t.Fatal("accepted an unsafe runtime path")
				}
				if _, err := os.Stat(out); !os.IsNotExist(err) {
					t.Fatalf("unsafe runtime path left staged files: %v", err)
				}
			})
		}
	}
}
