package main

import (
	"crypto/ed25519"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/yhan-sun/p2wlan/server/internal/privatefile"
)

func envFile(t *testing.T, path string) map[string]string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]string{}
	for _, line := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			t.Fatal("invalid env entry")
		}
		out[key] = value
	}
	return out
}
func TestGenerateMatchingSecureConfiguration(t *testing.T) {
	for _, mode := range []string{"native", "docker"} {
		t.Run(mode, func(t *testing.T) {
			out := filepath.Join(t.TempDir(), "config")
			o := options{output: out, mode: mode, endpoint: "tls://localhost:18081", dev: true, controlPort: 18080, metricsPort: 18082}
			if err := generate(o); err != nil {
				t.Fatal(err)
			}
			for _, name := range []string{"control.env", "relay.env", "tls.key"} {
				if err := privatefile.Verify(filepath.Join(out, name)); err != nil {
					t.Fatalf("generated %s is not private: %v", name, err)
				}
			}
			c, r := envFile(t, filepath.Join(out, "control.env")), envFile(t, filepath.Join(out, "relay.env"))
			if len(c["JWT_SECRET"]) != 64 || len(c["RELAY_REVOCATION_FEED_TOKEN"]) != 64 || c["RELAY_REVOCATION_FEED_TOKEN"] != r["RELAY_REVOCATION_FEED_TOKEN"] {
				t.Fatal("credentials missing or mismatched")
			}

			var raw map[string]map[string]string
			var keys map[string]string
			if err := json.Unmarshal([]byte(c["RELAY_TICKET_SIGNER_JSON"]), &raw); err != nil {
				t.Fatal(err)
			}
			if err := json.Unmarshal([]byte(r["RELAY_TICKET_KEYRING_JSON"]), &keys); err != nil {
				t.Fatal(err)
			}
			seed, _ := hex.DecodeString(raw["active"]["private_key"])
			public := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
			if hex.EncodeToString(public) != keys[raw["active"]["kid"]] {
				t.Fatal("signing key and verifier mismatch")
			}
			if _, err := tls.LoadX509KeyPair(filepath.Join(out, "tls.crt"), filepath.Join(out, "tls.key")); err != nil {
				t.Fatal(err)
			}
			if r["RELAY_ALLOW_INSECURE_PLAINTEXT"] != "false" || r["RELAY_ALLOW_LEGACY_UNAUTH"] != "false" {
				t.Fatal("unsafe defaults")
			}
			if err := generate(o); err == nil {
				t.Fatal("existing deployment silently rotated")
			}
			if again := envFile(t, filepath.Join(out, "control.env")); again["JWT_SECRET"] != c["JWT_SECRET"] {
				t.Fatal("secrets overwritten")
			}
		})
	}
}
func TestRejectPublicDevelopmentAndMalformedConfiguration(t *testing.T) {
	for _, ep := range []string{"tls://relay.example.com:18081", "tls://localhost:0", "tls://localhost:65536", "tls://user:pass@localhost:18081", "tcp://localhost:18081", "tls://localhost:18081/a", "tls://localhost:18081?q=x"} {
		out := filepath.Join(t.TempDir(), "config")
		if err := generate(options{output: out, mode: "native", endpoint: ep, dev: true, controlPort: 18080, metricsPort: 18082}); err == nil {
			t.Errorf("accepted %s", ep)
		}
		if _, err := os.Stat(out); !os.IsNotExist(err) {
			t.Fatal("invalid config left deployment files")
		}
	}
}
