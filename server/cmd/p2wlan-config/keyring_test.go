package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func clearSignerEnvironment(t *testing.T) {
	t.Helper()
	for _, name := range []string{"RELAY_TICKET_SIGNER_JSON", "RELAY_TICKET_SIGNER_KEY_FILE", "RELAY_TICKET_SIGNER_KID", "RELAY_TICKET_SIGNER_PREV_KEY_FILE", "RELAY_TICKET_SIGNER_PREV_KID", "RELAY_TICKET_TTL"} {
		t.Setenv(name, "")
	}
}

func TestPrintRelayKeyringUsesExistingControlSigner(t *testing.T) {
	for _, mode := range []string{"inline", "pem"} {
		t.Run(mode, func(t *testing.T) {
			clearSignerEnvironment(t)
			publicKeys := map[string]string{}
			privateSeeds := []string{}
			signerConfig := map[string]map[string]string{}
			for _, item := range []struct{ role, kid, fileEnv, kidEnv string }{
				{"active", "current", "RELAY_TICKET_SIGNER_KEY_FILE", "RELAY_TICKET_SIGNER_KID"},
				{"previous", "retiring", "RELAY_TICKET_SIGNER_PREV_KEY_FILE", "RELAY_TICKET_SIGNER_PREV_KID"},
			} {
				public, private, err := ed25519.GenerateKey(rand.Reader)
				if err != nil {
					t.Fatal(err)
				}
				seed := hex.EncodeToString(private.Seed())
				privateSeeds = append(privateSeeds, seed)
				publicKeys[item.kid] = hex.EncodeToString(public)
				signerConfig[item.role] = map[string]string{"kid": item.kid, "private_key": seed}
				if mode == "pem" {
					der, err := x509.MarshalPKCS8PrivateKey(private)
					if err != nil {
						t.Fatal(err)
					}
					keyFile := filepath.Join(t.TempDir(), "signer.pem")
					if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0600); err != nil {
						t.Fatal(err)
					}
					t.Setenv(item.fileEnv, keyFile)
					t.Setenv(item.kidEnv, item.kid)
				}
			}
			raw, err := json.Marshal(signerConfig)
			if err != nil {
				t.Fatal(err)
			}
			if mode == "pem" {
				// A configured PEM signer takes precedence over inline values,
				// exactly as it does in the running Control service.
				raw = []byte("invalid ignored inline signer")
			}
			t.Setenv("RELAY_TICKET_SIGNER_JSON", string(raw))
			var output bytes.Buffer
			if err := printRelayKeyring(&output); err != nil {
				t.Fatal(err)
			}
			var keys map[string]string
			if err := json.Unmarshal(output.Bytes(), &keys); err != nil {
				t.Fatal(err)
			}
			if len(keys) != len(publicKeys) {
				t.Fatal("key rotation coverage differs from the Control signer")
			}
			for kid, want := range publicKeys {
				if keys[kid] != want {
					t.Fatalf("wrong verification key for %s", kid)
				}
			}
			for _, seed := range privateSeeds {
				if strings.Contains(output.String(), seed) {
					t.Fatal("private signing seed appeared in output")
				}
			}
		})
	}
}

func TestPrintRelayKeyringRejectsAbsentOrInvalidSignerWithoutOutput(t *testing.T) {
	for _, raw := range []string{"", "{", `{"active":{"kid":"current","private_key":"invalid"}}`} {
		t.Run(raw, func(t *testing.T) {
			clearSignerEnvironment(t)
			t.Setenv("RELAY_TICKET_SIGNER_JSON", raw)
			var output bytes.Buffer
			if err := printRelayKeyring(&output); err == nil {
				t.Fatal("invalid or missing signer accepted")
			}
			if output.Len() != 0 {
				t.Fatal("failed export produced a partial keyring")
			}
		})
	}
}

type failingKeyringWriter struct{ err error }

func (w failingKeyringWriter) Write([]byte) (int, error) { return 0, w.err }

func TestPrintRelayKeyringReportsOutputFailure(t *testing.T) {
	clearSignerEnvironment(t)
	t.Setenv("RELAY_TICKET_SIGNER_JSON", `{"active":{"kid":"test","private_key":"`+strings.Repeat("01", 32)+`"}}`)
	want := errors.New("output unavailable")
	if err := printRelayKeyring(failingKeyringWriter{want}); !errors.Is(err, want) {
		t.Fatalf("output failure not preserved: %v", err)
	}
}
