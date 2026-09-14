package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func generatedEnvironment(t *testing.T, path string) map[string]string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	values := make(map[string]string)
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			t.Fatal("invalid generated environment entry")
		}
		values[key] = value
	}
	return values
}

func TestDevelopmentRelayAddressMatchesListenerAndPublishedHost(t *testing.T) {
	for _, mode := range []string{"native", "docker"} {
		for _, host := range []string{"localhost", "127.0.0.1", "127.0.0.2", "::1"} {
			t.Run(mode+"/"+host, func(t *testing.T) {
				output := filepath.Join(t.TempDir(), "config")
				o := options{output: output, mode: mode, endpoint: "tls://" + net.JoinHostPort(host, "18081"), dev: true, controlPort: 18080, metricsPort: 18082}
				if err := generate(o); err != nil {
					t.Fatal(err)
				}
				bindHost := host
				if host == "localhost" {
					bindHost = "127.0.0.1"
				}
				compose := generatedEnvironment(t, filepath.Join(output, "compose.env"))
				if got := compose["RELAY_PUBLISH_HOST"]; got != bindHost {
					t.Errorf("advertised %s but publish host is %s; want %s", host, got, bindHost)
				}
				if mode == "docker" {
					bindHost = ""
				}
				relay := generatedEnvironment(t, filepath.Join(output, "relay.env"))
				if got, want := relay["RELAY_BIND"], net.JoinHostPort(bindHost, "18081"); got != want {
					t.Errorf("advertised %s but bind is %s; want %s", host, got, want)
				}
				if relay["RELAY_ALLOW_INSECURE_PLAINTEXT"] != "false" || relay["RELAY_REQUIRE_AUTH"] != "true" {
					t.Fatal("loopback selection changed authentication requirements")
				}
			})
		}
	}
}

func TestRejectEndpointWithEmptyQueryOrFragment(t *testing.T) {
	for _, suffix := range []string{"?", "#", "?#"} {
		t.Run(suffix, func(t *testing.T) {
			output := filepath.Join(t.TempDir(), "config")
			err := generate(options{output: output, mode: "native", endpoint: "tls://localhost:18081" + suffix, dev: true, controlPort: 18080, metricsPort: 18082})
			if err == nil {
				t.Fatal("accepted endpoint containing an unsupported URL component")
			}
			if _, err := os.Stat(output); !os.IsNotExist(err) {
				t.Fatal("invalid endpoint left deployment files")
			}
		})
	}
}

func TestSuppliedCertificateMustPermitServerAuthentication(t *testing.T) {
	cases := []struct {
		name    string
		usage   []x509.ExtKeyUsage
		unknown []asn1.ObjectIdentifier
		allowed bool
	}{
		{name: "server", usage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, allowed: true},
		{name: "client-only", usage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}},
		{name: "any", usage: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}, allowed: true},
		{name: "unrestricted", allowed: true},
		{name: "mixed", usage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth}, allowed: true},
		{name: "unknown-only", unknown: []asn1.ObjectIdentifier{{1, 2, 3, 4, 5}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			pub, key, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			now := time.Now()
			template := &x509.Certificate{
				SerialNumber:       big.NewInt(1),
				Subject:            pkix.Name{CommonName: "selfhost usage regression"},
				DNSNames:           []string{"relay.example.test"},
				NotBefore:          now.Add(-time.Minute),
				NotAfter:           now.Add(time.Hour),
				KeyUsage:           x509.KeyUsageDigitalSignature,
				ExtKeyUsage:        tc.usage,
				UnknownExtKeyUsage: tc.unknown,
			}
			der, err := x509.CreateCertificate(rand.Reader, template, template, pub, key)
			if err != nil {
				t.Fatal(err)
			}
			leaf, err := x509.ParseCertificate(der)
			if err != nil {
				t.Fatal(err)
			}
			roots := x509.NewCertPool()
			roots.AddCert(leaf)
			_, verifyErr := leaf.Verify(x509.VerifyOptions{Roots: roots, DNSName: "relay.example.test", KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}})
			if (verifyErr == nil) != tc.allowed {
				t.Fatalf("TLS verifier disagrees with certificate fixture: %v", verifyErr)
			}
			pkcs, err := x509.MarshalPKCS8PrivateKey(key)
			if err != nil {
				t.Fatal(err)
			}
			certPath, keyPath := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
			if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs}), 0600); err != nil {
				t.Fatal(err)
			}
			output := filepath.Join(dir, "config")
			err = generate(options{output: output, mode: "native", endpoint: "tls://relay.example.test:18081", cert: certPath, key: keyPath, controlPort: 18080, metricsPort: 18082})
			if !tc.allowed {
				if err == nil {
					t.Fatal("generated a deployment whose certificate cannot authenticate a TLS server")
				}
				if _, err := os.Stat(output); !os.IsNotExist(err) {
					t.Fatal("invalid certificate left deployment files")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			compose := generatedEnvironment(t, filepath.Join(output, "compose.env"))
			if compose["RELAY_PUBLISH_HOST"] != "127.0.0.1" {
				t.Fatal("production deployment must require explicit public port publication")
			}
		})
	}
}
