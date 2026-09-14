// p2wlan-config creates a complete matching control/relay configuration without
// printing secrets or overwriting an existing deployment.
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"math/big"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/yhan-sun/p2wlan/server/internal/privatefile"
)

type options struct {
	output, mode, endpoint, cert, key string
	dev                               bool
	controlPort, metricsPort          int
}

func main() {
	var o options
	flag.StringVar(&o.output, "output", "", "New private configuration directory (must not exist)")
	flag.StringVar(&o.mode, "mode", "native", "native or docker")
	flag.StringVar(&o.endpoint, "relay-endpoint", "tls://localhost:18081", "Public TLS relay endpoint, not a container service name")
	flag.StringVar(&o.cert, "tls-cert", "", "Existing TLS certificate chain PEM")
	flag.StringVar(&o.key, "tls-key", "", "Matching TLS private key PEM")
	flag.BoolVar(&o.dev, "dev-localhost", false, "Generate a loopback-only test certificate; not trusted by deployed clients")
	flag.IntVar(&o.controlPort, "control-port", 18080, "Control port")
	flag.IntVar(&o.metricsPort, "metrics-port", 18082, "Loopback relay readiness port")
	flag.Parse()
	if err := generate(o); err != nil {
		fmt.Fprintln(os.Stderr, "p2wlan-config:", err)
		os.Exit(1)
	}
	fmt.Println("Created configuration; secrets were written to files, not stdout. Configure trusted HTTPS for control before public use.")
}

func secret() (string, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}

func generate(o options) (err error) {
	if o.output == "" {
		return errors.New("--output is required")
	}
	if o.mode != "native" && o.mode != "docker" {
		return errors.New("--mode must be native or docker")
	}
	if o.controlPort < 1 || o.controlPort > 65535 || o.metricsPort < 1 || o.metricsPort > 65535 {
		return errors.New("ports must be between 1 and 65535")
	}
	u, err := url.Parse(o.endpoint)
	if err != nil || u.Scheme != "tls" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || u.ForceQuery || strings.Contains(o.endpoint, "#") {
		return errors.New("--relay-endpoint must be tls://host:port without credentials, path, query or fragment")
	}
	host, port, err := net.SplitHostPort(u.Host)
	if err != nil || host == "" || strings.ContainsAny(host, " \\?#@\r\n\t") {
		return errors.New("relay endpoint requires host and numeric port")
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return errors.New("invalid relay endpoint port")
	}
	if n == o.controlPort || n == o.metricsPort || o.controlPort == o.metricsPort {
		return errors.New("control, relay and metrics ports must differ")
	}
	if ip := net.ParseIP(host); ip != nil && ip.IsUnspecified() {
		return errors.New("relay endpoint cannot advertise a wildcard address")
	}
	if o.dev && (host != "localhost" && !net.ParseIP(host).IsLoopback()) {
		return errors.New("--dev-localhost requires a loopback relay endpoint")
	}
	if o.dev && (o.cert != "" || o.key != "") {
		return errors.New("choose supplied TLS files or --dev-localhost, not both")
	}
	var certPEM, keyPEM []byte
	if o.dev {
		certPEM, keyPEM, err = localCertificate(host)
	} else {
		if o.cert == "" || o.key == "" {
			return errors.New("--tls-cert and --tls-key are required; use --dev-localhost only for isolated tests")
		}
		certPEM, err = os.ReadFile(o.cert)
		if err == nil {
			keyPEM, err = os.ReadFile(o.key)
		}
	}
	if err != nil {
		return fmt.Errorf("load TLS material: %w", err)
	}
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return errors.New("TLS certificate and private key are invalid or do not match")
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return errors.New("invalid TLS certificate")
	}
	if err = leaf.VerifyHostname(host); err != nil {
		return errors.New("TLS certificate SAN does not cover the advertised relay host")
	}
	if now := time.Now(); now.Before(leaf.NotBefore) || !now.Before(leaf.NotAfter) {
		return errors.New("TLS certificate is not currently valid")
	}
	if !permitsServerAuthentication(leaf) {
		return errors.New("TLS certificate extended key usage does not permit server authentication")
	}
	if strings.ContainsAny(o.output, "\r\n") {
		return errors.New("output path must not contain newlines")
	}
	out, err := filepath.Abs(o.output)
	if err != nil {
		return err
	}
	// Mkdir is exclusive: rerunning must not rotate active deployment secrets.
	if err = os.Mkdir(out, 0700); err != nil {
		return fmt.Errorf("create new configuration directory (existing files are never overwritten): %w", err)
	}
	defer func() {
		if err != nil {
			_ = os.RemoveAll(out)
		}
	}()
	jwtSecret, err := secret()
	if err != nil {
		return err
	}
	feedSecret, err := secret()
	if err != nil {
		return err
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	kid := "selfhost-1"
	signer, _ := json.Marshal(map[string]any{"active": map[string]string{"kid": kid, "private_key": hex.EncodeToString(priv.Seed())}})
	keyring, _ := json.Marshal(map[string]string{kid: hex.EncodeToString(pub)})
	catalog, _ := json.Marshal([]map[string]string{{"region": "selfhost", "audience": "selfhost-relay-1", "endpoint": o.endpoint}})
	dataDir := filepath.Join(out, "data")
	if err = os.Mkdir(dataDir, 0700); err != nil {
		return err
	}
	runtimeDir, runtimeData := filepath.ToSlash(out), filepath.ToSlash(dataDir)
	controlHost, feedHost := "127.0.0.1", "127.0.0.1"
	relayHost, publishHost := "", "127.0.0.1"
	if o.dev {
		if ip := net.ParseIP(host); ip != nil {
			publishHost = ip.String()
		}
		relayHost = publishHost
	}
	if o.mode == "docker" {
		runtimeDir = "/etc/p2wlan"
		runtimeData = "/data"
		controlHost = ""
		feedHost = "control"
		relayHost = ""
	}
	control := fmt.Sprintf("CONTROL_BIND=%s\nPORT=%d\nDB_PATH=%s/p2pnet.db\nLOG_UPLOAD_DIR=%s/log-uploads\nJWT_SECRET=%s\nRELAY_CATALOG_JSON=%s\nRELAY_TICKET_SIGNER_JSON=%s\nRELAY_TICKET_TTL=5m\nRELAY_REVOCATION_FEED_TOKEN=%s\n", net.JoinHostPort(controlHost, strconv.Itoa(o.controlPort)), o.controlPort, runtimeData, runtimeData, jwtSecret, catalog, signer, feedSecret)
	relay := fmt.Sprintf("RELAY_BIND=%s\nRELAY_REQUIRE_AUTH=true\nRELAY_ALLOW_LEGACY_UNAUTH=false\nRELAY_ALLOW_INSECURE_PLAINTEXT=false\nRELAY_TLS_CERT=%s/tls.crt\nRELAY_TLS_KEY=%s/tls.key\nRELAY_TICKET_KEYRING_JSON=%s\nRELAY_AUDIENCE=selfhost-relay-1\nRELAY_REGION=selfhost\nRELAY_REVOCATION_FEED_URL=http://%s/api/v1/relay/revocations\nRELAY_REVOCATION_FEED_TOKEN=%s\nRELAY_REVOCATION_POLL_INTERVAL=5s\nRELAY_METRICS_BIND=127.0.0.1:%d\n", net.JoinHostPort(relayHost, port), runtimeDir, runtimeDir, keyring, net.JoinHostPort(feedHost, strconv.Itoa(o.controlPort)), feedSecret, o.metricsPort)
	uid, gid := os.Getuid(), os.Getgid()
	if uid <= 0 {
		uid = 10001
	}
	if gid <= 0 {
		gid = 10001
	}
	compose := fmt.Sprintf("P2WLAN_UID=%d\nP2WLAN_GID=%d\nCONTROL_PORT=%d\nRELAY_PORT=%d\nMETRICS_PORT=%d\nRELAY_PUBLISH_HOST=%s\n", uid, gid, o.controlPort, n, o.metricsPort, publishHost)
	for name, data := range map[string][]byte{"control.env": []byte(control), "relay.env": []byte(relay), "compose.env": []byte(compose), "tls.crt": certPEM, "tls.key": keyPEM} {
		if err = privatefile.WriteNew(filepath.Join(out, name), data); err != nil {
			return err
		}
	}
	// Docker runs unprivileged, including when an administrator generated files.
	if o.mode == "docker" && os.Getuid() == 0 {
		if err = filepath.Walk(out, func(path string, _ os.FileInfo, e error) error {
			if e != nil {
				return e
			}
			return os.Chown(path, uid, gid)
		}); err != nil {
			return err
		}
	}
	return nil
}

func permitsServerAuthentication(cert *x509.Certificate) bool {
	if len(cert.ExtKeyUsage) == 0 && len(cert.UnknownExtKeyUsage) == 0 {
		return true
	}
	for _, usage := range cert.ExtKeyUsage {
		if usage == x509.ExtKeyUsageServerAuth || usage == x509.ExtKeyUsageAny {
			return true
		}
	}
	return false
}

func localCertificate(host string) ([]byte, []byte, error) {
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, err
	}
	now := time.Now()
	template := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "P2WLAN local test only"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(24 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, DNSNames: []string{"localhost"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")}}
	if ip := net.ParseIP(host); ip != nil {
		template.IPAddresses = append(template.IPAddresses, ip)
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, pub, key)
	if err != nil {
		return nil, nil, err
	}
	pkcs, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs}), nil
}
