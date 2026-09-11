package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

func TestSecurityBooleanEnvironmentFailsClosed(t *testing.T) {
	for _, key := range []string{"RELAY_REQUIRE_AUTH", "RELAY_ALLOW_LEGACY_UNAUTH", "RELAY_ALLOW_INSECURE_PLAINTEXT", "RELAY_METRICS_ALLOW_PUBLIC", "RELAY_DEBUG_FRAMES"} {
		t.Run(key, func(t *testing.T) {
			for _, value := range []string{"true", "TRUE", "1", " true "} {
				t.Setenv(key, value)
				parsed, err := getBoolEnv(key, false)
				if err != nil || !parsed {
					t.Fatalf("%q should enable %s: %v", value, key, err)
				}
			}
			for _, value := range []string{"false", "FALSE", "0"} {
				t.Setenv(key, value)
				parsed, err := getBoolEnv(key, true)
				if err != nil || parsed {
					t.Fatalf("%q should disable %s", value, key)
				}
			}
			for _, value := range []string{"", "yes", "typo"} {
				t.Setenv(key, value)
				if _, err := parseConfig([]string{"-require-auth=false"}); err == nil {
					t.Fatalf("invalid %s=%q did not fail startup", key, value)
				}
			}
		})
	}
}

func TestTLSOverloadDoesNotHandshakeOnAcceptLoop(t *testing.T) {
	private, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cert := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "localhost"}, DNSNames: []string{"localhost"}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, &private.PublicKey, private)
	if err != nil {
		t.Fatal(err)
	}
	key, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	config := testConfig()
	config.MaxConnections = 1
	config.TLSCertChainPath, config.TLSPrivateKeyPath = filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	if err := os.WriteFile(config.TLSCertChainPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(config.TLSPrivateKeyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key}), 0600); err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	server, addr, cleanup := startTestServerWithInstance(t, config)
	defer cleanup()
	dial := func() *tls.Conn {
		t.Helper()
		c, err := tls.DialWithDialer(&net.Dialer{Timeout: time.Second}, "tcp", addr, &tls.Config{RootCAs: roots, ServerName: "localhost", MinVersion: tls.VersionTLS13})
		if err != nil {
			t.Fatal(err)
		}
		c.SetDeadline(time.Now().Add(2 * time.Second))
		if err := writeFull(c, makeFrame(msgRegister, []byte("tls-node"))); err != nil {
			t.Fatal(err)
		}
		typ, _ := readTestFrame(t, c)
		if typ != msgRegistered {
			t.Fatal("TLS registration failed")
		}
		return c
	}
	first := dial()
	defer first.Close()
	blocked, err := net.DialTimeout("tcp", addr, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer blocked.Close()
	blocked.SetReadDeadline(time.Now().Add(400 * time.Millisecond))
	buf := make([]byte, 1)
	if n, err := blocked.Read(buf); n != 0 || err == nil {
		t.Fatal("overload must close without application/TLS bytes")
	} else if e, ok := err.(net.Error); ok && e.Timeout() {
		t.Fatal("overload connection waited for TLS handshake")
	}
	first.Close()
	deadline := time.Now().Add(time.Second)
	for server.Stats().ActiveConnections != 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if server.Stats().ActiveConnections != 0 {
		t.Fatal("old connection was not retired")
	}
	recovered := dial()
	recovered.Close()
}

func TestRelayBackpressurePreservesOtherSourcesAndControl(t *testing.T) {
	h := newHub()
	local, remote := net.Pipe()
	defer local.Close()
	defer remote.Close()
	destination := &peer{conn: local, send: make(chan []byte, 8), done: make(chan struct{})}
	h.register(destination, "scope", "target")
	for i := 0; i < 4; i++ {
		if code, _ := h.forward("scope", "busy", "target", []byte("data"), 65535); code != 0 {
			t.Fatal(code)
		}
	}
	if code, _ := h.forward("scope", "busy", "target", []byte("excess"), 65535); code != 4008 {
		t.Fatal("missing per-source backpressure")
	}
	if code, _ := h.forward("scope", "other", "target", []byte("data"), 65535); code != 0 {
		t.Fatal("busy source starved other source")
	}
	if !destination.enqueue(makeFrame(msgPong, []byte("control"))) {
		t.Fatal("no control headroom")
	}
	if h.lookup("scope", "target") != destination {
		t.Fatal("backpressure unpublished destination")
	}
	probeDone := make(chan error, 1)
	go func() { _, err := remote.Write([]byte{7}); probeDone <- err }()
	local.SetReadDeadline(time.Now().Add(time.Second))
	b := make([]byte, 1)
	if _, err := local.Read(b); err != nil {
		t.Fatal("backpressure closed destination", err)
	}
	if err := <-probeDone; err != nil {
		t.Fatal(err)
	}
	for len(destination.send) > 0 {
		destination.releaseFrame(<-destination.send)
	}
	if destination.queuedBytes != 0 || len(destination.queuedBySource) != 0 {
		t.Fatal("queue credits leaked")
	}
	if code, _ := h.forward("different-scope", "other", "target", []byte("cross-scope"), 65535); code != 404 {
		t.Fatal("cross-scope frame forwarded")
	}
}

func TestRelayQueueByteBudgetAndInFlightAccounting(t *testing.T) {
	p := &peer{send: make(chan []byte, 1024), done: make(chan struct{})}
	frame, _ := receivedFrame("source", make([]byte, 60000))
	accepted := 0
	for p.enqueue(frame) {
		accepted++
		if accepted > 1024 {
			t.Fatal("unbounded queue")
		}
	}
	if accepted == 0 || p.queuedBytes > maxPeerQueuedBytes {
		t.Fatal("byte limit not enforced")
	}
	inFlight := <-p.send
	if p.enqueue(frame) {
		t.Fatal("dequeue prematurely released in-flight credit")
	}
	if !p.enqueue(makeFrame(msgPong, []byte{1})) {
		t.Fatal("business bytes consumed control headroom")
	}
	p.releaseFrame(inFlight)
	if !p.enqueue(frame) {
		t.Fatal("write completion did not release budget")
	}
}

func TestRevocationPagingRetriesExactCursorAndGatesReadiness(t *testing.T) {
	var fail atomic.Bool
	fail.Store(true)
	var requests atomic.Int32
	feed := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.URL.Query().Get("protocol") != "2" || r.Header.Get("Authorization") != "Bearer fixture-feed" {
			t.Error("missing authenticated v2 request")
		}
		page := relayRevocationFeedSnapshot{ProtocolVersion: 2, Version: 2}
		switch r.URL.Query().Get("after") {
		case "0":
			page.NextCursor = 1
			page.HasMore = true
			page.RevokedDeviceIDs = []string{"revoked-a"}
		case "1":
			if r.URL.Query().Get("through") != "2" {
				t.Error("lost high-water")
			}
			if fail.Load() {
				w.WriteHeader(503)
				return
			}
			page.After = 1
			page.NextCursor = 2
			page.RevokedDeviceIDs = []string{"revoked-b"}
		default:
			t.Error("wrong cursor")
			w.WriteHeader(400)
			return
		}
		json.NewEncoder(w).Encode(page)
	}))
	defer feed.Close()
	s := &RelayServer{config: &RelayConfig{RevocationFeedURL: feed.URL, RevocationFeedToken: "fixture-feed", RevocationPollInterval: time.Second}, hub: newHub()}
	if err := s.refreshRevocationFeed(context.Background()); err == nil {
		t.Fatal("failed page accepted")
	}
	if s.revocationCursor != 1 || s.revocationFeedUsableLocked(time.Now()) {
		t.Fatal("partial catch-up opened authorization")
	}
	fail.Store(false)
	if err := s.refreshRevocationFeed(context.Background()); err != nil {
		t.Fatal(err)
	}
	if requests.Load() != 3 || s.revocationCursor != 2 || !s.revocationFeedUsableLocked(time.Now()) {
		t.Fatal("retry restarted feed or failed to become ready")
	}
	if !s.identityRevokedLocked("revoked-a", "", "") || !s.identityRevokedLocked("revoked-b", "", "") {
		t.Fatal("page lost revocation")
	}
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	p := &peer{conn: a, ticketJTI: "active", send: make(chan []byte, 1), done: make(chan struct{})}
	s.hub.register(p, "scope", "active")
	s.revocationLastSuccess = time.Now().Add(-time.Minute)
	s.closePeersWhenRevocationsStale()
	if !p.revoked.Load() || s.hub.count() != 0 {
		t.Fatal("stale feed left authenticated peers active")
	}
}

func TestRevocationRejectsNonProgressAndRedirects(t *testing.T) {
	var leaked atomic.Bool
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { leaked.Store(true) }))
	defer target.Close()
	redirect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, target.URL, 302) }))
	defer redirect.Close()
	s := &RelayServer{config: &RelayConfig{RevocationFeedURL: redirect.URL, RevocationFeedToken: "fixture-feed"}}
	if err := s.refreshRevocationFeed(context.Background()); err == nil || leaked.Load() {
		t.Fatal("followed credential-bearing redirect")
	}
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(relayRevocationFeedSnapshot{ProtocolVersion: 2, Version: 2, HasMore: true})
	}))
	defer bad.Close()
	s.config.RevocationFeedURL = bad.URL
	if err := s.refreshRevocationFeed(context.Background()); err == nil {
		t.Fatal("non-progressing page accepted")
	}
	if s.revocationCursor != 0 || !s.revocationLastSuccess.IsZero() {
		t.Fatal("invalid page changed progress")
	}
}

func TestRevocationCacheRetainsRecentDecisionsAndPrunesSafely(t *testing.T) {
	s := &RelayServer{}
	if err := s.applyRevocationSnapshot(relayRevocationFeedSnapshot{Version: 1, RevokedDeviceIDs: []string{"old-device", "recent-device"}}); err != nil {
		t.Fatal(err)
	}
	s.revokedDeviceIDs = map[string]struct{}{"permanent": {}}
	s.revocationObservedAt[revocationIdentity{"device", "old-device"}] = time.Now().Add(-relayRevocationCacheRetention - time.Minute)
	s.pruneRevocationCacheLocked(time.Now())
	if s.identityRevokedLocked("old-device", "", "") {
		t.Fatal("expired cache entry retained forever")
	}
	if !s.identityRevokedLocked("recent-device", "", "") || !s.identityRevokedLocked("permanent", "", "") {
		t.Fatal("prune removed recent or static decision")
	}
	if s.revocationVersion != 1 {
		t.Fatal("cache pruning rewound version")
	}
}
