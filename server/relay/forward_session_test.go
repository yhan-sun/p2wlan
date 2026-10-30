package main

import (
	"net"
	"sync/atomic"
	"testing"
	"time"
)

// net.Pipe Write cannot complete before the test reads its peer. The event
// proves entry into the real writer independently of scheduler/sleep guesses.
type observedWriteConn struct {
	net.Conn
	started chan struct{}
}

func (c *observedWriteConn) Write(data []byte) (int, error) {
	select {
	case c.started <- struct{}{}:
	default:
	}
	return c.Conn.Write(data)
}

func waitRelayEvent(t *testing.T, event <-chan struct{}) {
	t.Helper()
	select {
	case <-event:
	case <-time.After(2 * time.Second):
		t.Fatal("relay event timed out")
	}
}

func TestQueuedForwardPreservesSourceSessionUntilWriter(t *testing.T) {
	for _, mutation := range []string{"revocation", "replacement"} {
		t.Run(mutation, func(t *testing.T) {
			cfg := testConfig()
			s := &RelayServer{config: cfg, hub: newHub(), activeConnections: 1}
			local, remote := net.Pipe()
			defer remote.Close()
			_ = remote.SetDeadline(time.Now().Add(3 * time.Second))
			observed := &observedWriteConn{Conn: local, started: make(chan struct{}, 8)}
			finished := make(chan struct{})
			go func() { s.handleConn(observed); close(finished) }()
			defer func() { remote.Close(); waitRelayEvent(t, finished) }()
			if err := writeFull(remote, makeFrame(msgRegister, []byte("target"))); err != nil {
				t.Fatal(err)
			}
			waitRelayEvent(t, observed.started)
			if typ, _ := readTestFrame(t, remote); typ != msgRegistered {
				t.Fatal("destination not registered")
			}
			sourceConn, sourceRemote := net.Pipe()
			defer sourceConn.Close()
			defer sourceRemote.Close()
			source := &peer{conn: sourceConn, done: make(chan struct{})}
			claims := &relayTicketClaims{NodeID: "source", DeviceID: "device", CredentialID: "old-credential"}
			claims.ID = "old-ticket"
			if !s.registerAuthenticated(source, claims) {
				t.Fatal("source registration rejected")
			}
			if code, _ := s.hub.forward(source, "target", []byte("already-started"), cfg.MaxFramePayload); code != 0 {
				t.Fatal(code)
			}
			waitRelayEvent(t, observed.started)
			if code, _ := s.hub.forward(source, "target", []byte("queued-old-session"), cfg.MaxFramePayload); code != 0 {
				t.Fatal(code)
			}
			if mutation == "revocation" {
				if err := s.applyRevocationSnapshot(relayRevocationFeedSnapshot{Version: 1, RevokedCredentialIDs: []string{"old-credential"}}); err != nil {
					t.Fatal(err)
				}
			}
			newConn, newRemote := net.Pipe()
			defer newConn.Close()
			defer newRemote.Close()
			replacement := &peer{conn: newConn, done: make(chan struct{})}
			claims.CredentialID, claims.ID = "new-credential", "new-ticket"
			if !s.registerAuthenticated(replacement, claims) {
				t.Fatal("replacement registration rejected")
			}
			if code, _ := s.hub.forward(source, "target", []byte("stale-entry"), cfg.MaxFramePayload); code != errIdentityMismatch {
				t.Fatalf("old source borrowed new identity: code=%d", code)
			}
			if code, _ := s.hub.forward(replacement, "target", []byte("current-session"), cfg.MaxFramePayload); code != 0 {
				t.Fatal(code)
			}
			// An already-entered write may complete. Mutation must not wait for
			// blocked network I/O while holding the authoritative registry lock.
			for _, want := range []string{"already-started", "current-session"} {
				typ, payload := readTestFrame(t, remote)
				src, data, ok := parsePeerPayload(payload)
				if typ != msgReceived || !ok || src != "source" || string(data) != want {
					t.Fatalf("unexpected frame after mutation: type=%d src=%s data=%s want=%s", typ, src, data, want)
				}
			}
			if atomic.LoadUint64(&s.stats.forwardErrorsTotal) != 1 {
				t.Fatal("queued stale frame rejection is not counted")
			}
		})
	}
}

func TestForwardDelayCannotOutliveSourceSession(t *testing.T) {
	h := newHub()
	h.forwardDelay = 100 * time.Millisecond
	sourceConn, sourceRemote := net.Pipe()
	defer sourceConn.Close()
	defer sourceRemote.Close()
	source := &peer{conn: sourceConn, done: make(chan struct{})}
	destination := &peer{send: make(chan queuedFrame, 8), done: make(chan struct{})}
	h.register(source, "room", "source")
	h.register(destination, "room", "target")
	result := make(chan uint16, 1)
	go func() { code, _ := h.forward(source, "target", []byte("old-session"), 65535); result <- code }()
	// Either ordering is stale: unregister before entry or during the delay.
	h.unregister(source)
	if code := <-result; code != errIdentityMismatch {
		t.Fatalf("stale delayed source accepted: code=%d", code)
	}
	if len(destination.send) != 0 {
		t.Fatal("stale delayed frame reached destination queue")
	}
}
