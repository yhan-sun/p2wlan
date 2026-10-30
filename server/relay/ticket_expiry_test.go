package main

import (
	"net"
	"testing"
	"testing/synctest"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func TestExpiredAuthenticatedReplacementPreservesCurrentOwner(t *testing.T) {
	s := &RelayServer{hub: newHub()}
	oldConn, oldRemote := net.Pipe()
	defer oldConn.Close()
	defer oldRemote.Close()
	old := &peer{conn: oldConn}
	claims := &relayTicketClaims{DeviceID: "device", CredentialID: "credential", NetworkID: "room", NodeID: "node"}
	claims.ID = "current-ticket"
	claims.ExpiresAt = jwt.NewNumericDate(time.Now().Add(time.Minute))
	if !s.registerAuthenticated(old, claims) {
		t.Fatal("current registration rejected")
	}
	badConn, badRemote := net.Pipe()
	defer badConn.Close()
	defer badRemote.Close()
	replacement := &peer{conn: badConn}
	claims.ID = "expired-ticket"
	claims.ExpiresAt = jwt.NewNumericDate(time.Now().Add(-time.Second))
	if s.registerAuthenticated(replacement, claims) {
		t.Fatal("expired replacement was published")
	}
	if s.hub.lookup("room", "node") != old {
		t.Fatal("expired replacement retired the current owner")
	}
	// The still-current connection must remain physically usable.
	done := make(chan error, 1)
	go func() { _, err := oldRemote.Write([]byte{1}); done <- err }()
	oldConn.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := oldConn.Read(make([]byte, 1)); err != nil {
		t.Fatal("expired replacement closed the current connection", err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestForwardDelayRejectsTicketThatExpiresBeforeEnqueue(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		h := newHub()
		h.forwardDelay = time.Second
		source := &peer{done: make(chan struct{}), ticketExpiresAt: time.Now().Add(500 * time.Millisecond)}
		destination := &peer{done: make(chan struct{}), send: make(chan queuedFrame, 8)}
		h.register(source, "room", "source")
		h.register(destination, "room", "target")
		if code, _ := h.forward(source, "target", []byte("expires-during-delay"), 65535); code != errIdentityMismatch {
			t.Fatalf("expired delayed source was accepted: code=%d", code)
		}
		if len(destination.send) != 0 {
			t.Fatal("expired frame reached the destination queue")
		}
	})
}

func TestQueuedForwardRechecksTicketExpiryAtWriterBoundary(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		h := newHub()
		source := &peer{done: make(chan struct{}), ticketExpiresAt: time.Now().Add(time.Second)}
		destination := &peer{done: make(chan struct{}), send: make(chan queuedFrame, 8)}
		h.register(source, "room", "source")
		h.register(destination, "room", "target")
		if code, _ := h.forward(source, "target", []byte("queued-before-expiry"), 65535); code != 0 {
			t.Fatal(code)
		}
		frame := <-destination.send
		time.Sleep(2 * time.Second)
		if h.currentForward(frame.source, destination) {
			t.Fatal("queued frame borrowed authorization beyond its ticket expiry")
		}
		destination.releaseFrame(frame.data)
	})
}
