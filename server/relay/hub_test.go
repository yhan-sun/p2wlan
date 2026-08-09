package main

import (
	"net"
	"testing"
)

// A second connection from the same (network, node) atomically replaces the
// first: the make-before-break ticket renewal relies on this newest-wins
// register, so the old connection is closed and all forwarding goes to the
// new one with no stale dual-affinity window.
func TestHubRegisterNewestWinsClosesOldConnection(t *testing.T) {
	h := newHub()

	oldServer, oldClient := net.Pipe()
	defer oldClient.Close()
	oldPeer := &peer{id: "node-1", networkID: "net-1", deviceID: "dev-1", conn: oldServer, send: make(chan []byte, 8), done: make(chan struct{})}
	h.register(oldPeer, "net-1", "node-1")
	if h.count() != 1 {
		t.Fatalf("expected 1 peer after first register, got %d", h.count())
	}

	newServer, newClient := net.Pipe()
	defer newClient.Close()
	newPeer := &peer{id: "node-1", networkID: "net-1", deviceID: "dev-1", conn: newServer, send: make(chan []byte, 8), done: make(chan struct{})}
	h.register(newPeer, "net-1", "node-1")

	// The old connection is closed by the register.
	_, err := oldClient.Read(make([]byte, 1))
	if err == nil {
		t.Fatal("expected the old connection to be closed by the newest-wins register")
	}

	// Forwarding now resolves to the NEW peer.
	dst := h.lookup("net-1", "node-1")
	if dst != newPeer {
		t.Fatalf("expected forwarding to resolve to the new peer")
	}

	// Unregistering the OLD peer must not remove the new one.
	h.unregister(oldPeer)
	if h.lookup("net-1", "node-1") != newPeer {
		t.Fatalf("unregister of the old peer must not remove the replacement")
	}
	h.unregister(newPeer)
	if h.count() != 0 {
		t.Fatalf("expected 0 peers after final unregister, got %d", h.count())
	}
}

// A plain unregister of the current peer leaves the hub empty; re-register
// after unregister is a fresh entry.
func TestHubUnregisterThenRegisterIsFresh(t *testing.T) {
	h := newHub()
	server, client := net.Pipe()
	defer client.Close()
	p := &peer{id: "node-2", networkID: "net-1", deviceID: "dev-2", conn: server, send: make(chan []byte, 8), done: make(chan struct{})}
	h.register(p, "net-1", "node-2")
	h.unregister(p)
	if h.lookup("net-1", "node-2") != nil {
		t.Fatal("expected the peer to be gone after unregister")
	}
	if h.count() != 0 {
		t.Fatalf("expected 0 peers, got %d", h.count())
	}
}
