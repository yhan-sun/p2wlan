package main

import (
	"fmt"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

type networkNodeKey struct {
	networkID string
	nodeID    string
}

type peer struct {
	id           string // node_id (for logging)
	networkID    string
	deviceID     string
	credentialID string
	ticketJTI    string
	// Immutable after publication; expiry is checked even if its timer is late.
	ticketExpiresAt time.Time
	revoked         atomic.Bool
	conn            net.Conn
	send            chan queuedFrame
	done            chan struct{}
	// writeFailed is set when the per-peer writer goroutine fails to write a
	// frame; handleConn's deferred close logging uses it as the disconnect
	// cause when a write failure raced the read loop's classification.
	writeFailed    atomic.Bool
	queueMu        sync.Mutex
	queuedBytes    int
	queuedBySource map[string]int
}

// queuedFrame preserves the exact source connection across delay and queue
// boundaries. A node ID alone could accidentally borrow its replacement's auth.
type queuedFrame struct {
	data   []byte
	source *peer // nil only for relay-generated control frames
}

type hub struct {
	mu    sync.RWMutex
	peers map[networkNodeKey]*peer
	// Artificial per-frame forwarding delay (slow-relay diagnostics).
	forwardDelay time.Duration
	debugFrames  bool
}

func newHub() *hub {
	return &hub{peers: map[networkNodeKey]*peer{}}
}

func (h *hub) register(p *peer, networkID, nodeID string) {
	if old := h.registerSwap(p, networkID, nodeID); old != nil {
		_ = old.conn.Close()
	}
}

// registerSwap publishes a connection without doing network I/O under locks.
func (h *hub) registerSwap(p *peer, networkID, nodeID string) *peer {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.registerSwapLocked(p, networkID, nodeID)
}

func (h *hub) registerAuthenticatedSwap(p *peer, networkID, nodeID string) (*peer, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	// A verified ticket can expire while waiting for publication. Never retire
	// the healthy current owner on behalf of an already-expired replacement.
	if !p.authorizedAt(time.Now()) {
		return nil, false
	}
	return h.registerSwapLocked(p, networkID, nodeID), true
}

func (h *hub) registerSwapLocked(p *peer, networkID, nodeID string) *peer {
	key := networkNodeKey{networkID: networkID, nodeID: nodeID}
	old := h.peers[key]
	p.id, p.networkID = nodeID, networkID
	h.peers[key] = p
	if old == p {
		return nil
	}
	return old
}

func (p *peer) authorizedAt(now time.Time) bool {
	return !p.revoked.Load() && (p.ticketExpiresAt.IsZero() || now.Before(p.ticketExpiresAt))
}

func (h *hub) unregister(p *peer) {
	h.mu.Lock()
	defer h.mu.Unlock()
	// Legacy registrations intentionally use an empty network ID.  The hub
	// key still includes that empty value, so requiring networkID != "" here
	// leaves every legacy peer behind after disconnect and can route to a dead
	// connection indefinitely.
	if p.id != "" {
		key := networkNodeKey{networkID: p.networkID, nodeID: p.id}
		if h.peers[key] == p {
			delete(h.peers, key)
		}
	}
}

// lookup returns the peer for a given network+node, or nil.
func (h *hub) lookup(networkID, nodeID string) *peer {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.peers[networkNodeKey{networkID: networkID, nodeID: nodeID}]
}

func (h *hub) count() int {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return len(h.peers)
}

// forward forwards payload and returns error code (0 for success) and a diagnostic message.
// Uses network-scoped lookup: source and destination must be in the same network.
func (h *hub) forward(src *peer, dstID string, data []byte, maxFramePayload int) (uint16, string) {
	dst := h.lookup(src.networkID, dstID)
	if dst == nil || dst.revoked.Load() {
		// Do not reveal peers in another network.
		return 404, "peer not found: " + dstID
	}
	if !h.currentForward(src, dst) {
		return errIdentityMismatch, "source session is no longer current"
	}
	if 1+len(src.id)+len(data) > maxFramePayload {
		return 4006, "forwarded frame too large"
	}
	frame, err := receivedFrame(src.id, data)
	if err != nil {
		return 4000, "malformed received frame"
	}
	if h.forwardDelay > 0 {
		timer := time.NewTimer(h.forwardDelay)
		defer timer.Stop()
		select {
		case <-timer.C:
		case <-src.done:
			return errIdentityMismatch, "source session is no longer current"
		case <-dst.done:
			return 404, "peer disconnected: " + dstID
		}
	}
	// Delay can cross revocation, disconnect or replacement of either peer.
	if !h.currentForward(src, dst) {
		return errIdentityMismatch, "forward session is no longer current"
	}
	if !dst.enqueueFrame(queuedFrame{data: frame, source: src}) {
		return 4008, "peer backpressure: " + dstID
	}
	if h.debugFrames {
		log.Printf("event=relay_forward_enqueued src=%s dst=%s bytes=%d wire_fp=%s", src.id, dstID, len(data), opaqueFrameFingerprint(data))
	}
	return 0, ""
}

// currentForward checks the one authoritative peer registry. Its lock is never
// held during a delay or network I/O. The writer calls it again at write start.
func (h *hub) currentForward(src, dst *peer) bool {
	h.mu.RLock()
	defer h.mu.RUnlock()
	now := time.Now()
	return src != nil && dst != nil && src.authorizedAt(now) && dst.authorizedAt(now) &&
		src.networkID == dst.networkID &&
		h.peers[networkNodeKey{src.networkID, src.id}] == src &&
		h.peers[networkNodeKey{dst.networkID, dst.id}] == dst
}

// opaqueFrameFingerprint correlates an encrypted frame across local relay
// traces without recording any of its contents. It is diagnostic metadata,
// not an authentication primitive.
func opaqueFrameFingerprint(data []byte) string {
	var hash uint64 = 0xcbf29ce484222325
	for _, b := range data {
		hash ^= uint64(b)
		hash *= 0x100000001b3
	}
	return fmt.Sprintf("%016x", hash)
}
