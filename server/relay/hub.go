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
	id        string // node_id (for logging)
	networkID string
	deviceID  string
	conn      net.Conn
	send      chan []byte
	done      chan struct{}
	// writeFailed is set when the per-peer writer goroutine fails to write a
	// frame; handleConn's deferred close logging uses it as the disconnect
	// cause when a write failure raced the read loop's classification.
	writeFailed atomic.Bool
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
	h.mu.Lock()
	defer h.mu.Unlock()
	key := networkNodeKey{networkID: networkID, nodeID: nodeID}
	if old := h.peers[key]; old != nil && old != p {
		_ = old.conn.Close()
	}
	p.id = nodeID
	p.networkID = networkID
	h.peers[key] = p
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
func (h *hub) forward(srcNetwork, srcID, dstID string, data []byte, maxFramePayload int) (uint16, string) {
	dst := h.lookup(srcNetwork, dstID)
	if dst == nil {
		// Return 404 even if peer exists in a different network — do not leak
		// that information to the sender.
		return 404, "peer not found: " + dstID
	}

	// Enforce max_frame_payload limit on outbound frames
	totalLen := 1 + len(srcID) + len(data)
	if totalLen > maxFramePayload {
		return 4006, "forwarded frame too large" // ERR_FRAME_TOO_LARGE
	}

	frame, err := receivedFrame(srcID, data)
	if err != nil {
		return 4000, "malformed received frame"
	}
	// Slow-relay diagnostics: apply the artificial per-frame delay BEFORE
	// handing the frame to the destination queue, so the sender observes the
	// full one-way latency (and the relay keeps servicing other peers during
	// the delay).
	if h.forwardDelay > 0 {
		select {
		case <-time.After(h.forwardDelay):
		case <-dst.done:
			return 404, "peer disconnected: " + dstID
		}
	}
	select {
	case dst.send <- frame:
		if h.debugFrames {
			log.Printf("event=relay_forward_enqueued src=%s dst=%s bytes=%d wire_fp=%s", srcID, dstID, len(data), opaqueFrameFingerprint(data))
		}
		return 0, ""
	case <-dst.done:
		return 404, "peer disconnected: " + dstID
	default:
		// slow consumer backpressure: close target connection
		_ = dst.conn.Close()
		return 4008, "peer backpressure: " + dstID
	}
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
