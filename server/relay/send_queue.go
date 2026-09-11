package main

const maxPeerQueuedBytes = 4 << 20
const relayControlByteReserve = 64 << 10

func forwardedSource(frame []byte) (string, bool) {
	if len(frame) < frameHeader || frame[5] != msgReceived {
		return "", false
	}
	source, _, ok := parsePeerPayload(frame[frameHeader:])
	return source, ok
}

// Reserve packet, byte and per-source budgets together with queue publication.
// Credits include the frame currently being written; a blocked writer cannot
// admit unbounded memory or make one source occupy the whole destination.
func (p *peer) enqueue(frame []byte) bool {
	p.queueMu.Lock()
	defer p.queueMu.Unlock()
	if p.revoked.Load() || len(frame) > maxPeerQueuedBytes-p.queuedBytes {
		return false
	}
	source, business := forwardedSource(frame)
	if business {
		reserve := min(16, cap(p.send)/4)
		if len(frame) > maxPeerQueuedBytes-relayControlByteReserve-p.queuedBytes ||
			len(p.send) >= cap(p.send)-reserve || p.queuedBySource[source] >= max(1, cap(p.send)/2) {
			return false
		}
	}
	select {
	case <-p.done:
		return false
	default:
	}
	select {
	case p.send <- frame:
		p.queuedBytes += len(frame)
		if business {
			if p.queuedBySource == nil {
				p.queuedBySource = make(map[string]int)
			}
			p.queuedBySource[source]++
		}
		return true
	default:
		return false
	}
}

func (p *peer) releaseFrame(frame []byte) {
	p.queueMu.Lock()
	defer p.queueMu.Unlock()
	p.queuedBytes = max(0, p.queuedBytes-len(frame))
	if source, business := forwardedSource(frame); business {
		if p.queuedBySource[source] <= 1 {
			delete(p.queuedBySource, source)
		} else {
			p.queuedBySource[source]--
		}
	}
}
