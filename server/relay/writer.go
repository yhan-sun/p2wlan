package main

import (
	"crypto/tls"
	"net"
	"sync/atomic"
	"time"
)

const writeBatchBytes = 16 * 1024
const writeBatchFrames = 16

// The writer owns the queue credits through write completion. It drains only
// immediately available work. A second burst never delays the first one.
func (s *RelayServer) writePeer(p *peer) bool {
	_, tlsStream := p.conn.(*tls.Conn)
	_, tcpStream := p.conn.(*net.TCPConn)
	limit := 1
	if tlsStream || tcpStream {
		limit = writeBatchFrames
	}
	var frames [writeBatchFrames]queuedFrame
	var buffers [writeBatchFrames][]byte
	var pending queuedFrame
	for {
		first := pending
		pending = queuedFrame{}
		if first.data == nil {
			select {
			case frame, open := <-p.send:
				if !open {
					return true
				}
				first = frame
			case <-p.done:
				return true
			}
		}
		frames[0] = first
		count, size := 1, len(first.data)
	collect:
		for count < limit && size < writeBatchBytes {
			select {
			case next, open := <-p.send:
				if !open {
					break collect
				}
				if size+len(next.data) > writeBatchBytes {
					pending = next
					break collect
				}
				count++
				size += len(next.data)
				frames[count-1] = next
			default:
				break collect
			}
		}
		_ = p.conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
		if !p.authorizedAt(time.Now()) {
			p.releaseQueued(pending)
			for _, frame := range frames[:count] {
				p.releaseQueued(frame)
			}
			return true
		}
		valid, bytes := 0, 0
		for _, frame := range frames[:count] {
			// The current source and destination connection are rechecked
			// at the write boundary. No registry lock spans a socket write.
			if frame.source != nil && !s.hub.currentForward(frame.source, p) {
				atomic.AddUint64(&s.stats.forwardErrorsTotal, 1)
				continue
			}
			buffers[valid] = frame.data
			valid++
			bytes += len(frame.data)
		}
		var err error
		switch {
		case valid == 0:
		case valid == 1:
			err = writeFull(p.conn, buffers[0])
		case tlsStream:
			store := acquireFrame(bytes)
			offset := 0
			for _, frame := range buffers[:valid] {
				offset += copy(store.bytes[offset:], frame)
			}
			err = writeFull(p.conn, store.bytes)
			store.release()
		default:
			batch := net.Buffers(buffers[:valid])
			_, err = batch.WriteTo(p.conn)
		}
		for index, frame := range frames[:count] {
			p.releaseQueued(frame)
			frames[index] = queuedFrame{}
		}
		clear(buffers[:valid])
		if err != nil {
			p.releaseQueued(pending)
			return false
		}
	}
}
