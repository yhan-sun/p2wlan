package main

import (
	"encoding/binary"
	"time"
)

const datagramHeader = 13
const datagramChunk = 1024
const maxPendingDatagrams = 24
const datagramLifetime = 500 * time.Millisecond

type fragments struct {
	bytes    []byte
	seen     [2]uint64
	received int
	deadline time.Time
}

type datagramReader struct {
	partial   map[uint64]*fragments
	maxLength int
}

// Relay application framing sits above QUIC DATAGRAM. Chunking is at this
// layer so a large inner IP packet never requires outer IP fragmentation.
func (r *datagramReader) push(chunk []byte, now time.Time) []byte {
	if len(chunk) < datagramHeader {
		return nil
	}
	id := binary.BigEndian.Uint64(chunk[:8])
	length := int(binary.BigEndian.Uint32(chunk[8:12]))
	part := int(chunk[12])
	offset := part * datagramChunk
	payload := chunk[datagramHeader:]
	if length < frameHeader || length > r.maxLength || offset >= length ||
		len(payload) != min(datagramChunk, length-offset) {
		return nil
	}
	if length <= datagramChunk {
		return payload
	}
	if r.partial == nil {
		r.partial = make(map[uint64]*fragments)
	}
	for key, entry := range r.partial {
		if !now.Before(entry.deadline) {
			delete(r.partial, key)
		}
	}
	entry := r.partial[id]
	if entry == nil {
		if len(r.partial) >= maxPendingDatagrams {
			return nil
		}
		entry = &fragments{bytes: make([]byte, length), deadline: now.Add(datagramLifetime)}
		r.partial[id] = entry
	}
	if len(entry.bytes) != length {
		return nil
	}
	mask := uint64(1) << (part % 64)
	if entry.seen[part/64]&mask != 0 {
		return nil
	}
	entry.seen[part/64] |= mask
	entry.received += copy(entry.bytes[offset:], payload)
	if entry.received != length {
		return nil
	}
	delete(r.partial, id)
	return entry.bytes
}
