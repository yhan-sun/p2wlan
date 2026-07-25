package main

import (
	"encoding/binary"
	"encoding/hex"
	"testing"

	"golang.org/x/crypto/blake2s"
)

const (
	probeV2Domain       = "p2wlan-udp-probe-v2"
	probeV2Magic        = "PNCH"
	probeV2Version      = byte(0x02)
	probeV2TypePunch    = byte(0x01)
	probeV2TypeAck      = byte(0x02)
	probeV2UseCandidate = byte(0x01)
	probeV2MACSize      = 16
)

func TestAuthenticatedProbeV2GoldenVectors(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	nonce := []byte{0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7}

	punch := buildProbeV2PacketForTest(
		t,
		key,
		probeV2TypePunch,
		nonce,
		0x0102030405060708,
		probeV2UseCandidate,
		"node-a",
		"node-b",
	)
	assertHexEqual(t, punch, "504e43480201a0a1a2a3a4a5a6a701020304050607080106066e6f64652d616e6f64652d62fa09a10aa09da3d47f1b7d003a7adadb")

	ack := buildProbeV2PacketForTest(
		t,
		key,
		probeV2TypeAck,
		nonce,
		0x0102030405060709,
		0x00,
		"node-b",
		"node-a",
	)
	assertHexEqual(t, ack, "504e43480202a0a1a2a3a4a5a6a701020304050607090006066e6f64652d626e6f64652d619080783cb1a90b982675b2fab7399bbd")
}

func buildProbeV2PacketForTest(t *testing.T, key []byte, kind byte, nonce []byte, generation uint64, flags byte, sourceNodeID, targetNodeID string) []byte {
	t.Helper()
	if len(nonce) != 8 {
		t.Fatalf("nonce must be 8 bytes, got %d", len(nonce))
	}
	if len(sourceNodeID) > 255 || len(targetNodeID) > 255 {
		t.Fatalf("node IDs must fit in one byte")
	}

	frame := make([]byte, 0, len(probeV2Magic)+1+1+8+8+1+1+1+len(sourceNodeID)+len(targetNodeID)+probeV2MACSize)
	frame = append(frame, []byte(probeV2Magic)...)
	frame = append(frame, probeV2Version, kind)
	frame = append(frame, nonce...)
	frame = binary.BigEndian.AppendUint64(frame, generation)
	frame = append(frame, flags, byte(len(sourceNodeID)), byte(len(targetNodeID)))
	frame = append(frame, sourceNodeID...)
	frame = append(frame, targetNodeID...)
	frame = append(frame, probeV2MAC(frame, key)...)
	return frame
}

func probeV2MAC(frameWithoutMAC []byte, key []byte) []byte {
	input := make([]byte, 0, len(probeV2Domain)+len(frameWithoutMAC))
	input = append(input, []byte(probeV2Domain)...)
	input = append(input, frameWithoutMAC...)
	full := hmacBlake2s256(key, input)
	return full[:probeV2MACSize]
}

func hmacBlake2s256(key []byte, message []byte) []byte {
	const blockSize = 64

	blockKey := make([]byte, blockSize)
	if len(key) > blockSize {
		digest := blake2s.Sum256(key)
		copy(blockKey, digest[:])
	} else {
		copy(blockKey, key)
	}

	innerPad := make([]byte, blockSize)
	outerPad := make([]byte, blockSize)
	for i := 0; i < blockSize; i++ {
		innerPad[i] = blockKey[i] ^ 0x36
		outerPad[i] = blockKey[i] ^ 0x5c
	}

	innerInput := make([]byte, 0, blockSize+len(message))
	innerInput = append(innerInput, innerPad...)
	innerInput = append(innerInput, message...)
	inner := blake2s.Sum256(innerInput)

	outerInput := make([]byte, 0, blockSize+len(inner))
	outerInput = append(outerInput, outerPad...)
	outerInput = append(outerInput, inner[:]...)
	outer := blake2s.Sum256(outerInput)
	return outer[:]
}

func assertHexEqual(t *testing.T, got []byte, want string) {
	t.Helper()
	if hex.EncodeToString(got) != want {
		t.Fatalf("packet mismatch\nwant %s\n got %s", want, hex.EncodeToString(got))
	}
}
