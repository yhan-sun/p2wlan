package main

import (
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"
)

// testConfig returns a RelayConfig suitable for local testing (plaintext enabled).
func testConfig() *RelayConfig {
	return &RelayConfig{
		SendQueueCapacity:      10,
		RegisterTimeout:        1 * time.Second,
		IdleTimeout:            5 * time.Second,
		MaxConnections:         10,
		MaxFramePayload:        65535,
		AllowInsecurePlaintext: true,
		RequireAuthentication:  false,
	}
}

func startTestServer(t *testing.T, config *RelayConfig) (string, func()) {
	t.Helper()
	_, addr, cleanup := startTestServerWithInstance(t, config)
	return addr, cleanup
}

func startTestServerWithInstance(t *testing.T, config *RelayConfig) (*RelayServer, string, func()) {
	t.Helper()
	server, err := NewRelayServer(config)
	if err != nil {
		t.Fatalf("failed to start relay server: %v", err)
	}

	go server.Serve()

	cleanup := func() {
		_ = server.Close()
	}

	return server, server.Addr().String(), cleanup
}

func readTestFrame(t *testing.T, conn net.Conn) (byte, []byte) {
	t.Helper()
	header := make([]byte, frameHeader)
	if _, err := io.ReadFull(conn, header); err != nil {
		t.Fatalf("read frame header: %v", err)
	}
	if string(header[:4]) != string(magic) {
		t.Fatalf("unexpected frame magic: %q", string(header[:4]))
	}
	length := int(binary.BigEndian.Uint16(header[6:8]))
	payload := make([]byte, length)
	if length > 0 {
		if _, err := io.ReadFull(conn, payload); err != nil {
			t.Fatalf("read frame payload: %v", err)
		}
	}
	return header[5], payload
}
