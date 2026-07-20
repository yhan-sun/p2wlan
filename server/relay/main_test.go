package main

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

func startTestServer(t *testing.T, config *RelayConfig) (string, func()) {
	t.Helper()
	server, err := NewRelayServer(config)
	if err != nil {
		t.Fatalf("failed to start relay server: %v", err)
	}

	go server.Serve()

	cleanup := func() {
		_ = server.Close()
	}

	return server.Addr().String(), cleanup
}

func TestEnvValidation(t *testing.T) {
	t.Setenv("RELAY_MAX_CONNECTIONS", "abc")
	_, err := parseConfig(nil)
	if err == nil {
		t.Error("expected error for invalid RELAY_MAX_CONNECTIONS env value, got nil")
	}
}

func TestConfigValidation(t *testing.T) {
	// Test invalid config values reject on parseConfig
	_, err := parseConfig([]string{"-send-queue=0"})
	if err == nil {
		t.Error("expected error for 0 send queue capacity")
	}

	// Test valid configuration parsing
	cfg, err := parseConfig([]string{"-send-queue=64", "-register-timeout=10s"})
	if err != nil {
		t.Fatalf("unexpected parsing error: %v", err)
	}
	if cfg.SendQueueCapacity != 64 {
		t.Errorf("expected SendQueueCapacity 64, got %d", cfg.SendQueueCapacity)
	}
	if cfg.RegisterTimeout != 10*time.Second {
		t.Errorf("expected RegisterTimeout 10s, got %v", cfg.RegisterTimeout)
	}
}

func TestSendQueueFullBackpressure(t *testing.T) {
	config := &RelayConfig{
		SendQueueCapacity: 1,
		RegisterTimeout:   1 * time.Second,
		IdleTimeout:       5 * time.Second,
		MaxConnections:    10,
		MaxFramePayload:   65535,
	}
	addr, cleanup := startTestServer(t, config)
	defer cleanup()

	bob, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial bob: %v", err)
	}
	defer bob.Close()
	_, _ = bob.Write(makeFrame(msgRegister, []byte("bob")))

	buf := make([]byte, 1024)
	_, err = io.ReadAtLeast(bob, buf, frameHeader)
	if err != nil {
		t.Fatalf("read bob registered: %v", err)
	}
	if buf[5] != msgRegistered {
		t.Fatalf("expected registered, got %d", buf[5])
	}

	alice, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial alice: %v", err)
	}
	defer alice.Close()
	_, _ = alice.Write(makeFrame(msgRegister, []byte("alice")))
	_, _ = io.ReadAtLeast(alice, buf, frameHeader)

	payload := make([]byte, 60000)
	payload[0] = byte(len("bob"))
	copy(payload[1:], "bob")

	gotBackpressure := false
	for i := 0; i < 150; i++ {
		_, err = alice.Write(makeFrame(msgForward, payload))
		if err != nil {
			break
		}
		_ = alice.SetReadDeadline(time.Now().Add(10 * time.Millisecond))
		n, err := alice.Read(buf)
		if err == nil && n >= frameHeader && buf[5] == msgError {
			code := binary.BigEndian.Uint16(buf[8:10])
			if code == 4008 {
				gotBackpressure = true
				break
			}
		}
	}
	if !gotBackpressure {
		t.Error("expected backpressure error 4008")
	}
}

func TestRegisterTimeout(t *testing.T) {
	config := &RelayConfig{
		SendQueueCapacity: 10,
		RegisterTimeout:   100 * time.Millisecond,
		IdleTimeout:       5 * time.Second,
		MaxConnections:    10,
		MaxFramePayload:   65535,
	}
	addr, cleanup := startTestServer(t, config)
	defer cleanup()

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	time.Sleep(200 * time.Millisecond)

	buf := make([]byte, 100)
	n, err := conn.Read(buf)
	if err != nil && err != io.EOF {
		t.Fatalf("read: %v", err)
	}
	if n < frameHeader {
		t.Fatalf("expected error frame, got %d bytes", n)
	}
	if buf[5] != msgError {
		t.Fatalf("expected error msg, got %d", buf[5])
	}
	code := binary.BigEndian.Uint16(buf[8:10])
	if code != 4003 {
		t.Errorf("expected code 4003 (register timeout), got %d", code)
	}
}

func TestIdleTimeout(t *testing.T) {
	config := &RelayConfig{
		SendQueueCapacity: 10,
		RegisterTimeout:   1 * time.Second,
		IdleTimeout:       100 * time.Millisecond,
		MaxConnections:    10,
		MaxFramePayload:   65535,
	}
	addr, cleanup := startTestServer(t, config)
	defer cleanup()

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	_, _ = conn.Write(makeFrame(msgRegister, []byte("idle-client")))

	buf := make([]byte, 100)
	_, _ = io.ReadAtLeast(conn, buf, frameHeader)

	time.Sleep(200 * time.Millisecond)

	n, err := conn.Read(buf)
	if err != nil && err != io.EOF {
		t.Fatalf("read: %v", err)
	}
	if n < frameHeader {
		t.Fatalf("expected error frame, got %d bytes", n)
	}
	if buf[5] != msgError {
		t.Fatalf("expected error msg, got %d", buf[5])
	}
	code := binary.BigEndian.Uint16(buf[8:10])
	if code != 4009 {
		t.Errorf("expected code 4009 (idle timeout), got %d", code)
	}
}

func TestMaxConnections(t *testing.T) {
	config := &RelayConfig{
		SendQueueCapacity: 10,
		RegisterTimeout:   1 * time.Second,
		IdleTimeout:       5 * time.Second,
		MaxConnections:    1,
		MaxFramePayload:   65535,
	}
	addr, cleanup := startTestServer(t, config)
	defer cleanup()

	conn1, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial 1: %v", err)
	}
	defer conn1.Close()

	conn2, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial 2: %v", err)
	}
	defer conn2.Close()

	buf := make([]byte, 100)
	n, err := conn2.Read(buf)
	if err != nil && err != io.EOF {
		t.Fatalf("read: %v", err)
	}
	if n < frameHeader {
		t.Fatalf("expected error frame, got %d bytes", n)
	}
	code := binary.BigEndian.Uint16(buf[8:10])
	if code != 4005 {
		t.Errorf("expected code 4005 (max connections), got %d", code)
	}
}

func TestFrameSizeBoundary(t *testing.T) {
	config := &RelayConfig{
		SendQueueCapacity: 10,
		RegisterTimeout:   1 * time.Second,
		IdleTimeout:       5 * time.Second,
		MaxConnections:    10,
		MaxFramePayload:   10,
	}
	addr, cleanup := startTestServer(t, config)
	defer cleanup()

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	largePayload := make([]byte, 100)
	_, _ = conn.Write(makeFrame(msgRegister, largePayload))

	buf := make([]byte, 100)
	n, err := conn.Read(buf)
	if err != nil && err != io.EOF {
		t.Fatalf("read: %v", err)
	}
	if n < frameHeader {
		t.Fatalf("expected error frame, got %d bytes", n)
	}
	code := binary.BigEndian.Uint16(buf[8:10])
	if code != 4006 {
		t.Errorf("expected code 4006 (frame too large), got %d", code)
	}
}

func TestOutboundFrameSizeBoundary(t *testing.T) {
	config := &RelayConfig{
		SendQueueCapacity: 10,
		RegisterTimeout:   1 * time.Second,
		IdleTimeout:       5 * time.Second,
		MaxConnections:    10,
		MaxFramePayload:   30, // Limit is 30 bytes
	}
	addr, cleanup := startTestServer(t, config)
	defer cleanup()

	bob, _ := net.Dial("tcp", addr)
	defer bob.Close()
	_, _ = bob.Write(makeFrame(msgRegister, []byte("bob")))
	buf := make([]byte, 1024)
	_, _ = io.ReadAtLeast(bob, buf, frameHeader)

	alice, _ := net.Dial("tcp", addr)
	defer alice.Close()
	_, _ = alice.Write(makeFrame(msgRegister, []byte("alice")))
	_, _ = io.ReadAtLeast(alice, buf, frameHeader)

	// Received payload: 1 + len("alice") + len(data) = 1 + 5 + 25 = 31 bytes (exceeds 30)
	data := make([]byte, 25)
	payload := make([]byte, 1+len("bob")+len(data))
	payload[0] = byte(len("bob"))
	copy(payload[1:], "bob")
	copy(payload[1+len("bob"):], data)

	_, _ = alice.Write(makeFrame(msgForward, payload))

	_ = alice.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	n, err := alice.Read(buf)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if n < frameHeader {
		t.Fatalf("expected error frame, got %d bytes", n)
	}
	if buf[5] != msgError {
		t.Fatalf("expected error frame type, got %d", buf[5])
	}
	code := binary.BigEndian.Uint16(buf[8:10])
	if code != 4006 {
		t.Errorf("expected 4006, got %d", code)
	}
}

func TestDuplicateRegistration(t *testing.T) {
	config := &RelayConfig{
		SendQueueCapacity: 10,
		RegisterTimeout:   1 * time.Second,
		IdleTimeout:       5 * time.Second,
		MaxConnections:    10,
		MaxFramePayload:   65535,
	}
	addr, cleanup := startTestServer(t, config)
	defer cleanup()

	conn1, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial 1: %v", err)
	}
	defer conn1.Close()
	_, _ = conn1.Write(makeFrame(msgRegister, []byte("dup")))
	buf := make([]byte, 100)
	_, _ = io.ReadAtLeast(conn1, buf, frameHeader)

	conn2, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial 2: %v", err)
	}
	defer conn2.Close()
	_, _ = conn2.Write(makeFrame(msgRegister, []byte("dup")))
	_, _ = io.ReadAtLeast(conn2, buf, frameHeader)

	_ = conn1.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	_, err = conn1.Read(buf)
	if err == nil {
		t.Error("expected conn1 to be closed by server")
	}

	_, _ = conn2.Write(makeFrame(msgRegister, []byte("other")))
	n, err := conn2.Read(buf)
	if err != nil && err != io.EOF {
		t.Fatalf("read: %v", err)
	}
	if n < frameHeader {
		t.Fatalf("expected error, got %d bytes", n)
	}
	code := binary.BigEndian.Uint16(buf[8:10])
	if code != 4004 {
		t.Errorf("expected duplicate registration error 4004, got %d", code)
	}
}

func TestRustGoErrorCodesCompatibility(t *testing.T) {
	// 1. peer-backpressure (4008)
	err4008 := errorFrame(4008, "backpressure")
	expected4008 := []byte{
		'D', 'E', 'R', 'P',
		1,
		msgError,
		0, 14,
		15, 168,
		'b', 'a', 'c', 'k', 'p', 'r', 'e', 's', 's', 'u', 'r', 'e',
	}
	if !bytes.Equal(err4008, expected4008) {
		t.Errorf("errorFrame 4008 mismatch\ngot:  %v\nwant: %v", err4008, expected4008)
	}

	// 2. peer-not-found (404)
	err404 := errorFrame(404, "peer not found")
	expected404 := []byte{
		'D', 'E', 'R', 'P',
		1,
		msgError,
		0, 16,
		1, 148,
		'p', 'e', 'e', 'r', ' ', 'n', 'o', 't', ' ', 'f', 'o', 'u', 'n', 'd',
	}
	if !bytes.Equal(err404, expected404) {
		t.Errorf("errorFrame 404 mismatch\ngot:  %v\nwant: %v", err404, expected404)
	}

	// 3. registered (msgRegistered 0x02)
	registered := makeFrame(msgRegistered, []byte("nodeA"))
	expectedRegistered := []byte{
		'D', 'E', 'R', 'P',
		1,
		msgRegistered,
		0, 5,
		'n', 'o', 'd', 'e', 'A',
	}
	if !bytes.Equal(registered, expectedRegistered) {
		t.Errorf("registered frame mismatch\ngot:  %v\nwant: %v", registered, expectedRegistered)
	}

	// 4. frame-too-large (4006)
	err4006 := errorFrame(4006, "frame too large")
	expected4006 := []byte{
		'D', 'E', 'R', 'P',
		1,
		msgError,
		0, 17,
		15, 166,
		'f', 'r', 'a', 'm', 'e', ' ', 't', 'o', 'o', ' ', 'l', 'a', 'r', 'g', 'e',
	}
	if !bytes.Equal(err4006, expected4006) {
		t.Errorf("errorFrame 4006 mismatch\ngot:  %v\nwant: %v", err4006, expected4006)
	}

	// 5. unknown error code (9999)
	err9999 := errorFrame(9999, "unknown")
	expected9999 := []byte{
		'D', 'E', 'R', 'P',
		1,
		msgError,
		0, 9,
		39, 15,
		'u', 'n', 'k', 'n', 'o', 'w', 'n',
	}
	if !bytes.Equal(err9999, expected9999) {
		t.Errorf("errorFrame 9999 mismatch\ngot:  %v\nwant: %v", err9999, expected9999)
	}
}

func TestServerCloseReclaimsImmediately(t *testing.T) {
	config := &RelayConfig{
		SendQueueCapacity: 10,
		RegisterTimeout:   10 * time.Second,
		IdleTimeout:       1 * time.Hour,
		MaxConnections:    10,
		MaxFramePayload:   65535,
	}
	server, err := NewRelayServer(config)
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}
	go server.Serve()

	conn, err := net.Dial("tcp", server.Addr().String())
	if err != nil {
		t.Fatalf("failed to dial: %v", err)
	}
	defer conn.Close()
	_, _ = conn.Write(makeFrame(msgRegister, []byte("nodeA")))

	buf := make([]byte, 100)
	_, _ = io.ReadAtLeast(conn, buf, frameHeader)

	start := time.Now()
	err = server.Close()
	if err != nil {
		t.Errorf("Close returned error: %v", err)
	}
	duration := time.Since(start)

	if duration > 200*time.Millisecond {
		t.Errorf("Close took too long to reclaim connection: %v (expected < 200ms)", duration)
	}
}

func TestIllegalUTF8NodeID(t *testing.T) {
	config := &RelayConfig{
		SendQueueCapacity: 10,
		RegisterTimeout:   1 * time.Second,
		IdleTimeout:       5 * time.Second,
		MaxConnections:    10,
		MaxFramePayload:   65535,
	}
	addr, cleanup := startTestServer(t, config)
	defer cleanup()

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	illegalBytes := []byte{0xff, 0xfe, 0xfd}
	_, _ = conn.Write(makeFrame(msgRegister, illegalBytes))

	buf := make([]byte, 100)
	n, err := conn.Read(buf)
	if err != nil && err != io.EOF {
		t.Fatalf("read: %v", err)
	}
	if n < frameHeader {
		t.Fatalf("expected error frame, got %d bytes", n)
	}
	code := binary.BigEndian.Uint16(buf[8:10])
	if code != 4000 {
		t.Errorf("expected 4000 (invalid node ID), got %d", code)
	}
}

func TestServerCloseConcurrentAccept(t *testing.T) {
	config := &RelayConfig{
		SendQueueCapacity: 10,
		RegisterTimeout:   1 * time.Second,
		IdleTimeout:       5 * time.Second,
		MaxConnections:    10,
		MaxFramePayload:   65535,
	}
	server, err := NewRelayServer(config)
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}
	go server.Serve()

	stop := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
					conn, err := net.Dial("tcp", server.Addr().String())
					if err == nil {
						_ = conn.Close()
					}
				}
			}
		}()
	}

	time.Sleep(50 * time.Millisecond)

	start := time.Now()
	_ = server.Close()
	duration := time.Since(start)

	close(stop)
	wg.Wait()

	if duration > 200*time.Millisecond {
		t.Errorf("Close took too long to complete during concurrent accepts: %v", duration)
	}
}
