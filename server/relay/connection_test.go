package main

import (
	"encoding/binary"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

type shortWriter struct {
	max int
	buf []byte
}

func (w *shortWriter) Write(data []byte) (int, error) {
	n := w.max
	if n > len(data) {
		n = len(data)
	}
	w.buf = append(w.buf, data[:n]...)
	return n, nil
}

func TestWriteFullHandlesShortWrites(t *testing.T) {
	w := &shortWriter{max: 3}
	want := []byte("complete relay frame")
	if err := writeFull(w, want); err != nil {
		t.Fatalf("writeFull: %v", err)
	}
	if string(w.buf) != string(want) {
		t.Fatalf("writeFull wrote %q, want %q", w.buf, want)
	}
}

func TestWriteFullRejectsZeroProgress(t *testing.T) {
	w := &shortWriter{max: 0}
	if err := writeFull(w, []byte("frame")); err != io.ErrShortWrite {
		t.Fatalf("writeFull error = %v, want io.ErrShortWrite", err)
	}
}

func TestSendQueueFullBackpressure(t *testing.T) {
	// Exercise the queue-full branch directly.  Driving this through a real
	// TCP connection is inherently racy: the destination writer can drain the
	// one-slot application queue into the kernel send buffer before the next
	// forward arrives, so the result depends on scheduler and socket-buffer
	// timing rather than relay backpressure semantics.
	h := newHub()
	dstServer, dstClient := net.Pipe()
	defer dstClient.Close()
	dst := &peer{
		id:        "bob",
		networkID: "",
		conn:      dstServer,
		send:      make(chan []byte, 1),
		done:      make(chan struct{}),
	}
	h.register(dst, "", "bob")
	// Occupy the only slot; the next frame must take the deterministic 4008
	// path without relying on whether a writer goroutine happened to run.
	dst.send <- []byte("already queued")

	code, message := h.forward("", "alice", "bob", []byte("payload"), 65535)
	if code != 4008 {
		t.Fatalf("forward code = %d, want 4008 (message=%q)", code, message)
	}
	if message != "peer backpressure: bob" {
		t.Fatalf("forward message = %q, want peer backpressure", message)
	}
}

func TestRegisterTimeout(t *testing.T) {
	config := testConfig()
	config.RegisterTimeout = 100 * time.Millisecond
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
	config := testConfig()
	config.IdleTimeout = 100 * time.Millisecond
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
	config := testConfig()
	config.MaxConnections = 1
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
	config := testConfig()
	config.MaxFramePayload = 10
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
	config := testConfig()
	config.MaxFramePayload = 30
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

func TestRelayStatsTrackRegistrationLimitsAndForwarding(t *testing.T) {
	config := testConfig()
	config.MaxConnections = 2
	server, addr, cleanup := startTestServerWithInstance(t, config)
	defer cleanup()

	bob, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial bob: %v", err)
	}
	defer bob.Close()
	_, _ = bob.Write(makeFrame(msgRegister, []byte("bob")))
	typ, payload := readTestFrame(t, bob)
	if typ != msgRegistered || string(payload) != "bob" {
		t.Fatalf("unexpected bob registration frame: type=%d payload=%q", typ, string(payload))
	}

	alice, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial alice: %v", err)
	}
	defer alice.Close()
	_, _ = alice.Write(makeFrame(msgRegister, []byte("alice")))
	typ, payload = readTestFrame(t, alice)
	if typ != msgRegistered || string(payload) != "alice" {
		t.Fatalf("unexpected alice registration frame: type=%d payload=%q", typ, string(payload))
	}

	extra, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial extra: %v", err)
	}
	defer extra.Close()
	typ, payload = readTestFrame(t, extra)
	if typ != msgError || binary.BigEndian.Uint16(payload[:2]) != 4005 {
		t.Fatalf("expected connection-limit error, got type=%d payload=%v", typ, payload)
	}

	forward := func(dst string, data []byte) []byte {
		payload := make([]byte, 1+len(dst)+len(data))
		payload[0] = byte(len(dst))
		copy(payload[1:], dst)
		copy(payload[1+len(dst):], data)
		return payload
	}

	_, _ = alice.Write(makeFrame(msgForward, forward("bob", []byte("hello"))))
	typ, payload = readTestFrame(t, bob)
	if typ != msgReceived {
		t.Fatalf("expected received frame for bob, got type=%d payload=%v", typ, payload)
	}
	_, _ = alice.Write(makeFrame(msgForward, forward("missing", []byte("hello"))))
	typ, payload = readTestFrame(t, alice)
	if typ != msgError || binary.BigEndian.Uint16(payload[:2]) != 404 {
		t.Fatalf("expected peer-not-found error, got type=%d payload=%v", typ, payload)
	}

	stats := server.Stats()
	if stats.AcceptedConnectionsTotal != 2 || stats.RejectedConnectionsTotal != 1 {
		t.Fatalf("unexpected connection stats: %+v", stats)
	}
	if stats.LegacyRegistrationsTotal != 2 || stats.RegisteredPeers != 2 {
		t.Fatalf("unexpected registration stats: %+v", stats)
	}
	if stats.ForwardedFramesTotal != 1 || stats.ForwardErrorsTotal != 1 {
		t.Fatalf("unexpected forwarding stats: %+v", stats)
	}
}

func TestDuplicateRegistration(t *testing.T) {
	config := testConfig()
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

func TestServerCloseReclaimsImmediately(t *testing.T) {
	config := testConfig()
	config.RegisterTimeout = 10 * time.Second
	config.IdleTimeout = 1 * time.Hour
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
	config := testConfig()
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
	config := testConfig()
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
