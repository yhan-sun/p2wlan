package main

import (
	"bytes"
	"fmt"
	"net"
	"os"
	"runtime"
	"sync"
	"testing"
	"time"
)

func TestPooledForwardSteadyStateDoesNotAllocate(t *testing.T) {
	hub := newHub()
	a := &peer{done: make(chan struct{}), send: make(chan queuedFrame, 8)}
	b := &peer{done: make(chan struct{}), send: make(chan queuedFrame, 8)}
	hub.register(a, "test-net", "alice")
	hub.register(b, "test-net", "bob")
	payload := bytes.Repeat([]byte{33}, 1300)
	const runs = 1000
	allocations := testing.AllocsPerRun(runs, func() {
		if code, details := hub.forward(a, "bob", payload, 65535); code != 0 {
			t.Fatalf("relay forward %d: %s", code, details)
		}
		frame := <-b.send
		if !bytes.Equal(frame.data[frameHeader+1+len(a.id):], payload) {
			t.Fatal("payload corruption")
		}
		b.releaseQueued(frame)
	})
	if allocations != 0 {
		t.Fatalf("steady-state relay forwarding allocated %g times per frame", allocations)
	}
	t.Logf("%d forwards, %g allocations per frame", runs, allocations)
}

func fdCount() int {
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		return -1
	}
	return len(entries)
}

func TestTransportSlowPeerIsolatedWithBoundedMemoryAndDescriptors(t *testing.T) {
	cfg := testConfig()
	cfg.Bind = "127.0.0.1:0"
	cfg.MaxConnections = 16
	cfg.SendQueueCapacity = 32
	// The suite warms netpoll when creating the server. This baseline includes
	// its listening descriptor and excludes all test clients.
	server, addr, cleanup := startTestServerWithInstance(t, cfg)
	defer cleanup()
	baselineFD := fdCount()
	connect := func(id string) *net.TCPConn {
		t.Helper()
		client, err := net.DialTimeout("tcp", addr, time.Second)
		if err != nil {
			t.Fatal(err)
		}
		socket := client.(*net.TCPConn)
		t.Cleanup(func() { _ = socket.Close() })
		_ = socket.SetDeadline(time.Now().Add(6 * time.Second))
		if err := writeFull(socket, makeFrame(msgRegister, []byte(id))); err != nil {
			t.Fatal(err)
		}
		if typ, payload := readTestFrame(t, socket); typ != msgRegistered || string(payload) != id {
			t.Fatalf("register %s: frame %d", id, typ)
		}
		return socket
	}
	slow := connect("slow")
	_ = slow.SetReadBuffer(1024)
	slowPeer := server.hub.lookup("", "slow")
	if slowPeer == nil {
		t.Fatal("slow connection was never registered")
	}
	_ = slowPeer.conn.(*net.TCPConn).SetWriteBuffer(1024)
	flood := connect("flood")
	defer flood.Close()
	target := func(id string, payload []byte) []byte {
		data := make([]byte, 1+len(id)+len(payload))
		data[0] = byte(len(id))
		copy(data[1:], id)
		copy(data[1+len(id):], payload)
		return makeFrame(msgForward, data)
	}
	traffic := target("slow", bytes.Repeat([]byte{73}, 16384))
	floodFinished := make(chan struct{})
	go func() {
		defer close(floodFinished)
		for range 1600 {
			if writeFull(flood, traffic) != nil {
				return
			}
		}
	}()
	floodRead := make(chan struct{})
	go func() {
		defer close(floodRead)
		buffer := make([]byte, 4096)
		for {
			if _, err := flood.Read(buffer); err != nil {
				return
			}
		}
	}()
	deadline := time.Now().Add(2 * time.Second)
	for server.statsSnapshot().ForwardErrorsTotal == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if server.statsSnapshot().ForwardErrorsTotal == 0 {
		t.Fatal("slow peer did not exert backpressure")
	}

	const peers = 4
	const exchanges = 256
	const packetBytes = 1300
	var group sync.WaitGroup
	started := time.Now()
	for index := range peers {
		aID, bID := fmt.Sprintf("a%d", index), fmt.Sprintf("b%d", index)
		a, b := connect(aID), connect(bID)
		group.Go(func() {
			defer a.Close()
			defer b.Close()
			payload := bytes.Repeat([]byte{byte(index)}, packetBytes)
			frame := target(bID, payload)
			for range exchanges {
				if err := writeFull(a, frame); err != nil {
					t.Error(err)
					return
				}
				typ, body := readTestFrame(t, b)
				id, got, ok := parsePeerPayload(body)
				if typ != msgReceived || !ok || id != aID || !bytes.Equal(got, payload) {
					t.Errorf("fast peer %s saw wrong payload", bID)
					return
				}
			}
		})
	}
	group.Wait()
	elapsed := time.Since(started)
	if elapsed > 3*time.Second {
		t.Fatalf("ordinary connections stalled for %s", elapsed)
	}
	slowPeer.queueMu.Lock()
	queued := slowPeer.queuedBytes
	slowPeer.queueMu.Unlock()
	if queued < 0 || queued > maxPeerQueuedBytes {
		t.Fatalf("slow peer retained %d bytes", queued)
	}
	_ = flood.Close()
	<-floodFinished
	<-floodRead
	cleanup()
	// Close is synchronous and must retire all connections and queue leases.
	stats := server.statsSnapshot()
	if stats.ActiveConnections != 0 || stats.RegisteredPeers != 0 {
		t.Fatalf("connections leaked after shutdown: %+v", stats)
	}
	slowPeer.queueMu.Lock()
	remaining := slowPeer.queuedBytes
	slowPeer.queueMu.Unlock()
	if remaining != 0 {
		t.Fatalf("%d bytes retained after socket shutdown", remaining)
	}
	// The Go side of the active sockets is closed by the server. Clients are
	// owned by this test and closed before taking the descriptor sample.
	for _, p := range []net.Conn{slow, flood} {
		_ = p.Close()
	}
	runtime.GC()
	finalFD := fdCount()
	if baselineFD >= 0 && finalFD > baselineFD {
		t.Fatalf("descriptor leak: listener baseline %d, after cleanup %d", baselineFD, finalFD)
	}
	t.Logf("%d fast forwards alongside slow peer in %s, %.2f Mbit/s, %d backpressure rejects, %d bytes at sample, listener baseline fd=%d final fd=%d",
		peers*exchanges, elapsed, float64(peers*exchanges*packetBytes*8)/elapsed.Seconds()/1e6, stats.ForwardErrorsTotal, queued, baselineFD, finalFD)
}
