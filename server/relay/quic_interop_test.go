package main

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestUDPFallbackWithRustClient(t *testing.T) {
	probe := os.Getenv("P2WLAN_RUST_RELAY_PROBE")
	if probe == "" {
		t.Skip("run scripts/validation/verify-relay-datagrams.sh to build the Rust peer")
	}
	cfg := testConfig()
	cfg.RequireAuthentication = true
	cfg.AllowInsecurePlaintext = false
	cfg.RelayAudience = "relay-test"
	cfg.RelayRegion = "test-region"
	cfg.IdleTimeout = 12 * time.Second
	pub, secret, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cfg.TicketKeyringJSON = fmt.Sprintf("{%q:%q}", "relay-test", hex.EncodeToString(pub))
	relayTestCertificate(t, cfg)

	bind, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	cfg.Bind = bind.Addr().String()
	cfg.UDPBind = "127.0.0.1:0"
	_ = bind.Close()
	server, addr, closeServer := startTestServerWithInstance(t, cfg)
	defer closeServer()
	blockUDP := startUDPRelayTestProxy(t, addr, server.datagramListener.Addr().(*net.UDPAddr))
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	client := exec.CommandContext(ctx, probe)
	client.Env = append(os.Environ(),
		"P2WLAN_VERIFY_RELAY_ENDPOINT=tls://"+addr,
		"P2WLAN_VERIFY_RELAY_CA="+cfg.TLSCertChainPath,
		"P2WLAN_VERIFY_RELAY_TICKET_A="+signRelayTicketForTest(t, secret, "relay-test", "relay-probe-jti-a", "relay-probe-a"),
		"P2WLAN_VERIFY_RELAY_TICKET_B="+signRelayTicketForTest(t, secret, "relay-test", "relay-probe-jti-b", "relay-probe-b"),
	)
	reader, err := client.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	client.Stderr = os.Stderr
	if err := client.Start(); err != nil {
		t.Fatal(err)
	}
	output := bufio.NewScanner(reader)
	sawUDP, sawTLS := false, false
	for output.Scan() {
		line := output.Text()
		t.Log(line)
		if line == "UDP bidirectional verified" {
			sawUDP = true
			blockUDP.Store(true)
		}
		if strings.HasPrefix(line, "TLS bidirectional verified,") {
			sawTLS = true
		}
	}
	if err := client.Wait(); err != nil {
		t.Fatalf("Rust client exited unsuccessfully: %v", err)
	}
	if err := output.Err(); err != nil {
		t.Fatal(err)
	}
	if !sawUDP || !sawTLS || server.statsSnapshot().AuthenticatedRegistrationsTotal != 4 {
		t.Fatalf("expected two authenticated UDP and two authenticated TLS registrations, UDP=%t TLS=%t stats=%+v", sawUDP, sawTLS, server.statsSnapshot())
	}
}

// Stand in for a firewall that silently drops UDP without closing either
// endpoint. The TCP connection goes straight to the same public address.
func startUDPRelayTestProxy(t *testing.T, bind string, backend *net.UDPAddr) *atomic.Bool {
	t.Helper()
	address, err := net.ResolveUDPAddr("udp4", bind)
	if err != nil {
		t.Fatal(err)
	}
	front, err := net.ListenUDP("udp4", address)
	if err != nil {
		t.Fatal(err)
	}
	var blocked atomic.Bool
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		upstreams := make(map[netip.AddrPort]*net.UDPConn)
		var readers sync.WaitGroup
		defer func() {
			for _, socket := range upstreams {
				_ = socket.Close()
			}
			readers.Wait()
		}()
		buffer := make([]byte, 65535)
		for {
			n, client, err := front.ReadFromUDPAddrPort(buffer)
			if err != nil {
				return
			}
			if blocked.Load() {
				continue
			}
			upstream := upstreams[client]
			if upstream == nil {
				upstream, err = net.DialUDP("udp4", nil, backend)
				if err != nil {
					return
				}
				upstreams[client] = upstream
				readers.Go(func() {
					reply := make([]byte, 65535)
					for {
						n, err := upstream.Read(reply)
						if err != nil {
							return
						}
						if !blocked.Load() {
							_, _ = front.WriteToUDPAddrPort(reply[:n], client)
						}
					}
				})
			}
			_, _ = upstream.Write(buffer[:n])
		}
	}()
	t.Cleanup(func() {
		_ = front.Close()
		<-finished
	})
	return &blocked
}
