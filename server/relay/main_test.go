package main

import (
	"bytes"
	"encoding/binary"
	"net"
	"testing"
	"time"
)

func TestEnvValidation(t *testing.T) {
	t.Setenv("RELAY_MAX_CONNECTIONS", "abc")
	_, err := parseConfig(nil)
	if err == nil {
		t.Error("expected error for invalid RELAY_MAX_CONNECTIONS env value, got nil")
	}
}

func TestRevocationPollIntervalEnvValidation(t *testing.T) {
	t.Setenv("RELAY_REVOCATION_POLL_INTERVAL", "not-a-duration")
	_, err := parseConfig([]string{"-require-auth=false"})
	if err == nil {
		t.Fatal("expected error for invalid RELAY_REVOCATION_POLL_INTERVAL env value")
	}
}

func TestConfigValidation(t *testing.T) {
	// Test invalid config values reject on parseConfig
	_, err := parseConfig([]string{"-send-queue=0"})
	if err == nil {
		t.Error("expected error for 0 send queue capacity")
	}

	// Test valid configuration parsing (with auth disabled for test)
	cfg, err := parseConfig([]string{"-send-queue=64", "-register-timeout=10s", "-require-auth=false"})
	if err != nil {
		t.Fatalf("unexpected parsing error: %v", err)
	}
	if cfg.SendQueueCapacity != 64 {
		t.Errorf("expected SendQueueCapacity 64, got %d", cfg.SendQueueCapacity)
	}
	if cfg.RegisterTimeout != 10*time.Second {
		t.Errorf("expected RegisterTimeout 10s, got %v", cfg.RegisterTimeout)
	}

	_, err = parseConfig([]string{"-require-auth=false", "-revocation-feed-url=https://control.example.test/api/v1/relay/revocations"})
	if err == nil {
		t.Fatal("expected error when revocation feed URL is configured without token")
	}
}

func TestUDPObserverRespondsToSTUNBindingRequest(t *testing.T) {
	config := testConfig()
	config.UDPObserverBind = "127.0.0.1:0"
	server, _, cleanup := startTestServerWithInstance(t, config)
	defer cleanup()

	observerAddr := server.UDPObserverAddr()
	if observerAddr == nil {
		t.Fatal("expected UDP observer address")
	}

	conn, err := net.Dial("udp", observerAddr.String())
	if err != nil {
		t.Fatalf("dial observer: %v", err)
	}
	defer conn.Close()

	transactionID := []byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x10, 0x32, 0x54, 0x76}
	request := make([]byte, stunHeaderLen)
	binary.BigEndian.PutUint16(request[0:2], stunBindingRequest)
	binary.BigEndian.PutUint32(request[4:8], stunMagicCookie)
	copy(request[8:20], transactionID)

	if err := conn.SetDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}
	if _, err := conn.Write(request); err != nil {
		t.Fatalf("write STUN request: %v", err)
	}

	response := make([]byte, 256)
	n, err := conn.Read(response)
	if err != nil {
		t.Fatalf("read STUN response: %v", err)
	}
	response = response[:n]
	if len(response) < stunHeaderLen+12 {
		t.Fatalf("short STUN response: %d bytes", len(response))
	}
	if got := binary.BigEndian.Uint16(response[0:2]); got != stunBindingResponse {
		t.Fatalf("response type = 0x%04x, want 0x%04x", got, stunBindingResponse)
	}
	if got := binary.BigEndian.Uint32(response[4:8]); got != stunMagicCookie {
		t.Fatalf("magic cookie = 0x%08x, want 0x%08x", got, stunMagicCookie)
	}
	if !bytes.Equal(response[8:20], transactionID) {
		t.Fatalf("transaction ID mismatch")
	}
	if got := binary.BigEndian.Uint16(response[20:22]); got != stunXorMappedAddr {
		t.Fatalf("attribute type = 0x%04x, want 0x%04x", got, stunXorMappedAddr)
	}
	if got := binary.BigEndian.Uint16(response[22:24]); got != 8 {
		t.Fatalf("XOR-MAPPED-ADDRESS length = %d, want 8", got)
	}
	if response[25] != 0x01 {
		t.Fatalf("XOR-MAPPED-ADDRESS family = %d, want IPv4", response[25])
	}

	localAddr := conn.LocalAddr().(*net.UDPAddr)
	gotPort := binary.BigEndian.Uint16(response[26:28]) ^ uint16(stunMagicCookie>>16)
	if gotPort != uint16(localAddr.Port) {
		t.Fatalf("mapped port = %d, want %d", gotPort, localAddr.Port)
	}
	cookie := make([]byte, 4)
	binary.BigEndian.PutUint32(cookie, stunMagicCookie)
	gotIP := make(net.IP, 4)
	for i := 0; i < 4; i++ {
		gotIP[i] = response[28+i] ^ cookie[i]
	}
	if !gotIP.Equal(localAddr.IP.To4()) {
		t.Fatalf("mapped IP = %s, want %s", gotIP, localAddr.IP)
	}

	stats := server.Stats()
	if stats.UDPObserverRequestsTotal != 1 {
		t.Fatalf("expected one observer request, got %+v", stats)
	}
}

func TestAuthFailureRateLimitConfigValidation(t *testing.T) {
	cfg, err := parseConfig([]string{"-require-auth=false", "-auth-failure-limit=7", "-auth-failure-window=2m"})
	if err != nil {
		t.Fatalf("unexpected parsing error: %v", err)
	}
	if cfg.AuthFailureLimit != 7 || cfg.AuthFailureWindow != 2*time.Minute {
		t.Fatalf("unexpected auth failure limit config: %+v", cfg)
	}

	if _, err := parseConfig([]string{"-require-auth=false", "-auth-failure-limit=-1"}); err == nil {
		t.Fatal("expected error for negative auth failure limit")
	}
	if _, err := parseConfig([]string{"-require-auth=false", "-auth-failure-limit=1", "-auth-failure-window=0s"}); err == nil {
		t.Fatal("expected error for enabled auth failure limit with zero window")
	}

	cfg, err = parseConfig([]string{"-require-auth=false", "-auth-failure-limit=0", "-auth-failure-window=0s"})
	if err != nil {
		t.Fatalf("disabled auth failure limiter should allow zero window: %v", err)
	}
	if cfg.AuthFailureLimit != 0 {
		t.Fatalf("expected disabled auth failure limiter, got %d", cfg.AuthFailureLimit)
	}
}
