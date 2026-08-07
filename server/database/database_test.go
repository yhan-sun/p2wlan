package database

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestDatabase_CreateDevice_UniqueIPAllocation(t *testing.T) {
	// Use a temporary DB file
	tmpFile := "test_p2wlan_db.db"
	defer os.Remove(tmpFile)
	defer os.Remove(tmpFile + "-shm")
	defer os.Remove(tmpFile + "-wal")

	db, err := New(tmpFile)
	if err != nil {
		t.Fatalf("Failed to create database: %v", err)
	}
	defer db.Close()

	// 1. Create a user
	user, err := db.CreateUser("test@p2wlan.local", "hashpwd")
	if err != nil {
		t.Fatalf("Failed to create user: %v", err)
	}

	// 2. Create multiple devices concurrently to verify transaction safety and unique IP allocations
	const deviceCount = 10
	var wg sync.WaitGroup
	errorsChan := make(chan error, deviceCount)
	devicesChan := make(chan *Device, deviceCount)

	for i := 0; i < deviceCount; i++ {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()
			pubKey := fmt.Sprintf("%02d-pubkey-device", index)
			devName := fmt.Sprintf("device-%d", index)
			device, err := db.CreateDevice(user.ID, "default", pubKey, devName, "linux", "")
			if err != nil {
				errorsChan <- err
				return
			}
			devicesChan <- device
		}(i)
	}

	wg.Wait()
	close(errorsChan)
	close(devicesChan)

	for err := range errorsChan {
		t.Errorf("Device registration failed: %v", err)
	}

	// Gather all allocated virtual IPs and check uniqueness
	allocatedIPs := make(map[string]bool)
	for dev := range devicesChan {
		if allocatedIPs[dev.VirtualIP] {
			t.Errorf("Duplicate virtual IP allocated: %s", dev.VirtualIP)
		}
		allocatedIPs[dev.VirtualIP] = true
	}

	// Verify count
	if len(allocatedIPs) != deviceCount {
		t.Errorf("Expected %d unique IPs, got %d", deviceCount, len(allocatedIPs))
	}
}

func TestCreateTunnelAutoAllocatesRemotePorts(t *testing.T) {
	db, device := createTestDevice(t, "auto-tunnel@p2wlan.local", "auto-tunnel-device")
	defer db.Close()

	first, err := db.CreateTunnel(device.ID, "tcp", 8080, 0, "127.0.0.1")
	if err != nil {
		t.Fatalf("CreateTunnel first failed: %v", err)
	}
	second, err := db.CreateTunnel(device.ID, "tcp", 8081, 0, "127.0.0.1")
	if err != nil {
		t.Fatalf("CreateTunnel second failed: %v", err)
	}

	if first.RemotePort != tunnelPortStart {
		t.Fatalf("expected first auto port %d, got %d", tunnelPortStart, first.RemotePort)
	}
	if second.RemotePort != tunnelPortStart+1 {
		t.Fatalf("expected second auto port %d, got %d", tunnelPortStart+1, second.RemotePort)
	}
	if first.PublicEndpoint != fmt.Sprintf("relay.p2pnet.io:%d", first.RemotePort) {
		t.Fatalf("unexpected public endpoint: %s", first.PublicEndpoint)
	}
}

func TestCreateTunnelRejectsDuplicateProtocolPort(t *testing.T) {
	db, device := createTestDevice(t, "dup-tunnel@p2wlan.local", "dup-tunnel-device")
	defer db.Close()

	if _, err := db.CreateTunnel(device.ID, "tcp", 8080, 32000, "127.0.0.1"); err != nil {
		t.Fatalf("CreateTunnel initial failed: %v", err)
	}
	if _, err := db.CreateTunnel(device.ID, "tcp", 8081, 32000, "127.0.0.1"); err == nil {
		t.Fatal("expected duplicate tcp remote port to fail")
	} else if err != ErrTunnelPortInUse {
		t.Fatalf("expected ErrTunnelPortInUse, got %v", err)
	}

	if _, err := db.CreateTunnel(device.ID, "udp", 8081, 32000, "127.0.0.1"); err != nil {
		t.Fatalf("same numeric port should be allowed for udp after tcp allocation: %v", err)
	}
}

func TestSignalsKeepEverySignalInServerSequenceOrder(t *testing.T) {
	db, device := createTestDevice(t, "signal-seq@p2wlan.local", "signal-seq-source")
	defer db.Close()

	target, err := db.CreateDevice(device.UserID, "default", "signal-seq-target-pubkey", "signal-seq-target", "linux", "")
	if err != nil {
		t.Fatalf("CreateDevice target failed: %v", err)
	}

	if _, err := db.CreateSignal(device.ID, target.ID, "peer_offer", []string{"old"}, nil, "old-handshake"); err != nil {
		t.Fatalf("CreateSignal old failed: %v", err)
	}
	if _, err := db.CreateSignal(device.ID, target.ID, "peer_offer", []string{"new"}, map[string]string{"new": "predicted"}, "new-handshake"); err != nil {
		t.Fatalf("CreateSignal new failed: %v", err)
	}

	signals, err := db.ListAndDeleteSignals(target.ID)
	if err != nil {
		t.Fatalf("ListAndDeleteSignals failed: %v", err)
	}
	// The server never last-write-wins: both signals are delivered in send
	// order, and the receiver's candidate-generation high-water is the
	// authority on supersession.
	if len(signals) != 2 {
		t.Fatalf("expected both signals in send order, got %d", len(signals))
	}
	if signals[0].Handshake != "old-handshake" {
		t.Fatalf("expected first signal in send order, got %q", signals[0].Handshake)
	}
	if signals[1].Handshake != "new-handshake" {
		t.Fatalf("expected second signal in send order, got %q", signals[1].Handshake)
	}
	if signals[0].SignalSeq >= signals[1].SignalSeq {
		t.Fatalf("expected strictly increasing server sequence, got %d then %d", signals[0].SignalSeq, signals[1].SignalSeq)
	}
}

func TestSignalsLateArrivingOlderSignalNeverDeletesNewerOne(t *testing.T) {
	db, device := createTestDevice(t, "signal-g2-first@p2wlan.local", "signal-g2-first-source")
	defer db.Close()

	target, err := db.CreateDevice(device.UserID, "default", "signal-g2-first-target-pubkey", "signal-g2-first-target", "linux", "")
	if err != nil {
		t.Fatalf("CreateDevice target failed: %v", err)
	}

	// G2 is queued first, then G1 arrives late (older candidate generation).
	if _, err := db.CreateSignalWithTraversalMetadata(device.ID, target.ID, "peer_offer", []string{"g2-candidate"}, nil, "g2-handshake", 0, 2, 0); err != nil {
		t.Fatalf("CreateSignal G2 failed: %v", err)
	}
	if _, err := db.CreateSignalWithTraversalMetadata(device.ID, target.ID, "peer_offer", []string{"g1-candidate"}, nil, "g1-handshake", 0, 1, 0); err != nil {
		t.Fatalf("CreateSignal G1 failed: %v", err)
	}

	signals, err := db.ListAndDeleteSignals(target.ID)
	if err != nil {
		t.Fatalf("ListAndDeleteSignals failed: %v", err)
	}
	if len(signals) != 2 {
		t.Fatalf("the late-arriving G1 must not delete the already-queued G2; got %d signals", len(signals))
	}
	if signals[0].Handshake != "g2-handshake" || signals[0].CandidateGeneration != 2 {
		t.Fatalf("expected G2 first in delivery order, got %#v", signals[0])
	}
	if signals[1].Handshake != "g1-handshake" || signals[1].CandidateGeneration != 1 {
		t.Fatalf("expected G1 second in delivery order, got %#v", signals[1])
	}
}

func TestFreshSignalSurvivesOrdinaryRefresh(t *testing.T) {
	db, device := createTestDevice(t, "signal-fresh@p2wlan.local", "signal-fresh-source")
	defer db.Close()

	target, err := db.CreateDevice(device.UserID, "default", "signal-fresh-target-pubkey", "signal-fresh-target", "linux", "")
	if err != nil {
		t.Fatalf("CreateDevice target failed: %v", err)
	}

	// A fresh-mapping prediction advertisement on the independent queue key...
	fresh := map[string]string{"203.0.113.10:45393": "predicted_fresh:1742987654321:7"}
	if _, err := db.CreateSignalWithTraversalMetadata(device.ID, target.ID, "peer_offer_fresh", []string{"203.0.113.10:45393"}, fresh, "", 0, 5, 0); err != nil {
		t.Fatalf("CreateSignal fresh failed: %v", err)
	}
	// ...followed by an ordinary candidate refresh for the same peer pair.
	if _, err := db.CreateSignalWithTraversalMetadata(device.ID, target.ID, "peer_offer", []string{"203.0.113.10:42000"}, map[string]string{"203.0.113.10:42000": "stun_observed"}, "", 0, 6, 0); err != nil {
		t.Fatalf("CreateSignal refresh failed: %v", err)
	}

	signals, err := db.ListAndDeleteSignals(target.ID)
	if err != nil {
		t.Fatalf("ListAndDeleteSignals failed: %v", err)
	}
	if len(signals) != 2 {
		t.Fatalf("the ordinary refresh must not overwrite the fresh prediction; got %d signals", len(signals))
	}
	if signals[0].Type != "peer_offer_fresh" || signals[0].CandidateSources["203.0.113.10:45393"] != "predicted_fresh:1742987654321:7" {
		t.Fatalf("expected the fresh prediction first with its label intact, got %#v", signals[0])
	}
	if signals[1].Type != "peer_offer" {
		t.Fatalf("expected the ordinary refresh second, got %#v", signals[1])
	}
}

func TestSignalsWithinSameSecondStayInSendOrder(t *testing.T) {
	db, device := createTestDevice(t, "signal-same-second@p2wlan.local", "signal-same-second-source")
	defer db.Close()

	target, err := db.CreateDevice(device.UserID, "default", "signal-same-second-target-pubkey", "signal-same-second-target", "linux", "")
	if err != nil {
		t.Fatalf("CreateDevice target failed: %v", err)
	}

	if _, err := db.CreateSignal(device.ID, target.ID, "peer_offer", []string{"first"}, nil, "first-handshake"); err != nil {
		t.Fatalf("CreateSignal first failed: %v", err)
	}
	if _, err := db.CreateSignal(device.ID, target.ID, "peer_offer", []string{"second"}, nil, "second-handshake"); err != nil {
		t.Fatalf("CreateSignal second failed: %v", err)
	}
	// Force identical wall-clock seconds: ordering must come from the server
	// sequence, never from the per-second wall clock.
	if _, err := db.Exec(`UPDATE signals SET created_at = ?`, time.Now().Unix()); err != nil {
		t.Fatalf("failed to normalize created_at: %v", err)
	}

	signals, err := db.ListAndDeleteSignals(target.ID)
	if err != nil {
		t.Fatalf("ListAndDeleteSignals failed: %v", err)
	}
	if len(signals) != 2 || signals[0].Handshake != "first-handshake" || signals[1].Handshake != "second-handshake" {
		t.Fatalf("expected send order despite identical wall-clock seconds, got %#v", signals)
	}
}

func TestSignalsPreservePunchAtMS(t *testing.T) {
	db, device := createTestDevice(t, "signal-punch-window@p2wlan.local", "signal-punch-source")
	defer db.Close()

	target, err := db.CreateDevice(device.UserID, "default", "signal-punch-target-pubkey", "signal-punch-target", "linux", "")
	if err != nil {
		t.Fatalf("CreateDevice target failed: %v", err)
	}

	const punchAtMS int64 = 1_777_000_001_234
	if _, err := db.CreateSignalWithPunchAt(
		device.ID,
		target.ID,
		"peer_reflexive",
		[]string{"203.0.113.10:51820"},
		map[string]string{"203.0.113.10:51820": "peer_reflexive"},
		"",
		punchAtMS,
	); err != nil {
		t.Fatalf("CreateSignalWithPunchAt failed: %v", err)
	}

	signals, err := db.ListAndDeleteSignals(target.ID)
	if err != nil {
		t.Fatalf("ListAndDeleteSignals failed: %v", err)
	}
	if len(signals) != 1 {
		t.Fatalf("expected one signal, got %d", len(signals))
	}
	if signals[0].PunchAtMS != punchAtMS {
		t.Fatalf("expected punch_at_ms %d, got %d", punchAtMS, signals[0].PunchAtMS)
	}
	if got := signals[0].CandidateSources["203.0.113.10:51820"]; got != "peer_reflexive" {
		t.Fatalf("expected peer_reflexive source, got %q", got)
	}
}

func TestSignalsPreserveCandidateSetMetadata(t *testing.T) {
	db, device := createTestDevice(t, "signal-metadata@p2wlan.local", "signal-metadata-source")
	defer db.Close()
	target, err := db.CreateDevice(device.UserID, "default", "signal-metadata-target-pubkey", "signal-metadata-target", "linux", "")
	if err != nil {
		t.Fatalf("CreateDevice target failed: %v", err)
	}

	const generation int64 = 42
	const expiresAtMS int64 = 1_777_000_123_456
	if _, err := db.CreateSignalWithTraversalMetadata(
		device.ID, target.ID, "peer_offer", []string{"203.0.113.10:51820"},
		map[string]string{"203.0.113.10:51820": "upnp"}, "handshake", 0, generation, expiresAtMS,
	); err != nil {
		t.Fatalf("CreateSignalWithTraversalMetadata failed: %v", err)
	}

	signals, err := db.ListAndDeleteSignals(target.ID)
	if err != nil {
		t.Fatalf("ListAndDeleteSignals failed: %v", err)
	}
	if len(signals) != 1 || signals[0].CandidateGeneration != generation || signals[0].CandidatesExpiresAtMS != expiresAtMS {
		t.Fatalf("candidate metadata was not preserved: %#v", signals)
	}
}

func TestSignalsPreserveSessionID(t *testing.T) {
	db, device := createTestDevice(t, "signal-session@p2wlan.local", "signal-session-source")
	defer db.Close()
	target, err := db.CreateDevice(device.UserID, "default", "signal-session-target-pubkey", "signal-session-target", "linux", "")
	if err != nil {
		t.Fatalf("CreateDevice target failed: %v", err)
	}

	const sessionID = "0123456789abcdef0123456789abcdef"
	const probeEphemeralPublicKey = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
	if _, err := db.CreateSignalWithTraversalSession(
		device.ID, target.ID, "peer_offer", SignalProtocolVersion, []string{"203.0.113.10:51820"}, nil, "handshake", 0, 7, 0, sessionID, probeEphemeralPublicKey, "sender-fingerprint",
	); err != nil {
		t.Fatalf("CreateSignalWithTraversalSession failed: %v", err)
	}

	signals, err := db.ListAndDeleteSignals(target.ID)
	if err != nil {
		t.Fatalf("ListAndDeleteSignals failed: %v", err)
	}
	if len(signals) != 1 || signals[0].SessionID != sessionID || signals[0].ProbeEphemeralPublicKey != probeEphemeralPublicKey {
		t.Fatalf("session key material was not preserved: %#v", signals)
	}
	if signals[0].ProtocolVersion != SignalProtocolVersion {
		t.Fatalf("protocol version was not preserved: %#v", signals)
	}
}

func TestSignalsIgnoreExpiredRows(t *testing.T) {
	db, device := createTestDevice(t, "signal-ttl@p2wlan.local", "signal-ttl-source")
	defer db.Close()

	target, err := db.CreateDevice(device.UserID, "default", "signal-ttl-target-pubkey", "signal-ttl-target", "linux", "")
	if err != nil {
		t.Fatalf("CreateDevice target failed: %v", err)
	}

	if _, err := db.CreateSignal(device.ID, target.ID, "peer_offer", []string{"stale"}, nil, "stale-handshake"); err != nil {
		t.Fatalf("CreateSignal stale failed: %v", err)
	}
	_, err = db.Exec(`UPDATE signals SET created_at = ? WHERE to_node_id = ?`, time.Now().Unix()-signalTTLSeconds-1, target.ID)
	if err != nil {
		t.Fatalf("failed to age signal: %v", err)
	}

	signals, err := db.ListAndDeleteSignals(target.ID)
	if err != nil {
		t.Fatalf("ListAndDeleteSignals failed: %v", err)
	}
	if len(signals) != 0 {
		t.Fatalf("expected expired signal to be ignored, got %d", len(signals))
	}
}

func createTestDevice(t *testing.T, email, deviceName string) (*DB, *Device) {
	t.Helper()

	db, err := New(filepath.Join(t.TempDir(), "p2wlan.db"))
	if err != nil {
		t.Fatalf("New database: %v", err)
	}

	user, err := db.CreateUser(email, "pwd")
	if err != nil {
		db.Close()
		t.Fatalf("CreateUser failed: %v", err)
	}

	device, err := db.CreateDevice(user.ID, "default", deviceName+"-pubkey", deviceName, "linux", "")
	if err != nil {
		db.Close()
		t.Fatalf("CreateDevice failed: %v", err)
	}

	return db, device
}

func TestUpdateDeviceName(t *testing.T) {
	db, device := createTestDevice(t, "rename@p2wlan.local", "old-name")
	defer db.Close()

	if err := db.UpdateDeviceName(device.ID, "studio-mac"); err != nil {
		t.Fatalf("UpdateDeviceName failed: %v", err)
	}
	updated, err := db.GetDevice(device.ID)
	if err != nil {
		t.Fatalf("GetDevice failed: %v", err)
	}
	if updated.DeviceName != "studio-mac" {
		t.Fatalf("expected updated name, got %q", updated.DeviceName)
	}
}

func TestCreateDeviceWithOptionsStoresRequestedIPAndVersion(t *testing.T) {
	db, err := New(filepath.Join(t.TempDir(), "p2wlan.db"))
	if err != nil {
		t.Fatalf("New database: %v", err)
	}
	defer db.Close()

	user, err := db.CreateUser("versioned-device@p2wlan.local", "pwd")
	if err != nil {
		t.Fatalf("CreateUser failed: %v", err)
	}

	device, err := db.CreateDeviceWithOptions(
		user.ID,
		"default",
		"versioned-device-pubkey",
		"studio",
		"macos",
		"",
		"10.20.0.42",
		"0.1.68",
	)
	if err != nil {
		t.Fatalf("CreateDeviceWithOptions failed: %v", err)
	}
	if device.VirtualIP != "10.20.0.42" {
		t.Fatalf("expected requested IP, got %q", device.VirtualIP)
	}
	if device.AppVersion != "0.1.68" {
		t.Fatalf("expected app version, got %q", device.AppVersion)
	}

	updated, err := db.CreateDeviceWithOptions(
		user.ID,
		"default",
		"versioned-device-pubkey",
		"studio-renamed",
		"macos",
		"",
		"10.20.0.43",
		"",
	)
	if err != nil {
		t.Fatalf("CreateDeviceWithOptions update failed: %v", err)
	}
	if updated.ID != device.ID {
		t.Fatalf("expected existing device update, got %q want %q", updated.ID, device.ID)
	}
	if updated.VirtualIP != "10.20.0.43" {
		t.Fatalf("expected updated requested IP, got %q", updated.VirtualIP)
	}
	if updated.AppVersion != "0.1.68" {
		t.Fatalf("empty app_version should preserve previous value, got %q", updated.AppVersion)
	}
}

func TestUpdateDeviceVirtualIPValidatesNetworkPool(t *testing.T) {
	db, err := New(filepath.Join(t.TempDir(), "p2wlan.db"))
	if err != nil {
		t.Fatalf("New database: %v", err)
	}
	defer db.Close()

	user, err := db.CreateUser("custom-ip@p2wlan.local", "pwd")
	if err != nil {
		t.Fatalf("CreateUser failed: %v", err)
	}
	first, err := db.CreateDevice(user.ID, "default", "custom-ip-a", "device-a", "macos", "")
	if err != nil {
		t.Fatalf("CreateDevice first failed: %v", err)
	}
	second, err := db.CreateDevice(user.ID, "default", "custom-ip-b", "device-b", "macos", "")
	if err != nil {
		t.Fatalf("CreateDevice second failed: %v", err)
	}

	if err := db.UpdateDeviceVirtualIP(first.ID, "10.20.0.50"); err != nil {
		t.Fatalf("UpdateDeviceVirtualIP valid IP failed: %v", err)
	}
	updated, err := db.GetDevice(first.ID)
	if err != nil {
		t.Fatalf("GetDevice first failed: %v", err)
	}
	if updated.VirtualIP != "10.20.0.50" {
		t.Fatalf("expected custom virtual IP, got %q", updated.VirtualIP)
	}

	for _, tc := range []struct {
		name      string
		deviceID  string
		virtualIP string
		wantError string
	}{
		{name: "duplicate", deviceID: second.ID, virtualIP: "10.20.0.50", wantError: "already assigned"},
		{name: "outside cidr", deviceID: first.ID, virtualIP: "10.30.0.50", wantError: "outside network CIDR"},
		{name: "network address", deviceID: first.ID, virtualIP: "10.20.0.0", wantError: "network or broadcast"},
		{name: "broadcast address", deviceID: first.ID, virtualIP: "10.20.255.255", wantError: "network or broadcast"},
		{name: "not ipv4", deviceID: first.ID, virtualIP: "not-an-ip", wantError: "IPv4"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := db.UpdateDeviceVirtualIP(tc.deviceID, tc.virtualIP)
			if err == nil {
				t.Fatalf("expected %q to fail", tc.virtualIP)
			}
			if !strings.Contains(err.Error(), tc.wantError) {
				t.Fatalf("expected error containing %q, got %v", tc.wantError, err)
			}
		})
	}
}

func TestDatabase_UniqueConstraints(t *testing.T) {
	tmpFile := "test_unique_db.db"
	defer os.Remove(tmpFile)
	defer os.Remove(tmpFile + "-shm")
	defer os.Remove(tmpFile + "-wal")

	db, err := New(tmpFile)
	if err != nil {
		t.Fatalf("Failed to create database: %v", err)
	}
	defer db.Close()

	user, _ := db.CreateUser("user@p2wlan.local", "pwd")

	// Create device A
	_, err = db.CreateDevice(user.ID, "default", "pubkey-a", "device-a", "linux", "")
	if err != nil {
		t.Fatalf("CreateDevice failed: %v", err)
	}

	// Try to create device B with duplicate public key -> should return existing or update, not fail
	devB, err := db.CreateDevice(user.ID, "default", "pubkey-a", "device-b", "linux", "")
	if err != nil {
		t.Fatalf("Expected duplicate public key update to pass, but got: %v", err)
	}
	if devB.DeviceName != "device-b" {
		t.Errorf("Expected device name to be updated to device-b, got %s", devB.DeviceName)
	}

	// Try to register the same public key with another user -> should fail (Stage 2 requirement check)
	userB, _ := db.CreateUser("user-b@p2wlan.local", "pwd")
	_, err = db.CreateDevice(userB.ID, "default", "pubkey-a", "device-c", "linux", "")
	if err == nil {
		t.Error("Expected failure when registering same public key under a different user, but succeeded")
	}
}

func TestSignalQueueLimitsRejectFloods(t *testing.T) {
	// Per-pair row bound: the flood fills the pair and the next write is
	// rejected with a clear queue-limit error instead of unbounded growth.
	t.Run("pair_rows", func(t *testing.T) {
		db, device := createTestDevice(t, "signal-flood@p2wlan.local", "signal-flood-source")
		defer db.Close()
		target, err := db.CreateDevice(device.UserID, "default", "signal-flood-target-pubkey", "signal-flood-target", "linux", "")
		if err != nil {
			t.Fatalf("CreateDevice target failed: %v", err)
		}
		for i := 0; i < MaxSignalsPerPair; i++ {
			if _, err := db.CreateSignal(device.ID, target.ID, "peer_offer", []string{"candidate"}, nil, "0102"); err != nil {
				t.Fatalf("CreateSignal %d failed: %v", i, err)
			}
		}
		if _, err := db.CreateSignal(device.ID, target.ID, "peer_offer", []string{"candidate"}, nil, "0102"); !errors.Is(err, ErrSignalQueueLimit) {
			t.Fatalf("expected ErrSignalQueueLimit for a full pair, got %v", err)
		}
	})

	// Per-sender frequency bound: one sender cannot flood many pairs.  The
	// writes are spread across three targets so the pair bound (256) never
	// trips before the frequency bound (300).
	t.Run("sender_frequency", func(t *testing.T) {
		db, device := createTestDevice(t, "signal-rate@p2wlan.local", "signal-rate-source")
		defer db.Close()
		var targets []*Device
		for i := 0; i < 3; i++ {
			target, err := db.CreateDevice(device.UserID, "default", fmt.Sprintf("signal-rate-target-%d-pubkey", i), fmt.Sprintf("signal-rate-target-%d", i), "linux", "")
			if err != nil {
				t.Fatalf("CreateDevice target %d failed: %v", i, err)
			}
			targets = append(targets, target)
		}
		created := 0
		for created < MaxSignalCreatesPerSenderPerMinute {
			for _, target := range targets {
				if created >= MaxSignalCreatesPerSenderPerMinute {
					break
				}
				if _, err := db.CreateSignal(device.ID, target.ID, "peer_offer", []string{"candidate"}, nil, "0102"); err != nil {
					t.Fatalf("CreateSignal rate %d failed: %v", created, err)
				}
				created++
			}
		}
		if _, err := db.CreateSignal(device.ID, targets[0].ID, "peer_offer", []string{"candidate"}, nil, "0102"); !errors.Is(err, ErrSignalQueueLimit) {
			t.Fatalf("expected ErrSignalQueueLimit for sender frequency, got %v", err)
		}
	})

	// Global row bound.  The rows are bulk-inserted in one transaction (the
	// per-pair bound would otherwise trip first at 256 rows per pair); the
	// enforcement under test is that a fresh pair still hits the global cap.
	t.Run("global", func(t *testing.T) {
		db, device := createTestDevice(t, "signal-global@p2wlan.local", "signal-global-source")
		defer db.Close()
		target, err := db.CreateDevice(device.UserID, "default", "signal-global-target-pubkey", "signal-global-target", "linux", "")
		if err != nil {
			t.Fatalf("CreateDevice global target failed: %v", err)
		}
		tx, err := db.Begin()
		if err != nil {
			t.Fatalf("begin bulk insert: %v", err)
		}
		now := time.Now().Unix()
		for i := 0; i < MaxSignalsGlobal; i++ {
			if _, err := tx.Exec(`INSERT INTO signals (id, from_node_id, to_node_id, type, candidates, created_at, signal_seq) VALUES (?, ?, ?, 'peer_offer', '["c"]', ?, ?)`,
				fmt.Sprintf("bulk-%d", i), device.ID, target.ID, now, i+1); err != nil {
				t.Fatalf("bulk insert %d failed: %v", i, err)
			}
		}
		if err := tx.Commit(); err != nil {
			t.Fatalf("commit bulk insert: %v", err)
		}
		if _, err := db.CreateSignal(device.ID, target.ID, "peer_offer", []string{"candidate"}, nil, "0102"); !errors.Is(err, ErrSignalQueueLimit) {
			t.Fatalf("expected ErrSignalQueueLimit for the global bound, got %v", err)
		}
	})
}

func TestSignalQueueByteBoundRejectsLargeFlood(t *testing.T) {
	db, device := createTestDevice(t, "signal-bytes@p2wlan.local", "signal-bytes-source")
	defer db.Close()

	target, err := db.CreateDevice(device.UserID, "default", "signal-bytes-target-pubkey", "signal-bytes-target", "linux", "")
	if err != nil {
		t.Fatalf("CreateDevice target failed: %v", err)
	}
	big := strings.Repeat("203.0.113.10:", 2000) + "x" // ~26 KB candidate row
	// Under the byte cap for a while, then the pair crosses it.
	for i := 0; i < MaxSignalBytesPerPair/(len(big)+64); i++ {
		if _, err := db.CreateSignal(device.ID, target.ID, "peer_offer", []string{big}, nil, "0102"); err != nil {
			t.Fatalf("CreateSignal %d failed: %v", i, err)
		}
	}
	if _, err := db.CreateSignal(device.ID, target.ID, "peer_offer", []string{big}, nil, "0102"); !errors.Is(err, ErrSignalQueueLimit) {
		t.Fatalf("expected ErrSignalQueueLimit for the byte bound, got %v", err)
	}
}

func TestListSignalsDeliversBoundedBatchesAndResumes(t *testing.T) {
	db, device := createTestDevice(t, "signal-batch@p2wlan.local", "signal-batch-source")
	defer db.Close()

	target, err := db.CreateDevice(device.UserID, "default", "signal-batch-target-pubkey", "signal-batch-target", "linux", "")
	if err != nil {
		t.Fatalf("CreateDevice target failed: %v", err)
	}

	// Multiple senders (each under the per-pair and per-sender limits) so the
	// target's total queue exceeds one batch: draining must then paginate.
	const senders = 5
	const perSender = MaxSignalsPerPair - 8 // 248 per sender, under the pair limit
	const total = senders * perSender
	if total <= MaxSignalBatch {
		t.Fatalf("test setup must exceed one batch")
	}
	var sources []*Device
	for s := 0; s < senders; s++ {
		src, err := db.CreateDevice(device.UserID, "default", fmt.Sprintf("signal-batch-src-%d-pubkey", s), fmt.Sprintf("signal-batch-src-%d", s), "linux", "")
		if err != nil {
			t.Fatalf("CreateDevice source %d failed: %v", s, err)
		}
		sources = append(sources, src)
		for i := 0; i < perSender; i++ {
			if _, err := db.CreateSignal(src.ID, target.ID, "peer_offer", []string{fmt.Sprintf("s%d-candidate-%d", s, i)}, nil, "0102"); err != nil {
				t.Fatalf("CreateSignal %d/%d failed: %v", s, i, err)
			}
		}
	}

	// Drain across consecutive polls; every batch respects the cap and the
	// union is exactly the queued set, without loss or dupes, and each
	// (from, to) pair arrives in its own per-pair sequence order (cross-pair
	// order is deliberately unspecified).
	var delivered []Signal
	for {
		batch, err := db.ListAndDeleteSignals(target.ID)
		if err != nil {
			t.Fatalf("ListAndDeleteSignals failed: %v", err)
		}
		if len(batch) == 0 {
			break
		}
		if len(batch) > MaxSignalBatch {
			t.Fatalf("batch exceeded the cap: %d > %d", len(batch), MaxSignalBatch)
		}
		delivered = append(delivered, batch...)
	}
	if len(delivered) != total {
		t.Fatalf("expected exactly %d delivered signals, got %d", total, len(delivered))
	}
	seen := map[string]bool{}
	perPair := map[string]int64{}
	for _, s := range delivered {
		if len(s.Candidates) != 1 {
			t.Fatalf("signal %s: expected one candidate, got %#v", s.ID, s.Candidates)
		}
		if seen[s.ID] {
			t.Fatalf("signal %s delivered twice", s.ID)
		}
		seen[s.ID] = true
		pair := s.FromNodeID + "->" + s.ToNodeID
		if prev, ok := perPair[pair]; ok && s.SignalSeq <= prev {
			t.Fatalf("pair %s delivered out of sequence: %d after %d", pair, s.SignalSeq, prev)
		}
		perPair[pair] = s.SignalSeq
	}
	// Every queued pair was fully drained.
	if len(perPair) != senders {
		t.Fatalf("expected %d pairs drained, got %d", senders, len(perPair))
	}
}

func TestConcurrentSignalWritersNeverShareASequence(t *testing.T) {
	db, device := createTestDevice(t, "signal-concurrent@p2wlan.local", "signal-concurrent-source")
	defer db.Close()

	target, err := db.CreateDevice(device.UserID, "default", "signal-concurrent-target-pubkey", "signal-concurrent-target", "linux", "")
	if err != nil {
		t.Fatalf("CreateDevice target failed: %v", err)
	}

	const writers = 16
	const perWriter = 15
	var wg sync.WaitGroup
	errs := make(chan error, writers)
	seqs := make(chan int64, writers*perWriter)
	for w := 0; w < writers; w++ {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			for i := 0; i < perWriter; i++ {
				s, err := db.CreateSignal(device.ID, target.ID, "peer_offer", []string{fmt.Sprintf("w%d-%d", worker, i)}, nil, "0102")
				if err != nil {
					errs <- err
					return
				}
				if s.SignalSeq <= 0 {
					errs <- fmt.Errorf("worker %d got a zero/placeholder sequence", worker)
					return
				}
				seqs <- s.SignalSeq
			}
		}(w)
	}
	wg.Wait()
	close(errs)
	close(seqs)
	for err := range errs {
		t.Fatalf("concurrent writer failed: %v", err)
	}

	// Every sequence is unique and the delivery order matches send order.
	got := make([]int64, 0, writers*perWriter)
	for seq := range seqs {
		got = append(got, seq)
	}
	uniq := map[int64]bool{}
	for _, seq := range got {
		if uniq[seq] {
			t.Fatalf("duplicate signal sequence %d assigned to two concurrent writers", seq)
		}
		uniq[seq] = true
	}
	signals, err := db.ListAndDeleteSignals(target.ID)
	if err != nil {
		t.Fatalf("ListAndDeleteSignals failed: %v", err)
	}
	if len(signals) != writers*perWriter {
		t.Fatalf("expected %d delivered signals, got %d", writers*perWriter, len(signals))
	}
	for i := 1; i < len(signals); i++ {
		if signals[i-1].SignalSeq >= signals[i].SignalSeq {
			t.Fatalf("delivery order is not the per-pair sequence order")
		}
	}
}

func TestSignalSeqBackfillOrdersPreMigrationRows(t *testing.T) {
	db, device := createTestDevice(t, "signal-backfill@p2wlan.local", "signal-backfill-source")
	defer db.Close()

	target, err := db.CreateDevice(device.UserID, "default", "signal-backfill-target-pubkey", "signal-backfill-target", "linux", "")
	if err != nil {
		t.Fatalf("CreateDevice target failed: %v", err)
	}

	// Simulate pre-migration rows: queued before signal_seq existed, all with
	// the default 0 and a deliberate out-of-order wall-clock insertion.
	if _, err := db.Exec(`INSERT INTO signals (id, from_node_id, to_node_id, type, candidates, created_at) VALUES ('legacy-1', ?, ?, 'peer_offer', '["a"]', ?)`, device.ID, target.ID, time.Now().Unix()-10); err != nil {
		t.Fatalf("insert legacy-1: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO signals (id, from_node_id, to_node_id, type, candidates, created_at) VALUES ('legacy-2', ?, ?, 'peer_offer', '["b"]', ?)`, device.ID, target.ID, time.Now().Unix()-5); err != nil {
		t.Fatalf("insert legacy-2: %v", err)
	}

	// Re-run the migration: the backfill must assign stable per-pair
	// sequences to the legacy rows without touching the schema twice.
	if err := migrate(db.DB); err != nil {
		t.Fatalf("re-running migrate failed: %v", err)
	}

	// A new insert queues after the backfilled rows and continues their
	// per-pair sequence (before the queue is drained).
	s, err := db.CreateSignal(device.ID, target.ID, "peer_offer", []string{"new"}, nil, "0102")
	if err != nil {
		t.Fatalf("CreateSignal after backfill failed: %v", err)
	}
	if s.SignalSeq <= 0 {
		t.Fatalf("new insert must carry a real sequence, got %d", s.SignalSeq)
	}

	signals, err := db.ListAndDeleteSignals(target.ID)
	if err != nil {
		t.Fatalf("ListAndDeleteSignals failed: %v", err)
	}
	if len(signals) != 3 {
		t.Fatalf("expected all three rows, got %d", len(signals))
	}
	if signals[0].ID != "legacy-1" || signals[1].ID != "legacy-2" || signals[2].ID != s.ID {
		t.Fatalf("legacy rows must be delivered in creation order before the new insert, got %s, %s, %s", signals[0].ID, signals[1].ID, signals[2].ID)
	}
	if signals[0].SignalSeq >= signals[1].SignalSeq || signals[1].SignalSeq >= signals[2].SignalSeq {
		t.Fatalf("sequences must be strictly increasing across the backfill and the new insert, got %d, %d, %d", signals[0].SignalSeq, signals[1].SignalSeq, signals[2].SignalSeq)
	}
}

func TestCreateSignalReturnsTheRealDatabaseSequence(t *testing.T) {
	db, device := createTestDevice(t, "signal-seq-return@p2wlan.local", "signal-seq-return-source")
	defer db.Close()

	target, err := db.CreateDevice(device.UserID, "default", "signal-seq-return-target-pubkey", "signal-seq-return-target", "linux", "")
	if err != nil {
		t.Fatalf("CreateDevice target failed: %v", err)
	}

	first, err := db.CreateSignal(device.ID, target.ID, "peer_offer", []string{"first"}, nil, "0102")
	if err != nil {
		t.Fatalf("CreateSignal first failed: %v", err)
	}
	second, err := db.CreateSignal(device.ID, target.ID, "peer_offer", []string{"second"}, nil, "0102")
	if err != nil {
		t.Fatalf("CreateSignal second failed: %v", err)
	}
	if first.SignalSeq <= 0 || second.SignalSeq <= first.SignalSeq {
		t.Fatalf("POST response must carry the real strictly-increasing database sequence, got %d then %d", first.SignalSeq, second.SignalSeq)
	}
}

// The sender's per-minute create frequency is counted from the PERSISTENT
// send-event table, never from the queued rows: draining the queue by polling
// must not let a sender bypass the limit by "send -> poll -> send" cycles.
func TestSignalRateLimitCannotBeBypassedByPolling(t *testing.T) {
	db, device := createTestDevice(t, "signal-rate-poll@p2wlan.local", "signal-rate-poll-source")
	defer db.Close()
	target, err := db.CreateDevice(device.UserID, "default", "signal-rate-poll-target-pubkey", "signal-rate-poll-target", "linux", "")
	if err != nil {
		t.Fatalf("CreateDevice target failed: %v", err)
	}

	// Fill the per-minute budget (spread over two pairs so the per-pair row
	// bound never trips before the frequency bound).
	target2, err := db.CreateDevice(device.UserID, "default", "signal-rate-poll-target2-pubkey", "signal-rate-poll-target2", "linux", "")
	if err != nil {
		t.Fatalf("CreateDevice target2 failed: %v", err)
	}
	created := 0
	for created < MaxSignalCreatesPerSenderPerMinute {
		targets := []*Device{target, target2}
		for _, tgt := range targets {
			if created >= MaxSignalCreatesPerSenderPerMinute {
				break
			}
			if _, err := db.CreateSignal(device.ID, tgt.ID, "peer_offer", []string{"candidate"}, nil, "0102"); err != nil {
				t.Fatalf("CreateSignal rate %d failed: %v", created, err)
			}
			created++
		}
	}

	// Drain the WHOLE queue: every queued row (and thus every queued-row
	// based frequency counter) is gone now.
	if _, err := db.ListAndDeleteSignals(target.ID); err != nil {
		t.Fatalf("drain target: %v", err)
	}
	if _, err := db.ListAndDeleteSignals(target2.ID); err != nil {
		t.Fatalf("drain target2: %v", err)
	}
	var queued int64
	if err := db.QueryRow(`SELECT COUNT(*) FROM signals WHERE from_node_id = ?`, device.ID).Scan(&queued); err != nil {
		t.Fatalf("count queued: %v", err)
	}
	if queued != 0 {
		t.Fatalf("the queue must be fully drained before the bypass attempt, got %d rows", queued)
	}

	// The send-event table still counts the creates: the next create must be
	// rejected even though the queue is empty.
	if _, err := db.CreateSignal(device.ID, target.ID, "peer_offer", []string{"candidate"}, nil, "0102"); !errors.Is(err, ErrSignalQueueLimit) {
		t.Fatalf("polling the queue empty must not bypass the sender frequency limit, got %v", err)
	}
	var events int64
	if err := db.QueryRow(`SELECT COUNT(*) FROM signal_send_events WHERE from_node_id = ?`, device.ID).Scan(&events); err != nil {
		t.Fatalf("count send events: %v", err)
	}
	if events != MaxSignalCreatesPerSenderPerMinute {
		t.Fatalf("the send-event table must keep exactly the window's creates, got %d", events)
	}
}

// The per-(from, to) sequence is a PERSISTED counter: after the queue is
// drained, the next signal continues the sequence instead of restarting from
// 1 (a restarted sequence would reorder delivery across polls).
func TestSignalSeqPersistsAcrossQueueDrains(t *testing.T) {
	db, device := createTestDevice(t, "signal-seq-drain@p2wlan.local", "signal-seq-drain-source")
	defer db.Close()
	target, err := db.CreateDevice(device.UserID, "default", "signal-seq-drain-target-pubkey", "signal-seq-drain-target", "linux", "")
	if err != nil {
		t.Fatalf("CreateDevice target failed: %v", err)
	}

	first, err := db.CreateSignal(device.ID, target.ID, "peer_offer", []string{"first"}, nil, "0102")
	if err != nil {
		t.Fatalf("CreateSignal first failed: %v", err)
	}
	second, err := db.CreateSignal(device.ID, target.ID, "peer_offer", []string{"second"}, nil, "0102")
	if err != nil {
		t.Fatalf("CreateSignal second failed: %v", err)
	}
	if _, err := db.ListAndDeleteSignals(target.ID); err != nil {
		t.Fatalf("drain: %v", err)
	}
	var queued int64
	if err := db.QueryRow(`SELECT COUNT(*) FROM signals`).Scan(&queued); err != nil {
		t.Fatalf("count queued: %v", err)
	}
	if queued != 0 {
		t.Fatalf("queue must be empty after the drain, got %d rows", queued)
	}
	third, err := db.CreateSignal(device.ID, target.ID, "peer_offer", []string{"third"}, nil, "0102")
	if err != nil {
		t.Fatalf("CreateSignal after drain failed: %v", err)
	}
	if third.SignalSeq <= second.SignalSeq {
		t.Fatalf("the sequence must continue across queue drains: got %d then %d", second.SignalSeq, third.SignalSeq)
	}
	if first.SignalSeq <= 0 || second.SignalSeq <= first.SignalSeq {
		t.Fatalf("sequences must be strictly increasing, got %d, %d", first.SignalSeq, second.SignalSeq)
	}
}

// One malformed row (bad candidates JSON, as a mixed-version fleet can
// produce) must not block the healthy rows of the same batch: the malformed
// row is skipped and deleted, the healthy rows are delivered.
func TestListSignalsSkipsMalformedRowsWithoutBlockingBatch(t *testing.T) {
	db, device := createTestDevice(t, "signal-malformed@p2wlan.local", "signal-malformed-source")
	defer db.Close()
	target, err := db.CreateDevice(device.UserID, "default", "signal-malformed-target-pubkey", "signal-malformed-target", "linux", "")
	if err != nil {
		t.Fatalf("CreateDevice target failed: %v", err)
	}

	healthy, err := db.CreateSignal(device.ID, target.ID, "peer_offer", []string{"healthy-1"}, nil, "0102")
	if err != nil {
		t.Fatalf("CreateSignal healthy failed: %v", err)
	}
	// A legacy writer (or a corrupted row) wrote malformed JSON directly.
	if _, err := db.Exec(`INSERT INTO signals (id, from_node_id, to_node_id, type, candidates, candidate_sources, signal_seq, created_at) VALUES (?, ?, ?, 'peer_offer', '{not json', '{}', ?, ?)`,
		"malformed-row", device.ID, target.ID, healthy.SignalSeq+1, time.Now().Unix()); err != nil {
		t.Fatalf("insert malformed row: %v", err)
	}
	if _, err := db.CreateSignal(device.ID, target.ID, "peer_offer", []string{"healthy-2"}, nil, "0102"); err != nil {
		t.Fatalf("CreateSignal healthy2 failed: %v", err)
	}

	signals, err := db.ListAndDeleteSignals(target.ID)
	if err != nil {
		t.Fatalf("ListAndDeleteSignals must not fail on a malformed row: %v", err)
	}
	var candidates []string
	for _, s := range signals {
		candidates = append(candidates, s.Candidates...)
	}
	if len(signals) != 2 {
		t.Fatalf("both healthy signals must be delivered, got %d: %v", len(signals), candidates)
	}
	if strings.Join(candidates, ",") != "healthy-1,healthy-2" {
		t.Fatalf("healthy candidates must arrive in order, got %v", candidates)
	}
	// The malformed row is consumed (deleted), so the queue never re-poisons.
	if _, err := db.ListAndDeleteSignals(target.ID); err != nil {
		t.Fatalf("second poll failed: %v", err)
	}
	var queued int64
	if err := db.QueryRow(`SELECT COUNT(*) FROM signals WHERE to_node_id = ?`, target.ID).Scan(&queued); err != nil {
		t.Fatalf("count queued: %v", err)
	}
	if queued != 0 {
		t.Fatalf("the malformed row must be consumed, got %d rows still queued", queued)
	}
}

// The migration seeds the persistent sequence table from the backfilled rows,
// so a pre-migration database's sequence continues instead of restarting.
func TestSignalSeqMigrationSeedsFromBackfilledRows(t *testing.T) {
	tmpFile := "test_p2wlan_seq_migration.db"
	defer os.Remove(tmpFile)
	defer os.Remove(tmpFile + "-shm")
	defer os.Remove(tmpFile + "-wal")

	db, err := New(tmpFile)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}
	defer db.Close()

	// Simulate a PRE-migration database: queued rows with signal_seq = 0 that
	// the backfill assigns, and no persistent seq rows yet.
	if _, err := db.Exec(`DELETE FROM signals`); err != nil {
		t.Fatalf("clear signals: %v", err)
	}
	if _, err := db.Exec(`DELETE FROM signal_seqs`); err != nil {
		t.Fatalf("clear signal_seqs: %v", err)
	}
	now := time.Now().Unix()
	if _, err := db.Exec(`INSERT INTO signals (id, from_node_id, to_node_id, type, candidates, signal_seq, created_at) VALUES (?, ?, ?, 'peer_offer', '["a"]', 0, ?)`,
		"pre-1", "from-old", "to-old", now); err != nil {
		t.Fatalf("insert pre-migration row 1: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO signals (id, from_node_id, to_node_id, type, candidates, signal_seq, created_at) VALUES (?, ?, ?, 'peer_offer', '["b"]', 0, ?)`,
		"pre-2", "from-old", "to-old", now+1); err != nil {
		t.Fatalf("insert pre-migration row 2: %v", err)
	}

	if err := migrate(db.DB); err != nil {
		t.Fatalf("re-run migrations: %v", err)
	}
	// The backfill assigned sequences 0 and 1 (created_at order); the seeded
	// counter must continue from 2, never restart from 1.
	var seq int64
	if err := db.QueryRow(`SELECT seq FROM signal_seqs WHERE from_node_id = 'from-old' AND to_node_id = 'to-old'`).Scan(&seq); err != nil {
		t.Fatalf("seeded seq missing: %v", err)
	}
	var maxAssigned int64
	if err := db.QueryRow(`SELECT MAX(signal_seq) FROM signals WHERE from_node_id = 'from-old' AND to_node_id = 'to-old'`).Scan(&maxAssigned); err != nil {
		t.Fatalf("max assigned: %v", err)
	}
	if maxAssigned != seq {
		t.Fatalf("the seeded counter must equal the backfilled MAX, got max=%d seq=%d", maxAssigned, seq)
	}
	// A new create AFTER the migration continues the sequence instead of
	// restarting from 1 (delivery ordering must survive the migration).
	next, err := db.CreateSignal("from-old", "to-old", "peer_offer", []string{"post"}, nil, "0102")
	if err != nil {
		t.Fatalf("CreateSignal after migration failed: %v", err)
	}
	if next.SignalSeq != maxAssigned+1 {
		t.Fatalf("the next create must continue the backfilled sequence (max=%d), got %d", maxAssigned, next.SignalSeq)
	}
}
