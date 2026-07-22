package database

import (
	"fmt"
	"os"
	"path/filepath"
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

func TestSignalsDeduplicateByPairAndType(t *testing.T) {
	db, device := createTestDevice(t, "signal-dedupe@p2wlan.local", "signal-source")
	defer db.Close()

	target, err := db.CreateDevice(device.UserID, "default", "signal-target-pubkey", "signal-target", "linux", "")
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
	if len(signals) != 1 {
		t.Fatalf("expected one deduplicated signal, got %d", len(signals))
	}
	if signals[0].Handshake != "new-handshake" {
		t.Fatalf("expected latest handshake, got %q", signals[0].Handshake)
	}
	if len(signals[0].Candidates) != 1 || signals[0].Candidates[0] != "new" {
		t.Fatalf("expected latest candidates, got %#v", signals[0].Candidates)
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
func TestDeviceOnlineTTL(t *testing.T) {
	tmpFile := "test_online_ttl.db"
	defer os.Remove(tmpFile)
	defer os.Remove(tmpFile + "-shm")
	defer os.Remove(tmpFile + "-wal")

	db, err := New(tmpFile)
	if err != nil {
		t.Fatalf("Failed to create database: %v", err)
	}
	defer db.Close()

	user, _ := db.CreateUser("ttl@p2wlan.local", "pwd")

	// Register a device.
	dev, err := db.CreateDevice(user.ID, "default", "pubkey-ttl", "device-ttl", "linux", "")
	if err != nil {
		t.Fatalf("CreateDevice failed: %v", err)
	}

	// Set its last_seen to the distant past (epoch 0) while online=1.
	_, err = db.Exec(`UPDATE devices SET last_seen = 0, online = 1 WHERE id = ?`, dev.ID)
	if err != nil {
		t.Fatalf("Failed to update last_seen: %v", err)
	}

	// ListDevicesByNetwork should report it offline due to TTL.
	devices, err := db.ListDevicesByNetwork("default")
	if err != nil {
		t.Fatalf("ListDevicesByNetwork failed: %v", err)
	}
	found := false
	for _, d := range devices {
		if d.ID == dev.ID {
			found = true
			if d.Online {
				t.Errorf("stale device (last_seen=0) should be offline, got online=true")
			}
			if d.LastSeen != 0 {
				t.Errorf("expected last_seen=0, got %d", d.LastSeen)
			}
		}
	}
	if !found {
		t.Errorf("device %s not found in list", dev.ID)
	}

	oldLastSeen := time.Now().Unix() - DeviceOnlineTTL - 10
	_, err = db.Exec(`UPDATE devices SET last_seen = ?, online = 1 WHERE id = ?`, oldLastSeen, dev.ID)
	if err != nil {
		t.Fatalf("Failed to update stale last_seen: %v", err)
	}
	devices, err = db.ListDevicesByNetwork("default")
	if err != nil {
		t.Fatalf("ListDevicesByNetwork failed: %v", err)
	}
	found = false
	for _, d := range devices {
		if d.ID == dev.ID {
			found = true
			if d.Online {
				t.Errorf("stale device (last_seen=%d) should be offline, got online=true", oldLastSeen)
			}
			if d.LastSeen != oldLastSeen {
				t.Errorf("expected last_seen=%d, got %d", oldLastSeen, d.LastSeen)
			}
		}
	}
	if !found {
		t.Errorf("stale device %s should still be returned", dev.ID)
	}

	// Now touch endpoint to refresh last_seen and online.
	if err := db.UpdateDeviceEndpoint(dev.ID, "127.0.0.1:51820", "FullCone"); err != nil {
		t.Fatalf("UpdateDeviceEndpoint failed: %v", err)
	}
	devices, err = db.ListDevicesByNetwork("default")
	if err != nil {
		t.Fatalf("ListDevicesByNetwork failed: %v", err)
	}
	for _, d := range devices {
		if d.ID == dev.ID && !d.Online {
			t.Errorf("freshly updated device should be online, got offline")
		}
	}

	// Empty endpoint is a valid lease heartbeat when the client has no public
	// UDP endpoint to advertise.
	if err := db.UpdateDeviceEndpoint(dev.ID, "", "unknown"); err != nil {
		t.Fatalf("UpdateDeviceEndpoint empty heartbeat failed: %v", err)
	}
	refreshed, err := db.GetDevice(dev.ID)
	if err != nil {
		t.Fatalf("GetDevice after empty heartbeat failed: %v", err)
	}
	if !refreshed.Online {
		t.Fatal("empty endpoint heartbeat should keep device online")
	}
	if refreshed.Endpoint != "" {
		t.Fatalf("expected empty endpoint after heartbeat, got %q", refreshed.Endpoint)
	}
}
