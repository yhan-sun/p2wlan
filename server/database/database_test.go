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
}
