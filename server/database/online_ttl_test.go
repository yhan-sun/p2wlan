package database

import (
	"os"
	"testing"
	"time"
)

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
	if err := db.UpdateDeviceEndpoint(dev.ID, "127.0.0.1:51820", "FullCone", nil); err != nil {
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
	if err := db.UpdateDeviceEndpoint(dev.ID, "", "unknown", nil); err != nil {
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
