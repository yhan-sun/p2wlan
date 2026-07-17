package database

import (
	"fmt"
	"os"
	"sync"
	"testing"
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
			device, err := db.CreateDevice(user.ID, "default", pubKey, devName, "linux")
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
	_, err = db.CreateDevice(user.ID, "default", "pubkey-a", "device-a", "linux")
	if err != nil {
		t.Fatalf("CreateDevice failed: %v", err)
	}

	// Try to create device B with duplicate public key -> should return existing or update, not fail
	devB, err := db.CreateDevice(user.ID, "default", "pubkey-a", "device-b", "linux")
	if err != nil {
		t.Fatalf("Expected duplicate public key update to pass, but got: %v", err)
	}
	if devB.DeviceName != "device-b" {
		t.Errorf("Expected device name to be updated to device-b, got %s", devB.DeviceName)
	}

	// Try to register the same public key with another user -> should fail (Stage 2 requirement check)
	userB, _ := db.CreateUser("user-b@p2wlan.local", "pwd")
	_, err = db.CreateDevice(userB.ID, "default", "pubkey-a", "device-c", "linux")
	if err == nil {
		t.Error("Expected failure when registering same public key under a different user, but succeeded")
	}
}
