package database

import (
	"errors"
	"path/filepath"
	"testing"
)

func TestCapabilitiesBelongToExactRegistrationLifecycle(t *testing.T) {
	db, err := New(filepath.Join(t.TempDir(), "capabilities.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	user, err := db.CreateUser("capabilities@example.com", "hash")
	if err != nil {
		t.Fatal(err)
	}
	capable := PeerCapabilities{HH2PairNomination: true, HH2PlanV2: true, ProbeOpaqueIDsV1: true}
	register := func(boot int64, caps PeerCapabilities) (*Device, error) {
		return db.RegisterDeviceWithOptions(user.ID, "default", "capability-key", "daemon", "linux", "", "", "test",
			DeviceRegistrationAttempt{Incarnation: &boot, EnforceIncarnation: true, Capabilities: caps})
	}
	first, err := register(10, capable)
	if err != nil {
		t.Fatal(err)
	}
	duplicate, err := register(10, capable)
	if err != nil || duplicate.RegistrationSeq != first.RegistrationSeq {
		t.Fatalf("same declaration must be idempotent: duplicate=%+v err=%v", duplicate, err)
	}
	for _, lookup := range []func() (*Device, error){
		func() (*Device, error) { return db.GetDevice(first.ID) },
		func() (*Device, error) { return db.GetDeviceByPublicKey("default", first.PublicKey) },
	} {
		stored, err := lookup()
		if err != nil || stored.Capabilities != capable {
			t.Fatalf("capabilities lost: stored=%+v err=%v", stored, err)
		}
	}
	roster, err := db.ListDevicesByUserAndNetwork(user.ID, "default")
	if err != nil || len(roster) != 1 || roster[0].Capabilities != capable {
		t.Fatalf("roster did not carry capabilities: roster=%+v err=%v", roster, err)
	}
	_, err = register(10, PeerCapabilities{})
	var conflict *RegistrationConflictError
	if !errors.As(err, &conflict) || conflict.Code != "registration_capability_conflict" {
		t.Fatalf("same boot cannot change its declaration: %v", err)
	}
	replacement, err := register(11, PeerCapabilities{})
	if err != nil || replacement.RegistrationSeq <= first.RegistrationSeq || replacement.Capabilities != (PeerCapabilities{}) {
		t.Fatalf("new legacy declaration must revoke bits: replacement=%+v err=%v", replacement, err)
	}
	if _, err := register(10, capable); !errors.As(err, &conflict) {
		t.Fatalf("old incarnation restored capability: %v", err)
	}
	stored, err := db.GetDevice(first.ID)
	if err != nil || stored.Capabilities != (PeerCapabilities{}) {
		t.Fatalf("revocation was lost: %+v %v", stored, err)
	}
}

func TestLegacyRegistrationCannotAdvertiseUnfencedCapabilities(t *testing.T) {
	db, err := New(filepath.Join(t.TempDir(), "legacy.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	user, err := db.CreateUser("legacy-capabilities@example.com", "hash")
	if err != nil {
		t.Fatal(err)
	}
	device, err := db.RegisterDeviceWithOptions(user.ID, "default", "legacy-capability-key", "daemon", "linux", "", "", "999.0.0",
		DeviceRegistrationAttempt{EnforceIncarnation: true, Capabilities: PeerCapabilities{HH2PairNomination: true, HH2PlanV2: true, ProbeOpaqueIDsV1: true}})
	if err != nil || device.Capabilities != (PeerCapabilities{}) {
		t.Fatalf("legacy capabilities enabled: %+v %v", device, err)
	}
}
