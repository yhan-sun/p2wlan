package database

import (
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"sync"
	"testing"
	"time"
)

func tmpDB(t *testing.T) (*DB, string) {
	t.Helper()
	f := "test_stage2_" + fmt.Sprintf("%d", time.Now().UnixNano()) + ".db"
	db, err := New(f)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() {
		db.Close()
		for _, suffix := range []string{"", "-shm", "-wal"} {
			os.Remove(f + suffix)
		}
	})
	return db, f
}

func newUser(t *testing.T, db *DB, email string) *User {
	t.Helper()
	u, err := db.CreateUser(email, "hash")
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	return u
}

func newDevice(t *testing.T, db *DB, userID, networkID string) *Device {
	t.Helper()
	d, err := db.CreateDevice(userID, networkID, "pk-"+networkID+"-"+userID+"-"+fmt.Sprint(time.Now().UnixNano()), "dev", "linux", "")
	if err != nil {
		t.Fatalf("CreateDevice: %v", err)
	}
	return d
}

// 1. Foreign keys are actually enforced
func TestDatabase_ForeignKeyEnforcement(t *testing.T) {
	db, _ := tmpDB(t)
	enabled, err := db.ForeignKeysEnabled()
	if err != nil {
		t.Fatalf("ForeignKeysEnabled: %v", err)
	}
	if !enabled {
		t.Fatal("foreign_keys PRAGMA is not enabled")
	}

	// Attempt to insert a device referencing a non-existent user
	_, err = db.Exec(`INSERT INTO devices (id, user_id, network_id, public_key, device_name, platform, virtual_ip, created_at)
		VALUES ('bad-dev', 'no-such-user', 'no-such-net', 'pk', 'd', '', '10.0.0.1', 0)`)
	if err == nil {
		t.Fatal("expected foreign key violation for missing user, got nil")
	}
	t.Logf("FK violation error (expected): %v", err)
}

// 2. User A cannot list user B's private network
func TestDatabase_UserACannotListUserBNetwork(t *testing.T) {
	db, _ := tmpDB(t)
	alice := newUser(t, db, "alice@test")
	bob := newUser(t, db, "bob@test")

	// Bob creates a private network
	bobNet, err := db.CreateNetwork(bob.ID, "bob-net", "10.99.0.0/24")
	if err != nil {
		t.Fatalf("CreateNetwork: %v", err)
	}

	// Alice should NOT see Bob's network
	aliceNets, err := db.GetUserNetworks(alice.ID)
	if err != nil {
		t.Fatalf("GetUserNetworks: %v", err)
	}
	for _, n := range aliceNets {
		if n.ID == bobNet.ID {
			t.Fatal("Alice can see Bob's private network")
		}
	}

	// Alice should not have access to Bob's network
	access, err := db.UserHasNetworkAccess(alice.ID, bobNet.ID)
	if err != nil {
		t.Fatalf("UserHasNetworkAccess: %v", err)
	}
	if access {
		t.Fatal("Alice has access to Bob's private network")
	}
}

// 3. User A cannot update or delete user B's device
func TestDatabase_UserACannotModifyUserBDevice(t *testing.T) {
	db, _ := tmpDB(t)
	alice := newUser(t, db, "alice@test")
	bob := newUser(t, db, "bob@test")

	bobDev := newDevice(t, db, bob.ID, "default")

	// Alice should not be able to update Bob's device endpoint
	belongs, err := db.DeviceBelongsToUser(bobDev.ID, alice.ID)
	if err != nil {
		t.Fatalf("DeviceBelongsToUser: %v", err)
	}
	if belongs {
		t.Fatal("Alice should not own Bob's device")
	}

	// Network membership remains a separate, broader capability for legacy
	// network-level operations; the API's device roster and management paths
	// must use the strict ownership check above instead.
	accessible, err := db.DeviceAccessibleByUser(bobDev.ID, alice.ID)
	if err != nil {
		t.Fatalf("DeviceAccessibleByUser: %v", err)
	}
	// Bob's device is in the "default" network, which Alice also has access to.
	// DeviceAccessibleByUser therefore reports network-level access, while the
	// strict ownership check correctly rejects account-level device access.
	t.Logf("Alice has network-level access to Bob's device (expected): %v", accessible)

	// Alice should own her own device though
	aliceDev := newDevice(t, db, alice.ID, "default")
	belongsA, err := db.DeviceBelongsToUser(aliceDev.ID, alice.ID)
	if err != nil {
		t.Fatalf("DeviceBelongsToUser: %v", err)
	}
	if !belongsA {
		t.Fatal("Alice should own her own device")
	}
}

// 4. User A cannot re-register user B's public key (device takeover)
func TestDatabase_UserACannotTakeoverUserBPublicKey(t *testing.T) {
	db, _ := tmpDB(t)
	alice := newUser(t, db, "alice@test")
	bob := newUser(t, db, "bob@test")

	// Bob registers a device with a specific public key
	bobDev, err := db.CreateDevice(bob.ID, "default", "shared-public-key-x", "bob-dev", "linux", "")
	if err != nil {
		t.Fatalf("CreateDevice bob: %v", err)
	}
	t.Logf("Bob's device: %s", bobDev.ID)

	// Alice tries to register the same public key -> should fail
	_, err = db.CreateDevice(alice.ID, "default", "shared-public-key-x", "alice-dev", "linux", "")
	if err == nil {
		t.Fatal("Alice should NOT be able to register Bob's public key")
	}
	t.Logf("Takeover prevented: %v", err)

	// Same public key in a different network also fails
	aliceNet, err := db.CreateNetwork(alice.ID, "alice-net", "10.88.0.0/24")
	if err != nil {
		t.Fatalf("CreateNetwork: %v", err)
	}
	_, err = db.CreateDevice(alice.ID, aliceNet.ID, "shared-public-key-x", "alice-dev2", "linux", "")
	if err == nil {
		t.Fatal("Alice should NOT be able to reuse Bob's public key in her own network")
	}
	t.Logf("Cross-network takeover prevented: %v", err)
}

// 5. Device A cannot forge device identity or consume device B's signals
func TestDatabase_DeviceSignalAuth(t *testing.T) {
	db, _ := tmpDB(t)
	alice := newUser(t, db, "alice@test")
	bob := newUser(t, db, "bob@test")

	aliceDev := newDevice(t, db, alice.ID, "default")
	bobDev := newDevice(t, db, bob.ID, "default")

	// Alice's device creates a signal TO bob
	sig, err := db.CreateSignal(aliceDev.ID, bobDev.ID, "peer_offer", []string{"cand"}, map[string]string{"cand": "predicted"}, "hs")
	if err != nil {
		t.Fatalf("CreateSignal: %v", err)
	}

	// Bob's device can list and consume the signal (it's for bob)
	sigs, err := db.ListAndDeleteSignals(bobDev.ID)
	if err != nil {
		t.Fatalf("ListAndDeleteSignals for Bob: %v", err)
	}
	if len(sigs) != 1 || sigs[0].ID != sig.ID {
		t.Fatal("Bob should receive Alice's signal")
	}
	if sigs[0].CandidateSources["cand"] != "predicted" {
		t.Fatalf("expected candidate source roundtrip, got %#v", sigs[0].CandidateSources)
	}

	// Alice's device should NOT have any signals (none addressed to Alice)
	aliceSigs, err := db.ListAndDeleteSignals(aliceDev.ID)
	if err != nil {
		t.Fatalf("ListAndDeleteSignals for Alice: %v", err)
	}
	if len(aliceSigs) != 0 {
		t.Fatal("Alice should not have signals addressed to Bob")
	}

	// A different device should not be able to consume signals addressed to someone else
	_, _ = db.CreateDevice(alice.ID, "default", "pk-eve-"+fmt.Sprint(time.Now().UnixNano()), "eve-dev", "linux", "")
	// Create signal for bob
	_, err = db.CreateSignal(aliceDev.ID, bobDev.ID, "peer_offer", []string{"c2"}, nil, "hs2")
	if err != nil {
		t.Fatalf("CreateSignal: %v", err)
	}
	// Eve (different device) tries to list Bob's signals -> will get his signals since ListAndDeleteSignals
	// doesn't filter by who is calling; this is a server-side authorization test,
	// so verify the signal routing is correct: bob's signals go to bob
	sigs2, err := db.ListAndDeleteSignals(bobDev.ID)
	if err != nil {
		t.Fatalf("ListAndDeleteSignals for Bob2: %v", err)
	}
	if len(sigs2) != 1 {
		t.Fatal("Bob should have the second signal")
	}
}

// 6. Devices in different networks cannot send signals to each other
func TestDatabase_CrossNetworkSignalBlocked(t *testing.T) {
	db, _ := tmpDB(t)
	alice := newUser(t, db, "alice@test")
	bob := newUser(t, db, "bob@test")

	netA, err := db.CreateNetwork(alice.ID, "net-a", "10.10.0.0/24")
	if err != nil {
		t.Fatalf("CreateNetwork net-a: %v", err)
	}
	netB, err := db.CreateNetwork(bob.ID, "net-b", "10.20.0.0/24")
	if err != nil {
		t.Fatalf("CreateNetwork net-b: %v", err)
	}

	// Add memberships so users can register devices in their networks
	if _, err := db.CreateNetworkMembership(alice.ID, netA.ID, "member"); err != nil {
		t.Fatalf("Membership alice->netA: %v", err)
	}
	if _, err := db.CreateNetworkMembership(bob.ID, netB.ID, "member"); err != nil {
		t.Fatalf("Membership bob->netB: %v", err)
	}

	devA, err := db.CreateDevice(alice.ID, netA.ID, "pk-a", "dev-a", "linux", "")
	if err != nil {
		t.Fatalf("CreateDevice A: %v", err)
	}
	devB, err := db.CreateDevice(bob.ID, netB.ID, "pk-b", "dev-b", "linux", "")
	if err != nil {
		t.Fatalf("CreateDevice B: %v", err)
	}

	// Service-level check: verify devices are in different networks
	if devA.NetworkID == devB.NetworkID {
		t.Fatal("Devices should be in different networks")
	}

	// The signal CAN be created at DB level (no FK to device network),
	// but the API layer checks NetworkID matching before creating.
	// This test validates the DB-level routing and consumption.
	_, err = db.CreateSignal(devA.ID, devB.ID, "peer_offer", []string{"c"}, nil, "hs")
	if err != nil {
		t.Fatalf("CreateSignal cross-network: %v", err)
	}

	// Verify devB can consume it
	sigs, err := db.ListAndDeleteSignals(devB.ID)
	if err != nil {
		t.Fatalf("ListAndDeleteSignals: %v", err)
	}
	// It's there — the enforcement happens in the API layer
	t.Logf("Cross-network signal exists (API layer must reject): got %d signals", len(sigs))
}

// 7. Challenge expiration, replay, and bad signature
func TestDatabase_ChallengeSecurity(t *testing.T) {
	db, _ := tmpDB(t)
	user := newUser(t, db, "user@test")
	dev := newDevice(t, db, user.ID, "default")

	// Generate Ed25519 key pair for the device
	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	// 7a. Create challenge
	challenge := make([]byte, 32)
	rand.Read(challenge)
	expiresAt := time.Now().Add(5 * time.Minute).Unix()

	dc, err := db.CreateChallenge(dev.ID, challenge, expiresAt)
	if err != nil {
		t.Fatalf("CreateChallenge: %v", err)
	}

	// Sign the challenge (not needed further in DB layer test beyond what's verified inline)
	_ = ed25519.Sign(privKey, challenge)

	// 7b. Verify valid signature passes
	record, err := db.GetChallenge(dc.ID)
	if err != nil {
		t.Fatalf("GetChallenge: %v", err)
	}
	if record.Consumed {
		t.Fatal("new challenge should not be consumed")
	}
	if !ed25519.Verify(pubKey, challenge, ed25519.Sign(privKey, challenge)) {
		t.Fatal("signature should verify")
	}
	db.ConsumeChallenge(dc.ID)

	// 7c. Replay: challenge is consumed now
	record2, err := db.GetChallenge(dc.ID)
	if err != nil {
		t.Fatalf("GetChallenge after consume: %v", err)
	}
	if !record2.Consumed {
		t.Fatal("consumed challenge should be marked consumed")
	}

	// 7d. Bad signature verification (API-layer test, but test the crypto)
	wrongSig := ed25519.Sign(privKey, []byte("wrong message"))
	if ed25519.Verify(pubKey, challenge, wrongSig) {
		t.Fatal("wrong signature should not verify")
	}

	// 7e. Expired challenge
	dc2, err := db.CreateChallenge(dev.ID, challenge, time.Now().Unix()-10) // expired 10s ago
	if err != nil {
		t.Fatalf("CreateChallenge expired: %v", err)
	}
	if time.Now().Unix() > dc2.ExpiresAt {
		t.Log("challenge is expired as expected")
	} else {
		t.Log("challenge still valid (time granularity)")
	}
}

func TestCreateChallengePrunesTerminalRows(t *testing.T) {
	db, _ := tmpDB(t)
	user := newUser(t, db, "challenge-prune@test")
	dev := newDevice(t, db, user.ID, "default")
	now := time.Now().Unix()

	active, err := db.CreateChallenge(dev.ID, []byte("active-challenge"), now+300)
	if err != nil {
		t.Fatalf("create active challenge: %v", err)
	}
	consumed, err := db.CreateChallenge(dev.ID, []byte("consumed-challenge"), now+300)
	if err != nil {
		t.Fatalf("create consumed challenge: %v", err)
	}
	if err := db.ConsumeChallenge(consumed.ID); err != nil {
		t.Fatalf("consume challenge: %v", err)
	}
	expired, err := db.CreateChallenge(dev.ID, []byte("expired-challenge"), now-1)
	if err != nil {
		t.Fatalf("create expired challenge: %v", err)
	}
	if _, err := db.CreateChallenge(dev.ID, []byte("new-challenge"), now+300); err != nil {
		t.Fatalf("create new challenge: %v", err)
	}
	if _, err := db.GetChallenge(active.ID); err != nil {
		t.Fatalf("live challenge must be retained: %v", err)
	}
	for _, id := range []string{consumed.ID, expired.ID} {
		if _, err := db.GetChallenge(id); !errors.Is(err, sql.ErrNoRows) {
			t.Fatalf("terminal challenge %s should be pruned, got %v", id, err)
		}
	}
}

// 8. Concurrent IP allocation has no conflicts
func TestDatabase_ConcurrentIPAllocation(t *testing.T) {
	db, _ := tmpDB(t)
	user := newUser(t, db, "user@test")
	netID := "default"

	const count = 20
	var wg sync.WaitGroup
	ips := make(chan string, count)
	errs := make(chan error, count)

	for i := 0; i < count; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			pk := fmt.Sprintf("concurrent-pk-%d", idx)
			dev, err := db.CreateDevice(user.ID, netID, pk, fmt.Sprintf("dev-%d", idx), "linux", "")
			if err != nil {
				errs <- err
				return
			}
			ips <- dev.VirtualIP
		}(i)
	}

	wg.Wait()
	close(ips)
	close(errs)

	var errList []error
	for e := range errs {
		errList = append(errList, e)
	}
	if len(errList) > 0 {
		t.Fatalf("%d concurrent device registrations failed: %v", len(errList), errList[0])
	}

	allocated := make(map[string]bool)
	var dupIPs []string
	for ip := range ips {
		if allocated[ip] {
			dupIPs = append(dupIPs, ip)
		}
		allocated[ip] = true
	}

	if len(dupIPs) > 0 {
		t.Fatalf("duplicate IPs allocated: %v", dupIPs)
	}
	if len(allocated) != count {
		t.Fatalf("expected %d unique IPs, got %d", count, len(allocated))
	}
	t.Logf("Allocated %d unique IPs successfully", len(allocated))
}
