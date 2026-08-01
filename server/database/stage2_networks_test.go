package database

import "testing"

// 10. Default network and membership for new users
func TestDatabase_NewUserGetsDefaultNetwork(t *testing.T) {
	db, _ := tmpDB(t)
	user := newUser(t, db, "newuser@test")

	nets, err := db.GetUserNetworks(user.ID)
	if err != nil {
		t.Fatalf("GetUserNetworks: %v", err)
	}
	hasDefault := false
	for _, n := range nets {
		if n.ID == "default" {
			hasDefault = true
			break
		}
	}
	if !hasDefault {
		t.Fatal("new user should have access to default network")
	}

	// User should be able to create a device in default network
	dev, err := db.CreateDevice(user.ID, "default", "pk-new", "new-dev", "linux", "")
	if err != nil {
		t.Fatalf("CreateDevice in default: %v", err)
	}
	if dev.VirtualIP == "" {
		t.Fatal("device should have a virtual IP")
	}
}

// 11. CreateNetwork + membership isolation
func TestDatabase_NetworkIsolation(t *testing.T) {
	db, _ := tmpDB(t)
	alice := newUser(t, db, "alice@iso")
	bob := newUser(t, db, "bob@iso")

	netA, err := db.CreateNetwork(alice.ID, "alice-private", "10.50.0.0/24")
	if err != nil {
		t.Fatalf("CreateNetwork: %v", err)
	}

	// Alice should see her network
	netsA, err := db.GetUserNetworks(alice.ID)
	if err != nil {
		t.Fatalf("GetUserNetworks alice: %v", err)
	}
	found := false
	for _, n := range netsA {
		if n.ID == netA.ID {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("Alice should see her own network")
	}

	// Bob should NOT see Alice's network
	netsB, err := db.GetUserNetworks(bob.ID)
	if err != nil {
		t.Fatalf("GetUserNetworks bob: %v", err)
	}
	for _, n := range netsB {
		if n.ID == netA.ID {
			t.Fatal("Bob should not see Alice's private network")
		}
	}
}

// 12. Network membership grants device registration access
func TestDatabase_MembershipRequiredForDevice(t *testing.T) {
	db, _ := tmpDB(t)
	alice := newUser(t, db, "alice@mem")
	net, err := db.CreateNetwork(alice.ID, "alice-net", "10.55.0.0/24")
	if err != nil {
		t.Fatalf("CreateNetwork: %v", err)
	}

	// Alice can register in her own network
	_, err = db.CreateDevice(alice.ID, net.ID, "pk-alice", "dev", "linux", "")
	if err != nil {
		t.Fatalf("Alice should register in her network: %v", err)
	}

	// Bob (no membership) cannot — DB check via UserHasNetworkAccess in API layer
	// at DB layer, CreateDevice will succeed since we don't enforce membership in SQL.
	// This is enforced in the API handler (UserHasNetworkAccess check before CreateDevice).
	bob := newUser(t, db, "bob@mem")
	accessible, err := db.UserHasNetworkAccess(bob.ID, net.ID)
	if err != nil {
		t.Fatalf("UserHasNetworkAccess: %v", err)
	}
	if accessible {
		t.Fatal("Bob should not have access to Alice's network")
	}

	// After adding Bob as a member, he should have access
	if _, err := db.CreateNetworkMembership(bob.ID, net.ID, "member"); err != nil {
		t.Fatalf("CreateNetworkMembership: %v", err)
	}
	accessible2, err := db.UserHasNetworkAccess(bob.ID, net.ID)
	if err != nil {
		t.Fatalf("UserHasNetworkAccess: %v", err)
	}
	if !accessible2 {
		t.Fatal("Bob should have access after membership")
	}
}
