package database

import (
	"encoding/hex"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestGeneratedRecordIDsAreClockIndependent(t *testing.T) {
	db, err := New(filepath.Join(t.TempDir(), "ids.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	seen := make(map[string]bool)
	check := func(prefix, id string) {
		t.Helper()
		raw, err := hex.DecodeString(strings.TrimPrefix(id, prefix))
		if err != nil || len(raw) != 16 || !strings.HasPrefix(id, prefix) || seen[id] {
			t.Fatalf("record ID lacks unique 128-bit random identity: %q", id)
		}
		seen[id] = true
	}
	for i := 0; i < 32; i++ {
		user, err := db.CreateUser(fmt.Sprintf("clock-%d@example.test", i), "hash")
		if err != nil {
			t.Fatal(err)
		}
		check("user-", user.ID)
		membership, err := db.CreateNetworkMembership(user.ID, "default", "member")
		if err != nil {
			t.Fatal(err)
		}
		check("mem-", membership.ID)
		device, err := db.CreateDevice(user.ID, "default", fmt.Sprintf("clock-key-%d", i), "device", "windows", "")
		if err != nil {
			t.Fatal(err)
		}
		check(fmt.Sprintf("node-clock-key-%d-", i), device.ID)
		for j := 0; j < 8; j++ {
			challenge, err := db.CreateChallenge(device.ID, []byte{byte(j)}, time.Now().Unix()+60)
			if err != nil {
				t.Fatal(err)
			}
			check("challenge-", challenge.ID)
			credential, _, err := db.CreateDeviceCredential(device.ID, 60)
			if err != nil {
				t.Fatal(err)
			}
			check("cred-", credential.ID)
		}
		tunnel, err := db.CreateTunnel(device.ID, "tcp", 8080, 0, "127.0.0.1")
		if err != nil {
			t.Fatal(err)
		}
		check("tunnel-", tunnel.ID)
	}
}

func TestCreateUserRollsBackWhenDefaultMembershipFails(t *testing.T) {
	db, _ := tmpDB(t)
	if _, err := db.Exec(`CREATE TRIGGER reject_default_membership BEFORE INSERT ON network_memberships
        WHEN NEW.network_id = 'default' BEGIN SELECT RAISE(ABORT, 'forced membership failure'); END`); err != nil {
		t.Fatal(err)
	}
	user, err := db.CreateUser("rollback@example.test", "hash")
	if err == nil || user != nil {
		t.Fatalf("reported success without membership: user=%v err=%v", user, err)
	}
	var count int
	if err := db.QueryRow(`SELECT COUNT(*) FROM users WHERE email = 'rollback@example.test'`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("orphan user survived failed membership: %d", count)
	}
}

func TestMembershipIdempotenceReturnsStoredIdentityAndRole(t *testing.T) {
	db, _ := tmpDB(t)
	user := newUser(t, db, "member@example.test")
	first, err := db.CreateNetworkMembership(user.ID, "default", "member")
	if err != nil {
		t.Fatal(err)
	}
	next, err := db.CreateNetworkMembership(user.ID, "default", "owner")
	if err != nil {
		t.Fatal(err)
	}
	if *first != *next || next.Role != "member" {
		t.Fatalf("returned fabricated membership: first=%+v next=%+v", first, next)
	}
	var stored NetworkMembership
	err = db.QueryRow(`SELECT id, user_id, network_id, role, created_at FROM network_memberships WHERE id = ?`, next.ID).
		Scan(&stored.ID, &stored.UserID, &stored.NetworkID, &stored.Role, &stored.CreatedAt)
	if err != nil || stored != *next {
		t.Fatalf("returned identity does not match the database: %+v %v", stored, err)
	}
}

func TestConcurrentUsersAlwaysOwnCommittedDefaultMembership(t *testing.T) {
	db, _ := tmpDB(t)
	var workers sync.WaitGroup
	for i := 0; i < 32; i++ {
		workers.Add(1)
		go func(i int) {
			defer workers.Done()
			user, err := db.CreateUser(fmt.Sprintf("parallel-%d@example.test", i), "hash")
			if err != nil {
				t.Errorf("CreateUser: %v", err)
				return
			}
			allowed, err := db.UserHasNetworkAccess(user.ID, "default")
			if err != nil || !allowed {
				t.Errorf("committed user lacks membership: %v %v", allowed, err)
			}
		}(i)
	}
	workers.Wait()
}
