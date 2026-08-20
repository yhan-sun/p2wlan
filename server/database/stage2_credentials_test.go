package database

import "testing"

// 9. Device credential expiration and revocation
func TestDatabase_DeviceCredentialLifecycle(t *testing.T) {
	db, _ := tmpDB(t)
	user := newUser(t, db, "user@test")
	dev := newDevice(t, db, user.ID, "default")

	// Create a credential with 1-hour TTL
	cred, rawToken, err := db.CreateDeviceCredential(dev.ID, 3600)
	if err != nil {
		t.Fatalf("CreateDeviceCredential: %v", err)
	}
	if cred.ID == "" {
		t.Fatal("credential ID should not be empty")
	}
	if rawToken == "" {
		t.Fatal("raw token should not be empty")
	}

	// Validate the credential
	validated, device, err := db.ValidateDeviceCredential(rawToken)
	if err != nil {
		t.Fatalf("ValidateDeviceCredential: %v", err)
	}
	if validated == nil || device == nil {
		t.Fatal("should return credential and device")
	}
	if device.ID != dev.ID {
		t.Fatal("device mismatch")
	}

	// Revoke it
	if err := db.RevokeDeviceCredential(cred.ID); err != nil {
		t.Fatalf("RevokeDeviceCredential: %v", err)
	}

	// Validation should now fail
	_, _, err = db.ValidateDeviceCredential(rawToken)
	if err == nil {
		t.Fatal("revoked credential should not validate")
	}
	t.Logf("Revoked credential rejected: %v", err)

	// Unknown token should not validate
	_, _, err = db.ValidateDeviceCredential("totally-fake-token")
	if err == nil {
		t.Fatal("fake token should not validate")
	}
	t.Logf("Fake token rejected: %v", err)
}

func TestDatabase_RevokeDeviceCredentialsInvalidatesAllCurrentTokens(t *testing.T) {
	db, _ := tmpDB(t)
	user := newUser(t, db, "revoke-all@test")
	dev := newDevice(t, db, user.ID, "default")

	credA, tokenA, err := db.CreateDeviceCredential(dev.ID, 3600)
	if err != nil {
		t.Fatalf("CreateDeviceCredential A: %v", err)
	}
	credB, tokenB, err := db.CreateDeviceCredential(dev.ID, 3600)
	if err != nil {
		t.Fatalf("CreateDeviceCredential B: %v", err)
	}

	revoked, err := db.RevokeDeviceCredentials(dev.ID)
	if err != nil {
		t.Fatalf("RevokeDeviceCredentials: %v", err)
	}
	if revoked != 2 {
		t.Fatalf("expected 2 revoked credentials, got %d", revoked)
	}
	if _, _, err := db.ValidateDeviceCredential(tokenA); err == nil {
		t.Fatal("first credential should be revoked")
	}
	if _, _, err := db.ValidateDeviceCredential(tokenB); err == nil {
		t.Fatal("second credential should be revoked")
	}
	snapshot, err := db.RelayRevocationSnapshot()
	if err != nil {
		t.Fatalf("RelayRevocationSnapshot after bulk revoke: %v", err)
	}
	if !stringSliceContains(snapshot.RevokedCredentialIDs, credA.ID) {
		t.Fatalf("snapshot missing bulk-revoked credential %s: %+v", credA.ID, snapshot)
	}
	if !stringSliceContains(snapshot.RevokedCredentialIDs, credB.ID) {
		t.Fatalf("snapshot missing bulk-revoked credential %s: %+v", credB.ID, snapshot)
	}

	_, freshToken, err := db.CreateDeviceCredential(dev.ID, 3600)
	if err != nil {
		t.Fatalf("CreateDeviceCredential fresh: %v", err)
	}
	if _, _, err := db.ValidateDeviceCredential(freshToken); err != nil {
		t.Fatalf("fresh credential should validate after bulk revoke: %v", err)
	}
}

func TestDatabase_RelayRevocationSnapshotSurvivesDeviceDelete(t *testing.T) {
	db, _ := tmpDB(t)
	user := newUser(t, db, "relay-revocations@test")
	dev := newDevice(t, db, user.ID, "default")

	credA, _, err := db.CreateDeviceCredential(dev.ID, 3600)
	if err != nil {
		t.Fatalf("CreateDeviceCredential A: %v", err)
	}
	credB, _, err := db.CreateDeviceCredential(dev.ID, 3600)
	if err != nil {
		t.Fatalf("CreateDeviceCredential B: %v", err)
	}

	if err := db.RevokeDeviceCredential(credA.ID); err != nil {
		t.Fatalf("RevokeDeviceCredential: %v", err)
	}
	snapshot, err := db.RelayRevocationSnapshot()
	if err != nil {
		t.Fatalf("RelayRevocationSnapshot after credential revoke: %v", err)
	}
	if !stringSliceContains(snapshot.RevokedCredentialIDs, credA.ID) {
		t.Fatalf("snapshot missing revoked credential %s: %+v", credA.ID, snapshot)
	}

	if err := db.DeleteDevice(dev.ID); err != nil {
		t.Fatalf("DeleteDevice: %v", err)
	}
	snapshot, err = db.RelayRevocationSnapshot()
	if err != nil {
		t.Fatalf("RelayRevocationSnapshot after device delete: %v", err)
	}
	if !stringSliceContains(snapshot.RevokedDeviceIDs, dev.ID) {
		t.Fatalf("snapshot missing deleted device %s: %+v", dev.ID, snapshot)
	}
	if !stringSliceContains(snapshot.RevokedCredentialIDs, credB.ID) {
		t.Fatalf("snapshot missing deleted device credential %s: %+v", credB.ID, snapshot)
	}
	if snapshot.GeneratedAt == "" || snapshot.Version == 0 {
		t.Fatalf("snapshot should include generated_at and version: %+v", snapshot)
	}
}

func TestDatabase_RelayRevocationVersionAdvancesWithinSameSecond(t *testing.T) {
	db, _ := tmpDB(t)
	const createdAt = int64(1_700_000_000)
	if _, err := db.Exec(`INSERT INTO relay_revocations (kind, value, created_at) VALUES (?, ?, ?)`,
		RelayRevocationJTI, "jti-a", createdAt); err != nil {
		t.Fatalf("insert first tombstone: %v", err)
	}
	first, err := db.RelayRevocationSnapshot()
	if err != nil {
		t.Fatalf("first snapshot: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO relay_revocations (kind, value, created_at) VALUES (?, ?, ?)`,
		RelayRevocationJTI, "jti-b", createdAt); err != nil {
		t.Fatalf("insert second tombstone: %v", err)
	}
	second, err := db.RelayRevocationSnapshot()
	if err != nil {
		t.Fatalf("second snapshot: %v", err)
	}
	if second.Version <= first.Version {
		t.Fatalf("same-second append must advance version: first=%d second=%d", first.Version, second.Version)
	}
}

func stringSliceContains(values []string, needle string) bool {
	for _, value := range values {
		if value == needle {
			return true
		}
	}
	return false
}
