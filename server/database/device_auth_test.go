package database

import (
	"errors"
	"testing"
)

func TestCredentialRejectionIsDistinctFromStorageFailure(t *testing.T) {
	db, _ := tmpDB(t)
	user := newUser(t, db, "credential-errors@example.test")
	device := newDevice(t, db, user.ID, "default")
	credential, token, err := db.CreateDeviceCredential(device.ID, 3600)
	if err != nil {
		t.Fatal(err)
	}
	_, expired, err := db.CreateDeviceCredential(device.ID, -1)
	if err != nil {
		t.Fatal(err)
	}
	for _, rejected := range []string{"dc-unknown", expired} {
		if _, _, err := db.ValidateDeviceCredential(rejected); !errors.Is(err, ErrInvalidDeviceCredential) {
			t.Fatalf("unknown/expired token must be an authoritative rejection: %v", err)
		}
	}
	if err := db.RevokeDeviceCredential(credential.ID); err != nil {
		t.Fatal(err)
	}
	if _, _, err := db.ValidateDeviceCredential(token); !errors.Is(err, ErrInvalidDeviceCredential) {
		t.Fatalf("revoked token must be an authoritative rejection: %v", err)
	}
	_, live, err := db.CreateDeviceCredential(device.ID, 3600)
	if err != nil {
		t.Fatal(err)
	}
	// Exercise the later access check with a real SQL failure, after both the
	// credential and device have been read successfully.
	if _, err := db.Exec("DROP TABLE room_device_access"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := db.ValidateDeviceCredential(live); err == nil || errors.Is(err, ErrInvalidDeviceCredential) || errors.Is(err, ErrRoomAccess) {
		t.Fatal("access-query outage must not masquerade as credential or room revocation")
	}
}
