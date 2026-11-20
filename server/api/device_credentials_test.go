package api

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/yhan-sun/p2wlan/server/auth"
	"github.com/yhan-sun/p2wlan/server/database"
)

func challengeFixture(t *testing.T) (*database.DB, *database.Device, *database.Device, ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	db := newCredentialTestDB(t)
	user, err := db.CreateUser("challenge@example.com", "hash")
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	first, err := db.CreateDevice(user.ID, "default", "challenge-key-a", "a", "linux", "")
	if err != nil {
		t.Fatalf("CreateDevice first: %v", err)
	}
	second, err := db.CreateDevice(user.ID, "default", "challenge-key-b", "b", "linux", "")
	if err != nil {
		t.Fatalf("CreateDevice second: %v", err)
	}
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	return db, first, second, publicKey, privateKey
}

func TestVerifyChallengeIsDeviceBoundAndConsumesInvalidSignature(t *testing.T) {
	db, first, second, publicKey, privateKey := challengeFixture(t)
	challenge := []byte("device-bound-challenge-0000000001")
	record, err := db.CreateChallenge(first.ID, challenge, time.Now().Add(time.Minute).Unix())
	if err != nil {
		t.Fatalf("CreateChallenge: %v", err)
	}
	validSignature := ed25519.Sign(privateKey, challenge)

	if err := verifyChallenge(db, record.ID, second.ID, hex.EncodeToString(publicKey), hex.EncodeToString(validSignature)); err == nil {
		t.Fatal("challenge for one device must not authorize another device")
	}
	stored, err := db.GetChallenge(record.ID)
	if err != nil {
		t.Fatalf("GetChallenge: %v", err)
	}
	if stored.Consumed {
		t.Fatal("device-ID mismatch must not consume the rightful device's challenge")
	}

	badSignature := make([]byte, ed25519.SignatureSize)
	if err := verifyChallenge(db, record.ID, first.ID, hex.EncodeToString(publicKey), hex.EncodeToString(badSignature)); err == nil {
		t.Fatal("invalid signature must be rejected")
	}
	if err := verifyChallenge(db, record.ID, first.ID, hex.EncodeToString(publicKey), hex.EncodeToString(validSignature)); err == nil {
		t.Fatal("a claimed challenge must not be reusable after signature failure")
	}
}

func TestVerifyChallengeAllowsOnlyOneConcurrentClaim(t *testing.T) {
	db, first, _, publicKey, privateKey := challengeFixture(t)
	challenge := []byte("concurrent-challenge-0000000000001")
	record, err := db.CreateChallenge(first.ID, challenge, time.Now().Add(time.Minute).Unix())
	if err != nil {
		t.Fatalf("CreateChallenge: %v", err)
	}
	publicKeyHex := hex.EncodeToString(publicKey)
	signatureHex := hex.EncodeToString(ed25519.Sign(privateKey, challenge))

	const contenders = 8
	start := make(chan struct{})
	results := make(chan error, contenders)
	var ready sync.WaitGroup
	ready.Add(contenders)
	for i := 0; i < contenders; i++ {
		go func() {
			ready.Done()
			<-start
			results <- verifyChallenge(db, record.ID, first.ID, publicKeyHex, signatureHex)
		}()
	}
	ready.Wait()
	close(start)

	successes := 0
	for i := 0; i < contenders; i++ {
		if <-results == nil {
			successes++
		}
	}
	if successes != 1 {
		t.Fatalf("expected exactly one successful claim, got %d", successes)
	}
}

func TestDeviceCredentialEnrollmentPreservesBoundSigningKey(t *testing.T) {
	db := newCredentialTestDB(t)
	service := auth.NewService("credential-signing-key-test", db)
	jwt, owner, err := service.Register("owner@example.com", "passphrase")
	if err != nil {
		t.Fatal(err)
	}
	control := NewServer(service, nil, db)
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/v1/devices", auth.RequireAnyAuth(service, db)(control.RegisterDevice))
	mux.HandleFunc("POST /api/v1/devices/credential", service.RequireAuth(control.SubmitDeviceCredential))
	mux.HandleFunc("POST /api/v1/challenges", service.RequireAuth(control.CreateChallenge))

	firstPublic, firstPrivate, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	secondPublic, secondPrivate, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	first := hex.EncodeToString(firstPublic)
	second := hex.EncodeToString(secondPublic)
	device, err := db.CreateDevice(owner.ID, "default", "bound-ed-device", "device", "linux", strings.ToUpper(first))
	if err != nil {
		t.Fatal(err)
	}
	legacy, err := db.CreateDevice(owner.ID, "default", "legacy-ed-device", "legacy", "linux", "")
	if err != nil {
		t.Fatal(err)
	}
	request := func(path, token string, input map[string]any, want int) map[string]any {
		t.Helper()
		body, err := json.Marshal(input)
		if err != nil {
			t.Fatal(err)
		}
		req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(string(body)))
		req.Header.Set("Authorization", "Bearer "+token)
		recorder := httptest.NewRecorder()
		mux.ServeHTTP(recorder, req)
		if recorder.Code != want {
			t.Fatalf("%s returned HTTP %d, want %d", path, recorder.Code, want)
		}
		var output map[string]any
		if err = json.Unmarshal(recorder.Body.Bytes(), &output); err != nil {
			t.Fatal(err)
		}
		return output
	}
	proof := func(id, key string, private ed25519.PrivateKey) map[string]any {
		t.Helper()
		challenge := request("/api/v1/challenges", jwt, map[string]any{"device_id": id}, http.StatusOK)
		raw, err := hex.DecodeString(challenge["challenge"].(string))
		if err != nil {
			t.Fatal(err)
		}
		return map[string]any{"device_id": id, "ed25519_public_key": key, "challenge_id": challenge["challenge_id"],
			"challenge_signature": hex.EncodeToString(ed25519.Sign(private, raw))}
	}
	registration := func(d *database.Device, boot int64, fields map[string]any) map[string]any {
		input := map[string]any{"public_key": d.PublicKey, "device_name": d.DeviceName, "platform": d.Platform, "registration_incarnation": boot}
		for key, value := range fields {
			input[key] = value
		}
		return input
	}
	requireStoredKey := func(id, expected string) {
		t.Helper()
		stored, err := db.GetDevice(id)
		if err != nil || !strings.EqualFold(stored.Ed25519PublicKey, expected) {
			t.Fatalf("registered signing key changed unexpectedly for %s", id)
		}
	}

	request("/api/v1/devices", jwt, registration(device, 1, nil), http.StatusOK)
	request("/api/v1/devices", jwt, registration(device, 2, map[string]any{"ed25519_public_key": second}), http.StatusOK)
	requireStoredKey(device.ID, first)
	request("/api/v1/devices/credential", jwt, proof(device.ID, second, secondPrivate), http.StatusUnauthorized)
	request("/api/v1/devices", jwt, registration(device, 3, proof(device.ID, second, secondPrivate)), http.StatusUnauthorized)
	hasCredential, err := db.HasActiveDeviceCredential(device.ID, time.Now().Unix())
	if err != nil || hasCredential {
		t.Fatalf("unauthorized key created a credential: %v", err)
	}
	requireStoredKey(device.ID, first)
	credential := request("/api/v1/devices", jwt, registration(device, 3, proof(device.ID, first, firstPrivate)), http.StatusOK)
	token, _ := credential["device_credential"].(string)
	if _, _, err = db.ValidateDeviceCredential(token); err != nil {
		t.Fatal("same-key inline enrollment did not create a valid credential")
	}
	request("/api/v1/devices", token, registration(device, 4, map[string]any{"ed25519_public_key": second}), http.StatusOK)
	requireStoredKey(device.ID, second)

	request("/api/v1/devices", jwt, registration(legacy, 1, map[string]any{"ed25519_public_key": second}), http.StatusOK)
	requireStoredKey(legacy.ID, "")
	request("/api/v1/devices/credential", jwt, proof(legacy.ID, first, firstPrivate), http.StatusOK)
	requireStoredKey(legacy.ID, first)
	request("/api/v1/devices/credential", jwt, proof(legacy.ID, second, secondPrivate), http.StatusUnauthorized)
	request("/api/v1/devices/credential", jwt, proof(legacy.ID, first, firstPrivate), http.StatusOK)
}

func newCredentialTestDB(t *testing.T) *database.DB {
	t.Helper()
	db, err := database.New(filepath.Join(t.TempDir(), "control.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}
