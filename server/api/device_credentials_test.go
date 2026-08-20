package api

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/yhan-sun/p2wlan/server/database"
)

func challengeFixture(t *testing.T) (*database.DB, *database.Device, *database.Device, ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	db, err := database.New(filepath.Join(t.TempDir(), "control.db"))
	if err != nil {
		t.Fatalf("database.New: %v", err)
	}
	t.Cleanup(func() { db.Close() })
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
