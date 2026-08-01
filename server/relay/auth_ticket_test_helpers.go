package main

import (
	"crypto/ed25519"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func newAuthTestRelayServer(pub ed25519.PublicKey, kid string) *RelayServer {
	return &RelayServer{
		config: &RelayConfig{
			RelayAudience:      "relay-test",
			RelayRegion:        "test-region",
			TicketMaxClockSkew: time.Second,
		},
		ticketKeyring: map[string]ed25519.PublicKey{kid: pub},
	}
}

func signRelayTicketForTest(t *testing.T, privateKey ed25519.PrivateKey, kid, jti, deviceID string, credentialID ...string) string {
	t.Helper()
	now := time.Now()
	credID := "credential-test"
	if len(credentialID) > 0 {
		credID = credentialID[0]
	}
	claims := relayTicketClaims{
		DeviceID:      deviceID,
		CredentialID:  credID,
		NetworkID:     "network-test",
		NodeID:        deviceID,
		RelayRegion:   "test-region",
		RelayProtocol: 1,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "p2wlan-control",
			Subject:   deviceID,
			Audience:  jwt.ClaimStrings{"relay-test"},
			ID:        jti,
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now.Add(-time.Second)),
			ExpiresAt: jwt.NewNumericDate(now.Add(time.Minute)),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
	token.Header["kid"] = kid
	token.Header["typ"] = "p2wlan-relay+jwt"
	signed, err := token.SignedString(privateKey)
	if err != nil {
		t.Fatalf("SignedString: %v", err)
	}
	return signed
}
