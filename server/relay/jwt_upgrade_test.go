package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func TestJWTUpgradeRelayTicketValidation(t *testing.T) {
	pub, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate test key: %v", err)
	}
	_, wrongKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate wrong test key: %v", err)
	}
	server := newAuthTestRelayServer(pub, "key-test")
	now := time.Now()
	type testCase struct {
		name   string
		mutate func(jwt.MapClaims, map[string]any)
		key    ed25519.PrivateKey
		valid  bool
	}
	for _, tc := range []testCase{
		{name: "array_audience", valid: true},
		{name: "string_audience", valid: true, mutate: func(c jwt.MapClaims, _ map[string]any) { c["aud"] = "relay-test" }},
		{name: "expired", mutate: func(c jwt.MapClaims, _ map[string]any) { c["exp"] = now.Add(-time.Hour).Unix() }},
		{name: "expired_inside_clock_skew", mutate: func(c jwt.MapClaims, _ map[string]any) {
			c["iat"], c["nbf"], c["exp"] = now.Add(-time.Minute).Unix(), now.Add(-time.Minute).Unix(), now.Unix()
		}},
		{name: "not_yet_valid", mutate: func(c jwt.MapClaims, _ map[string]any) { c["nbf"] = now.Add(time.Hour).Unix() }},
		{name: "wrong_issuer", mutate: func(c jwt.MapClaims, _ map[string]any) { c["iss"] = "other-control" }},
		{name: "wrong_audience", mutate: func(c jwt.MapClaims, _ map[string]any) { c["aud"] = []string{"other-relay"} }},
		{name: "wrong_type", mutate: func(_ jwt.MapClaims, h map[string]any) { h["typ"] = "JWT" }},
		{name: "missing_key_id", mutate: func(_ jwt.MapClaims, h map[string]any) { delete(h, "kid") }},
		{name: "unknown_key_id", mutate: func(_ jwt.MapClaims, h map[string]any) { h["kid"] = "other-key" }},
		{name: "wrong_signature", key: wrongKey},
		{name: "invalid_expiry_type", mutate: func(c jwt.MapClaims, _ map[string]any) { c["exp"] = "tomorrow" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			claims := jwt.MapClaims{
				"device_id": "device-test", "credential_id": "credential-test", "network_id": "network-test",
				"node_id": "device-test", "relay_region": "test-region", "relay_protocol": 1,
				"iss": "p2wlan-control", "sub": "device-test", "aud": []string{"relay-test"}, "jti": "jti-test",
				"iat": now.Unix(), "nbf": now.Add(-time.Second).Unix(), "exp": now.Add(time.Minute).Unix(),
			}
			token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
			token.Header["kid"] = "key-test"
			token.Header["typ"] = "p2wlan-relay+jwt"
			if tc.mutate != nil {
				tc.mutate(claims, token.Header)
			}
			key := privateKey
			if tc.key != nil {
				key = tc.key
			}
			raw, err := token.SignedString(key)
			if err != nil {
				t.Fatalf("sign test ticket: %v", err)
			}
			got, err := server.verifyTicket(raw)
			if tc.valid {
				if err != nil || got == nil || got.DeviceID != "device-test" || got.CredentialID != "credential-test" {
					t.Fatalf("valid ticket changed: claims=%+v err=%v", got, err)
				}
			} else if err == nil || got != nil {
				t.Fatalf("invalid ticket granted claims: claims=%+v err=%v", got, err)
			}
		})
	}
}
