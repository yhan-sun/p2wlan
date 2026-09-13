package api

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestRelayCatalogAddressValidation(t *testing.T) {
	for _, ep := range []string{"tls://:18081", "tls://relay.example:0", "tls://relay.example:65536", "tls://relay.example:https", "tls://0.0.0.0:18081", "tls://[::]:18081", "tls://relay.example:18081/path"} {
		raw, _ := json.Marshal([]map[string]string{{"region": "test", "audience": "one", "endpoint": ep}})
		if _, err := ParseRelayCatalogJSON(string(raw)); err == nil {
			t.Errorf("accepted unusable endpoint %s", ep)
		}
	}
	cat, err := ParseRelayCatalogJSON(`[{"region":" test ","audience":" one ","endpoint":" tls://localhost:18081 "}]`)
	if err != nil {
		t.Fatal(err)
	}
	if d := cat.LookupByAudience("one"); d == nil || d.Endpoint != "tls://localhost:18081" || d.Region != "test" {
		t.Fatal("normalization and lookup disagree")
	}
	_, err = ParseRelayCatalogJSON(`[{"region":"a","audience":"same","endpoint":"tls://a:1"},{"region":"b","audience":" same ","endpoint":"tls://b:2"}]`)
	if err == nil {
		t.Fatal("canonical duplicate audience accepted")
	}
}

func TestControlRejectsBrokenExplicitRelayConfig(t *testing.T) {
	for _, key := range []string{"RELAY_CATALOG_JSON", "RELAY_SERVERS", "RELAY_TICKET_SIGNER_JSON", "RELAY_TICKET_SIGNER_KEY_FILE", "RELAY_TICKET_SIGNER_KID"} {
		t.Setenv(key, "")
	}
	if _, err := NewServerFromEnv(nil, nil, nil); err != nil {
		t.Fatalf("direct-only: %v", err)
	}
	t.Setenv("RELAY_CATALOG_JSON", "not-json")
	if _, err := NewServerFromEnv(nil, nil, nil); err == nil {
		t.Fatal("invalid catalog silently disabled Relay")
	}
	t.Setenv("RELAY_CATALOG_JSON", `[{"region":"test","audience":"one","endpoint":"tls://localhost:18081"}]`)
	if _, err := NewServerFromEnv(nil, nil, nil); err == nil {
		t.Fatal("explicit catalog without signing key accepted")
	}
	t.Setenv("RELAY_TICKET_SIGNER_JSON", `{"active":{"kid":"key","private_key":"`+strings.Repeat("01", 32)+`"}}`)
	if _, err := NewServerFromEnv(nil, nil, nil); err != nil {
		t.Fatal(err)
	}
	t.Setenv("RELAY_CATALOG_JSON", "[]")
	if _, err := NewServerFromEnv(nil, nil, nil); err == nil {
		t.Fatal("empty catalog with active signer accepted")
	}
}
