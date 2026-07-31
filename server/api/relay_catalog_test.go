package api

import "testing"

func TestParseRelayCatalogAcceptsUDPObserverEndpoint(t *testing.T) {
	catalog, err := ParseRelayCatalogJSON(`[
		{
			"region":"cn",
			"audience":"relay-cn-1",
			"endpoint":"tls://relay.example.com:18081",
			"udp_observer_endpoint":"udp://relay.example.com:18082",
			"udp_observer_endpoints":["udp://stun.l.google.com:19302","stun.example.com:19302"]
		}
	]`)
	if err != nil {
		t.Fatalf("ParseRelayCatalogJSON: %v", err)
	}
	entries := catalog.Entries()
	if len(entries) != 1 {
		t.Fatalf("expected one catalog entry, got %d", len(entries))
	}
	if entries[0].UDPObserverEndpoint != "relay.example.com:18082" {
		t.Fatalf("unexpected observer endpoint: %+v", entries[0])
	}
	wantObservers := []string{"stun.l.google.com:19302", "stun.example.com:19302"}
	if len(entries[0].UDPObserverEndpoints) != len(wantObservers) {
		t.Fatalf("unexpected observer endpoints: %+v", entries[0])
	}
	for i, want := range wantObservers {
		if entries[0].UDPObserverEndpoints[i] != want {
			t.Fatalf("observer endpoint %d = %q, want %q", i, entries[0].UDPObserverEndpoints[i], want)
		}
	}
}

func TestParseRelayCatalogRejectsInvalidUDPObserverEndpoint(t *testing.T) {
	_, err := ParseRelayCatalogJSON(`[
		{"region":"cn","audience":"relay-cn-1","endpoint":"tls://relay.example.com:18081","udp_observer_endpoint":"bad-observer"}
	]`)
	if err == nil {
		t.Fatal("expected invalid observer endpoint to fail")
	}
}

func TestParseRelayCatalogRejectsInvalidUDPObserverEndpoints(t *testing.T) {
	_, err := ParseRelayCatalogJSON(`[
		{"region":"cn","audience":"relay-cn-1","endpoint":"tls://relay.example.com:18081","udp_observer_endpoints":["stun.l.google.com"]}
	]`)
	if err == nil {
		t.Fatal("expected invalid observer endpoint list to fail")
	}
}
