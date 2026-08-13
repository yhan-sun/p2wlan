package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"testing"
	"time"
)

func TestMetricsBindAllowed(t *testing.T) {
	cases := []struct {
		bind        string
		allowPublic bool
		want        bool
	}{
		{"127.0.0.1:9090", false, true},
		{"localhost:9090", false, false}, // hostname is not verifiable loopback
		{"[::1]:9090", false, true},
		{"10.0.0.5:9090", false, true},
		{"172.16.4.4:9090", false, true},
		{"192.168.1.20:9090", false, true},
		{"169.254.1.1:9090", false, true}, // link-local
		{"0.0.0.0:9090", false, false},    // wildcard = public exposure
		{"[::]:9090", false, false},
		{"8.8.8.8:9090", false, false}, // public IP
		{"203.0.113.9:9090", false, false},
		{"0.0.0.0:9090", true, true}, // explicit escape hatch
		{"[::]:9090", true, true},
		{"8.8.8.8:9090", true, true},
	}
	for _, tc := range cases {
		if got := metricsBindAllowed(tc.bind, tc.allowPublic); got != tc.want {
			t.Errorf("metricsBindAllowed(%q, allowPublic=%v) = %v, want %v", tc.bind, tc.allowPublic, got, tc.want)
		}
	}
}

func TestMetricsDisabledByDefault(t *testing.T) {
	// Without MetricsBind the relay must not listen anywhere for metrics.
	server := startMetricsTestRelay(t, "", false)
	defer server.Close()
	if server.metricsHTTP != nil {
		t.Fatal("metrics server must be nil when MetricsBind is empty")
	}
}

func TestMetricsPublicBindRefusedWithoutEscapeHatch(t *testing.T) {
	server := startMetricsTestRelay(t, "0.0.0.0:0", false)
	defer server.Close()
	ln, err := server.ServeMetrics()
	if err == nil {
		if ln != nil {
			ln.Close()
		}
		t.Fatal("a public/wildcard metrics bind must be refused without -metrics-allow-public")
	}
	if server.metricsHTTP != nil {
		t.Fatal("no metrics server may be registered after a refused bind")
	}
}

func TestMetricsLifecycleAndReadOnlyExposure(t *testing.T) {
	server := startMetricsTestRelay(t, "127.0.0.1:0", false)
	defer server.Close()

	ln, err := server.ServeMetrics()
	if err != nil {
		t.Fatalf("loopback metrics bind must be allowed: %v", err)
	}
	defer ln.Close()
	baseURL := "http://" + ln.Addr().String()

	// GET /metrics returns the aggregate stats JSON (read-only).
	resp, err := http.Get(baseURL + "/metrics")
	if err != nil {
		t.Fatalf("metrics request failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("metrics status = %d, want 200", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("metrics body read failed: %v", err)
	}
	var stats RelayStatsSnapshot
	if err := json.Unmarshal(body, &stats); err != nil {
		t.Fatalf("metrics body must be RelayStatsSnapshot JSON: %v", err)
	}
	if bytes.Contains(body, []byte("auth_failure_sources")) || bytes.Contains(body, []byte("source_key")) {
		t.Fatal("metrics must not expose authentication source identifiers")
	}

	// /metrics must be read-only: POST is rejected.
	postResp, err := http.Post(baseURL+"/metrics", "text/plain", nil)
	if err != nil {
		t.Fatalf("POST /metrics failed: %v", err)
	}
	postResp.Body.Close()
	if postResp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("POST /metrics status = %d, want 405 (read-only endpoint)", postResp.StatusCode)
	}

	// The relay must stay serving after the metrics server is created.
	relayAddr := server.Addr().String()
	conn, err := net.DialTimeout("tcp", relayAddr, 2*time.Second)
	if err != nil {
		t.Fatalf("relay stopped serving after metrics start: %v", err)
	}
	conn.Close()

	// Shutting the relay down must also shut the metrics server down.
	if err := server.Close(); err != nil {
		t.Fatalf("relay close failed: %v", err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for {
		resp, err := http.Get(baseURL + "/metrics")
		if err != nil {
			break // listener closed: lifecycle clean
		}
		resp.Body.Close()
		if time.Now().After(deadline) {
			t.Fatal("metrics endpoint still serving after relay Close")
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func startMetricsTestRelay(t *testing.T, metricsBind string, allowPublic bool) *RelayServer {
	t.Helper()
	config := testConfig()
	config.MetricsBind = metricsBind
	config.MetricsAllowPublic = allowPublic
	server, err := NewRelayServer(config)
	if err != nil {
		t.Fatalf("failed to start relay: %v", err)
	}
	go server.Serve()
	return server
}
