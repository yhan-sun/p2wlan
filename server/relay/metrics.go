package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"time"
)

// metricsBindAllowed reports whether a metrics bind host is safe to expose
// without authentication: loopback and private RFC1918 / IPv6 ULA ranges are
// allowed by default; anything else (public / wildcard addresses) requires the
// explicit -metrics-allow-public escape hatch so an operator cannot silently
// expose relay counters on the public internet.
func metricsBindAllowed(bind string, allowPublic bool) bool {
	if allowPublic {
		return true
	}
	host, _, err := net.SplitHostPort(bind)
	if err != nil {
		host = bind
	}
	ip := net.ParseIP(host)
	if ip == nil {
		// A bare hostname is not verifiable as loopback/private; refuse it
		// unless the operator explicitly opted into public exposure.
		return false
	}
	return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast()
}

// ServeMetrics exposes a read-only JSON snapshot of the relay counters over
// HTTP.  It is disabled unless MetricsBind is configured.  The handler only
// returns the aggregate counters from RelayStatsSnapshot — it never exposes
// tickets, tokens, or per-frame payloads.  A bind that is not loopback or
// private is refused unless MetricsAllowPublic is set.
func (s *RelayServer) ServeMetrics() (net.Listener, error) {
	if !metricsBindAllowed(s.config.MetricsBind, s.config.MetricsAllowPublic) {
		return nil, fmt.Errorf(
			"refusing to bind the read-only metrics endpoint to %q: only loopback/private addresses are allowed without -metrics-allow-public",
			s.config.MetricsBind,
		)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/metrics", s.handleMetrics)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok\n"))
	})
	ln, err := net.Listen("tcp", s.config.MetricsBind)
	if err != nil {
		return nil, err
	}
	// Metrics is diagnostic-only.  Bound every HTTP phase so a client that
	// connects and then stops reading/writing cannot retain a relay goroutine
	// or listener indefinitely.
	httpSrv := &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      5 * time.Second,
		IdleTimeout:       30 * time.Second,
		MaxHeaderBytes:    16 << 10,
	}
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		if err := httpSrv.Serve(ln); err != nil && err != http.ErrServerClosed {
			log.Printf("relay metrics server stopped: %v", err)
		}
	}()
	s.mu.Lock()
	s.metricsHTTP = httpSrv
	s.mu.Unlock()
	log.Printf("relay metrics endpoint listening at http://%s/metrics", ln.Addr())
	return ln, nil
}

func (s *RelayServer) handleMetrics(w http.ResponseWriter, r *http.Request) {
	// Read-only endpoint: refuse any non-GET method explicitly (the default
	// ServeMux would otherwise dispatch POST to the same handler).
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	// Stats() also serves internal diagnostics and includes bounded, hashed
	// authentication-source details.  Do not expose even those source
	// identifiers through the unauthenticated metrics endpoint.
	snapshot := s.Stats()
	snapshot.AuthFailureSources = nil
	if err := json.NewEncoder(w).Encode(snapshot); err != nil {
		log.Printf("relay metrics encode failed: %v", err)
	}
}
