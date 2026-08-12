package main

import (
	"encoding/json"
	"log"
	"net"
	"net/http"
)

// ServeMetrics exposes a read-only JSON snapshot of the relay counters over
// HTTP.  It is disabled unless MetricsBind is configured.  The handler only
// returns the aggregate counters from RelayStatsSnapshot — it never exposes
// tickets, tokens, or per-frame payloads.
func (s *RelayServer) ServeMetrics() (net.Listener, error) {
	mux := http.NewServeMux()
	mux.HandleFunc("/metrics", s.handleMetrics)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok\n"))
	})
	ln, err := net.Listen("tcp", s.config.MetricsBind)
	if err != nil {
		return nil, err
	}
	httpSrv := &http.Server{Handler: mux}
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

func (s *RelayServer) handleMetrics(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(s.Stats()); err != nil {
		log.Printf("relay metrics encode failed: %v", err)
	}
}
