// Package main is the P2PNet control server entry point.
//
// The control server handles:
//   - User authentication (JWT-based)
//   - Device registration and management
//   - WebSocket signaling for peer discovery
//   - NAT type coordination
//   - Relay server coordination
//   - Port mapping (tunnel) management
//   - ACL policy distribution
package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/yhan-sun/p2wlan/server/api"
	"github.com/yhan-sun/p2wlan/server/auth"
	"github.com/yhan-sun/p2wlan/server/database"
	"github.com/yhan-sun/p2wlan/server/signaling"
)

func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	log.Println("P2PNet Control Server starting...")

	// Configuration
	port := getEnv("PORT", "8080")
	dbPath := getEnv("DB_PATH", "p2pnet.db")
	jwtSecret := getEnv("JWT_SECRET", "")
	if jwtSecret == "" {
		// In production, JWT_SECRET must be explicitly set.
		// For testing with smoke scripts, use JWT_SECRET=smoke.
		log.Fatal("JWT_SECRET environment variable is required. Set JWT_SECRET=smoke for testing.")
	}

	// Initialize database
	db, err := database.New(dbPath)
	if err != nil {
		log.Fatalf("Failed to open database: %v", err)
	}
	defer db.Close()

	// Initialize auth
	authService := auth.NewService(jwtSecret, db)

	// Initialize signaling hub
	hub, err := signaling.NewHubFromEnv()
	if err != nil {
		log.Fatalf("Invalid WebSocket signaling configuration: %v", err)
	}
	defer hub.Close()

	// Initialize API server
	apiServer := api.NewServer(authService, hub, db)

	// HTTP mux
	mux := http.NewServeMux()

	// Public / auth-free routes
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "ok")
	})

	// User auth routes (JWT)
	mux.HandleFunc("POST /api/v1/login", rateLimit(apiServer.Login, 30, time.Minute))
	mux.HandleFunc("POST /api/v1/register", rateLimit(apiServer.Register, 10, time.Minute))
	mux.HandleFunc("POST /api/v1/challenges", authService.RequireAuth(apiServer.CreateChallenge))
	mux.HandleFunc("POST /api/v1/devices/credential", authService.RequireAuth(apiServer.SubmitDeviceCredential))
	mux.HandleFunc("GET /api/v1/networks", authService.RequireAuth(apiServer.ListNetworks))

	// Dual-auth routes (accept user JWT or device credential)
	anyAuth := auth.RequireAnyAuth(authService, db)
	mux.HandleFunc("POST /api/v1/devices", anyAuth(apiServer.RegisterDevice))
	mux.HandleFunc("GET /api/v1/nodes", anyAuth(apiServer.ListNodes))
	mux.HandleFunc("POST /api/v1/signals", anyAuth(apiServer.CreateSignal))
	mux.HandleFunc("GET /api/v1/signals", anyAuth(apiServer.ListSignals))
	mux.HandleFunc("POST /api/v1/signals/ack", anyAuth(apiServer.AckSignals))
	mux.HandleFunc("POST /api/v1/tunnels", anyAuth(apiServer.CreateTunnel))
	mux.HandleFunc("GET /api/v1/tunnels", anyAuth(apiServer.ListTunnels))
	mux.HandleFunc("DELETE /api/v1/tunnels/{id}", anyAuth(apiServer.DeleteTunnel))
	mux.HandleFunc("PATCH /api/v1/devices/{id}", anyAuth(apiServer.UpdateDevice))
	mux.HandleFunc("DELETE /api/v1/devices/{id}", anyAuth(apiServer.DeleteDevice))

	// Device-only routes (device credential required)
	deviceAuth := auth.RequireDeviceAuth(db)
	mux.HandleFunc("DELETE /api/v1/devices/credential", deviceAuth(apiServer.RevokeCurrentDeviceCredential))

	// Relay ticket endpoint (device-credential-only, rate limited)
	mux.HandleFunc("POST /api/v1/relay/tickets", deviceAuth(rateLimit(apiServer.CreateRelayTicket, 5, time.Minute)))
	mux.HandleFunc("GET /api/v1/relay/revocations", apiServer.RelayRevocations)

	// Backward-compat: endpoint update accepts user JWT (anyAuth)
	mux.HandleFunc("PATCH /api/v1/devices/{id}/endpoint", anyAuth(apiServer.UpdateDeviceEndpoint))

	// Device-authenticated WebSocket wake-up channel. Signal payloads remain
	// durable in the database and are consumed through GET /api/v1/signals.
	signalWS := deviceAuth(signaling.ServeWS(hub))
	mux.HandleFunc("GET /api/v1/signals/ws", signalWS)
	// Secure compatibility alias for pre-v1 endpoint discovery.
	mux.HandleFunc("GET /ws", signalWS)

	// HTTP server
	addr := fmt.Sprintf(":%s", port)
	// Wrap with body size limiter middleware (1MB max)
	limitedMux := withCORS(limitBodySize(mux))

	srv := &http.Server{
		Addr:              addr,
		Handler:           limitedMux,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    1 << 20, // 1 MB
	}

	// Start server
	go func() {
		log.Printf("Listening on %s", addr)
		if err := srv.ListenAndServe(); err != http.ErrServerClosed {
			log.Fatalf("Server error: %v", err)
		}
	}()

	// Wait for shutdown signal
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh

	log.Println("Shutting down...")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		log.Printf("Shutdown error: %v", err)
	}
	hub.Close()

	log.Println("Server stopped")
}

// withCORS allows explicitly configured browser origins to call the control
// API. The browser console was deleted and Flutter Web is out of scope, so
// there is no default browser origin: only origins listed in
// CONTROL_ALLOWED_ORIGINS (a comma list) are honored. The daemon and the
// Flutter/tray/CLI clients are native and never send an Origin header.
func withCORS(next http.Handler) http.Handler {
	allowed := parseAllowedOrigins(getEnv("CONTROL_ALLOWED_ORIGINS", ""))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin != "" && isAllowedOrigin(origin, allowed) {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Vary", "Origin")
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PATCH, DELETE, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type, Accept")
			w.Header().Set("Access-Control-Max-Age", "600")
		}
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func parseAllowedOrigins(raw string) map[string]struct{} {
	origins := map[string]struct{}{}
	for _, item := range strings.Split(raw, ",") {
		item = strings.TrimSpace(item)
		if item != "" {
			origins[item] = struct{}{}
		}
	}
	return origins
}

func isAllowedOrigin(origin string, extra map[string]struct{}) bool {
	if _, ok := extra[origin]; ok {
		return true
	}
	return false
}

// rateLimit is a simple per-process token-bucket style limiter for auth endpoints.
// maxEvents requests are allowed per window per remote IP.
func rateLimit(next http.HandlerFunc, maxEvents int, window time.Duration) http.HandlerFunc {
	type bucket struct {
		count int
		reset time.Time
	}
	var (
		mu             sync.Mutex
		buck           = map[string]*bucket{}
		nextCleanup    = time.Now().Add(window)
		trustedProxies = parseTrustedProxyCIDRs(getEnv("CONTROL_TRUSTED_PROXY_CIDRS", ""))
	)
	return func(w http.ResponseWriter, r *http.Request) {
		ip := rateLimitClientIP(r, trustedProxies)
		now := time.Now()
		mu.Lock()
		if !now.Before(nextCleanup) {
			for key, candidate := range buck {
				if !now.Before(candidate.reset) {
					delete(buck, key)
				}
			}
			nextCleanup = now.Add(window)
		}
		b, ok := buck[ip]
		if !ok || now.After(b.reset) {
			b = &bucket{count: 0, reset: now.Add(window)}
			buck[ip] = b
		}
		b.count++
		over := b.count > maxEvents
		mu.Unlock()
		if over {
			http.Error(w, `{"error":"rate limit exceeded"}`, http.StatusTooManyRequests)
			return
		}
		next(w, r)
	}
}

func parseTrustedProxyCIDRs(raw string) []*net.IPNet {
	trusted := make([]*net.IPNet, 0)
	for _, item := range strings.Split(raw, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		if ip := net.ParseIP(item); ip != nil {
			bits := 128
			if ip.To4() != nil {
				bits = 32
			}
			item = fmt.Sprintf("%s/%d", ip.String(), bits)
		}
		if _, network, err := net.ParseCIDR(item); err == nil {
			trusted = append(trusted, network)
		}
	}
	return trusted
}

func rateLimitClientIP(r *http.Request, trustedProxies []*net.IPNet) string {
	remote := strings.TrimSpace(r.RemoteAddr)
	if host, _, err := net.SplitHostPort(remote); err == nil {
		remote = host
	}
	remoteIP := net.ParseIP(strings.Trim(remote, "[]"))
	if remoteIP == nil {
		return remote
	}
	isTrusted := func(ip net.IP) bool {
		for _, network := range trustedProxies {
			if network.Contains(ip) {
				return true
			}
		}
		return false
	}
	if !isTrusted(remoteIP) {
		return remoteIP.String()
	}

	// Walk right-to-left: a trusted proxy appends its predecessor, while a
	// client-controlled leftmost value must never override that nearer hop.
	forwarded := strings.Split(r.Header.Get("X-Forwarded-For"), ",")
	for index := len(forwarded) - 1; index >= 0; index-- {
		candidate := net.ParseIP(strings.TrimSpace(forwarded[index]))
		if candidate != nil && !isTrusted(candidate) {
			return candidate.String()
		}
	}
	return remoteIP.String()
}

func getEnv(key, defaultVal string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return defaultVal
}

// limitBodySize wraps an http.Handler with a 1 MB body size limit.
func limitBodySize(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, 1<<20) // 1 MB
		next.ServeHTTP(w, r)
	})
}
