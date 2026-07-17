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
	hub := signaling.NewHub(db)
	go hub.Run()

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
	mux.HandleFunc("POST /api/v1/tunnels", anyAuth(apiServer.CreateTunnel))
	mux.HandleFunc("GET /api/v1/tunnels", anyAuth(apiServer.ListTunnels))
	mux.HandleFunc("DELETE /api/v1/tunnels/{id}", anyAuth(apiServer.DeleteTunnel))

	// Device-only routes (device credential required)
	deviceAuth := auth.RequireDeviceAuth(db)
	mux.HandleFunc("DELETE /api/v1/devices/{id}", deviceAuth(apiServer.DeleteDevice))

	// Backward-compat: endpoint update accepts user JWT (anyAuth)
	mux.HandleFunc("PATCH /api/v1/devices/{id}/endpoint", anyAuth(apiServer.UpdateDeviceEndpoint))

	// WebSocket signaling
	mux.HandleFunc("/ws", signaling.ServeWS(hub, authService))

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

	log.Println("Server stopped")
}

// withCORS allows the desktop shell and local dev UI to call the control API.
// Extra origins can be supplied with CONTROL_ALLOWED_ORIGINS as a comma list.
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
	if strings.HasPrefix(origin, "tauri://") ||
		strings.HasPrefix(origin, "http://tauri.") ||
		strings.HasPrefix(origin, "https://tauri.") {
		return true
	}
	if strings.HasPrefix(origin, "http://localhost:") ||
		strings.HasPrefix(origin, "http://127.0.0.1:") ||
		strings.HasPrefix(origin, "http://[::1]:") {
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
		mu   sync.Mutex
		buck = map[string]*bucket{}
	)
	return func(w http.ResponseWriter, r *http.Request) {
		ip := r.RemoteAddr
		if fwd := r.Header.Get("X-Forwarded-For"); fwd != "" {
			ip = strings.Split(fwd, ",")[0]
		}
		now := time.Now()
		mu.Lock()
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
