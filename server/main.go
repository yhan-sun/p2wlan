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
	jwtSecret := getEnv("JWT_SECRET", "change-me-in-production")

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

	// API routes
	mux.HandleFunc("POST /api/v1/login", apiServer.Login)
	mux.HandleFunc("POST /api/v1/register", apiServer.Register)
	mux.HandleFunc("GET /api/v1/nodes", authService.RequireAuth(apiServer.ListNodes))
	mux.HandleFunc("GET /api/v1/networks", authService.RequireAuth(apiServer.ListNetworks))
	mux.HandleFunc("POST /api/v1/devices", authService.RequireAuth(apiServer.RegisterDevice))
	mux.HandleFunc("DELETE /api/v1/devices/{id}", authService.RequireAuth(apiServer.DeleteDevice))

	// Port mapping routes
	mux.HandleFunc("POST /api/v1/tunnels", authService.RequireAuth(apiServer.CreateTunnel))
	mux.HandleFunc("GET /api/v1/tunnels", authService.RequireAuth(apiServer.ListTunnels))
	mux.HandleFunc("DELETE /api/v1/tunnels/{id}", authService.RequireAuth(apiServer.DeleteTunnel))

	// WebSocket signaling
	mux.HandleFunc("/ws", signaling.ServeWS(hub, authService))

	// Health check
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "ok")
	})

	// HTTP server
	addr := fmt.Sprintf(":%s", port)
	srv := &http.Server{
		Addr:         addr,
		Handler:      mux,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
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

func getEnv(key, defaultVal string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return defaultVal
}
