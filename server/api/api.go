// Package api provides the HTTP REST API for the control server.
package api

import (
	"log"
	"os"
	"strings"

	"github.com/yhan-sun/p2wlan/server/auth"
	"github.com/yhan-sun/p2wlan/server/database"
	"github.com/yhan-sun/p2wlan/server/signaling"
)

// Server handles API requests.
type Server struct {
	auth                     *auth.Service
	hub                      *signaling.Hub
	db                       *database.DB
	relayServers             []string
	relayCatalog             *RelayCatalog
	relayTicketSigner        *auth.RelayTicketSigner
	relayRevocationFeedToken string
	signalNotifier           *signalNotifier
}

// NewServer creates a new API server.
// Catalog and signer configuration errors are fatal in production mode
// (when RELAY_TICKET_SIGNER_KEY_FILE is set), but warnings in dev mode.
func NewServer(authService *auth.Service, hub *signaling.Hub, db *database.DB) *Server {
	catalog, catalogErr := LoadRelayCatalog()
	if catalogErr != nil {
		log.Printf("WARNING: failed to load relay catalog: %v", catalogErr)
		catalog = nil
	}

	signer, signerErr := auth.LoadSignerFromEnv()
	if signerErr != nil {
		// If a signer key file was explicitly configured, errors are fatal
		if os.Getenv("RELAY_TICKET_SIGNER_KEY_FILE") != "" || os.Getenv("RELAY_TICKET_SIGNER_JSON") != "" {
			log.Fatalf("FATAL: relay ticket signer configuration error: %v", signerErr)
		}
		log.Printf("WARNING: relay ticket signer not configured: %v", signerErr)
		signer = nil
	}

	// Fail fast: signer configured but no catalog
	if signer != nil && catalog == nil {
		log.Fatalf("FATAL: relay ticket signer is configured but no relay catalog is available. Set RELAY_CATALOG_JSON or RELAY_SERVERS.")
	}

	if signer != nil {
		log.Printf("Relay ticket signer active: kid=%s fingerprint=%s", signer.ActiveKid(), signer.Fingerprint())
	}

	return &Server{
		auth:                     authService,
		hub:                      hub,
		db:                       db,
		relayServers:             parseRelayServers(),
		relayCatalog:             catalog,
		relayTicketSigner:        signer,
		relayRevocationFeedToken: strings.TrimSpace(os.Getenv("RELAY_REVOCATION_FEED_TOKEN")),
		signalNotifier:           newSignalNotifier(),
	}
}

func parseRelayServers() []string {
	raw := strings.TrimSpace(os.Getenv("RELAY_SERVERS"))
	if raw == "" {
		return []string{}
	}
	servers := []string{}
	for _, part := range strings.Split(raw, ",") {
		part = strings.TrimSpace(part)
		if part != "" {
			servers = append(servers, part)
		}
	}
	return servers
}
