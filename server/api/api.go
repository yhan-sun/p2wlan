// Package api provides the HTTP REST API for the control server.
package api

import (
	"fmt"
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
	supportLogDir            string
	relayServers             []string
	relayCatalog             *RelayCatalog
	relayTicketSigner        *auth.RelayTicketSigner
	relayRevocationFeedToken string
	signalNotifier           *signalNotifier
	// registrationSessionLocks serializes a device's registration with its
	// device-token control actions.  The database performs the final conditional
	// update for lease-changing operations; this lock covers complex signal and
	// WebSocket actions that span multiple queries in this server process.
	registrationSessionLocks registrationSessionLocker
}

// NewServer retains the existing constructor for callers without an error return.
func NewServer(authService *auth.Service, hub *signaling.Hub, db *database.DB) *Server {
	server, err := NewServerFromEnv(authService, hub, db)
	if err != nil {
		log.Fatalf("Invalid control configuration: %v", err)
	}
	return server
}

// NewServerFromEnv validates explicit configuration before serving any request.
func NewServerFromEnv(authService *auth.Service, hub *signaling.Hub, db *database.DB) (*Server, error) {
	catalog, err := LoadRelayCatalog()
	if err != nil {
		return nil, fmt.Errorf("relay catalog configuration: %w", err)
	}
	signer, err := auth.LoadSignerFromEnv()
	if err != nil {
		return nil, fmt.Errorf("relay ticket signer configuration: %w", err)
	}
	if signer != nil && (catalog == nil || len(catalog.Entries()) == 0) {
		return nil, fmt.Errorf("relay ticket signer requires a non-empty RELAY_CATALOG_JSON or RELAY_SERVERS")
	}
	if strings.TrimSpace(os.Getenv("RELAY_CATALOG_JSON")) != "" && catalog != nil && len(catalog.Entries()) > 0 && signer == nil {
		return nil, fmt.Errorf("RELAY_CATALOG_JSON requires RELAY_TICKET_SIGNER_KEY_FILE with RELAY_TICKET_SIGNER_KID, or RELAY_TICKET_SIGNER_JSON")
	}

	if signer != nil {
		log.Printf("Relay ticket signer active: kid=%s fingerprint=%s", signer.ActiveKid(), signer.Fingerprint())
	}

	return &Server{
		auth:                     authService,
		hub:                      hub,
		db:                       db,
		supportLogDir:            supportLogDirFromEnv(),
		relayServers:             parseRelayServers(),
		relayCatalog:             catalog,
		relayTicketSigner:        signer,
		relayRevocationFeedToken: strings.TrimSpace(os.Getenv("RELAY_REVOCATION_FEED_TOKEN")),
		signalNotifier:           newSignalNotifier(),
		registrationSessionLocks: newRegistrationSessionLocks(),
	}, nil
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
