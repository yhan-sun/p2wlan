package main

import (
	"crypto/ed25519"
	"github.com/golang-jwt/jwt/v5"
	"net"
	"sync"
	"time"
)

const authFailureSourceSnapshotLimit = 10

type RelayConfig struct {
	Bind              string
	UDPObserverBind   string
	SendQueueCapacity int
	RegisterTimeout   time.Duration
	IdleTimeout       time.Duration
	MaxConnections    int
	MaxFramePayload   int
	AuthFailureLimit  int
	AuthFailureWindow time.Duration
	// A2: security settings
	RequireAuthentication      bool
	AllowLegacyUnauthenticated bool
	TLSCertChainPath           string
	TLSPrivateKeyPath          string
	AllowInsecurePlaintext     bool
	// A2: ticket verification
	TicketKeyringJSON        string
	RelayAudience            string
	RelayRegion              string
	TicketMaxClockSkew       time.Duration
	TicketRevokedJTIsJSON    string
	TicketRevokedDevicesJSON string
	RevocationFeedURL        string
	RevocationFeedToken      string
	RevocationPollInterval   time.Duration
}

type RelayServer struct {
	config            *RelayConfig
	listener          net.Listener
	udpObserverConn   *net.UDPConn
	hub               *hub
	activeConnections int64
	stats             relayStats
	wg                sync.WaitGroup
	shutdownChan      chan struct{}
	closeOnce         sync.Once

	mu          sync.Mutex
	closing     bool
	connections map[net.Conn]struct{}

	// A2: ticket verification
	ticketKeyring map[string]ed25519.PublicKey
	authFailures  *authFailureLimiter

	// Static local denylist from RELAY_TICKET_REVOKED_* JSON env/flags.
	revokedTicketJTIs map[string]struct{}
	revokedDeviceIDs  map[string]struct{}

	// Online control-plane revocation feed snapshot.
	revocationMu               sync.RWMutex
	onlineRevokedTicketJTIs    map[string]struct{}
	onlineRevokedDeviceIDs     map[string]struct{}
	onlineRevokedCredentialIDs map[string]struct{}
}

type relayStats struct {
	acceptedConnectionsTotal        uint64
	rejectedConnectionsTotal        uint64
	frameErrorsTotal                uint64
	udpObserverRequestsTotal        uint64
	udpObserverErrorsTotal          uint64
	authFailuresTotal               uint64
	authRateLimitedTotal            uint64
	legacyRegistrationsTotal        uint64
	authenticatedRegistrationsTotal uint64
	forwardedFramesTotal            uint64
	forwardErrorsTotal              uint64
	revocationRefreshesTotal        uint64
	revocationRefreshFailuresTotal  uint64
}

type RelayStatsSnapshot struct {
	ActiveConnections               int64                       `json:"active_connections"`
	RegisteredPeers                 int                         `json:"registered_peers"`
	AcceptedConnectionsTotal        uint64                      `json:"accepted_connections_total"`
	RejectedConnectionsTotal        uint64                      `json:"rejected_connections_total"`
	FrameErrorsTotal                uint64                      `json:"frame_errors_total"`
	UDPObserverRequestsTotal        uint64                      `json:"udp_observer_requests_total"`
	UDPObserverErrorsTotal          uint64                      `json:"udp_observer_errors_total"`
	AuthFailuresTotal               uint64                      `json:"auth_failures_total"`
	AuthRateLimitedTotal            uint64                      `json:"auth_rate_limited_total"`
	LegacyRegistrationsTotal        uint64                      `json:"legacy_registrations_total"`
	AuthenticatedRegistrationsTotal uint64                      `json:"authenticated_registrations_total"`
	ForwardedFramesTotal            uint64                      `json:"forwarded_frames_total"`
	ForwardErrorsTotal              uint64                      `json:"forward_errors_total"`
	RevocationRefreshesTotal        uint64                      `json:"revocation_refreshes_total"`
	RevocationRefreshFailuresTotal  uint64                      `json:"revocation_refresh_failures_total"`
	AuthFailureSources              []AuthFailureSourceSnapshot `json:"auth_failure_sources,omitempty"`
}

type AuthFailureSourceSnapshot struct {
	SourceKey       string `json:"source_key"`
	Failures        uint64 `json:"failures"`
	RateLimited     uint64 `json:"rate_limited"`
	WindowResetUnix int64  `json:"window_reset_unix"`
}

// RelayTicketClaims are the JWT claims for relay registration.
type relayTicketClaims struct {
	DeviceID      string `json:"device_id"`
	CredentialID  string `json:"credential_id,omitempty"`
	NetworkID     string `json:"network_id"`
	NodeID        string `json:"node_id"`
	RelayRegion   string `json:"relay_region"`
	RelayProtocol int    `json:"relay_protocol"`
	jwt.RegisteredClaims
}

type relayRevocationFeedSnapshot struct {
	GeneratedAt          string   `json:"generated_at"`
	Version              int64    `json:"version"`
	RevokedDeviceIDs     []string `json:"revoked_device_ids"`
	RevokedCredentialIDs []string `json:"revoked_credential_ids"`
	RevokedJTIs          []string `json:"revoked_jtis"`
}

const maxRevocationFeedJSONBytes = 1 << 20
