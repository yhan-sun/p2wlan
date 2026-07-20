package main

import (
	"crypto/ed25519"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unicode/utf8"

	"github.com/golang-jwt/jwt/v5"
)

var magic = []byte{'D', 'E', 'R', 'P'}

const (
	version          = byte(1)
	frameHeader      = 8
	msgRegister      = byte(0x01)
	msgRegistered    = byte(0x02)
	msgForward       = byte(0x03)
	msgReceived      = byte(0x04)
	msgPing          = byte(0x05)
	msgPong          = byte(0x06)
	msgError         = byte(0x07)
	msgClose         = byte(0x08)
	msgAuthRegister  = byte(0x09)
)

// A2 error codes (extending A1 codes)
const (
	errAuthRequired     = uint16(4011)
	errInvalidTicket    = uint16(4012)
	errTicketExpired    = uint16(4013)
	errAudienceMismatch = uint16(4014)
	errIdentityMismatch = uint16(4015)
	errNetworkMismatch  = uint16(4016)
	errTicketNotYetVal  = uint16(4017)
	errUnknownTicketKey = uint16(4018)
)

var (
	ErrInvalidMagic    = fmt.Errorf("invalid magic")
	ErrUnsupportedVers = fmt.Errorf("unsupported version")
	ErrFrameTooLarge   = fmt.Errorf("frame too large")
)

type RelayConfig struct {
	Bind                       string
	SendQueueCapacity          int
	RegisterTimeout            time.Duration
	IdleTimeout                time.Duration
	MaxConnections             int
	MaxFramePayload            int
	// A2: security settings
	RequireAuthentication      bool
	AllowLegacyUnauthenticated bool
	TLSCertChainPath           string
	TLSPrivateKeyPath          string
	AllowInsecurePlaintext     bool
	// A2: ticket verification
	TicketKeyringJSON          string
	RelayAudience              string
	RelayRegion                string
	TicketMaxClockSkew         time.Duration
}

// networkNodeKey is the composite key for the peer table: (network_id, node_id).
type networkNodeKey struct {
	networkID string
	nodeID    string
}

type peer struct {
	id        string // node_id (for logging)
	networkID string
	deviceID  string
	conn      net.Conn
	send      chan []byte
	done      chan struct{}
}

type hub struct {
	mu    sync.RWMutex
	peers map[networkNodeKey]*peer
}

func newHub() *hub {
	return &hub{peers: map[networkNodeKey]*peer{}}
}

func (h *hub) register(p *peer, networkID, nodeID string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	key := networkNodeKey{networkID: networkID, nodeID: nodeID}
	if old := h.peers[key]; old != nil && old != p {
		_ = old.conn.Close()
	}
	p.id = nodeID
	p.networkID = networkID
	h.peers[key] = p
}

func (h *hub) unregister(p *peer) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if p.id != "" && p.networkID != "" {
		key := networkNodeKey{networkID: p.networkID, nodeID: p.id}
		if h.peers[key] == p {
			delete(h.peers, key)
		}
	}
}

// lookup returns the peer for a given network+node, or nil.
func (h *hub) lookup(networkID, nodeID string) *peer {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.peers[networkNodeKey{networkID: networkID, nodeID: nodeID}]
}

// forward forwards payload and returns error code (0 for success).
// Uses network-scoped lookup: source and destination must be in the same network.
func (h *hub) forward(srcNetwork, srcID, dstID string, data []byte, maxFramePayload int) uint16 {
	dst := h.lookup(srcNetwork, dstID)
	if dst == nil {
		// Return 404 even if peer exists in a different network — do not leak
		// that information to the sender.
		return 404
	}

	// Enforce max_frame_payload limit on outbound frames
	totalLen := 1 + len(srcID) + len(data)
	if totalLen > maxFramePayload {
		return 4006 // ERR_FRAME_TOO_LARGE
	}

	frame, err := receivedFrame(srcID, data)
	if err != nil {
		return 4000
	}
	select {
	case dst.send <- frame:
		return 0
	case <-dst.done:
		return 404
	default:
		// slow consumer backpressure: close target connection
		_ = dst.conn.Close()
		return 4008
	}
}

type RelayServer struct {
	config            *RelayConfig
	listener          net.Listener
	hub               *hub
	activeConnections int64
	wg                sync.WaitGroup
	shutdownChan      chan struct{}
	closeOnce         sync.Once

	mu          sync.Mutex
	closing     bool
	connections map[net.Conn]struct{}

	// A2: ticket verification
	ticketKeyring map[string]ed25519.PublicKey
}

// RelayTicketClaims are the JWT claims for relay registration.
type relayTicketClaims struct {
	DeviceID      string `json:"device_id"`
	NetworkID     string `json:"network_id"`
	NodeID        string `json:"node_id"`
	RelayRegion   string `json:"relay_region"`
	RelayProtocol int    `json:"relay_protocol"`
	jwt.RegisteredClaims
}

func NewRelayServer(config *RelayConfig) (*RelayServer, error) {
	// Validate keyring BEFORE opening listener to avoid leaking listener on failure
	keyring, err := loadTicketKeyring(config)
	if err != nil {
		if config.RequireAuthentication {
			return nil, fmt.Errorf("ticket keyring required when authentication is enabled: %w", err)
		}
		log.Printf("WARNING: no ticket keyring configured; authentication disabled")
	}

	// Determine TLS or plaintext
	var listener net.Listener
	hasTLS := config.TLSCertChainPath != "" && config.TLSPrivateKeyPath != ""
	if hasTLS {
		cert, err := tls.LoadX509KeyPair(config.TLSCertChainPath, config.TLSPrivateKeyPath)
		if err != nil {
			return nil, fmt.Errorf("failed to load TLS certificate: %w", err)
		}
		tlsConfig := &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS13,
		}
		listener, err = tls.Listen("tcp", config.Bind, tlsConfig)
		if err != nil {
			return nil, fmt.Errorf("failed to listen with TLS on %s: %w", config.Bind, err)
		}
		log.Printf("TLS enabled on %s", config.Bind)
	} else {
		if !config.AllowInsecurePlaintext {
			return nil, fmt.Errorf("TLS must be configured or allow_insecure_plaintext must be set (development only)")
		}
		listener, err = net.Listen("tcp", config.Bind)
		if err != nil {
			return nil, err
		}
		log.Printf("WARNING: plaintext mode enabled on %s (development only)", config.Bind)
	}

	return &RelayServer{
		config:        config,
		listener:      listener,
		hub:           newHub(),
		shutdownChan:  make(chan struct{}),
		connections:   make(map[net.Conn]struct{}),
		ticketKeyring: keyring,
	}, nil
}

// loadTicketKeyring parses RELAY_TICKET_KEYRING_JSON or config field.
// Expected format: {"kid-1": "<hex-encoded 32-byte Ed25519 public key>", ...}
func loadTicketKeyring(config *RelayConfig) (map[string]ed25519.PublicKey, error) {
	raw := strings.TrimSpace(config.TicketKeyringJSON)
	if raw == "" {
		raw = strings.TrimSpace(os.Getenv("RELAY_TICKET_KEYRING_JSON"))
	}
	if raw == "" {
		return nil, fmt.Errorf("no ticket keyring configured")
	}

	var rawKeys map[string]string
	if err := json.Unmarshal([]byte(raw), &rawKeys); err != nil {
		return nil, fmt.Errorf("invalid ticket keyring JSON: %w", err)
	}

	keyring := make(map[string]ed25519.PublicKey)
	for kid, hexKey := range rawKeys {
		bytes, err := hex.DecodeString(strings.TrimSpace(hexKey))
		if err != nil {
			return nil, fmt.Errorf("invalid hex key for kid '%s': %w", kid, err)
		}
		if len(bytes) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("public key for kid '%s' is %d bytes (expected %d)", kid, len(bytes), ed25519.PublicKeySize)
		}
		keyring[kid] = ed25519.PublicKey(bytes)
	}

	if len(keyring) == 0 {
		return nil, fmt.Errorf("ticket keyring is empty")
	}

	return keyring, nil
}

// verifyTicket parses and validates a relay ticket JWT.
func (s *RelayServer) verifyTicket(tokenStr string) (*relayTicketClaims, error) {
	if s.ticketKeyring == nil {
		return nil, fmt.Errorf("ticket verification not configured")
	}

	clockSkew := s.config.TicketMaxClockSkew
	if clockSkew <= 0 {
		clockSkew = 30 * time.Second
	}

	parser := jwt.NewParser(
		jwt.WithValidMethods([]string{"EdDSA"}),
		jwt.WithIssuer("p2wlan-control"),
		jwt.WithLeeway(clockSkew),
	)

	token, err := parser.ParseWithClaims(tokenStr, &relayTicketClaims{},
		func(t *jwt.Token) (interface{}, error) {
			if t.Method.Alg() != "EdDSA" {
				return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
			}
			typ, _ := t.Header["typ"].(string)
			if typ != "p2wlan-relay+jwt" {
				return nil, fmt.Errorf("invalid token type")
			}
			kid, ok := t.Header["kid"].(string)
			if !ok || kid == "" {
				return nil, fmt.Errorf("missing kid")
			}
			pub, ok := s.ticketKeyring[kid]
			if !ok {
				return nil, fmt.Errorf("unknown kid: %s", kid)
			}
			return ed25519.PublicKey(pub), nil
		},
	)
	if err != nil {
		return nil, fmt.Errorf("ticket verification failed: %w", err)
	}

	claims, ok := token.Claims.(*relayTicketClaims)
	if !ok || !token.Valid {
		return nil, fmt.Errorf("invalid ticket claims")
	}

	// Validate required claims
	if claims.DeviceID == "" {
		return nil, fmt.Errorf("missing device_id")
	}
	if claims.NetworkID == "" {
		return nil, fmt.Errorf("missing network_id")
	}
	if claims.NodeID == "" {
		return nil, fmt.Errorf("missing node_id")
	}
	if claims.RelayProtocol != 1 {
		return nil, fmt.Errorf("unsupported relay protocol: %d", claims.RelayProtocol)
	}

	// Strict claim validation
	if claims.Subject != claims.DeviceID {
		return nil, fmt.Errorf("identity mismatch: sub '%s' != device_id '%s'",
			claims.Subject, claims.DeviceID)
	}
	if claims.ID == "" {
		return nil, fmt.Errorf("missing jti")
	}
	if claims.IssuedAt == nil {
		return nil, fmt.Errorf("missing iat")
	}
	if claims.ExpiresAt == nil {
		return nil, fmt.Errorf("missing exp")
	}
	if claims.NotBefore == nil {
		return nil, fmt.Errorf("missing nbf")
	}
	// Audience must be single value, not array
	if len(claims.Audience) != 1 {
		return nil, fmt.Errorf("audience must be a single value, got %d", len(claims.Audience))
	}

	// Validate audience matches this relay (mandatory when auth is enabled)
	if s.config.RelayAudience == "" {
		return nil, fmt.Errorf("relay audience not configured; required for ticket verification")
	}
	audMatch := false
	for _, aud := range claims.Audience {
		if aud == s.config.RelayAudience {
			audMatch = true
			break
		}
	}
	if !audMatch {
		return nil, fmt.Errorf("audience mismatch: ticket is for %v, relay expects %s",
			claims.Audience, s.config.RelayAudience)
	}

	// Validate region matches (mandatory when auth is enabled)
	if s.config.RelayRegion == "" {
		return nil, fmt.Errorf("relay region not configured; required for ticket verification")
	}
	if claims.RelayRegion != s.config.RelayRegion {
		return nil, fmt.Errorf("region mismatch: ticket is for '%s', relay serves '%s'",
			claims.RelayRegion, s.config.RelayRegion)
	}

	return claims, nil
}

func (s *RelayServer) Addr() net.Addr {
	return s.listener.Addr()
}

func (s *RelayServer) Serve() {
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			select {
			case <-s.shutdownChan:
				return
			default:
				if ne, ok := err.(net.Error); ok && ne.Timeout() {
					continue
				}
				return
			}
		}

		s.mu.Lock()
		if s.closing {
			s.mu.Unlock()
			_ = conn.Close()
			continue
		}

		// Atomic connection limit check
		if atomic.AddInt64(&s.activeConnections, 1) > int64(s.config.MaxConnections) {
			atomic.AddInt64(&s.activeConnections, -1)
			s.mu.Unlock()
			_ = conn.SetWriteDeadline(time.Now().Add(1 * time.Second))
			_, _ = conn.Write(errorFrame(4005, "connection limit exceeded"))
			_ = conn.Close()
			continue
		}

		s.connections[conn] = struct{}{}
		s.wg.Add(1)
		s.mu.Unlock()

		go func(c net.Conn) {
			defer func() {
				s.mu.Lock()
				delete(s.connections, c)
				s.mu.Unlock()
				s.wg.Done()
			}()
			s.handleConn(c)
		}(conn)
	}
}

func (s *RelayServer) Close() error {
	var err error
	s.closeOnce.Do(func() {
		s.mu.Lock()
		s.closing = true
		close(s.shutdownChan)
		err = s.listener.Close()

		for c := range s.connections {
			_ = c.Close()
		}
		s.mu.Unlock()

		s.wg.Wait()
	})
	return err
}

func main() {
	config, err := parseConfig(os.Args[1:])
	if err != nil {
		log.Fatalf("config error: %v", err)
	}

	server, err := NewRelayServer(config)
	if err != nil {
		log.Fatalf("listen error: %v", err)
	}

	log.Printf("p2wlan relay listening on %s (limits: connections=%d, payload=%d)", server.Addr(), config.MaxConnections, config.MaxFramePayload)

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-stop
		_ = server.Close()
	}()

	server.Serve()
}

func getenv(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}

func getIntEnv(key string, fallback int) (int, error) {
	val := os.Getenv(key)
	if val == "" {
		return fallback, nil
	}
	i, err := strconv.Atoi(val)
	if err != nil {
		return 0, fmt.Errorf("invalid env value for %s: %w", key, err)
	}
	return i, nil
}

func getDurationEnv(key string, fallback time.Duration) (time.Duration, error) {
	val := os.Getenv(key)
	if val == "" {
		return fallback, nil
	}
	d, err := time.ParseDuration(val)
	if err != nil {
		return 0, fmt.Errorf("invalid env value for %s: %w", key, err)
	}
	return d, nil
}

func parseConfig(args []string) (*RelayConfig, error) {
	fs := flag.NewFlagSet("relay", flag.ContinueOnError)

	envSendQueue, err := getIntEnv("RELAY_SEND_QUEUE", 128)
	if err != nil {
		return nil, err
	}
	envRegisterTimeout, err := getDurationEnv("RELAY_REGISTER_TIMEOUT", 5*time.Second)
	if err != nil {
		return nil, err
	}
	envIdleTimeout, err := getDurationEnv("RELAY_IDLE_TIMEOUT", 30*time.Second)
	if err != nil {
		return nil, err
	}
	envMaxConnections, err := getIntEnv("RELAY_MAX_CONNECTIONS", 1000)
	if err != nil {
		return nil, err
	}
	envMaxFramePayload, err := getIntEnv("RELAY_MAX_FRAME_PAYLOAD", 65535)
	if err != nil {
		return nil, err
	}

	bind := fs.String("bind", getenv("RELAY_BIND", ":18081"), "TCP listen address")
	sendQueue := fs.Int("send-queue", envSendQueue, "Send queue capacity")
	registerTimeout := fs.Duration("register-timeout", envRegisterTimeout, "Register timeout")
	idleTimeout := fs.Duration("idle-timeout", envIdleTimeout, "Idle timeout")
	maxConnections := fs.Int("max-connections", envMaxConnections, "Maximum connections")
	maxFramePayload := fs.Int("max-frame-payload", envMaxFramePayload, "Maximum frame payload")
	// A2 flags
	requireAuth := fs.Bool("require-auth", getenv("RELAY_REQUIRE_AUTH", "true") == "true", "Require authenticated registration")
	allowLegacy := fs.Bool("allow-legacy-unauthenticated", getenv("RELAY_ALLOW_LEGACY_UNAUTH", "false") == "true", "Allow legacy unauthenticated registration")
	tlsCert := fs.String("tls-cert", getenv("RELAY_TLS_CERT", ""), "TLS certificate chain PEM file")
	tlsKey := fs.String("tls-key", getenv("RELAY_TLS_KEY", ""), "TLS private key PEM file")
	allowPlaintext := fs.Bool("allow-insecure-plaintext", getenv("RELAY_ALLOW_INSECURE_PLAINTEXT", "false") == "true", "Allow plaintext TCP (development only)")
	ticketKeyring := fs.String("ticket-keyring", getenv("RELAY_TICKET_KEYRING_JSON", ""), "Ticket verification keyring JSON")
	relayAudience := fs.String("relay-audience", getenv("RELAY_AUDIENCE", ""), "This relay's audience ID")
	relayRegion := fs.String("relay-region", getenv("RELAY_REGION", ""), "This relay's region label")

	if err := fs.Parse(args); err != nil {
		return nil, err
	}

	config := &RelayConfig{
		Bind:                       *bind,
		SendQueueCapacity:          *sendQueue,
		RegisterTimeout:            *registerTimeout,
		IdleTimeout:                *idleTimeout,
		MaxConnections:             *maxConnections,
		MaxFramePayload:            *maxFramePayload,
		RequireAuthentication:      *requireAuth,
		AllowLegacyUnauthenticated: *allowLegacy,
		TLSCertChainPath:           *tlsCert,
		TLSPrivateKeyPath:          *tlsKey,
		AllowInsecurePlaintext:     *allowPlaintext,
		TicketKeyringJSON:          *ticketKeyring,
		RelayAudience:              *relayAudience,
		RelayRegion:                *relayRegion,
	}

	if config.SendQueueCapacity <= 0 {
		return nil, fmt.Errorf("send-queue capacity must be > 0")
	}
	if config.RegisterTimeout <= 0 {
		return nil, fmt.Errorf("register-timeout must be > 0")
	}
	if config.IdleTimeout <= 0 {
		return nil, fmt.Errorf("idle-timeout must be > 0")
	}
	if config.MaxConnections <= 0 {
		return nil, fmt.Errorf("max-connections must be > 0")
	}
	if config.MaxFramePayload <= 0 || config.MaxFramePayload > 65535 {
		return nil, fmt.Errorf("max-frame-payload must be between 1 and 65535")
	}

	// A2: validate security config at startup
	if config.RequireAuthentication {
		if config.TicketKeyringJSON == "" && os.Getenv("RELAY_TICKET_KEYRING_JSON") == "" {
			return nil, fmt.Errorf("require-auth is enabled but no ticket keyring configured (set -ticket-keyring or RELAY_TICKET_KEYRING_JSON)")
		}
		if config.RelayAudience == "" {
			return nil, fmt.Errorf("require-auth is enabled but relay-audience is not set")
		}
		if config.RelayRegion == "" {
			return nil, fmt.Errorf("require-auth is enabled but relay-region is not set")
		}
	}

	return config, nil
}

func (s *RelayServer) handleConn(conn net.Conn) {
	p := &peer{
		conn: conn,
		send: make(chan []byte, s.config.SendQueueCapacity),
		done: make(chan struct{}),
	}

	var writerWg sync.WaitGroup
	writerWg.Add(1)

	defer func() {
		s.hub.unregister(p)
		close(p.done)
		_ = conn.Close()
		writerWg.Wait()
		atomic.AddInt64(&s.activeConnections, -1)
	}()

	go func() {
		defer writerWg.Done()
		for {
			select {
			case frame, ok := <-p.send:
				if !ok {
					return
				}
				if _, err := conn.Write(frame); err != nil {
					_ = conn.Close()
					return
				}
			case <-p.done:
				return
			}
		}
	}()

	// Registration timeout
	_ = conn.SetReadDeadline(time.Now().Add(s.config.RegisterTimeout))
	typ, payload, err := readFrame(conn, s.config.MaxFramePayload)
	if err != nil {
		_ = conn.SetWriteDeadline(time.Now().Add(1 * time.Second))
		if ne, ok := err.(net.Error); ok && ne.Timeout() {
			_, _ = conn.Write(errorFrame(4003, "registration timed out"))
		} else if err == ErrInvalidMagic {
			_, _ = conn.Write(errorFrame(4000, "invalid magic"))
		} else if err == ErrUnsupportedVers {
			_, _ = conn.Write(errorFrame(4001, "unsupported version"))
		} else if err == ErrFrameTooLarge {
			_, _ = conn.Write(errorFrame(4006, "frame too large"))
		}
		return
	}

	// ---- Handle legacy MSG_REGISTER (0x01) ----
	if typ == msgRegister {
		if s.config.RequireAuthentication && !s.config.AllowLegacyUnauthenticated {
			_ = conn.SetWriteDeadline(time.Now().Add(1 * time.Second))
			_, _ = conn.Write(errorFrame(errAuthRequired, "authentication required"))
			return
		}

		nodeID := string(payload)
		if nodeID == "" || len(nodeID) > 255 || !utf8.Valid(payload) {
			_ = conn.SetWriteDeadline(time.Now().Add(1 * time.Second))
			_, _ = conn.Write(errorFrame(4000, "invalid node ID"))
			return
		}

		// Legacy: network_id defaults to "" (empty string)
		s.hub.register(p, "", nodeID)
		queue(p, makeFrame(msgRegistered, []byte(nodeID)))
		s.handlePostRegister(conn, p, nodeID, "")
		return
	}

	// ---- Handle MSG_AUTH_REGISTER (0x09) ----
	if typ == msgAuthRegister {
		nodeID, ticket, err := parseAuthRegister(payload)
		if err != nil {
			_ = conn.SetWriteDeadline(time.Now().Add(1 * time.Second))
			_, _ = conn.Write(errorFrame(errInvalidTicket, err.Error()))
			return
		}

		// Verify the ticket
		claims, err := s.verifyTicket(ticket)
		if err != nil {
			_ = conn.SetWriteDeadline(time.Now().Add(1 * time.Second))
			code := errInvalidTicket
			msg := err.Error()
			// Map specific error types to proper wire codes
			switch {
			case strings.Contains(msg, "expired"):
				code = errTicketExpired
			case strings.Contains(msg, "not yet valid"):
				code = errTicketNotYetVal
			case strings.Contains(msg, "audience"):
				code = errAudienceMismatch
			case strings.Contains(msg, "unknown kid"):
				code = errUnknownTicketKey
			case strings.Contains(msg, "identity"):
				code = errIdentityMismatch
			case strings.Contains(msg, "network"):
				code = errNetworkMismatch
			}
			_, _ = conn.Write(errorFrame(code, msg))
			return
		}

		// Verify node_id from frame matches ticket
		if nodeID != claims.NodeID {
			_ = conn.SetWriteDeadline(time.Now().Add(1 * time.Second))
			_, _ = conn.Write(errorFrame(errIdentityMismatch, "node_id does not match ticket"))
			return
		}

		// Register with network binding
		p.deviceID = claims.DeviceID
		s.hub.register(p, claims.NetworkID, nodeID)
		queue(p, makeFrame(msgRegistered, []byte(nodeID)))

		// Store ticket expiry for connection lifecycle management
		ticketExpiry := claims.ExpiresAt
		var expiryTimer *time.Timer
		if ticketExpiry != nil && ticketExpiry.Unix() > 0 {
			remaining := time.Until(ticketExpiry.Time)
			if remaining > 0 {
				expiryTimer = time.AfterFunc(remaining, func() {
					_ = conn.Close()
				})
			} else {
				// Ticket already expired
				_ = conn.SetWriteDeadline(time.Now().Add(1 * time.Second))
				_, _ = conn.Write(errorFrame(errTicketExpired, "ticket expired"))
				return
			}
		}

		// If we have a timer, stop it on connection close
		if expiryTimer != nil {
			defer expiryTimer.Stop()
		}

		s.handlePostRegister(conn, p, nodeID, claims.NetworkID)
		return
	}

	// Unknown first frame type
	_ = conn.SetWriteDeadline(time.Now().Add(1 * time.Second))
	if s.config.RequireAuthentication {
		_, _ = conn.Write(errorFrame(errAuthRequired, "authentication required"))
	} else {
		_, _ = conn.Write(errorFrame(4002, "registration required"))
	}
}

// handlePostRegister handles the read loop after registration completes.
func (s *RelayServer) handlePostRegister(conn net.Conn, p *peer, nodeID, networkID string) {
	for {
		_ = conn.SetReadDeadline(time.Now().Add(s.config.IdleTimeout))
		typ, payload, err := readFrame(conn, s.config.MaxFramePayload)
		if err != nil {
			_ = conn.SetWriteDeadline(time.Now().Add(1 * time.Second))
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				_, _ = conn.Write(errorFrame(4009, "idle timeout"))
			} else if err == ErrInvalidMagic {
				_, _ = conn.Write(errorFrame(4000, "invalid magic"))
			} else if err == ErrUnsupportedVers {
				_, _ = conn.Write(errorFrame(4001, "unsupported version"))
			} else if err == ErrFrameTooLarge {
				_, _ = conn.Write(errorFrame(4006, "frame too large"))
			}
			return
		}

		switch typ {
		case msgRegister:
			newID := string(payload)
			if newID != p.id || !utf8.Valid(payload) {
				queue(p, errorFrame(4004, "already registered with a different node ID"))
				time.Sleep(50 * time.Millisecond)
				return
			}
			queue(p, makeFrame(msgRegistered, []byte(newID)))

		case msgForward:
			dstID, data, ok := parsePeerPayload(payload)
			if !ok {
				queue(p, errorFrame(4000, "malformed forward payload"))
				continue
			}
			status := s.hub.forward(networkID, p.id, dstID, data, s.config.MaxFramePayload)
			if status != 0 {
				queue(p, errorFrame(status, "forward failed"))
			}

		case msgPing:
			queue(p, makeFrame(msgPong, payload))

		case msgClose:
			return

		default:
			queue(p, errorFrame(4000, "unsupported frame type"))
		}
	}
}

// parseAuthRegister parses the MSG_AUTH_REGISTER binary payload.
// Format: u8 node_id_len | node_id | u16 ticket_len (BE) | ticket
func parseAuthRegister(payload []byte) (nodeID, ticket string, err error) {
	if len(payload) < 1 {
		return "", "", fmt.Errorf("auth register payload empty")
	}
	nodeIDLen := int(payload[0])
	if nodeIDLen == 0 || nodeIDLen > 255 {
		return "", "", fmt.Errorf("invalid node_id_len: %d", nodeIDLen)
	}
	if len(payload) < 1+nodeIDLen+2 {
		return "", "", fmt.Errorf("auth register payload truncated")
	}
	nodeIDBytes := payload[1 : 1+nodeIDLen]
	if !utf8.Valid(nodeIDBytes) {
		return "", "", fmt.Errorf("node_id is not valid UTF-8")
	}
	nodeID = string(nodeIDBytes)

	ticketStart := 1 + nodeIDLen
	ticketLen := int(binary.BigEndian.Uint16(payload[ticketStart : ticketStart+2]))
	if ticketLen == 0 || ticketLen > 8192 {
		return "", "", fmt.Errorf("invalid ticket_len: %d", ticketLen)
	}
	ticketDataStart := ticketStart + 2
	if len(payload) != ticketDataStart+ticketLen {
		return "", "", fmt.Errorf("auth register payload has trailing bytes or is truncated")
	}
	ticket = string(payload[ticketDataStart : ticketDataStart+ticketLen])
	return nodeID, ticket, nil
}

func queue(p *peer, frame []byte) {
	select {
	case p.send <- frame:
	case <-p.done:
	default:
		_ = p.conn.Close()
	}
}

func readFrame(conn net.Conn, maxPayload int) (byte, []byte, error) {
	header := make([]byte, frameHeader)
	if _, err := io.ReadFull(conn, header); err != nil {
		return 0, nil, err
	}
	if string(header[:4]) != string(magic) {
		return 0, nil, ErrInvalidMagic
	}
	if header[4] != version {
		return 0, nil, ErrUnsupportedVers
	}
	length := int(binary.BigEndian.Uint16(header[6:8]))
	if length > maxPayload {
		return 0, nil, ErrFrameTooLarge
	}
	payload := make([]byte, length)
	if length > 0 {
		if _, err := io.ReadFull(conn, payload); err != nil {
			return 0, nil, err
		}
	}
	return header[5], payload, nil
}

func makeFrame(typ byte, payload []byte) []byte {
	frame := make([]byte, frameHeader+len(payload))
	copy(frame[:4], magic)
	frame[4] = version
	frame[5] = typ
	binary.BigEndian.PutUint16(frame[6:8], uint16(len(payload)))
	copy(frame[8:], payload)
	return frame
}

func receivedFrame(srcID string, data []byte) ([]byte, error) {
	if len(srcID) > 255 || len(data)+1+len(srcID) > 65535 {
		return nil, io.ErrShortBuffer
	}
	payload := make([]byte, 1+len(srcID)+len(data))
	payload[0] = byte(len(srcID))
	copy(payload[1:], srcID)
	copy(payload[1+len(srcID):], data)
	return makeFrame(msgReceived, payload), nil
}

func parsePeerPayload(payload []byte) (string, []byte, bool) {
	if len(payload) < 1 {
		return "", nil, false
	}
	idLen := int(payload[0])
	if len(payload) < 1+idLen {
		return "", nil, false
	}
	return string(payload[1 : 1+idLen]), payload[1+idLen:], true
}

func errorFrame(code uint16, message string) []byte {
	payload := make([]byte, 2+len(message))
	binary.BigEndian.PutUint16(payload[:2], code)
	copy(payload[2:], message)
	return makeFrame(msgError, payload)
}
