package main

import (
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

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

func getEnvDurationMs(key string, fallbackMs int64) time.Duration {
	if val := os.Getenv(key); val != "" {
		if ms, err := strconv.ParseInt(val, 10, 64); err == nil && ms >= 0 {
			return time.Duration(ms) * time.Millisecond
		}
	}
	return time.Duration(fallbackMs) * time.Millisecond
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

	// A bounded 256-packet bidirectional overlay burst can have a full
	// one-way burst plus control frames queued while the peer's TCP writer is
	// scheduled. Keep this finite, but leave enough headroom that a healthy
	// relay does not reject a valid burst at the queue boundary.
	envSendQueue, err := getIntEnv("RELAY_SEND_QUEUE", 1024)
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
	envAuthFailureLimit, err := getIntEnv("RELAY_AUTH_FAILURE_LIMIT", 20)
	if err != nil {
		return nil, err
	}
	envAuthFailureWindow, err := getDurationEnv("RELAY_AUTH_FAILURE_WINDOW", time.Minute)
	if err != nil {
		return nil, err
	}
	envRevocationPollInterval, err := getDurationEnv("RELAY_REVOCATION_POLL_INTERVAL", 30*time.Second)
	if err != nil {
		return nil, err
	}

	bind := fs.String("bind", getenv("RELAY_BIND", ":18081"), "TCP listen address")
	udpObserverBind := fs.String("udp-observer-bind", getenv("RELAY_UDP_OBSERVER_BIND", ""), "Optional UDP observer/STUN bind address")
	metricsBind := fs.String("metrics-bind", getenv("RELAY_METRICS_BIND", ""), "Optional read-only metrics HTTP listen address (empty disables)")
	metricsAllowPublic := fs.Bool("metrics-allow-public", getenv("RELAY_METRICS_ALLOW_PUBLIC", "false") == "true", "Explicitly allow the metrics endpoint on a public/wildcard bind (default: loopback/private only)")
	forwardDelay := fs.Duration("forward-delay", getEnvDurationMs("RELAY_FORWARD_DELAY_MS", 0), "Artificial per-frame forwarding delay in ms (diagnostics: slow-relay tests)")
	debugFrames := fs.Bool("debug-frames", getenv("RELAY_DEBUG_FRAMES", "false") == "true", "Log opaque encrypted frame fingerprints (diagnostics only)")
	sendQueue := fs.Int("send-queue", envSendQueue, "Send queue capacity")
	registerTimeout := fs.Duration("register-timeout", envRegisterTimeout, "Register timeout")
	idleTimeout := fs.Duration("idle-timeout", envIdleTimeout, "Idle timeout")
	maxConnections := fs.Int("max-connections", envMaxConnections, "Maximum connections")
	maxFramePayload := fs.Int("max-frame-payload", envMaxFramePayload, "Maximum frame payload")
	authFailureLimit := fs.Int("auth-failure-limit", envAuthFailureLimit, "Authentication failures allowed per source per window (0 disables)")
	authFailureWindow := fs.Duration("auth-failure-window", envAuthFailureWindow, "Authentication failure rate-limit window")
	// A2 flags
	requireAuth := fs.Bool("require-auth", getenv("RELAY_REQUIRE_AUTH", "true") == "true", "Require authenticated registration")
	allowLegacy := fs.Bool("allow-legacy-unauthenticated", getenv("RELAY_ALLOW_LEGACY_UNAUTH", "false") == "true", "Allow legacy unauthenticated registration")
	tlsCert := fs.String("tls-cert", getenv("RELAY_TLS_CERT", ""), "TLS certificate chain PEM file")
	tlsKey := fs.String("tls-key", getenv("RELAY_TLS_KEY", ""), "TLS private key PEM file")
	allowPlaintext := fs.Bool("allow-insecure-plaintext", getenv("RELAY_ALLOW_INSECURE_PLAINTEXT", "false") == "true", "Allow plaintext TCP (development only)")
	ticketKeyring := fs.String("ticket-keyring", getenv("RELAY_TICKET_KEYRING_JSON", ""), "Ticket verification keyring JSON")
	relayAudience := fs.String("relay-audience", getenv("RELAY_AUDIENCE", ""), "This relay's audience ID")
	relayRegion := fs.String("relay-region", getenv("RELAY_REGION", ""), "This relay's region label")
	revokedJTIs := fs.String("ticket-revoked-jtis", getenv("RELAY_TICKET_REVOKED_JTIS_JSON", ""), "JSON array of revoked relay ticket jti values")
	revokedDevices := fs.String("ticket-revoked-devices", getenv("RELAY_TICKET_REVOKED_DEVICES_JSON", ""), "JSON array of revoked relay ticket device_id values")
	revocationFeedURL := fs.String("revocation-feed-url", getenv("RELAY_REVOCATION_FEED_URL", ""), "Control-plane relay revocation feed URL")
	revocationFeedToken := fs.String("revocation-feed-token", getenv("RELAY_REVOCATION_FEED_TOKEN", ""), "Bearer token for the relay revocation feed")
	revocationPollInterval := fs.Duration("revocation-poll-interval", envRevocationPollInterval, "Relay revocation feed polling interval")

	if err := fs.Parse(args); err != nil {
		return nil, err
	}

	config := &RelayConfig{
		Bind:                       *bind,
		UDPObserverBind:            strings.TrimSpace(*udpObserverBind),
		MetricsBind:                strings.TrimSpace(*metricsBind),
		MetricsAllowPublic:         *metricsAllowPublic,
		ForwardDelay:               *forwardDelay,
		DebugFrames:                *debugFrames,
		SendQueueCapacity:          *sendQueue,
		RegisterTimeout:            *registerTimeout,
		IdleTimeout:                *idleTimeout,
		MaxConnections:             *maxConnections,
		MaxFramePayload:            *maxFramePayload,
		AuthFailureLimit:           *authFailureLimit,
		AuthFailureWindow:          *authFailureWindow,
		RequireAuthentication:      *requireAuth,
		AllowLegacyUnauthenticated: *allowLegacy,
		TLSCertChainPath:           *tlsCert,
		TLSPrivateKeyPath:          *tlsKey,
		AllowInsecurePlaintext:     *allowPlaintext,
		TicketKeyringJSON:          *ticketKeyring,
		RelayAudience:              *relayAudience,
		RelayRegion:                *relayRegion,
		TicketRevokedJTIsJSON:      *revokedJTIs,
		TicketRevokedDevicesJSON:   *revokedDevices,
		RevocationFeedURL:          strings.TrimSpace(*revocationFeedURL),
		RevocationFeedToken:        strings.TrimSpace(*revocationFeedToken),
		RevocationPollInterval:     *revocationPollInterval,
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
	if config.AuthFailureLimit < 0 {
		return nil, fmt.Errorf("auth-failure-limit must be >= 0")
	}
	if config.AuthFailureLimit > 0 && config.AuthFailureWindow <= 0 {
		return nil, fmt.Errorf("auth-failure-window must be > 0 when auth-failure-limit is enabled")
	}
	if config.RevocationPollInterval <= 0 {
		return nil, fmt.Errorf("revocation-poll-interval must be > 0")
	}
	if config.RevocationFeedURL != "" && config.RevocationFeedToken == "" {
		return nil, fmt.Errorf("revocation-feed-token is required when revocation-feed-url is set")
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
