package main

import (
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"strings"
	"sync/atomic"
	"time"
)

func NewRelayServer(config *RelayConfig) (*RelayServer, error) {
	// Validate keyring BEFORE opening listener to avoid leaking listener on failure
	keyring, err := loadTicketKeyring(config)
	if err != nil {
		if config.RequireAuthentication {
			return nil, fmt.Errorf("ticket keyring required when authentication is enabled: %w", err)
		}
		log.Printf("WARNING: no ticket keyring configured; authentication disabled")
	}
	revokedJTIs, err := loadStringSet(config.TicketRevokedJTIsJSON, "ticket revoked jtis")
	if err != nil {
		return nil, err
	}
	revokedDevices, err := loadStringSet(config.TicketRevokedDevicesJSON, "ticket revoked devices")
	if err != nil {
		return nil, err
	}
	authFailures, err := newAuthFailureLimiter(config.AuthFailureLimit, config.AuthFailureWindow)
	if err != nil {
		return nil, err
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

	var udpObserverConn *net.UDPConn
	if strings.TrimSpace(config.UDPObserverBind) != "" {
		udpAddr, err := net.ResolveUDPAddr("udp", config.UDPObserverBind)
		if err != nil {
			_ = listener.Close()
			return nil, fmt.Errorf("invalid UDP observer bind %q: %w", config.UDPObserverBind, err)
		}
		udpObserverConn, err = net.ListenUDP("udp", udpAddr)
		if err != nil {
			_ = listener.Close()
			return nil, fmt.Errorf("failed to listen for UDP observer on %s: %w", config.UDPObserverBind, err)
		}
		log.Printf("UDP observer enabled on %s", udpObserverConn.LocalAddr())
	}

	server := &RelayServer{
		config:            config,
		listener:          listener,
		udpObserverConn:   udpObserverConn,
		hub:               newHub(),
		shutdownChan:      make(chan struct{}),
		connections:       make(map[net.Conn]struct{}),
		ticketKeyring:     keyring,
		authFailures:      authFailures,
		revokedTicketJTIs: revokedJTIs,
		revokedDeviceIDs:  revokedDevices,
	}
	server.hub.forwardDelay = config.ForwardDelay
	server.hub.debugFrames = config.DebugFrames
	server.startRevocationPolling()
	return server, nil
}

func (s *RelayServer) Addr() net.Addr {
	return s.listener.Addr()
}

func (s *RelayServer) UDPObserverAddr() net.Addr {
	if s == nil || s.udpObserverConn == nil {
		return nil
	}
	return s.udpObserverConn.LocalAddr()
}

func (s *RelayServer) Stats() RelayStatsSnapshot {
	if s == nil {
		return RelayStatsSnapshot{}
	}
	registeredPeers := 0
	if s.hub != nil {
		registeredPeers = s.hub.count()
	}
	return RelayStatsSnapshot{
		ActiveConnections:               atomic.LoadInt64(&s.activeConnections),
		RegisteredPeers:                 registeredPeers,
		AcceptedConnectionsTotal:        atomic.LoadUint64(&s.stats.acceptedConnectionsTotal),
		RejectedConnectionsTotal:        atomic.LoadUint64(&s.stats.rejectedConnectionsTotal),
		FrameErrorsTotal:                atomic.LoadUint64(&s.stats.frameErrorsTotal),
		UDPObserverRequestsTotal:        atomic.LoadUint64(&s.stats.udpObserverRequestsTotal),
		UDPObserverErrorsTotal:          atomic.LoadUint64(&s.stats.udpObserverErrorsTotal),
		AuthFailuresTotal:               atomic.LoadUint64(&s.stats.authFailuresTotal),
		AuthRateLimitedTotal:            atomic.LoadUint64(&s.stats.authRateLimitedTotal),
		LegacyRegistrationsTotal:        atomic.LoadUint64(&s.stats.legacyRegistrationsTotal),
		AuthenticatedRegistrationsTotal: atomic.LoadUint64(&s.stats.authenticatedRegistrationsTotal),
		ForwardedFramesTotal:            atomic.LoadUint64(&s.stats.forwardedFramesTotal),
		ForwardErrorsTotal:              atomic.LoadUint64(&s.stats.forwardErrorsTotal),
		RevocationRefreshesTotal:        atomic.LoadUint64(&s.stats.revocationRefreshesTotal),
		RevocationRefreshFailuresTotal:  atomic.LoadUint64(&s.stats.revocationRefreshFailuresTotal),
		AuthFailureSources:              s.authFailures.snapshots(time.Now(), authFailureSourceSnapshotLimit),
	}
}

func (s *RelayServer) Serve() {
	if s.udpObserverConn != nil {
		s.wg.Add(1)
		go s.serveUDPObserver()
	}

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
			atomic.AddUint64(&s.stats.rejectedConnectionsTotal, 1)
			s.mu.Unlock()
			_ = conn.SetWriteDeadline(time.Now().Add(1 * time.Second))
			_, _ = conn.Write(errorFrame(4005, "connection limit exceeded"))
			_ = conn.Close()
			continue
		}

		s.connections[conn] = struct{}{}
		atomic.AddUint64(&s.stats.acceptedConnectionsTotal, 1)
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
		if s.udpObserverConn != nil {
			_ = s.udpObserverConn.Close()
		}

		for c := range s.connections {
			_ = c.Close()
		}
		s.mu.Unlock()

		s.mu.Lock()
		if s.metricsHTTP != nil {
			_ = s.metricsHTTP.Close()
			s.metricsHTTP = nil
		}
		s.mu.Unlock()

		s.wg.Wait()
	})
	return err
}
