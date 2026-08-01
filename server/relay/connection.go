package main

import (
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"
)

func authFailureSource(addr net.Addr) string {
	if addr == nil {
		return "unknown"
	}
	if tcpAddr, ok := addr.(*net.TCPAddr); ok && tcpAddr.IP != nil {
		return tcpAddr.IP.String()
	}
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		host = addr.String()
	}
	host = strings.Trim(strings.TrimSpace(host), "[]")
	if ip := net.ParseIP(host); ip != nil {
		return ip.String()
	}
	host = strings.ToLower(strings.TrimSpace(host))
	if host == "" {
		return "unknown"
	}
	return host
}

func (s *RelayServer) recordAuthFailure(source string) {
	atomic.AddUint64(&s.stats.authFailuresTotal, 1)
	if s.authFailures != nil {
		s.authFailures.recordFailure(source, time.Now())
	}
}

func (s *RelayServer) rejectAuthRateLimited(conn net.Conn, source string) bool {
	if s.authFailures == nil || s.authFailures.allow(source, time.Now()) {
		return false
	}
	atomic.AddUint64(&s.stats.authFailuresTotal, 1)
	atomic.AddUint64(&s.stats.authRateLimitedTotal, 1)
	_ = conn.SetWriteDeadline(time.Now().Add(1 * time.Second))
	_, _ = conn.Write(errorFrame(errAuthRateLimited, "authentication rate limited"))
	return true
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

	source := authFailureSource(conn.RemoteAddr())
	if s.rejectAuthRateLimited(conn, source) {
		return
	}

	// Registration timeout
	_ = conn.SetReadDeadline(time.Now().Add(s.config.RegisterTimeout))
	typ, payload, err := readFrame(conn, s.config.MaxFramePayload)
	if err != nil {
		atomic.AddUint64(&s.stats.frameErrorsTotal, 1)
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
			s.recordAuthFailure(source)
			_ = conn.SetWriteDeadline(time.Now().Add(1 * time.Second))
			_, _ = conn.Write(errorFrame(errAuthRequired, "authentication required"))
			return
		}

		nodeID := string(payload)
		if nodeID == "" || len(nodeID) > 255 || !utf8.Valid(payload) {
			atomic.AddUint64(&s.stats.frameErrorsTotal, 1)
			_ = conn.SetWriteDeadline(time.Now().Add(1 * time.Second))
			_, _ = conn.Write(errorFrame(4000, "invalid node ID"))
			return
		}

		// Legacy: network_id defaults to "" (empty string)
		s.hub.register(p, "", nodeID)
		atomic.AddUint64(&s.stats.legacyRegistrationsTotal, 1)
		queue(p, makeFrame(msgRegistered, []byte(nodeID)))
		s.handlePostRegister(conn, p, nodeID, "")
		return
	}

	// ---- Handle MSG_AUTH_REGISTER (0x09) ----
	if typ == msgAuthRegister {
		nodeID, ticket, err := parseAuthRegister(payload)
		if err != nil {
			s.recordAuthFailure(source)
			_ = conn.SetWriteDeadline(time.Now().Add(1 * time.Second))
			_, _ = conn.Write(errorFrame(errInvalidTicket, err.Error()))
			return
		}

		// Verify the ticket
		claims, err := s.verifyTicket(ticket)
		if err != nil {
			s.recordAuthFailure(source)
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
			s.recordAuthFailure(source)
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
				s.recordAuthFailure(source)
				_ = conn.SetWriteDeadline(time.Now().Add(1 * time.Second))
				_, _ = conn.Write(errorFrame(errTicketExpired, "ticket expired"))
				return
			}
		}

		// If we have a timer, stop it on connection close
		if expiryTimer != nil {
			defer expiryTimer.Stop()
		}

		atomic.AddUint64(&s.stats.authenticatedRegistrationsTotal, 1)
		s.handlePostRegister(conn, p, nodeID, claims.NetworkID)
		return
	}

	// Unknown first frame type
	_ = conn.SetWriteDeadline(time.Now().Add(1 * time.Second))
	if s.config.RequireAuthentication {
		s.recordAuthFailure(source)
		_, _ = conn.Write(errorFrame(errAuthRequired, "authentication required"))
	} else {
		atomic.AddUint64(&s.stats.frameErrorsTotal, 1)
		_, _ = conn.Write(errorFrame(4002, "registration required"))
	}
}

// handlePostRegister handles the read loop after registration completes.
func (s *RelayServer) handlePostRegister(conn net.Conn, p *peer, nodeID, networkID string) {
	for {
		_ = conn.SetReadDeadline(time.Now().Add(s.config.IdleTimeout))
		typ, payload, err := readFrame(conn, s.config.MaxFramePayload)
		if err != nil {
			atomic.AddUint64(&s.stats.frameErrorsTotal, 1)
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
				atomic.AddUint64(&s.stats.frameErrorsTotal, 1)
				queue(p, errorFrame(4004, "already registered with a different node ID"))
				time.Sleep(50 * time.Millisecond)
				return
			}
			queue(p, makeFrame(msgRegistered, []byte(newID)))

		case msgForward:
			dstID, data, ok := parsePeerPayload(payload)
			if !ok {
				atomic.AddUint64(&s.stats.frameErrorsTotal, 1)
				queue(p, errorFrame(4000, "malformed forward payload"))
				continue
			}
			status, message := s.hub.forward(networkID, p.id, dstID, data, s.config.MaxFramePayload)
			if status != 0 {
				atomic.AddUint64(&s.stats.forwardErrorsTotal, 1)
				queue(p, errorFrame(status, message))
			} else {
				atomic.AddUint64(&s.stats.forwardedFramesTotal, 1)
			}

		case msgPing:
			queue(p, makeFrame(msgPong, payload))

		case msgClose:
			return

		default:
			atomic.AddUint64(&s.stats.frameErrorsTotal, 1)
			queue(p, errorFrame(4000, "unsupported frame type"))
		}
	}
}
