package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

var errRevocationFeedUnavailable = errors.New("revocation feed not ready or stale")

type revocationIdentity struct {
	kind  string
	value string
}

const relayRevocationCacheRetention = 24 * time.Hour

func (s *RelayServer) pruneRevocationCacheLocked(now time.Time) {
	for key, observed := range s.revocationObservedAt {
		if now.Sub(observed) <= relayRevocationCacheRetention {
			continue
		}
		switch key.kind {
		case "device":
			delete(s.onlineRevokedDeviceIDs, key.value)
		case "credential":
			delete(s.onlineRevokedCredentialIDs, key.value)
		case "ticket":
			delete(s.onlineRevokedTicketJTIs, key.value)
		}
		delete(s.revocationObservedAt, key)
	}
}

func (s *RelayServer) startRevocationPolling() {
	if s.config == nil || strings.TrimSpace(s.config.RevocationFeedURL) == "" {
		return
	}
	interval := s.config.RevocationPollInterval
	if interval <= 0 {
		interval = 30 * time.Second
	}

	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		go func() {
			<-s.shutdownChan
			cancel()
		}()

		for {
			s.pollRevocationFeedOnce(ctx)
			delay := interval
			s.revocationMu.RLock()
			catchingUp := s.revocationThrough > s.revocationCursor
			s.revocationMu.RUnlock()
			if catchingUp {
				delay = 250 * time.Millisecond
			}
			timer := time.NewTimer(delay)
			select {
			case <-timer.C:
			case <-s.shutdownChan:
				timer.Stop()
				return
			}
		}
	}()
}

func (s *RelayServer) pollRevocationFeedOnce(parent context.Context) {
	ctx, cancel := context.WithTimeout(parent, 10*time.Second)
	defer cancel()
	if err := s.refreshRevocationFeed(ctx); err != nil {
		atomic.AddUint64(&s.stats.revocationRefreshFailuresTotal, 1)
		log.Printf("relay revocation feed refresh failed: %v", err)
	}
	s.closePeersWhenRevocationsStale()
}

func (s *RelayServer) refreshRevocationFeed(ctx context.Context) error {
	s.revocationSyncMu.Lock()
	defer s.revocationSyncMu.Unlock()
	endpoint := strings.TrimSpace(s.config.RevocationFeedURL)
	feedCredential := strings.TrimSpace(s.config.RevocationFeedToken)
	if endpoint == "" {
		return nil
	}
	if feedCredential == "" {
		return fmt.Errorf("revocation feed credential is required")
	}
	base, err := url.Parse(endpoint)
	if err != nil {
		return fmt.Errorf("invalid revocation feed URL")
	}
	s.revocationMu.RLock()
	cursor, through := s.revocationCursor, s.revocationThrough
	s.revocationMu.RUnlock()
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	for pageNumber := 0; pageNumber < 64; pageNumber++ {
		target := *base
		query := target.Query()
		query.Set("protocol", "2")
		query.Set("after", strconv.FormatInt(cursor, 10))
		if through > 0 {
			query.Set("through", strconv.FormatInt(through, 10))
		} else {
			query.Del("through")
		}
		target.RawQuery = query.Encode()
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, target.String(), nil)
		if err != nil {
			return fmt.Errorf("build revocation request: %w", err)
		}
		req.Header.Set("Authorization", "Bearer "+feedCredential)
		req.Header.Set("Accept", "application/json")
		resp, err := client.Do(req)
		if err != nil {
			return fmt.Errorf("fetch revocation feed: %w", err)
		}
		body, readErr := io.ReadAll(io.LimitReader(resp.Body, maxRevocationFeedJSONBytes+1))
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("revocation feed HTTP %d", resp.StatusCode)
		}
		if readErr != nil {
			return fmt.Errorf("read revocation feed: %w", readErr)
		}
		if len(body) > maxRevocationFeedJSONBytes {
			return fmt.Errorf("revocation feed body exceeds %d bytes", maxRevocationFeedJSONBytes)
		}
		var page relayRevocationFeedSnapshot
		decoder := json.NewDecoder(bytes.NewReader(body))
		if err := decoder.Decode(&page); err != nil {
			return fmt.Errorf("decode revocation feed: %w", err)
		}
		if decoder.Decode(&struct{}{}) != io.EOF {
			return fmt.Errorf("revocation feed has trailing JSON data")
		}
		if page.ProtocolVersion != 0 && page.ProtocolVersion != 2 {
			return fmt.Errorf("unsupported revocation protocol")
		}
		if page.ProtocolVersion == 2 {
			if page.After != cursor || page.NextCursor < cursor || page.NextCursor > page.Version ||
				(through > 0 && page.Version != through) ||
				(page.HasMore && (page.NextCursor == cursor || page.NextCursor == page.Version)) ||
				(!page.HasMore && page.NextCursor != page.Version) {
				return fmt.Errorf("invalid revocation page progression")
			}
		}
		if err := s.applyRevocationSnapshot(page); err != nil {
			return err
		}
		s.revocationMu.Lock()
		if page.ProtocolVersion == 2 {
			cursor = page.NextCursor
			s.revocationCursor = cursor
		}
		more := page.ProtocolVersion == 2 && page.HasMore
		if more {
			through = page.Version
			s.revocationThrough = through
		} else {
			s.revocationThrough = 0
			s.revocationLastSuccess = time.Now()
			s.pruneRevocationCacheLocked(s.revocationLastSuccess)
		}
		s.revocationMu.Unlock()
		if !more {
			atomic.AddUint64(&s.stats.revocationRefreshesTotal, 1)
			return nil
		}
	}
	return nil
}

func (s *RelayServer) revocationFeedUsableLocked(now time.Time) bool {
	if s.config == nil || strings.TrimSpace(s.config.RevocationFeedURL) == "" {
		return true
	}
	interval := s.config.RevocationPollInterval
	if interval <= 0 {
		interval = 30 * time.Second
	}
	maxAge := 3*interval + 10*time.Second
	return !s.revocationLastSuccess.IsZero() && now.Sub(s.revocationLastSuccess) <= maxAge
}

func (s *RelayServer) closePeersWhenRevocationsStale() {
	s.revocationMu.Lock()
	var retired []*peer
	if !s.revocationFeedUsableLocked(time.Now()) && s.hub != nil {
		s.hub.mu.Lock()
		for key, p := range s.hub.peers {
			if p.ticketJTI != "" {
				p.revoked.Store(true)
				delete(s.hub.peers, key)
				retired = append(retired, p)
			}
		}
		s.hub.mu.Unlock()
	}
	s.revocationMu.Unlock()
	for _, p := range retired {
		_ = p.conn.Close()
	}
}

func (s *RelayServer) applyRevocationSnapshot(snapshot relayRevocationFeedSnapshot) error {
	if snapshot.Version < 0 {
		return fmt.Errorf("revocation snapshot version must not be negative")
	}
	s.revocationMu.Lock()
	if snapshot.Version < s.revocationVersion {
		version := s.revocationVersion
		s.revocationMu.Unlock()
		return fmt.Errorf(
			"revocation snapshot rollback: version %d is older than %d",
			snapshot.Version,
			version,
		)
	}

	// Control-plane revocations are tombstones, not a mutable allow/deny list.
	// Merge every accepted full snapshot so a stale cache, temporarily empty
	// database, or equal-version response can never resurrect a credential that
	// this relay has already observed as revoked.
	if s.onlineRevokedDeviceIDs == nil {
		s.onlineRevokedDeviceIDs = make(map[string]struct{})
	}
	if s.onlineRevokedCredentialIDs == nil {
		s.onlineRevokedCredentialIDs = make(map[string]struct{})
	}
	if s.onlineRevokedTicketJTIs == nil {
		s.onlineRevokedTicketJTIs = make(map[string]struct{})
	}
	if s.revocationObservedAt == nil {
		s.revocationObservedAt = make(map[revocationIdentity]time.Time)
	}
	observed := time.Now()
	for value := range stringSetFromValues(snapshot.RevokedDeviceIDs) {
		s.onlineRevokedDeviceIDs[value] = struct{}{}
		s.revocationObservedAt[revocationIdentity{"device", value}] = observed
	}
	for value := range stringSetFromValues(snapshot.RevokedCredentialIDs) {
		s.onlineRevokedCredentialIDs[value] = struct{}{}
		s.revocationObservedAt[revocationIdentity{"credential", value}] = observed
	}
	for value := range stringSetFromValues(snapshot.RevokedJTIs) {
		s.onlineRevokedTicketJTIs[value] = struct{}{}
		s.revocationObservedAt[revocationIdentity{"ticket", value}] = observed
	}
	if snapshot.Version > s.revocationVersion {
		s.revocationVersion = snapshot.Version
	}
	// Lock order is revocationMu -> hub.mu, shared with authenticated registration.
	// Mark and unpublish before releasing either lock; close sockets afterwards.
	var retired []*peer
	if s.hub != nil {
		s.hub.mu.Lock()
		for key, p := range s.hub.peers {
			if p.ticketJTI != "" && s.identityRevokedLocked(p.deviceID, p.credentialID, p.ticketJTI) {
				p.revoked.Store(true)
				delete(s.hub.peers, key)
				retired = append(retired, p)
			}
		}
		s.hub.mu.Unlock()
	}
	s.revocationMu.Unlock()
	for _, p := range retired {
		_ = p.conn.Close()
	}
	return nil
}

// Caller holds revocationMu. Static revocations are immutable after startup.
func (s *RelayServer) identityRevokedLocked(deviceID, credentialID, jti string) bool {
	_, staticDevice := s.revokedDeviceIDs[deviceID]
	_, staticTicket := s.revokedTicketJTIs[jti]
	_, device := s.onlineRevokedDeviceIDs[deviceID]
	_, credential := s.onlineRevokedCredentialIDs[credentialID]
	_, ticket := s.onlineRevokedTicketJTIs[jti]
	return staticDevice || staticTicket || device || ticket || (credentialID != "" && credential)
}

// Recheck at publication so a revocation arriving after signature verification
// cannot be missed by both the registration and the snapshot's active-peer scan.
func (s *RelayServer) registerAuthenticated(p *peer, claims *relayTicketClaims) bool {
	s.revocationMu.RLock()
	if !s.revocationFeedUsableLocked(time.Now()) || s.identityRevokedLocked(claims.DeviceID, claims.CredentialID, claims.ID) {
		s.revocationMu.RUnlock()
		return false
	}
	p.deviceID, p.credentialID, p.ticketJTI = claims.DeviceID, claims.CredentialID, claims.ID
	old := s.hub.registerSwap(p, claims.NetworkID, claims.NodeID)
	s.revocationMu.RUnlock()
	if old != nil {
		_ = old.conn.Close()
	}
	return true
}
