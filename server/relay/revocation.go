package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"sync/atomic"
	"time"
)

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

		s.pollRevocationFeedOnce(ctx)

		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				s.pollRevocationFeedOnce(ctx)
			case <-s.shutdownChan:
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
}

func (s *RelayServer) refreshRevocationFeed(ctx context.Context) error {
	url := strings.TrimSpace(s.config.RevocationFeedURL)
	token := strings.TrimSpace(s.config.RevocationFeedToken)
	if url == "" {
		return nil
	}
	if token == "" {
		return fmt.Errorf("revocation feed token is required when feed url is configured")
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return fmt.Errorf("build revocation feed request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("fetch revocation feed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("revocation feed HTTP %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxRevocationFeedJSONBytes+1))
	if err != nil {
		return fmt.Errorf("read revocation feed: %w", err)
	}
	if len(body) > maxRevocationFeedJSONBytes {
		return fmt.Errorf("revocation feed body exceeds %d bytes", maxRevocationFeedJSONBytes)
	}

	var snapshot relayRevocationFeedSnapshot
	decoder := json.NewDecoder(bytes.NewReader(body))
	if err := decoder.Decode(&snapshot); err != nil {
		return fmt.Errorf("decode revocation feed: %w", err)
	}
	if decoder.Decode(&struct{}{}) != io.EOF {
		return fmt.Errorf("decode revocation feed: trailing JSON data")
	}
	if err := s.applyRevocationSnapshot(snapshot); err != nil {
		return err
	}
	atomic.AddUint64(&s.stats.revocationRefreshesTotal, 1)
	log.Printf("relay revocation feed updated: version=%d devices=%d credentials=%d jtis=%d",
		snapshot.Version,
		len(snapshot.RevokedDeviceIDs),
		len(snapshot.RevokedCredentialIDs),
		len(snapshot.RevokedJTIs),
	)
	return nil
}

func (s *RelayServer) applyRevocationSnapshot(snapshot relayRevocationFeedSnapshot) error {
	if snapshot.Version < 0 {
		return fmt.Errorf("revocation snapshot version must not be negative")
	}
	s.revocationMu.Lock()
	defer s.revocationMu.Unlock()
	if snapshot.Version < s.revocationVersion {
		return fmt.Errorf(
			"revocation snapshot rollback: version %d is older than %d",
			snapshot.Version,
			s.revocationVersion,
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
	for value := range stringSetFromValues(snapshot.RevokedDeviceIDs) {
		s.onlineRevokedDeviceIDs[value] = struct{}{}
	}
	for value := range stringSetFromValues(snapshot.RevokedCredentialIDs) {
		s.onlineRevokedCredentialIDs[value] = struct{}{}
	}
	for value := range stringSetFromValues(snapshot.RevokedJTIs) {
		s.onlineRevokedTicketJTIs[value] = struct{}{}
	}
	if snapshot.Version > s.revocationVersion {
		s.revocationVersion = snapshot.Version
	}
	return nil
}
