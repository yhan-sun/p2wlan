package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"
)

type authFailureBucket struct {
	windowStart time.Time
	failures    uint64
	rateLimited uint64
	lastSeen    time.Time
}

type authFailureLimiter struct {
	mu      sync.Mutex
	limit   int
	window  time.Duration
	salt    []byte
	buckets map[string]*authFailureBucket
}

func newAuthFailureLimiter(limit int, window time.Duration) (*authFailureLimiter, error) {
	if limit <= 0 || window <= 0 {
		return nil, nil
	}
	salt := make([]byte, 32)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("initialize auth failure source salt: %w", err)
	}
	return &authFailureLimiter{
		limit:   limit,
		window:  window,
		salt:    salt,
		buckets: make(map[string]*authFailureBucket),
	}, nil
}

func (l *authFailureLimiter) allow(source string, now time.Time) bool {
	if l == nil {
		return true
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	bucket := l.bucketForSourceLocked(source, now)
	if bucket.failures >= uint64(l.limit) {
		bucket.rateLimited++
		bucket.lastSeen = now
		return false
	}
	return true
}

func (l *authFailureLimiter) recordFailure(source string, now time.Time) {
	if l == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	bucket := l.bucketForSourceLocked(source, now)
	bucket.failures++
	bucket.lastSeen = now
}

func (l *authFailureLimiter) bucketForSourceLocked(source string, now time.Time) *authFailureBucket {
	source = strings.TrimSpace(source)
	if source == "" {
		source = "unknown"
	}
	bucket := l.buckets[source]
	if bucket == nil || now.Before(bucket.windowStart) || now.Sub(bucket.windowStart) >= l.window {
		bucket = &authFailureBucket{windowStart: now, lastSeen: now}
		l.buckets[source] = bucket
	}
	return bucket
}

func (l *authFailureLimiter) snapshots(now time.Time, maxEntries int) []AuthFailureSourceSnapshot {
	if l == nil || maxEntries <= 0 {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	snapshots := make([]AuthFailureSourceSnapshot, 0, len(l.buckets))
	for source, bucket := range l.buckets {
		if now.Before(bucket.windowStart) || now.Sub(bucket.windowStart) >= l.window {
			continue
		}
		if bucket.failures == 0 && bucket.rateLimited == 0 {
			continue
		}
		snapshots = append(snapshots, AuthFailureSourceSnapshot{
			SourceKey:       l.sourceKey(source),
			Failures:        bucket.failures,
			RateLimited:     bucket.rateLimited,
			WindowResetUnix: bucket.windowStart.Add(l.window).Unix(),
		})
	}
	sort.Slice(snapshots, func(i, j int) bool {
		leftTotal := snapshots[i].Failures + snapshots[i].RateLimited
		rightTotal := snapshots[j].Failures + snapshots[j].RateLimited
		if leftTotal != rightTotal {
			return leftTotal > rightTotal
		}
		return snapshots[i].SourceKey < snapshots[j].SourceKey
	})
	if len(snapshots) > maxEntries {
		snapshots = snapshots[:maxEntries]
	}
	return snapshots
}

func (l *authFailureLimiter) sourceKey(source string) string {
	mac := hmac.New(sha256.New, l.salt)
	_, _ = mac.Write([]byte(source))
	return hex.EncodeToString(mac.Sum(nil))[:16]
}

func loadStringSet(raw, label string) (map[string]struct{}, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}
	var values []string
	if err := json.Unmarshal([]byte(raw), &values); err != nil {
		return nil, fmt.Errorf("invalid %s JSON: %w", label, err)
	}
	set := make(map[string]struct{}, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		set[value] = struct{}{}
	}
	return set, nil
}

func stringSetFromValues(values []string) map[string]struct{} {
	set := make(map[string]struct{}, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		set[value] = struct{}{}
	}
	return set
}
