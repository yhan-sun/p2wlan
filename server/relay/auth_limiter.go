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

const maxAuthFailureSources = 4096

type authFailureBucket struct {
	windowStart time.Time
	failures    uint64
	rateLimited uint64
}

type authFailureLimiter struct {
	mu      sync.Mutex
	limit   int
	window  time.Duration
	salt    []byte
	buckets map[string]*authFailureBucket
	// Unknown sources share a conservative bucket at capacity instead of
	// evicting a source that has already exhausted its authentication budget.
	overflow  *authFailureBucket
	nextPrune time.Time
	lastNow   time.Time
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
}

func (l *authFailureLimiter) expired(bucket *authFailureBucket, now time.Time) bool {
	return bucket == nil || now.Before(bucket.windowStart) || now.Sub(bucket.windowStart) >= l.window
}

func (l *authFailureLimiter) pruneExpiredLocked(now time.Time) {
	l.nextPrune = time.Time{}
	for source, bucket := range l.buckets {
		if l.expired(bucket, now) {
			delete(l.buckets, source)
		} else {
			l.noteExpiryLocked(bucket.windowStart.Add(l.window))
		}
	}
	if l.expired(l.overflow, now) {
		l.overflow = nil
	} else {
		l.noteExpiryLocked(l.overflow.windowStart.Add(l.window))
	}
	l.lastNow = now
}

func (l *authFailureLimiter) noteExpiryLocked(expiry time.Time) {
	if l.nextPrune.IsZero() || expiry.Before(l.nextPrune) {
		l.nextPrune = expiry
	}
}

func (l *authFailureLimiter) bucketForSourceLocked(source string, now time.Time) *authFailureBucket {
	source = strings.TrimSpace(source)
	if source == "" {
		source = "unknown"
	}
	if bucket := l.buckets[source]; !l.expired(bucket, now) {
		return bucket
	}
	// Reclaim windows on a new/expired source. Both memory and the maximum
	// work under the limiter lock are bounded by maxAuthFailureSources.
	if l.nextPrune.IsZero() || !now.Before(l.nextPrune) || now.Before(l.lastNow) {
		l.pruneExpiredLocked(now)
	}
	l.lastNow = now
	if len(l.buckets) >= maxAuthFailureSources {
		if l.overflow == nil {
			l.overflow = &authFailureBucket{windowStart: now}
			l.noteExpiryLocked(now.Add(l.window))
		}
		return l.overflow
	}
	bucket := &authFailureBucket{windowStart: now}
	l.buckets[source] = bucket
	l.noteExpiryLocked(now.Add(l.window))
	return bucket
}

func (l *authFailureLimiter) snapshots(now time.Time, maxEntries int) []AuthFailureSourceSnapshot {
	if l == nil || maxEntries <= 0 {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.pruneExpiredLocked(now)
	// Keep only the requested top entries while scanning the bounded table;
	// metrics never allocates a copy proportional to historical source count.
	maxEntries = min(maxEntries, maxAuthFailureSources+1)
	snapshots := make([]AuthFailureSourceSnapshot, 0, maxEntries)
	appendBucket := func(source string, bucket *authFailureBucket, overflow bool) {
		if bucket == nil || (bucket.failures == 0 && bucket.rateLimited == 0) {
			return
		}
		snapshot := AuthFailureSourceSnapshot{
			Overflow:        overflow,
			SourceKey:       l.sourceKey(source),
			Failures:        bucket.failures,
			RateLimited:     bucket.rateLimited,
			WindowResetUnix: bucket.windowStart.Add(l.window).Unix(),
		}
		index := sort.Search(len(snapshots), func(i int) bool {
			leftTotal := snapshot.Failures + snapshot.RateLimited
			rightTotal := snapshots[i].Failures + snapshots[i].RateLimited
			return leftTotal > rightTotal || (leftTotal == rightTotal && snapshot.SourceKey < snapshots[i].SourceKey)
		})
		if index >= maxEntries {
			return
		}
		if len(snapshots) < maxEntries {
			snapshots = append(snapshots, AuthFailureSourceSnapshot{})
		}
		copy(snapshots[index+1:], snapshots[index:len(snapshots)-1])
		snapshots[index] = snapshot
	}
	for source, bucket := range l.buckets {
		appendBucket(source, bucket, false)
	}
	appendBucket("overflow", l.overflow, true)
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
