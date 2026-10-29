package main

import (
	"sync"
	"time"
)

const maxAuthRequestSources = 4096

type authRequestBucket struct {
	count int
	start time.Time
}

// Each authentication route owns one bounded table. New sources share one
// conservative budget at capacity; source churn cannot evict active limits.
type authRequestLimiter struct {
	mu        sync.Mutex
	limit     int
	window    time.Duration
	sources   map[string]*authRequestBucket
	overflow  *authRequestBucket
	nextPrune time.Time
	lastNow   time.Time
}

func newAuthRequestLimiter(limit int, window time.Duration) *authRequestLimiter {
	return &authRequestLimiter{limit: limit, window: window, sources: make(map[string]*authRequestBucket)}
}

func (l *authRequestLimiter) expired(b *authRequestBucket, now time.Time) bool {
	return b == nil || now.Before(b.start) || now.Sub(b.start) >= l.window
}

func (l *authRequestLimiter) noteExpiry(b *authRequestBucket) {
	expiry := b.start.Add(l.window)
	if l.nextPrune.IsZero() || expiry.Before(l.nextPrune) {
		l.nextPrune = expiry
	}
}

func (l *authRequestLimiter) allow(source string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.nextPrune.IsZero() || !now.Before(l.nextPrune) || now.Before(l.lastNow) {
		l.nextPrune = time.Time{}
		for key, bucket := range l.sources {
			if l.expired(bucket, now) {
				delete(l.sources, key)
			} else {
				l.noteExpiry(bucket)
			}
		}
		if l.expired(l.overflow, now) {
			l.overflow = nil
		} else {
			l.noteExpiry(l.overflow)
		}
	}
	l.lastNow = now
	bucket := l.sources[source]
	if bucket == nil {
		if len(l.sources) >= maxAuthRequestSources {
			if l.overflow == nil {
				l.overflow = &authRequestBucket{start: now}
				l.noteExpiry(l.overflow)
			}
			bucket = l.overflow
		} else {
			bucket = &authRequestBucket{start: now}
			l.sources[source] = bucket
			l.noteExpiry(bucket)
		}
	}
	if bucket.count >= l.limit {
		return false
	}
	bucket.count++
	return true
}
