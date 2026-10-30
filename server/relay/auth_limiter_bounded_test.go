package main

import (
	"fmt"
	"testing"
	"time"
)

func TestAuthFailureSourcesBoundedWithoutResettingActiveBudgets(t *testing.T) {
	limiter, err := newAuthFailureLimiter(2, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1000, 0)
	limiter.recordFailure("blocked", now)
	limiter.recordFailure("blocked", now)
	for i := 0; i < maxAuthFailureSources*2; i++ {
		limiter.recordFailure(fmt.Sprintf("source-%d", i), now)
	}
	if len(limiter.buckets) != maxAuthFailureSources {
		t.Fatalf("source table is not bounded: %d", len(limiter.buckets))
	}
	if limiter.allow("blocked", now) {
		t.Fatal("source churn reset an active source's failure budget")
	}
	if limiter.allow("new-source-at-capacity", now) {
		t.Fatal("source churn bypassed the conservative overflow budget")
	}
	snapshots := limiter.snapshots(now, 3)
	if len(snapshots) != 3 || cap(snapshots) != 3 {
		t.Fatalf("snapshot allocation did not honor limit: len=%d cap=%d", len(snapshots), cap(snapshots))
	}
	if !snapshots[0].Overflow || snapshots[0].Failures < uint64(maxAuthFailureSources) {
		t.Fatal("overflow failures are not observable")
	}
	later := now.Add(24 * time.Hour)
	if got := limiter.snapshots(later, 3); len(got) != 0 || len(limiter.buckets) != 0 || limiter.overflow != nil {
		t.Fatalf("expired source buckets retained: snapshots=%v buckets=%d", got, len(limiter.buckets))
	}
	if !limiter.allow("new-source-after-expiry", later) {
		t.Fatal("expired overflow kept rejecting a fresh window")
	}
}

func TestAuthFailureSourceCleanupOnTrafficAndClockRollback(t *testing.T) {
	limiter, err := newAuthFailureLimiter(1, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1000, 0)
	limiter.recordFailure("old", now)
	limiter.recordFailure("new", now.Add(time.Minute))
	if len(limiter.buckets) != 1 || limiter.buckets["old"] != nil {
		t.Fatal("traffic did not reclaim expired buckets")
	}
	if !limiter.allow("new", now.Add(-time.Minute)) {
		t.Fatal("clock rollback retained a future failure window")
	}
}
