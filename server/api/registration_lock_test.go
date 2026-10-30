package api

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
)

func TestRegistrationLocksReclaimEntriesAndCancelWaiters(t *testing.T) {
	locks := newRegistrationSessionLocks()
	unlock, err := locks.LockContext(context.Background(), "device")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() { _, err := locks.LockContext(ctx, "device"); result <- err }()
	cancel()
	if err := <-result; !errors.Is(err, context.Canceled) {
		t.Fatalf("waiter ignored cancellation: %v", err)
	}
	unlock()
	unlock()
	if len(locks.locks) != 0 || locks.users != 0 {
		t.Fatalf("session locks retained: entries=%d users=%d", len(locks.locks), locks.users)
	}
}

func TestRegistrationLockAdmissionIsBounded(t *testing.T) {
	locks := newRegistrationSessionLocks()
	releases := make([]func(), 0, maxRegistrationSessionUsers)
	for i := 0; i < maxRegistrationSessionUsers; i++ {
		unlock, err := locks.LockContext(context.Background(), fmt.Sprint(i))
		if err != nil {
			t.Fatal(err)
		}
		releases = append(releases, unlock)
	}
	if _, err := locks.LockContext(context.Background(), "overflow"); !errors.Is(err, errRegistrationSessionCapacity) {
		t.Fatalf("unbounded admission: %v", err)
	}
	for _, unlock := range releases {
		unlock()
	}
	if len(locks.locks) != 0 || locks.users != 0 {
		t.Fatal("released registration entries were not reclaimed")
	}
}

func TestRegistrationLockRemainsExclusiveAcrossRetirement(t *testing.T) {
	locks := newRegistrationSessionLocks()
	var active atomic.Int64
	var violated atomic.Bool
	var workers sync.WaitGroup
	for range 16 {
		workers.Go(func() {
			for range 100 {
				unlock, err := locks.LockContext(context.Background(), "same-device")
				if err != nil {
					t.Error(err)
					return
				}
				if active.Add(1) != 1 {
					violated.Store(true)
				}
				active.Add(-1)
				unlock()
			}
		})
	}
	workers.Wait()
	if violated.Load() || len(locks.locks) != 0 {
		t.Fatal("entry retirement broke exclusive ownership or leaked a lock")
	}
}
