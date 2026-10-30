package api

import (
	"context"
	"errors"
	"sync"
	"time"
)

const (
	maxRegistrationSessionUsers = 4096
	maxRegistrationSessionWait  = 5 * time.Second
)

var (
	errRegistrationSessionCapacity    = errors.New("registration session capacity exhausted")
	errRegistrationSessionWaitTimeout = errors.New("registration session lock wait timed out")
)

type registrationSessionLocker interface {
	LockContext(context.Context, string) (func(), error)
}

type registrationSessionLock struct {
	token chan struct{}
	refs  int
}

// Entries exist only while an action holds or waits for its device's lock.
// One global admission bound includes waiters; canceled requests release their
// reference without running a control action after their caller has gone away.
type deviceRegistrationSessionLocks struct {
	mu    sync.Mutex
	locks map[string]*registrationSessionLock
	users int
}

func newRegistrationSessionLocks() *deviceRegistrationSessionLocks {
	return &deviceRegistrationSessionLocks{locks: make(map[string]*registrationSessionLock)}
}

func (locks *deviceRegistrationSessionLocks) LockContext(ctx context.Context, deviceID string) (func(), error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	waitCtx, cancel := context.WithTimeout(ctx, maxRegistrationSessionWait)
	defer cancel()
	waitError := func() error {
		if err := ctx.Err(); err != nil {
			return err
		}
		return errRegistrationSessionWaitTimeout
	}
	locks.mu.Lock()
	if waitCtx.Err() != nil {
		locks.mu.Unlock()
		return nil, waitError()
	}
	if locks.users >= maxRegistrationSessionUsers {
		locks.mu.Unlock()
		return nil, errRegistrationSessionCapacity
	}
	entry := locks.locks[deviceID]
	if entry == nil {
		entry = &registrationSessionLock{token: make(chan struct{}, 1)}
		entry.token <- struct{}{}
		locks.locks[deviceID] = entry
	}
	entry.refs++
	locks.users++
	locks.mu.Unlock()
	forget := func() {
		locks.mu.Lock()
		entry.refs--
		locks.users--
		if entry.refs == 0 {
			delete(locks.locks, deviceID)
		}
		locks.mu.Unlock()
	}
	select {
	case <-waitCtx.Done():
		forget()
		return nil, waitError()
	case <-entry.token:
	}
	var once sync.Once
	unlock := func() {
		once.Do(func() {
			entry.token <- struct{}{}
			forget()
		})
	}
	// A token and cancellation can become ready together. Expired waiters
	// never enter the critical section merely because select chose the token.
	if waitCtx.Err() != nil {
		unlock()
		return nil, waitError()
	}
	return unlock, nil
}
