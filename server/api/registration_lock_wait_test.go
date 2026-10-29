package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"testing/synctest"
	"time"
)

func TestRegistrationLockWaitHasDeadlineWithoutCallerCancellation(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		locks := newRegistrationSessionLocks()
		unlock, err := locks.LockContext(context.Background(), "device")
		if err != nil {
			t.Fatal(err)
		}
		defer unlock()
		result := make(chan error, 1)
		go func() {
			_, err := locks.LockContext(context.Background(), "device")
			result <- err
		}()
		synctest.Wait()
		started := time.Now()
		time.Sleep(maxRegistrationSessionWait - time.Nanosecond)
		select {
		case err := <-result:
			t.Fatalf("lock wait ended before its deadline: %v", err)
		default:
		}
		time.Sleep(time.Nanosecond)
		if err := <-result; !errors.Is(err, errRegistrationSessionWaitTimeout) {
			t.Fatalf("unbounded or misclassified wait: %v", err)
		}
		if time.Since(started) != maxRegistrationSessionWait {
			t.Fatal("lock wait extended its fixed acquisition budget")
		}
		if locks.users != 1 || len(locks.locks) != 1 || len(locks.locks["device"].token) != 0 {
			t.Fatal("wait timeout leaked a waiter or forcibly released the active holder")
		}
		unlock()
		if locks.users != 0 || len(locks.locks) != 0 {
			t.Fatal("lock entries survived their final reference")
		}
	})
}

func TestRegistrationLockCallerCancellationPrecedesWaitDeadline(t *testing.T) {
	for _, reason := range []string{"cancel", "deadline"} {
		t.Run(reason, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				locks := newRegistrationSessionLocks()
				unlock, err := locks.LockContext(context.Background(), "device")
				if err != nil {
					t.Fatal(err)
				}
				defer unlock()
				var ctx context.Context
				var cancel context.CancelFunc
				want := context.Canceled
				if reason == "deadline" {
					ctx, cancel = context.WithTimeout(context.Background(), time.Second)
					want = context.DeadlineExceeded
				} else {
					ctx, cancel = context.WithCancel(context.Background())
				}
				defer cancel()
				result := make(chan error, 1)
				go func() { _, err := locks.LockContext(ctx, "device"); result <- err }()
				synctest.Wait()
				time.Sleep(time.Second)
				if reason == "cancel" {
					cancel()
				}
				if err := <-result; !errors.Is(err, want) || errors.Is(err, errRegistrationSessionWaitTimeout) {
					t.Fatalf("caller termination lost its reason: got %v, want %v", err, want)
				}
				if locks.users != 1 || len(locks.locks["device"].token) != 0 {
					t.Fatal("caller termination leaked a waiter or released the holder")
				}
				unlock()
				if locks.users != 0 || len(locks.locks) != 0 {
					t.Fatal("canceled lock references were retained")
				}
			})
		})
	}
}

type registrationFailureLocker struct{ err error }

func (l registrationFailureLocker) LockContext(context.Context, string) (func(), error) {
	return nil, l.err
}

func TestRegistrationLockFailureResponseDistinguishesTimeoutAndCapacity(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
		code string
	}{
		{"wait_timeout", errRegistrationSessionWaitTimeout, "registration_session_wait_timeout"},
		{"capacity", errRegistrationSessionCapacity, "registration_session_capacity"},
		{"unavailable", errors.New("lock provider failed"), "registration_session_unavailable"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := &Server{registrationSessionLocks: registrationFailureLocker{err: tc.err}}
			w := httptest.NewRecorder()
			r := httptest.NewRequest(http.MethodGet, "/api/v1/signals", nil)
			if unlock, ok := s.lockDeviceRegistrationSession(w, r, "device"); ok || unlock != nil {
				t.Fatal("failed acquisition admitted a critical section")
			}
			var body struct {
				ErrorCode string `json:"error_code"`
			}
			if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
				t.Fatal(err)
			}
			if w.Code != http.StatusServiceUnavailable || w.Header().Get("Retry-After") == "" || body.ErrorCode != tc.code {
				t.Fatalf("failure not classified: HTTP %d body=%s", w.Code, w.Body.String())
			}
		})
	}
}

func TestRegistrationLockCanceledRequestDoesNotWriteFailureResponse(t *testing.T) {
	s := &Server{registrationSessionLocks: registrationFailureLocker{err: context.Canceled}}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r := httptest.NewRequest(http.MethodGet, "/api/v1/signals", nil).WithContext(ctx)
	w := httptest.NewRecorder()
	if unlock, ok := s.lockDeviceRegistrationSession(w, r, "device"); ok || unlock != nil {
		t.Fatal("canceled request admitted a critical section")
	}
	if w.Body.Len() != 0 || w.Header().Get("Retry-After") != "" {
		t.Fatal("canceled request wrote a late response")
	}
}
