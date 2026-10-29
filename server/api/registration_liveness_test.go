package api

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/yhan-sun/p2wlan/server/auth"
)

type observedRequestBody struct {
	io.ReadCloser
	started chan struct{}
	once    sync.Once
}

func (body *observedRequestBody) Read(data []byte) (int, error) {
	body.once.Do(func() { close(body.started) })
	return body.ReadCloser.Read(data)
}

func sessionRequest(f *registrationSessionFixture, method, path, body string) *http.Request {
	r := f.request(method, path, body)
	r.Header.Set(auth.RegistrationSequenceHeader, strconv.FormatInt(f.device.RegistrationSeq, 10))
	return r
}

func replacementRegistration(f *registrationSessionFixture) *httptest.ResponseRecorder {
	r := f.request(http.MethodPost, "/api/v1/devices", `{"public_key":"`+f.device.PublicKey+`","device_name":"replacement","platform":"linux","network_id":"default","registration_incarnation":9002}`)
	w := httptest.NewRecorder()
	auth.RequireAnyAuth(f.service, f.db)(f.server.RegisterDevice)(w, r)
	return w
}

func awaitSessionEvent(t *testing.T, event <-chan struct{}) {
	t.Helper()
	select {
	case <-event:
	case <-time.After(2 * time.Second):
		t.Fatal("registration event did not complete")
	}
}

func awaitReplacement(t *testing.T, result <-chan *httptest.ResponseRecorder) *httptest.ResponseRecorder {
	t.Helper()
	select {
	case w := <-result:
		return w
	case <-time.After(2 * time.Second):
		t.Fatal("replacement registration did not complete")
		return nil
	}
}

func TestSlowRequestBodyCannotHoldRegistrationOrApplyAfterReplacement(t *testing.T) {
	f := newRegistrationSessionFixture(t)
	reader, writer := io.Pipe()
	defer reader.Close()
	defer writer.Close()
	body := &observedRequestBody{ReadCloser: reader, started: make(chan struct{})}
	r := sessionRequest(f, http.MethodPatch, "/api/v1/devices/"+f.device.ID, "")
	r.SetPathValue("id", f.device.ID)
	r.Body = body
	oldResult := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		w := httptest.NewRecorder()
		f.anySession(f.server.UpdateDevice)(w, r)
		oldResult <- w
	}()
	awaitSessionEvent(t, body.started)
	replacement := make(chan *httptest.ResponseRecorder, 1)
	go func() { replacement <- replacementRegistration(f) }()
	select {
	case w := <-replacement:
		if w.Code != http.StatusOK {
			t.Fatalf("replacement: HTTP %d %s", w.Code, w.Body.String())
		}
	case <-time.After(500 * time.Millisecond):
		writer.Close()
		awaitReplacement(t, oldResult)
		awaitReplacement(t, replacement)
		t.Fatal("partial request body retained the device registration lock")
	}
	if _, err := io.WriteString(writer, `{"device_name":"stale-body-name"}`); err != nil {
		t.Fatal(err)
	}
	writer.Close()
	assertRegistrationLifecycleConflict(t, awaitReplacement(t, oldResult))
	stored, err := f.db.GetDevice(f.device.ID)
	if err != nil || stored.DeviceName != "replacement" {
		t.Fatalf("stale request mutated the replacement: %+v, %v", stored, err)
	}
}

type observedSessionReleases struct {
	base     registrationSessionLocker
	released chan struct{}
}

func (locks *observedSessionReleases) LockContext(ctx context.Context, id string) (func(), error) {
	unlock, err := locks.base.LockContext(ctx, id)
	if err != nil {
		return nil, err
	}
	return func() {
		unlock()
		select {
		case locks.released <- struct{}{}:
		default:
		}
	}, nil
}

func TestIdleSignalPollReleasesRegistrationAndRejectsOldSessionBeforeLeasing(t *testing.T) {
	f := newRegistrationSessionFixture(t)
	locks := &observedSessionReleases{base: f.server.registrationSessionLocks, released: make(chan struct{}, 8)}
	f.server.registrationSessionLocks = locks
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	r := sessionRequest(f, http.MethodGet, "/api/v1/signals?ack=1&wait_ms=1000", "").WithContext(ctx)
	poll := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		w := httptest.NewRecorder()
		f.anySession(f.server.ListSignals)(w, r)
		poll <- w
	}()
	// The first empty DB poll has completed and released its exact lock.
	awaitSessionEvent(t, locks.released)
	replacement := make(chan *httptest.ResponseRecorder, 1)
	go func() { replacement <- replacementRegistration(f) }()
	if w := awaitReplacement(t, replacement); w.Code != http.StatusOK {
		t.Fatalf("replacement: HTTP %d %s", w.Code, w.Body.String())
	}
	signal, err := f.db.CreateSignal(f.peer.ID, f.device.ID, "peer_offer", []string{}, nil, "")
	if err != nil {
		t.Fatal(err)
	}
	f.server.signalNotifier.notify(f.device.ID)
	assertRegistrationLifecycleConflict(t, awaitReplacement(t, poll))
	var lease string
	if err := f.db.QueryRow(`SELECT delivery_token FROM signals WHERE id = ?`, signal.ID).Scan(&lease); err != nil {
		t.Fatal(err)
	}
	if lease != "" {
		t.Fatal("obsolete long poll leased the replacement's signal")
	}
}

type blockedSessionResponse struct {
	header  http.Header
	started chan struct{}
	release chan struct{}
	once    sync.Once
}

func (w *blockedSessionResponse) Header() http.Header { return w.header }
func (w *blockedSessionResponse) WriteHeader(int) {
	w.once.Do(func() { close(w.started) })
	<-w.release
}
func (w *blockedSessionResponse) Write(body []byte) (int, error) { return len(body), nil }

func TestSlowResponseDoesNotHoldRegistrationLock(t *testing.T) {
	f := newRegistrationSessionFixture(t)
	r := sessionRequest(f, http.MethodPatch, "/api/v1/devices/"+f.device.ID, `{"device_name":"before-response"}`)
	r.SetPathValue("id", f.device.ID)
	w := &blockedSessionResponse{header: make(http.Header), started: make(chan struct{}), release: make(chan struct{})}
	finished := make(chan struct{})
	go func() { f.anySession(f.server.UpdateDevice)(w, r); close(finished) }()
	awaitSessionEvent(t, w.started)
	replacement := make(chan *httptest.ResponseRecorder, 1)
	go func() { replacement <- replacementRegistration(f) }()
	select {
	case result := <-replacement:
		if result.Code != http.StatusOK {
			t.Errorf("replacement: HTTP %d %s", result.Code, result.Body.String())
		}
	case <-time.After(500 * time.Millisecond):
		t.Error("network response write retained the device registration lock")
	}
	close(w.release)
	awaitSessionEvent(t, finished)
}

func TestSessionRequestBodyLimitRemainsBounded(t *testing.T) {
	for _, wrapped := range []bool{false, true} {
		t.Run(strconv.FormatBool(wrapped), func(t *testing.T) {
			f := newRegistrationSessionFixture(t)
			r := sessionRequest(f, http.MethodPost, "/api/v1/signals", "")
			r.Body = io.NopCloser(bytes.NewReader(bytes.Repeat([]byte("x"), (1<<20)+1)))
			w := httptest.NewRecorder()
			if wrapped {
				r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
			}
			called := false
			f.anySession(func(http.ResponseWriter, *http.Request) { called = true })(w, r)
			if w.Code != http.StatusRequestEntityTooLarge || called || !strings.Contains(w.Body.String(), "too large") {
				t.Fatalf("unbounded request: called=%v HTTP %d %s", called, w.Code, w.Body.String())
			}
		})
	}
}

func TestCredentialRevokedDuringBodyReadCannotCommit(t *testing.T) {
	f := newRegistrationSessionFixture(t)
	credential, _, err := f.db.ValidateDeviceCredential(f.credential)
	if err != nil {
		t.Fatal(err)
	}
	reader, writer := io.Pipe()
	defer reader.Close()
	defer writer.Close()
	body := &observedRequestBody{ReadCloser: reader, started: make(chan struct{})}
	r := sessionRequest(f, http.MethodPatch, "/api/v1/devices/"+f.device.ID, "")
	r.SetPathValue("id", f.device.ID)
	r.Body = body
	result := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		w := httptest.NewRecorder()
		f.anySession(f.server.UpdateDevice)(w, r)
		result <- w
	}()
	awaitSessionEvent(t, body.started)
	if err := f.db.RevokeDeviceCredential(credential.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(writer, `{"device_name":"revoked-name"}`); err != nil {
		t.Fatal(err)
	}
	writer.Close()
	if w := awaitReplacement(t, result); w.Code != http.StatusUnauthorized {
		t.Fatalf("revoked credential committed: HTTP %d %s", w.Code, w.Body.String())
	}
	stored, err := f.db.GetDevice(f.device.ID)
	if err != nil || stored.DeviceName == "revoked-name" {
		t.Fatalf("revoked request changed device: %+v, %v", stored, err)
	}
}
