package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestAuthRateLimitUsesBoundedOverflowWithoutResettingActiveBudgets(t *testing.T) {
	t.Setenv("CONTROL_TRUSTED_PROXY_CIDRS", "")
	handler := rateLimit(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }, 1, time.Minute)
	request := func(index int) int {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/login", nil)
		req.RemoteAddr = fmt.Sprintf("[2001:db8::%x]:12345", index)
		w := httptest.NewRecorder()
		handler(w, req)
		return w.Code
	}
	for source := 1; source <= 4097; source++ {
		if got := request(source); got != http.StatusNoContent {
			t.Fatalf("initial source %d: status %d", source, got)
		}
	}
	if got := request(4098); got != http.StatusTooManyRequests {
		t.Fatalf("new sources must share the exhausted overflow budget at capacity: status %d", got)
	}
	if got := request(1); got != http.StatusTooManyRequests {
		t.Fatalf("source churn reset an existing budget: status %d", got)
	}
}

func TestAuthRateLimitReclaimsExpiredAndFutureWindows(t *testing.T) {
	limiter := newAuthRequestLimiter(1, time.Minute)
	now := time.Unix(1_800_000_000, 0)
	for source := 0; source < maxAuthRequestSources+100; source++ {
		limiter.allow(fmt.Sprint(source), now)
	}
	if len(limiter.sources) != maxAuthRequestSources {
		t.Fatalf("unbounded source table: %d", len(limiter.sources))
	}
	if !limiter.allow("after-expiry", now.Add(time.Minute)) || len(limiter.sources) != 1 || limiter.overflow != nil {
		t.Fatal("expired sources or overflow budget were not reclaimed at their exact deadline")
	}
	if !limiter.allow("after-expiry", now.Add(-time.Second)) || len(limiter.sources) != 1 {
		t.Fatal("clock rollback retained an unreachable future window")
	}
}
