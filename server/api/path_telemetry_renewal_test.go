package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/yhan-sun/p2wlan/server/auth"
	"github.com/yhan-sun/p2wlan/server/database"
)

func TestStablePathSamplesRenewFreshnessWithoutCreatingTransitionsOrTrendSamples(t *testing.T) {
	f := newRegistrationSessionFixture(t)
	now := time.Now().Unix()
	old := now - database.DeviceOnlineTTL - 30
	submit := func(observedAt int64, path string) database.PathTelemetryIngestSummary {
		t.Helper()
		body := fmt.Sprintf(`{"observations":[{"remote_device_id":%q,"network_id":%q,"observation_revision":8,"network_generation":1,"peer_session_generation":1,"remote_candidate_epoch":1,"lifecycle":"online","current_path":%q,"transition_reason":"direct_committed","observed_at":%d}]}`, f.peer.ID, f.device.NetworkID, path, observedAt)
		req := f.request(http.MethodPost, "/api/v1/telemetry/paths", body)
		req.Header.Set(auth.RegistrationSequenceHeader, strconv.FormatInt(f.device.RegistrationSeq, 10))
		w := httptest.NewRecorder()
		f.deviceSession(f.server.SubmitPathTelemetry)(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("submit: HTTP %d %s", w.Code, w.Body.String())
		}
		var result database.PathTelemetryIngestSummary
		if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
			t.Fatal(err)
		}
		return result
	}
	if result := submit(old, "direct"); result.Accepted != 1 {
		t.Fatalf("initial sample: %+v", result)
	}
	if _, err := f.db.Exec(`UPDATE peer_path_observations SET received_at=? WHERE reporting_device_id=?`, old, f.device.ID); err != nil {
		t.Fatal(err)
	}
	assertFresh := func(want bool) {
		t.Helper()
		page, err := f.db.AdminConnections(database.AdminConnectionFilter{ReportingDeviceID: f.device.ID}, 10, 0)
		if err != nil || len(page.Items) != 1 || page.Items[0].Fresh != want {
			t.Fatalf("want fresh=%v, page=%+v err=%v", want, page, err)
		}
	}
	assertFresh(false)
	// A raw replay or contradictory state under the same committed revision
	// cannot make a stale path look current.
	if result := submit(old, "direct"); result.Duplicate != 1 {
		t.Fatalf("replay: %+v", result)
	}
	assertFresh(false)
	if result := submit(now, "relay"); result.Rejected != 1 {
		t.Fatalf("same-revision contradiction: %+v", result)
	}
	assertFresh(false)
	if result := submit(now, "direct"); result.Duplicate != 1 || result.Accepted != 0 {
		t.Fatalf("stable fresh sample: %+v", result)
	}
	assertFresh(true)
	health, err := f.db.AdminConnectionHealth(database.AdminConnectionHealthFilter{NetworkID: f.device.NetworkID})
	if err != nil || health.Summary.FreshObservations != 1 || health.Summary.StaleObservations != 0 {
		t.Fatalf("health diverged after renewal: %+v %v", health, err)
	}
	var transitions int
	if err := f.db.QueryRow(`SELECT COUNT(*) FROM peer_path_transitions WHERE reporting_device_id=?`, f.device.ID).Scan(&transitions); err != nil || transitions != 1 {
		t.Fatalf("stable sampling manufactured transitions: %d %v", transitions, err)
	}
	trends, err := f.db.AdminConnectionTrends(database.AdminConnectionTrendsFilter{NetworkID: f.device.NetworkID, WindowHours: 1})
	if err != nil || len(trends.Buckets) != 1 || trends.Buckets[0].AcceptedObservationSamples != 1 || trends.Buckets[0].PathSwitches != 0 {
		t.Fatalf("stable sampling manufactured trend samples: %+v %v", trends, err)
	}
}
