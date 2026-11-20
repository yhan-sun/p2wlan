package database

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"
)

const wakeTestMAC = "02:11:22:33:44:55"

func newWakeDevice(t *testing.T, db *DB, user, network, name string, proxy bool) (WakeDeviceSession, *Device) {
	t.Helper()
	device := roomTestDevice(t, db, user, network, name)
	credential, _, err := db.CreateDeviceCredential(device.ID, 3600)
	if err != nil {
		t.Fatal(err)
	}
	boot := int64(1)
	device, err = db.RegisterDeviceWithOptions(user, network, device.PublicKey, name, "linux", "", "", "",
		DeviceRegistrationAttempt{Incarnation: &boot, EnforceIncarnation: true,
			WakeProxyCredential: true, Capabilities: PeerCapabilities{WakeProxyV1: proxy}})
	if err != nil {
		t.Fatal(err)
	}
	return WakeDeviceSession{DeviceID: device.ID, CredentialID: credential.ID, RegistrationSeq: device.RegistrationSeq}, device
}

func requireWakeError(t *testing.T, err error, expected string) {
	t.Helper()
	var got *WakeError
	if !errors.As(err, &got) || got.Code != expected {
		t.Fatalf("error = %v, want %s", err, expected)
	}
}

func setWakeTestDeviceOffline(t *testing.T, db *DB, id string) {
	t.Helper()
	if _, err := db.Exec(`UPDATE devices SET online=0 WHERE id=?`, id); err != nil {
		t.Fatal(err)
	}
}

func createWakeTestManual(t *testing.T, db *DB, actor, network, name string) WakeTarget {
	t.Helper()
	mac := wakeTestMAC
	target, err := db.CreateManualWakeTarget(actor, network, ManualWakeTargetInput{Name: &name, MAC: &mac})
	if err != nil {
		t.Fatal(err)
	}
	return target
}

func TestWakeMACValidation(t *testing.T) {
	for _, input := range []string{"01:11:22:33:44:55", "00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff", "02:11:22:33:44", "02:11:22:33:44:55:66:77"} {
		_, err := normalizeWakeMAC(input)
		requireWakeError(t, err, "wake_invalid")
	}
	mac, err := normalizeWakeMAC(" 02-11-22-33-44-55 ")
	if err != nil || mac != wakeTestMAC {
		t.Fatalf("normalized MAC = %q, %v", mac, err)
	}
}

func TestWakeAtomicClaimReclaimAndResult(t *testing.T) {
	db := roomTestDB(t)
	user := roomTestUser(t, db, "wake-owner")
	session, _ := newWakeDevice(t, db, user, "default", "proxy", true)
	target := createWakeTestManual(t, db, user, "default", "desktop")
	ref := WakeTargetRef{TargetID: target.ID}
	job, err := db.EnqueueWakeJob(user, ref, "")
	if err != nil {
		t.Fatal(err)
	}
	duplicate, err := db.EnqueueWakeJob(user, ref, "")
	if err != nil || duplicate.ID != job.ID {
		t.Fatalf("duplicate %+v, %v", duplicate, err)
	}

	var path string
	if err := db.QueryRow(`SELECT file FROM pragma_database_list WHERE name='main'`).Scan(&path); err != nil {
		t.Fatal(err)
	}
	other, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	out := make(chan WakeClaim, 2)
	failures := make(chan error, 2)
	var wg sync.WaitGroup
	for _, connection := range []*DB{db, other} {
		wg.Go(func() {
			claim, err := connection.ClaimWakeJob(session, job.ID)
			if err != nil {
				failures <- err
				return
			}
			out <- claim
		})
	}
	wg.Wait()
	if len(out) != 1 || len(failures) != 1 {
		t.Fatalf("claims=%d failures=%d", len(out), len(failures))
	}
	requireWakeError(t, <-failures, "wake_job_unavailable")
	first := <-out
	if first.MAC != wakeTestMAC || first.LeaseMS <= 0 || first.LeaseMS > 10000 {
		t.Fatalf("claim returned wrong MAC or lease")
	}

	now := time.Now()
	if _, err = db.Exec(`UPDATE wake_jobs SET claimed_at=? WHERE id=?`, now.Unix()-wakeClaimTTL, job.ID); err != nil {
		t.Fatal(err)
	}
	ready, err := db.ListWakeJobs(session, 4)
	if err != nil || len(ready) != 1 || ready[0].ID != job.ID {
		t.Fatalf("job missing after lease expiry: %v", err)
	}
	reclaimed, err := db.ClaimWakeJob(session, job.ID)
	if err != nil || reclaimed.ClaimToken == first.ClaimToken {
		t.Fatalf("reclaim failed or reused token: %v", err)
	}
	_, err = db.FinishWakeJob(session, job.ID, first.ClaimToken, wakeSent, "")
	requireWakeError(t, err, "wake_job_stale")
	for range 2 {
		result, err := db.FinishWakeJob(session, job.ID, reclaimed.ClaimToken, wakeSent, "")
		if err != nil || result.State != wakeSent || result.Attempts != 2 {
			t.Fatalf("result %+v, %v", result, err)
		}
	}
	_, err = db.FinishWakeJob(session, job.ID, reclaimed.ClaimToken, wakeFailed, "send_failed")
	requireWakeError(t, err, "wake_job_unavailable")
	var storedMAC string
	if err = db.QueryRow(`SELECT target_mac FROM wake_jobs WHERE id=?`, job.ID).Scan(&storedMAC); err != nil || storedMAC != "" {
		t.Fatalf("terminal job retained target MAC: %v", err)
	}
	if err = db.MaintainWakeJobs(context.Background(), now.Add(8*24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	_, err = db.GetWakeJob(user, job.ID, nil)
	requireWakeError(t, err, "wake_not_found")
}

func TestWakeRegistrationAndOwnershipFence(t *testing.T) {
	db := roomTestDB(t)
	owner := roomTestUser(t, db, "owner")
	other := roomTestUser(t, db, "other")
	agent, device := newWakeDevice(t, db, owner, "default", "proxy", true)
	wrongCredential, _ := newWakeDevice(t, db, other, "default", "other-proxy", true)
	target, targetDevice := newWakeDevice(t, db, owner, "default", "target", false)
	if err := db.SetDeviceWakeTarget(target, wakeTestMAC, "ethernet", false); err != nil {
		t.Fatal(err)
	}
	setWakeTestDeviceOffline(t, db, targetDevice.ID)
	ref := WakeTargetRef{DeviceID: targetDevice.ID}
	_, err := db.EnqueueWakeJob(other, ref, "")
	requireWakeError(t, err, "wake_not_found")
	_, err = db.EnqueueWakeJob(owner, ref, wrongCredential.DeviceID)
	requireWakeError(t, err, "wake_agent_unavailable")

	job, err := db.EnqueueWakeJob(owner, ref, "")
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.ClaimWakeJob(wrongCredential, job.ID)
	requireWakeError(t, err, "wake_not_found")
	_, err = db.ClaimWakeJob(target, job.ID)
	requireWakeError(t, err, "wake_proxy_required")
	claim, err := db.ClaimWakeJob(agent, job.ID)
	if err != nil {
		t.Fatal(err)
	}
	boot := int64(2)
	replacement, err := db.RegisterDeviceWithOptions(owner, "default", device.PublicKey, device.DeviceName, "linux", "", "", "",
		DeviceRegistrationAttempt{Incarnation: &boot, EnforceIncarnation: true,
			WakeProxyCredential: true, Capabilities: PeerCapabilities{WakeProxyV1: true}})
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.ClaimWakeJob(agent, job.ID)
	var conflict *RegistrationSessionConflictError
	if !errors.As(err, &conflict) || conflict.CurrentSequence != replacement.RegistrationSeq {
		t.Fatalf("old session was not fenced: %v", err)
	}
	_, err = db.FinishWakeJob(agent, job.ID, claim.ClaimToken, wakeSent, "")
	if !errors.As(err, &conflict) {
		t.Fatalf("late result from the old session was not fenced: %v", err)
	}
	agent.RegistrationSeq = replacement.RegistrationSeq
	_, err = db.ClaimWakeJob(agent, job.ID)
	requireWakeError(t, err, "wake_job_stale")
	_, err = db.FinishWakeJob(agent, job.ID, claim.ClaimToken, wakeSent, "")
	requireWakeError(t, err, "wake_job_stale")

	expired := time.Unix(job.ExpiresAt, 0)
	if err = db.MaintainWakeJobs(context.Background(), expired); err != nil {
		t.Fatal(err)
	}
	state, err := db.GetWakeJob(owner, job.ID, nil)
	if err != nil || state.State != wakeExpired || state.Reason != "expired" {
		t.Fatalf("expiry result %+v, %v", state, err)
	}
}

func TestWakeProxySelectionRemembersSameNetworkChoice(t *testing.T) {
	db := roomTestDB(t)
	user := roomTestUser(t, db, "owner")
	agent, _ := newWakeDevice(t, db, user, "default", "proxy-a", true)
	other, _ := newWakeDevice(t, db, user, "default", "proxy-b", true)
	target, device := newWakeDevice(t, db, user, "default", "target", false)
	if err := db.SetDeviceWakeTarget(target, wakeTestMAC, "ethernet", false); err != nil {
		t.Fatal(err)
	}
	setWakeTestDeviceOffline(t, db, device.ID)
	ref := WakeTargetRef{DeviceID: device.ID}
	_, err := db.EnqueueWakeJob(user, ref, "")
	var ambiguous *WakeError
	if !errors.As(err, &ambiguous) || ambiguous.Code != "wake_agent_ambiguous" || len(ambiguous.Agents) != 2 {
		t.Fatalf("expected two proxy candidates: %v", err)
	}
	job, err := db.EnqueueWakeJob(user, ref, agent.DeviceID)
	if err != nil || job.AgentID != agent.DeviceID {
		t.Fatalf("explicit choice was not assigned: %v", err)
	}
	status, err := db.WakeTargetStatus(user, ref)
	if err != nil || status.PreferredAgentDeviceID != agent.DeviceID {
		t.Fatalf("explicit choice not remembered: %v", err)
	}
	if _, err = db.Exec(`UPDATE wake_jobs SET created_at=?,expires_at=? WHERE id=?`, time.Now().Unix()-31, time.Now().Unix()-1, job.ID); err != nil {
		t.Fatal(err)
	}
	job, err = db.EnqueueWakeJob(user, ref, "")
	if err != nil || job.AgentID != agent.DeviceID {
		t.Fatalf("remembered choice was not selected: %v", err)
	}
	if _, err = db.Exec(`UPDATE devices SET last_seen=? WHERE id=?`, time.Now().Unix()-DeviceOnlineTTL-1, agent.DeviceID); err != nil {
		t.Fatal(err)
	}
	status, err = db.WakeTargetStatus(user, ref)
	if err != nil || len(status.Agents) != 1 || status.Agents[0].ID != other.DeviceID {
		t.Fatalf("stale proxy lease was listed: %v", err)
	}
}

func TestWakeRoomAuthorizationRecheckedAtClaim(t *testing.T) {
	db := roomTestDB(t)
	owner := roomTestUser(t, db, "owner")
	member := roomTestUser(t, db, "member")
	outsider := roomTestUser(t, db, "outsider")
	room := roomTestRoom(t, db, owner)
	if _, err := db.JoinRoom(member, room.Code, "safe-password", ""); err != nil {
		t.Fatal(err)
	}
	agent, _ := newWakeDevice(t, db, owner, room.ID, "room-proxy", true)
	manual := createWakeTestManual(t, db, owner, room.ID, "manual")
	_, err := db.EnqueueWakeJob(member, WakeTargetRef{TargetID: manual.ID}, "")
	requireWakeError(t, err, "wake_not_found")
	_, err = db.EnqueueWakeJob(outsider, WakeTargetRef{TargetID: manual.ID}, "")
	requireWakeError(t, err, "wake_not_found")
	target, device := newWakeDevice(t, db, member, room.ID, "target", false)
	if err = db.SetDeviceWakeTarget(target, wakeTestMAC, "ethernet", false); err != nil {
		t.Fatal(err)
	}
	setWakeTestDeviceOffline(t, db, device.ID)
	ref := WakeTargetRef{DeviceID: device.ID}
	job, err := db.EnqueueWakeJob(owner, ref, "")
	if err != nil {
		t.Fatal(err)
	}
	var accessID string
	if err = db.QueryRow(`SELECT id FROM room_device_access WHERE network_id=? AND public_key=?`, room.ID, device.PublicKey).Scan(&accessID); err != nil {
		t.Fatal(err)
	}
	if _, err = db.ChangeRoomDeviceAccess(owner, room.ID, accessID, "block"); err != nil {
		t.Fatal(err)
	}
	_, err = db.ClaimWakeJob(agent, job.ID)
	requireWakeError(t, err, "target_blocked")
	_, err = db.EnqueueWakeJob(owner, ref, "")
	requireWakeError(t, err, "target_blocked")
}

func TestWakeRequesterRateLimitSurvivesTargetRemoval(t *testing.T) {
	db := roomTestDB(t)
	user := roomTestUser(t, db, "owner")
	newWakeDevice(t, db, user, "default", "proxy", true)
	for i := range 11 {
		target := createWakeTestManual(t, db, user, "default", fmt.Sprint(i))
		_, err := db.EnqueueWakeJob(user, WakeTargetRef{TargetID: target.ID}, "")
		if i >= 10 {
			requireWakeError(t, err, "wake_rate_limited")
		} else if err != nil {
			t.Fatal(err)
		}
		if _, err = db.ChangeManualWakeTarget(user, target.ID, ManualWakeTargetInput{}, true); err != nil {
			t.Fatal(err)
		}
	}
}
