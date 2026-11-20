package database

import (
	"database/sql"
	"errors"
	"time"
)

const wakeJobColumns = `id,network_id,wake_target_id,agent_device_id,state,reason,attempts,created_at,expires_at,finished_at,
 agent_registration_seq,claimed_at,claim_token,target_mac,requester_user_id`

func readWakeJob(row interface{ Scan(...any) error }) (WakeJob, error) {
	var j WakeJob
	err := row.Scan(&j.ID, &j.NetworkID, &j.TargetID, &j.AgentID, &j.State, &j.Reason,
		&j.Attempts, &j.CreatedAt, &j.ExpiresAt, &j.FinishedAt, &j.agentSeq, &j.claimedAt, &j.claimToken, &j.mac, &j.requesterID)
	return j, err
}

func loadWakeJob(tx *sql.Tx, id string) (WakeJob, error) {
	job, err := readWakeJob(tx.QueryRow(`SELECT `+wakeJobColumns+` FROM wake_jobs WHERE id=?`, id))
	return job, wakeMissing(err)
}

func wakeEligibleAgents(tx *sql.Tx, actor string, target WakeTarget, now int64) ([]WakeAgent, error) {
	rows, err := tx.Query(`SELECT d.id,d.device_name,d.registration_seq FROM devices d
		WHERE d.network_id=? AND d.id!=? AND d.wake_proxy=1 AND d.online=1 AND d.last_seen>=?
		AND d.registration_incarnation>0 AND EXISTS(SELECT 1 FROM device_credentials c WHERE c.device_id=d.id AND c.revoked=0 AND c.expires_at>=?)
		AND `+deviceRoomAllowedSQL+` AND `+deviceAccountVisibleSQL+` ORDER BY d.device_name,d.id`,
		target.NetworkID, target.device, now-DeviceOnlineTTL, now, actor, actor)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	agents := []WakeAgent{}
	for rows.Next() {
		var agent WakeAgent
		if err := rows.Scan(&agent.ID, &agent.Name, &agent.seq); err != nil {
			return nil, err
		}
		agents = append(agents, agent)
	}
	return agents, rows.Err()
}

func pickWakeAgent(agents []WakeAgent, explicitID, preferredID string) (WakeAgent, error) {
	if len(agents) == 0 {
		return WakeAgent{}, wakeError("wake_agent_unavailable")
	}
	if explicitID != "" {
		for _, agent := range agents {
			if agent.ID == explicitID {
				return agent, nil
			}
		}
		return WakeAgent{}, &WakeError{Code: "wake_agent_unavailable", Agents: agents}
	}
	if len(agents) == 1 {
		return agents[0], nil
	}
	for _, agent := range agents {
		if agent.ID == preferredID {
			return agent, nil
		}
	}
	return WakeAgent{}, &WakeError{Code: "wake_agent_ambiguous", Agents: agents}
}

func (db *DB) EnqueueWakeJob(actor string, ref WakeTargetRef, explicitAgent string) (WakeJob, error) {
	if !validateWakeText(explicitAgent, 256) {
		return WakeJob{}, wakeError("wake_invalid")
	}
	tx, err := db.beginRoomWrite()
	if err != nil {
		return WakeJob{}, err
	}
	defer tx.Rollback()
	now := time.Now().Unix()
	target, online, err := lookupWakeTarget(tx, actor, ref, now)
	if err != nil {
		return WakeJob{}, err
	}
	if !target.Enabled || target.mac == "" {
		return WakeJob{}, wakeError("target_no_mac")
	}
	existing, err := readWakeJob(tx.QueryRow(`SELECT `+wakeJobColumns+` FROM wake_jobs
		WHERE wake_target_id=? AND created_at>? ORDER BY created_at DESC,id DESC LIMIT 1`, target.ID, now-30))
	if err == nil {
		return visibleWakeJob(existing, now), tx.Commit()
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return WakeJob{}, err
	}
	if online {
		return WakeJob{}, wakeError("already_online")
	}
	agents, err := wakeEligibleAgents(tx, actor, target, now)
	if err != nil {
		return WakeJob{}, err
	}
	agent, err := pickWakeAgent(agents, explicitAgent, target.PreferredAgentDeviceID)
	if err != nil {
		return WakeJob{}, err
	}
	if err = checkWakeJobLimits(tx, actor, target, now); err != nil {
		return WakeJob{}, err
	}
	job, err := insertWakeJob(tx, actor, target, agent, now)
	if err != nil {
		return WakeJob{}, err
	}
	if explicitAgent != "" {
		_, err = tx.Exec(`UPDATE wake_targets SET preferred_agent_device_id=?,updated_at=?
			WHERE id=? AND (owner_user_id=? OR EXISTS(SELECT 1 FROM rooms WHERE network_id=wake_targets.network_id AND owner_id=?))`,
			agent.ID, now, target.ID, actor, actor)
		if err != nil {
			return WakeJob{}, err
		}
	}
	return job, tx.Commit()
}

func checkWakeJobLimits(tx *sql.Tx, actor string, target WakeTarget, now int64) error {
	var targetMinute, targetTen, actorMinute, activeTarget, activeNetwork int
	err := tx.QueryRow(`SELECT
		(SELECT count(*) FROM wake_jobs WHERE wake_target_id=? AND created_at>?),
		(SELECT count(*) FROM wake_jobs WHERE wake_target_id=? AND created_at>?),
		(SELECT count(*) FROM wake_jobs WHERE requester_user_id=? AND created_at>?),
		(SELECT count(*) FROM wake_jobs WHERE wake_target_id=? AND state IN ('queued','claimed') AND expires_at>?),
		(SELECT count(*) FROM wake_jobs WHERE network_id=? AND state IN ('queued','claimed') AND expires_at>?)`,
		target.ID, now-60, target.ID, now-10, actor, now-60, target.ID, now, target.NetworkID, now).
		Scan(&targetMinute, &targetTen, &actorMinute, &activeTarget, &activeNetwork)
	if err != nil {
		return err
	}
	if targetMinute >= 6 || targetTen >= 1 || actorMinute >= 10 || activeTarget >= 4 || activeNetwork >= 32 {
		return wakeError("wake_rate_limited")
	}
	return nil
}

func insertWakeJob(tx *sql.Tx, actor string, target WakeTarget, agent WakeAgent, now int64) (WakeJob, error) {
	id, err := roomRandomID("wake-job-", 16)
	if err != nil {
		return WakeJob{}, err
	}
	job := WakeJob{
		ID: id, NetworkID: target.NetworkID, TargetID: target.ID, AgentID: agent.ID,
		State: wakeQueued, CreatedAt: now, ExpiresAt: now + wakeJobTTL,
	}
	_, err = tx.Exec(`INSERT INTO wake_jobs (id,network_id,wake_target_id,target_mac,agent_device_id,agent_registration_seq,
		requester_user_id,state,created_at,expires_at) VALUES (?,?,?,?,?,?,?,'queued',?,?)`,
		id, target.NetworkID, target.ID, target.mac, agent.ID, agent.seq, actor, now, job.ExpiresAt)
	return job, err
}

func (db *DB) ListWakeJobs(session WakeDeviceSession, limit int) ([]WakeJob, error) {
	if limit < 1 || limit > 4 {
		return nil, wakeError("wake_invalid")
	}
	tx, err := db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	now := time.Now().Unix()
	if _, err = wakeRegistrationDevice(tx, session, true, now); err != nil {
		return nil, err
	}
	rows, err := tx.Query(`SELECT `+wakeJobColumns+` FROM wake_jobs WHERE agent_device_id=? AND agent_registration_seq=?
		AND state IN ('queued','claimed') AND expires_at>? AND (state='queued' OR (attempts<? AND claimed_at<=?))
		ORDER BY created_at,id LIMIT ?`, session.DeviceID, session.RegistrationSeq, now, wakeAttempts, now-wakeClaimTTL, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	jobs := []WakeJob{}
	for rows.Next() {
		job, err := readWakeJob(rows)
		if err != nil {
			return nil, err
		}
		jobs = append(jobs, job)
	}
	return jobs, rows.Err()
}

func wakeJobTarget(tx *sql.Tx, job WakeJob, actor string, now int64) (WakeTarget, bool, error) {
	var device string
	err := tx.QueryRow(`SELECT COALESCE(device_id,'') FROM wake_targets WHERE id=? AND network_id=?`, job.TargetID, job.NetworkID).Scan(&device)
	if err != nil {
		return WakeTarget{}, false, wakeMissing(err)
	}
	return lookupWakeTarget(tx, actor, WakeTargetRef{DeviceID: device, TargetID: job.TargetID}, now)
}

func (db *DB) GetWakeJob(actor, id string, session *WakeDeviceSession) (WakeJob, error) {
	tx, err := db.Begin()
	if err != nil {
		return WakeJob{}, err
	}
	defer tx.Rollback()
	now := time.Now().Unix()
	if session != nil {
		job, err := assignedWakeJob(tx, *session, id, now)
		return visibleWakeJob(job, now), err
	}
	job, err := loadWakeJob(tx, id)
	if err != nil {
		return WakeJob{}, err
	}
	if _, _, err = wakeJobTarget(tx, job, actor, now); err != nil {
		return WakeJob{}, err
	}
	return visibleWakeJob(job, now), nil
}

func visibleWakeJob(job WakeJob, now int64) WakeJob {
	if (job.State == wakeQueued || job.State == wakeClaimed) && now >= wakeJobDeadline(job) {
		job.FinishedAt = wakeJobDeadline(job)
		job.State = wakeExpired
		job.Reason = "expired"
	}
	return job
}

func assignedWakeJob(tx *sql.Tx, session WakeDeviceSession, id string, now int64) (WakeJob, error) {
	device, err := wakeRegistrationDevice(tx, session, true, now)
	if err != nil {
		return WakeJob{}, err
	}
	job, err := loadWakeJob(tx, id)
	if err != nil {
		return WakeJob{}, err
	}
	if job.AgentID != device.id || job.NetworkID != device.network {
		return WakeJob{}, wakeError("wake_not_found")
	}
	if job.agentSeq != session.RegistrationSeq {
		return WakeJob{}, wakeError("wake_job_stale")
	}
	return job, nil
}

func (db *DB) ClaimWakeJob(session WakeDeviceSession, id string) (WakeClaim, error) {
	tx, err := db.beginRoomWrite()
	if err != nil {
		return WakeClaim{}, err
	}
	defer tx.Rollback()
	now := time.Now().Unix()
	job, err := assignedWakeJob(tx, session, id, now)
	if err != nil {
		return WakeClaim{}, err
	}
	if job.State == wakeExpired || now >= wakeJobDeadline(job) {
		return WakeClaim{}, wakeError("expired")
	}
	if job.State != wakeQueued && (job.State != wakeClaimed || now < job.claimedAt+wakeClaimTTL) {
		return WakeClaim{}, wakeError("wake_job_unavailable")
	}
	target, online, err := wakeJobTarget(tx, job, job.requesterID, now)
	var denial *WakeError
	switch {
	case errors.As(err, &denial):
		return WakeClaim{}, rejectWakeClaim(tx, job, "target_blocked", now)
	case err != nil:
		return WakeClaim{}, err
	case !target.Enabled || target.ID != job.TargetID || target.mac != job.mac:
		return WakeClaim{}, rejectWakeClaim(tx, job, "target_no_mac", now)
	case online:
		return WakeClaim{}, rejectWakeClaim(tx, job, "already_online", now)
	}
	token, err := roomRandomID("", 16)
	if err != nil {
		return WakeClaim{}, err
	}
	if _, err = tx.Exec(`UPDATE wake_jobs SET state='claimed',claimed_at=?,claim_token=?,attempts=attempts+1 WHERE id=?`,
		now, token, job.ID); err != nil {
		return WakeClaim{}, err
	}
	if err = tx.Commit(); err != nil {
		return WakeClaim{}, err
	}
	deadline := min(job.ExpiresAt, now+wakeClaimTTL)
	return WakeClaim{
		MAC: job.mac, ExpiresAt: deadline, ClaimToken: token,
		LeaseMS: max(int64(0), time.Until(time.Unix(deadline, 0)).Milliseconds()),
	}, nil
}

func rejectWakeClaim(tx *sql.Tx, job WakeJob, reason string, now int64) error {
	if _, err := tx.Exec(`UPDATE wake_jobs SET state='failed',reason=?,target_mac='',claim_token='',finished_at=? WHERE id=?`,
		reason, now, job.ID); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	return wakeError(reason)
}

func (db *DB) FinishWakeJob(session WakeDeviceSession, id, token, state, reason string) (WakeJob, error) {
	if err := checkedWakeClaimToken(token); err != nil {
		return WakeJob{}, err
	}
	if err := validateWakeResult(state, reason); err != nil {
		return WakeJob{}, err
	}
	tx, err := db.beginRoomWrite()
	if err != nil {
		return WakeJob{}, err
	}
	defer tx.Rollback()
	now := time.Now().Unix()
	job, err := assignedWakeJob(tx, session, id, now)
	if err != nil {
		return WakeJob{}, err
	}
	if job.claimToken != token {
		return WakeJob{}, wakeError("wake_job_stale")
	}
	if job.State == state && job.Reason == reason {
		return job, nil
	}
	if now >= min(job.ExpiresAt, job.claimedAt+wakeClaimTTL) {
		return WakeJob{}, wakeError("expired")
	}
	if job.State != wakeClaimed {
		return WakeJob{}, wakeError("wake_job_unavailable")
	}
	if _, err = tx.Exec(`UPDATE wake_jobs SET state=?,reason=?,target_mac='',finished_at=? WHERE id=?`,
		state, reason, now, job.ID); err != nil {
		return WakeJob{}, err
	}
	job.State, job.Reason, job.FinishedAt = state, reason, now
	return job, tx.Commit()
}
