package database

import (
	"context"
	"database/sql"
	"net"
	"strings"
	"time"
)

const (
	wakeQueued   = "queued"
	wakeClaimed  = "claimed"
	wakeSent     = "sent"
	wakeFailed   = "failed"
	wakeExpired  = "expired"
	wakeJobTTL   = 30
	wakeClaimTTL = 10
	wakeAttempts = 2
	wakeHistory  = 7 * 24 * 60 * 60
)

type WakeError struct {
	Code     string
	Agents   []WakeAgent
	Terminal bool
}

func (e *WakeError) Error() string { return e.Code }

func wakeError(code string) error { return &WakeError{Code: code} }

// WakeAgent is a safe, account-visible description used for LAN selection.
type WakeAgent struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	seq  int64
}

type WakeTarget struct {
	ID                     string `json:"id"`
	NetworkID              string `json:"network_id"`
	Name                   string `json:"name"`
	Enabled                bool   `json:"enabled"`
	PreferredAgentDeviceID string `json:"preferred_agent_device_id,omitempty"`
	owner                  string
	device                 string
	mac                    string
}

type WakeTargetRef struct {
	DeviceID string
	TargetID string
}

type WakeTargetStatus struct {
	Online                 bool        `json:"online"`
	HasMAC                 bool        `json:"has_mac"`
	Agents                 []WakeAgent `json:"agents"`
	PreferredAgentDeviceID string      `json:"preferred_agent_device_id,omitempty"`
}

type WakeJob struct {
	ID          string `json:"id"`
	NetworkID   string `json:"network_id"`
	TargetID    string `json:"wake_target_id"`
	AgentID     string `json:"agent_device_id"`
	State       string `json:"state"`
	Reason      string `json:"reason,omitempty"`
	Attempts    int    `json:"attempts"`
	CreatedAt   int64  `json:"created_at"`
	ExpiresAt   int64  `json:"expires_at"`
	FinishedAt  int64  `json:"finished_at,omitempty"`
	agentSeq    int64
	claimedAt   int64
	claimToken  string
	mac         string
	requesterID string
}

// WakeClaim is the only public wire type that includes a target MAC.
type WakeClaim struct {
	MAC        string `json:"mac"`
	ExpiresAt  int64  `json:"expires_at"`
	ClaimToken string `json:"claim_token"`
	LeaseMS    int64  `json:"lease_ms"`
}

func migrateWake(db *sql.DB) error {
	_, err := db.Exec(`
CREATE TABLE IF NOT EXISTS wake_targets (
 id TEXT PRIMARY KEY,
 network_id TEXT NOT NULL REFERENCES networks(id) ON DELETE CASCADE,
 owner_user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 kind TEXT NOT NULL CHECK(kind IN ('device','manual')),
 device_id TEXT REFERENCES devices(id) ON DELETE CASCADE,
 name TEXT NOT NULL,
 mac TEXT NOT NULL,
 nic TEXT NOT NULL DEFAULT '',
 preferred_agent_device_id TEXT NOT NULL DEFAULT '',
 enabled INTEGER NOT NULL DEFAULT 1,
 created_at INTEGER NOT NULL,
 updated_at INTEGER NOT NULL,
 CHECK ((kind='device' AND device_id IS NOT NULL) OR (kind='manual' AND device_id IS NULL))
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_wake_targets_device ON wake_targets(device_id) WHERE device_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_wake_targets_network ON wake_targets(network_id, kind, owner_user_id);

-- Keep rate-limit history when equipment/targets are removed.
CREATE TABLE IF NOT EXISTS wake_jobs (
 id TEXT PRIMARY KEY,
 network_id TEXT NOT NULL REFERENCES networks(id) ON DELETE CASCADE,
 wake_target_id TEXT NOT NULL,
 target_mac TEXT NOT NULL,
 agent_device_id TEXT NOT NULL,
 agent_registration_seq INTEGER NOT NULL,
 requester_user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 state TEXT NOT NULL CHECK(state IN ('queued','claimed','sent','failed','expired')),
 reason TEXT NOT NULL DEFAULT '',
 attempts INTEGER NOT NULL DEFAULT 0,
 created_at INTEGER NOT NULL,
 expires_at INTEGER NOT NULL,
 claimed_at INTEGER NOT NULL DEFAULT 0,
 finished_at INTEGER NOT NULL DEFAULT 0,
 claim_token TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_wake_jobs_target_time ON wake_jobs(wake_target_id, created_at);
CREATE INDEX IF NOT EXISTS idx_wake_jobs_requester_time ON wake_jobs(requester_user_id, created_at);
CREATE INDEX IF NOT EXISTS idx_wake_jobs_active_network ON wake_jobs(network_id, expires_at) WHERE state IN ('queued','claimed');
CREATE INDEX IF NOT EXISTS idx_wake_jobs_active_agent ON wake_jobs(agent_device_id, agent_registration_seq, created_at) WHERE state IN ('queued','claimed');
CREATE INDEX IF NOT EXISTS idx_wake_jobs_active_expiry ON wake_jobs(expires_at) WHERE state IN ('queued','claimed');
CREATE INDEX IF NOT EXISTS idx_wake_jobs_finished ON wake_jobs(finished_at) WHERE finished_at > 0;

-- A replaced/deleted target cannot leave MAC data in a queued job.
CREATE TRIGGER IF NOT EXISTS wake_target_deleted AFTER DELETE ON wake_targets BEGIN
  UPDATE wake_jobs SET state='expired', reason='target_no_mac', target_mac='', claim_token='', finished_at=unixepoch()
  WHERE wake_target_id=OLD.id AND state IN ('queued','claimed');
END;
CREATE TRIGGER IF NOT EXISTS wake_target_changed AFTER UPDATE OF mac, enabled ON wake_targets
WHEN OLD.mac != NEW.mac OR (OLD.enabled=1 AND NEW.enabled=0) BEGIN
  UPDATE wake_jobs SET state='expired', reason='target_no_mac', target_mac='', claim_token='', finished_at=unixepoch()
  WHERE wake_target_id=OLD.id AND state IN ('queued','claimed');
END;
`)
	return err
}

func normalizeWakeMAC(input string) (string, error) {
	mac, err := net.ParseMAC(strings.TrimSpace(input))
	if err != nil || len(mac) != 6 || mac[0]&1 != 0 || mac.String() == "00:00:00:00:00:00" {
		return "", wakeError("wake_invalid")
	}
	return mac.String(), nil
}

type WakeDeviceSession struct {
	DeviceID, CredentialID string
	RegistrationSeq        int64
}

func wakeRegistrationDevice(tx *sql.Tx, session WakeDeviceSession, proxyRequired bool, now int64) (wakeDevice, error) {
	var device wakeDevice
	var allowed, proxy, credential bool
	var current, incarnation int64
	err := tx.QueryRow(`SELECT d.id,d.network_id,d.user_id,d.device_name,
		d.online=1 AND d.last_seen>=?,`+deviceRoomAllowedSQL+`, d.wake_proxy,d.registration_seq,d.registration_incarnation,
		EXISTS(SELECT 1 FROM device_credentials c WHERE c.id=? AND c.device_id=d.id AND c.revoked=0 AND c.expires_at>=?)
		FROM devices d WHERE d.id=?
		AND (NOT EXISTS(SELECT 1 FROM rooms WHERE network_id=d.network_id)
			OR EXISTS(SELECT 1 FROM network_memberships m WHERE m.network_id=d.network_id AND m.user_id=d.user_id))`,
		now-DeviceOnlineTTL, session.CredentialID, now, session.DeviceID).
		Scan(&device.id, &device.network, &device.owner, &device.name, &device.online, &allowed, &proxy, &current, &incarnation, &credential)
	if err != nil {
		return device, wakeMissing(err)
	}
	if !credential {
		return device, wakeError("wake_device_credential_required")
	}
	if session.RegistrationSeq <= 0 || session.RegistrationSeq != current || incarnation <= 0 {
		return device, &RegistrationSessionConflictError{CurrentSequence: current}
	}
	if !allowed {
		return device, wakeError("target_blocked")
	}
	if proxyRequired && !proxy {
		return device, wakeError("wake_proxy_required")
	}
	if proxyRequired && !device.online {
		return device, wakeError("agent_offline")
	}
	return device, nil
}

type wakeDevice struct {
	id, network, owner, name string
	online                   bool
}

// MaintainWakeJobs expires outstanding leases and bounds retained results even
// on installations with no recent wake traffic.
func (db *DB) MaintainWakeJobs(ctx context.Context, at time.Time) error {
	now := at.Unix()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.Exec(`UPDATE wake_jobs SET state='expired',reason='expired',target_mac='',claim_token='',
		finished_at=CASE WHEN state='claimed' AND attempts>=? THEN min(expires_at,claimed_at+?) ELSE expires_at END
		WHERE state IN ('queued','claimed') AND (expires_at<=? OR (state='claimed' AND attempts>=? AND claimed_at<=?))`,
		wakeAttempts, wakeClaimTTL, now, wakeAttempts, now-wakeClaimTTL); err != nil {
		return err
	}
	if _, err = tx.Exec(`DELETE FROM wake_jobs WHERE finished_at>0 AND finished_at<=?`, now-wakeHistory); err != nil {
		return err
	}
	return tx.Commit()
}

func validateWakeText(value string, limit int) bool {
	return len(value) <= limit && !strings.ContainsAny(value, "\x00\r\n")
}

// SQL statements never format MAC data into their text and errors are rendered
// as fixed API codes at the request boundary.
func wakeMissing(err error) error {
	if err == sql.ErrNoRows {
		return wakeError("wake_not_found")
	}
	return err
}

func validateWakeResult(state, reason string) error {
	if state == wakeSent && reason == "" {
		return nil
	}
	if state == wakeFailed {
		switch reason {
		case "no_agent", "agent_offline", "already_online", "target_no_mac", "target_blocked",
			"send_failed", "no_lan_interface", "unsupported_platform", "rate_limited", "expired":
			return nil
		}
	}
	return wakeError("wake_invalid")
}

func checkedWakeClaimToken(token string) error {
	if len(token) != 32 {
		return wakeError("wake_invalid")
	}
	for _, c := range token {
		if !(c >= '0' && c <= '9') && !(c >= 'a' && c <= 'f') {
			return wakeError("wake_invalid")
		}
	}
	return nil
}

func wakeJobDeadline(job WakeJob) int64 {
	if job.State == wakeClaimed && job.Attempts >= wakeAttempts {
		return min(job.ExpiresAt, job.claimedAt+wakeClaimTTL)
	}
	return job.ExpiresAt
}
