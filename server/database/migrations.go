package database

import "database/sql"

func migrate(db *sql.DB) error {
	schema := `
	CREATE TABLE IF NOT EXISTS users (
		id          TEXT PRIMARY KEY,
		email       TEXT UNIQUE NOT NULL,
		password_hash TEXT NOT NULL,
		created_at  INTEGER NOT NULL
	);

	CREATE TABLE IF NOT EXISTS networks (
		id          TEXT PRIMARY KEY,
		name        TEXT NOT NULL,
		cidr        TEXT NOT NULL DEFAULT '10.20.0.0/16',
		owner_id    TEXT NOT NULL REFERENCES users(id),
		created_at  INTEGER NOT NULL
	);

	CREATE TABLE IF NOT EXISTS devices (
		id          TEXT PRIMARY KEY,
		user_id     TEXT NOT NULL REFERENCES users(id),
		network_id  TEXT NOT NULL REFERENCES networks(id),
		public_key  TEXT NOT NULL,
		device_name TEXT NOT NULL,
		platform    TEXT NOT NULL DEFAULT '',
			virtual_ip  TEXT NOT NULL DEFAULT '',
			nat_type    TEXT NOT NULL DEFAULT '',
			endpoint    TEXT NOT NULL DEFAULT '',
			relay_rtt_ms INTEGER,
			last_seen   INTEGER NOT NULL DEFAULT 0,
			app_version TEXT NOT NULL DEFAULT '',
		online      INTEGER NOT NULL DEFAULT 0,
		created_at  INTEGER NOT NULL
	);

	CREATE TABLE IF NOT EXISTS tunnels (
		id            TEXT PRIMARY KEY,
		device_id     TEXT NOT NULL REFERENCES devices(id),
		protocol      TEXT NOT NULL DEFAULT 'tcp',
		local_port    INTEGER NOT NULL,
		remote_port   INTEGER NOT NULL,
		local_address TEXT NOT NULL DEFAULT '127.0.0.1',
		public_endpoint TEXT NOT NULL DEFAULT '',
		active        INTEGER NOT NULL DEFAULT 0,
		created_at    INTEGER NOT NULL
	);

	CREATE TABLE IF NOT EXISTS signals (
		id          TEXT PRIMARY KEY,
		from_node_id TEXT NOT NULL,
		to_node_id   TEXT NOT NULL,
		type        TEXT NOT NULL,
		candidates  TEXT NOT NULL DEFAULT '[]',
		protocol_version INTEGER NOT NULL DEFAULT 1,
		candidate_sources TEXT NOT NULL DEFAULT '{}',
		candidate_generation INTEGER NOT NULL DEFAULT 0,
		candidates_expires_at_ms INTEGER NOT NULL DEFAULT 0,
		session_id TEXT NOT NULL DEFAULT '',
		probe_ephemeral_public_key TEXT NOT NULL DEFAULT '',
		handshake   TEXT NOT NULL DEFAULT '',
		punch_at_ms INTEGER NOT NULL DEFAULT 0,
		created_at  INTEGER NOT NULL
	);

	CREATE INDEX IF NOT EXISTS idx_devices_user ON devices(user_id);
	CREATE INDEX IF NOT EXISTS idx_devices_network ON devices(network_id);
	CREATE INDEX IF NOT EXISTS idx_tunnels_device ON tunnels(device_id);
	CREATE UNIQUE INDEX IF NOT EXISTS idx_tunnels_protocol_remote_port ON tunnels(protocol, remote_port);
	CREATE INDEX IF NOT EXISTS idx_signals_to_node ON signals(to_node_id, created_at);

	CREATE UNIQUE INDEX IF NOT EXISTS idx_devices_net_ip ON devices(network_id, virtual_ip);
	CREATE UNIQUE INDEX IF NOT EXISTS idx_devices_net_pubkey ON devices(network_id, public_key);

	-- Stage 2: authorization and device identity
	CREATE TABLE IF NOT EXISTS device_challenges (
		id          TEXT PRIMARY KEY,
		device_id   TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
		challenge   BLOB NOT NULL,
		expires_at  INTEGER NOT NULL,
		consumed    INTEGER NOT NULL DEFAULT 0,
		created_at  INTEGER NOT NULL DEFAULT (strftime('%s','now'))
	);
	CREATE INDEX IF NOT EXISTS idx_dev_chan_device ON device_challenges(device_id);
	CREATE INDEX IF NOT EXISTS idx_dev_chan_expires ON device_challenges(expires_at);

	CREATE TABLE IF NOT EXISTS device_credentials (
		id          TEXT PRIMARY KEY,
		device_id   TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
		token_hash  BLOB NOT NULL,
		expires_at  INTEGER NOT NULL,
		revoked     INTEGER NOT NULL DEFAULT 0,
		created_at  INTEGER NOT NULL DEFAULT (strftime('%s','now'))
	);
	CREATE INDEX IF NOT EXISTS idx_dev_cred_device ON device_credentials(device_id);
	CREATE INDEX IF NOT EXISTS idx_dev_cred_hash ON device_credentials(token_hash);
	CREATE INDEX IF NOT EXISTS idx_dev_cred_expires ON device_credentials(expires_at);

	CREATE TABLE IF NOT EXISTS relay_revocations (
		kind       TEXT NOT NULL,
		value      TEXT NOT NULL,
		created_at INTEGER NOT NULL DEFAULT (strftime('%s','now')),
		PRIMARY KEY(kind, value)
	);
	CREATE INDEX IF NOT EXISTS idx_relay_revocations_created ON relay_revocations(created_at);

	CREATE TABLE IF NOT EXISTS network_memberships (
		id          TEXT PRIMARY KEY,
		user_id     TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
		network_id  TEXT NOT NULL REFERENCES networks(id) ON DELETE CASCADE,
		role        TEXT NOT NULL DEFAULT 'member',
		created_at  INTEGER NOT NULL DEFAULT (strftime('%s','now')),
		UNIQUE(user_id, network_id)
	);
	CREATE INDEX IF NOT EXISTS idx_net_mem_user ON network_memberships(user_id);
	CREATE INDEX IF NOT EXISTS idx_net_mem_network ON network_memberships(network_id);

	-- Add ed25519_public_key column to existing devices (IF NOT EXISTS is handled via ALTER IGNORE)
	`

	if _, err := db.Exec(schema); err != nil {
		return err
	}

	_, _ = db.Exec(`ALTER TABLE devices ADD COLUMN ed25519_public_key TEXT NOT NULL DEFAULT ''`)
	_, _ = db.Exec(`ALTER TABLE devices ADD COLUMN app_version TEXT NOT NULL DEFAULT ''`)
	_, _ = db.Exec(`ALTER TABLE devices ADD COLUMN relay_rtt_ms INTEGER`)
	_, _ = db.Exec(`ALTER TABLE signals ADD COLUMN protocol_version INTEGER NOT NULL DEFAULT 1`)
	_, _ = db.Exec(`ALTER TABLE signals ADD COLUMN candidate_sources TEXT NOT NULL DEFAULT '{}'`)
	_, _ = db.Exec(`ALTER TABLE signals ADD COLUMN candidate_generation INTEGER NOT NULL DEFAULT 0`)
	_, _ = db.Exec(`ALTER TABLE signals ADD COLUMN candidates_expires_at_ms INTEGER NOT NULL DEFAULT 0`)
	_, _ = db.Exec(`ALTER TABLE signals ADD COLUMN session_id TEXT NOT NULL DEFAULT ''`)
	_, _ = db.Exec(`ALTER TABLE signals ADD COLUMN probe_ephemeral_public_key TEXT NOT NULL DEFAULT ''`)
	_, _ = db.Exec(`ALTER TABLE signals ADD COLUMN punch_at_ms INTEGER NOT NULL DEFAULT 0`)

	// Insert default system user and network to satisfy foreign keys,
	// then grant the system user membership to the default network.
	initData := `
	INSERT OR IGNORE INTO users (id, email, password_hash, created_at)
	VALUES ('system', 'system@p2wlan.local', '', 0);

	INSERT OR IGNORE INTO networks (id, name, cidr, owner_id, created_at)
	VALUES ('default', 'Default Network', '10.20.0.0/16', 'system', 0);

	INSERT OR IGNORE INTO network_memberships (id, user_id, network_id, role)
	VALUES ('mem-default-system', 'system', 'default', 'owner');
	`
	_, err := db.Exec(initData)
	return err
}
