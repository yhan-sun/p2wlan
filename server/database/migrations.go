package database

import (
	"database/sql"
	"fmt"
)

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
		signal_seq  INTEGER NOT NULL DEFAULT 0,
		created_at  INTEGER NOT NULL
	);

	CREATE INDEX IF NOT EXISTS idx_devices_user ON devices(user_id);
	CREATE INDEX IF NOT EXISTS idx_devices_network ON devices(network_id);
	CREATE INDEX IF NOT EXISTS idx_tunnels_device ON tunnels(device_id);
	CREATE UNIQUE INDEX IF NOT EXISTS idx_tunnels_protocol_remote_port ON tunnels(protocol, remote_port);
	CREATE INDEX IF NOT EXISTS idx_signals_to_node ON signals(to_node_id, created_at);

	-- Persistent per-sender signal creation events.  Unlike the queued
	-- signals rows, these are NEVER deleted by ListAndDeleteSignals: the
	-- sender's per-minute create frequency must not be measured on the
	-- current queue depth, or a sender could bypass the limit by polling the
	-- queue empty and re-filling it endlessly.  Rows are pruned only after
	-- they fall outside the rate window.
	CREATE TABLE IF NOT EXISTS signal_send_events (
		id          TEXT PRIMARY KEY,
		from_node_id TEXT NOT NULL,
		created_at  INTEGER NOT NULL
	);
	CREATE INDEX IF NOT EXISTS idx_signal_send_events_from_time ON signal_send_events(from_node_id, created_at);

	-- Persistent per-(from, to) signal sequence counters.  The queue itself
	-- is drained by polling, so deriving the next sequence from the queued
	-- rows (MAX(signal_seq)) would restart from 1 after every drain.  The
	-- sequence is the delivery-ordering contract, so it must be monotonic
	-- across drains, restarts and migrations.
	CREATE TABLE IF NOT EXISTS signal_seqs (
		from_node_id TEXT NOT NULL,
		to_node_id   TEXT NOT NULL,
		seq          INTEGER NOT NULL,
		PRIMARY KEY (from_node_id, to_node_id)
	);

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

	// ALTER TABLE ADD COLUMN fails on an already-migrated database, so every
	// column addition first checks the live schema and only then runs.  Errors
	// from real ALTER statements are never swallowed: a silent failure would
	// leave the table behind the code that reads it.
	ensureColumn := func(table, column, definition string) error {
		has, err := columnExists(db, table, column)
		if err != nil {
			return err
		}
		if has {
			return nil
		}
		if _, err := db.Exec(`ALTER TABLE ` + table + ` ADD COLUMN ` + column + ` ` + definition); err != nil {
			return fmt.Errorf("adding column %s.%s: %w", table, column, err)
		}
		return nil
	}
	for _, column := range []struct{ table, column, definition string }{
		{"devices", "ed25519_public_key", "TEXT NOT NULL DEFAULT ''"},
		{"devices", "app_version", "TEXT NOT NULL DEFAULT ''"},
		{"devices", "relay_rtt_ms", "INTEGER"},
		{"signals", "protocol_version", "INTEGER NOT NULL DEFAULT 1"},
		{"signals", "candidate_sources", "TEXT NOT NULL DEFAULT '{}'"},
		{"signals", "candidate_generation", "INTEGER NOT NULL DEFAULT 0"},
		{"signals", "candidates_expires_at_ms", "INTEGER NOT NULL DEFAULT 0"},
		{"signals", "session_id", "TEXT NOT NULL DEFAULT ''"},
		{"signals", "probe_ephemeral_public_key", "TEXT NOT NULL DEFAULT ''"},
		{"signals", "punch_at_ms", "INTEGER NOT NULL DEFAULT 0"},
		{"signals", "signal_seq", "INTEGER NOT NULL DEFAULT 0"},
	} {
		if err := ensureColumn(column.table, column.column, column.definition); err != nil {
			return err
		}
	}
	if _, err := db.Exec(`CREATE INDEX IF NOT EXISTS idx_signals_to_node_seq ON signals(to_node_id, signal_seq)`); err != nil {
		return err
	}
	if _, err := db.Exec(`CREATE INDEX IF NOT EXISTS idx_signals_pair_seq ON signals(from_node_id, to_node_id, signal_seq)`); err != nil {
		return err
	}

	// Backfill the per-pair sequence for rows queued before the column
	// existed (signal_seq = 0): ordering by creation time then ID within a
	// pair gives every old row a stable, monotonic, collision-free sequence
	// that new inserts keep building on.  Idempotent: already-assigned rows
	// are never touched.
	if _, err := db.Exec(`
		UPDATE signals SET signal_seq = (
			SELECT COUNT(*) FROM signals AS older
			WHERE older.from_node_id = signals.from_node_id
			  AND older.to_node_id = signals.to_node_id
			  AND (older.created_at < signals.created_at
			       OR (older.created_at = signals.created_at AND older.id < signals.id))
		) WHERE signal_seq = 0`); err != nil {
		return fmt.Errorf("backfilling signal_seq: %w", err)
	}

	// Seed the persistent sequence table from the highest backfilled value of
	// every pair so NEW inserts continue the sequence instead of restarting
	// from 1 (the queue is drained by polling, so a restarted sequence would
	// reorder delivery across drains).  `INSERT OR IGNORE` keeps this
	// idempotent for databases that already ran it.
	if _, err := db.Exec(`
		INSERT OR IGNORE INTO signal_seqs (from_node_id, to_node_id, seq)
		SELECT from_node_id, to_node_id, MAX(signal_seq) FROM signals GROUP BY from_node_id, to_node_id`); err != nil {
		return fmt.Errorf("seeding signal_seqs: %w", err)
	}

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

// columnExists reports whether a column is present in a table's live schema.
func columnExists(db *sql.DB, table, column string) (bool, error) {
	rows, err := db.Query(`PRAGMA table_info(` + table + `)`)
	if err != nil {
		return false, fmt.Errorf("inspecting %s schema: %w", table, err)
	}
	defer rows.Close()
	for rows.Next() {
		var cid int
		var name, typ string
		var notNull, pk int
		var dflt interface{}
		if err := rows.Scan(&cid, &name, &typ, &notNull, &dflt, &pk); err != nil {
			return false, err
		}
		if name == column {
			return true, nil
		}
	}
	return false, rows.Err()
}
