package database

import "database/sql"

func migrateRooms(db *sql.DB) error {
	_, err := db.Exec(`
	CREATE TABLE IF NOT EXISTS room_allocator (
		id INTEGER PRIMARY KEY CHECK(id = 1),
		serial INTEGER NOT NULL DEFAULT 0
	);
	INSERT OR IGNORE INTO room_allocator(id) VALUES(1);
	CREATE TABLE IF NOT EXISTS rooms (
		id TEXT PRIMARY KEY,
		number TEXT NOT NULL UNIQUE,
		name TEXT NOT NULL,
		cidr TEXT NOT NULL UNIQUE,
		owner_id TEXT NOT NULL REFERENCES users(id),
		password_hash TEXT NOT NULL,
		invite_hash BLOB,
		invite_expires_at INTEGER NOT NULL DEFAULT 0,
		revision INTEGER NOT NULL DEFAULT 1,
		created_at INTEGER NOT NULL,
		deleted_at INTEGER NOT NULL DEFAULT 0
	);
	CREATE UNIQUE INDEX IF NOT EXISTS idx_rooms_active_owner ON rooms(owner_id) WHERE deleted_at = 0;
	CREATE TABLE IF NOT EXISTS room_members (
		room_id TEXT NOT NULL REFERENCES rooms(id),
		user_id TEXT NOT NULL REFERENCES users(id),
		joined_at INTEGER NOT NULL,
		banned INTEGER NOT NULL DEFAULT 0 CHECK(banned IN (0, 1)),
		PRIMARY KEY(room_id, user_id)
	);
	CREATE INDEX IF NOT EXISTS idx_room_members_user ON room_members(user_id, banned);
	CREATE TABLE IF NOT EXISTS room_devices (
		room_id TEXT NOT NULL REFERENCES rooms(id),
		device_id TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
		user_id TEXT NOT NULL,
		virtual_ip TEXT NOT NULL,
		created_at INTEGER NOT NULL,
		PRIMARY KEY(room_id, device_id),
		UNIQUE(room_id, virtual_ip),
		FOREIGN KEY(room_id, user_id) REFERENCES room_members(room_id, user_id) ON DELETE CASCADE
	);
	CREATE INDEX IF NOT EXISTS idx_room_devices_device ON room_devices(device_id);
	CREATE TABLE IF NOT EXISTS room_ip_holds (
		room_id TEXT NOT NULL REFERENCES rooms(id),
		virtual_ip TEXT NOT NULL,
		reusable_after INTEGER NOT NULL,
		PRIMARY KEY(room_id, virtual_ip)
	);
	CREATE TRIGGER IF NOT EXISTS hold_deleted_room_ip AFTER DELETE ON room_devices BEGIN
		INSERT INTO room_ip_holds(room_id, virtual_ip, reusable_after)
		VALUES(OLD.room_id, OLD.virtual_ip, unixepoch() + 120)
		ON CONFLICT(room_id, virtual_ip) DO UPDATE SET reusable_after = MAX(reusable_after, unixepoch() + 120);
	END;
	CREATE TRIGGER IF NOT EXISTS hold_changed_room_ip AFTER UPDATE OF virtual_ip ON room_devices
	WHEN OLD.virtual_ip <> NEW.virtual_ip BEGIN
		INSERT INTO room_ip_holds(room_id, virtual_ip, reusable_after)
		VALUES(OLD.room_id, OLD.virtual_ip, unixepoch() + 120)
		ON CONFLICT(room_id, virtual_ip) DO UPDATE SET reusable_after = MAX(reusable_after, unixepoch() + 120);
	END;
	CREATE TABLE IF NOT EXISTS room_join_attempts (
		user_id TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
		window_start INTEGER NOT NULL,
		attempts INTEGER NOT NULL
	);
	CREATE TABLE IF NOT EXISTS room_client_leases (
		device_id TEXT PRIMARY KEY REFERENCES devices(id) ON DELETE CASCADE,
		refreshed_at INTEGER NOT NULL
	);
	`)
	return err
}
