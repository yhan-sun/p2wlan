package database

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

const RelayRevocationRetentionSeconds = 24 * 60 * 60
const relayRevocationPageBytes = 512 << 10
const relayRevocationPageRows = 256

var ErrRevocationCursor = errors.New("invalid revocation cursor")

type RelayRevocationPage struct {
	RelayRevocationSnapshot
	ProtocolVersion int   `json:"protocol_version"`
	After           int64 `json:"after"`
	NextCursor      int64 `json:"next_cursor"`
	HasMore         bool  `json:"has_more"`
}

func migrateRelayRevocations(db *sql.DB) error {
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	_, err = tx.Exec(`
        CREATE TABLE IF NOT EXISTS relay_revocation_clock (
            id INTEGER PRIMARY KEY CHECK(id=1), revision INTEGER NOT NULL
        );
        INSERT OR IGNORE INTO relay_revocation_clock(id,revision)
            SELECT 1, COALESCE(MAX(created_at),0)*1000000 + COUNT(*) FROM relay_revocations;
        UPDATE relay_revocations SET sequence=(SELECT revision FROM relay_revocation_clock WHERE id=1)+rowid WHERE sequence=0;
        UPDATE relay_revocation_clock SET revision=MAX(revision,COALESCE((SELECT MAX(sequence) FROM relay_revocations),0)) WHERE id=1;
        CREATE UNIQUE INDEX IF NOT EXISTS idx_relay_revocation_sequence ON relay_revocations(sequence) WHERE sequence>0;
        CREATE TRIGGER IF NOT EXISTS relay_revocation_sequence_insert
        AFTER INSERT ON relay_revocations WHEN NEW.sequence=0 BEGIN
            UPDATE relay_revocation_clock SET revision=revision+1 WHERE id=1;
            UPDATE relay_revocations SET sequence=(SELECT revision FROM relay_revocation_clock WHERE id=1) WHERE rowid=NEW.rowid;
        END;
    `)
	if err != nil {
		return err
	}
	return tx.Commit()
}

// Tickets are limited to 15 minutes by the relay. Keep a full day of
// tombstones; pruning never rewinds the independent cursor/legacy version.
func (db *DB) PruneRelayRevocations(now time.Time) error {
	_, err := db.Exec(`DELETE FROM relay_revocations WHERE created_at>0 AND created_at<?`, now.Unix()-RelayRevocationRetentionSeconds)
	return err
}

func emptyRevocations() RelayRevocationSnapshot {
	return RelayRevocationSnapshot{
		GeneratedAt:      time.Now().UTC().Format(time.RFC3339),
		RevokedDeviceIDs: []string{}, RevokedCredentialIDs: []string{}, RevokedJTIs: []string{},
	}
}

func appendRevocation(snapshot *RelayRevocationSnapshot, kind, value string) error {
	switch kind {
	case RelayRevocationDeviceID:
		snapshot.RevokedDeviceIDs = append(snapshot.RevokedDeviceIDs, value)
	case RelayRevocationCredentialID:
		snapshot.RevokedCredentialIDs = append(snapshot.RevokedCredentialIDs, value)
	case RelayRevocationJTI:
		snapshot.RevokedJTIs = append(snapshot.RevokedJTIs, value)
	default:
		return fmt.Errorf("unknown revocation kind")
	}
	return nil
}

// through fixes the upper bound of a multi-page catch-up, so concurrent
// revocations cannot keep a reader chasing a moving end forever.
func (db *DB) RelayRevocationPage(after, through int64) (*RelayRevocationPage, error) {
	if after < 0 || through < 0 {
		return nil, ErrRevocationCursor
	}
	if err := db.PruneRelayRevocations(time.Now()); err != nil {
		return nil, err
	}
	tx, err := db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	page := &RelayRevocationPage{RelayRevocationSnapshot: emptyRevocations(), ProtocolVersion: 2, After: after}
	if err = tx.QueryRow(`SELECT revision FROM relay_revocation_clock WHERE id=1`).Scan(&page.Version); err != nil {
		return nil, err
	}
	if through > page.Version {
		return nil, ErrRevocationCursor
	}
	if through > 0 {
		page.Version = through
	}
	if after > page.Version {
		return nil, ErrRevocationCursor
	}
	rows, err := tx.Query(`SELECT sequence,kind,value FROM relay_revocations WHERE sequence>? AND sequence<=? ORDER BY sequence LIMIT ?`, after, page.Version, relayRevocationPageRows+1)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	count, size := 0, 1024
	page.NextCursor = after
	for rows.Next() {
		var seq int64
		var kind, value string
		if err = rows.Scan(&seq, &kind, &value); err != nil {
			return nil, err
		}
		encoded, err := json.Marshal(value)
		if err != nil {
			return nil, err
		}
		if len(encoded)+1024 > relayRevocationPageBytes {
			return nil, fmt.Errorf("revocation value exceeds page budget")
		}
		if count == relayRevocationPageRows || size+len(encoded)+1 > relayRevocationPageBytes {
			page.HasMore = true
			break
		}
		if err = appendRevocation(&page.RelayRevocationSnapshot, kind, value); err != nil {
			return nil, err
		}
		size += len(encoded) + 1
		count++
		page.NextCursor = seq
	}
	if err = rows.Err(); err != nil {
		return nil, err
	}
	if err = rows.Close(); err != nil {
		return nil, err
	}
	if !page.HasMore {
		page.NextCursor = page.Version
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return page, nil
}
