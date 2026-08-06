package database

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"sync/atomic"
	"time"
)

// ---- Signaling operations ----

// Signal represents one queued control-plane signaling message.
type Signal struct {
	ID                      string            `json:"id"`
	FromNodeID              string            `json:"from_node_id"`
	ToNodeID                string            `json:"to_node_id"`
	Type                    string            `json:"type"`
	ProtocolVersion         int64             `json:"protocol_version"`
	Candidates              []string          `json:"candidates"`
	CandidateSources        map[string]string `json:"candidate_sources,omitempty"`
	CandidateGeneration     int64             `json:"candidate_generation,omitempty"`
	CandidatesExpiresAtMS   int64             `json:"candidates_expires_at_ms,omitempty"`
	SessionID               string            `json:"session_id,omitempty"`
	ProbeEphemeralPublicKey string            `json:"probe_ephemeral_public_key,omitempty"`
	Handshake               string            `json:"handshake"`
	PunchAtMS               int64             `json:"punch_at_ms,omitempty"`
	CreatedAt               int64             `json:"created_at"`
	// Server-assigned monotonic sequence per (from, to) pair.  Delivery
	// ordering is defined by this sequence, never by the wall clock, so two
	// signals created within the same second still arrive in send order and a
	// late-arriving older signal can never overtake a newer one.
	SignalSeq int64 `json:"signal_seq,omitempty"`
}

const (
	SignalProtocolVersion int64 = 1
	signalTTLSeconds      int64 = 120
)

// Queue bounds.  The 120s TTL alone is not a bound: a flooded pair or node
// could otherwise accumulate unbounded rows and bytes within one TTL window.
// Every bound is enforced inside the same write transaction that inserts the
// signal, so concurrent writers can never jointly exceed a limit.
const (
	// Max queued rows per (from, to) pair.
	MaxSignalsPerPair = 256
	// Approximate queued payload bytes per (from, to) pair (candidates +
	// sources + handshake).  Sized so a legit synchronized-punch exchange of
	// a few offers/answers per window never touches it while a flood is
	// rejected with a clear 429.
	MaxSignalBytesPerPair = 512 * 1024
	// Max queued rows across the whole database.
	MaxSignalsGlobal = 50_000
	// Max signals one sender may create per minute (send-frequency bound).
	MaxSignalCreatesPerSenderPerMinute = 300
	// Max rows returned (and deleted) per ListAndDeleteSignals call.  Larger
	// queues are drained across consecutive polls, so no single request
	// materializes an unbounded batch into memory and a client that dies
	// mid-processing only loses one bounded batch, never the whole queue.
	MaxSignalBatch = 500
)

// ErrSignalQueueLimit marks a rejected signal because a queue bound was
// exceeded; the API layer maps it to HTTP 429 with a degradable message.
var ErrSignalQueueLimit = errors.New("signal queue limit exceeded")

// nextSignalID makes signal IDs collision-free under concurrent writers:
// `signal-<unixnano>` alone collided when two transactions shared a
// nanosecond, violating the PRIMARY KEY under load.
var nextSignalID atomic.Uint64

// CreateSignal queues a signaling message for a target node.
func (db *DB) CreateSignal(fromNodeID, toNodeID, typ string, candidates []string, candidateSources map[string]string, handshake string) (*Signal, error) {
	return db.CreateSignalWithPunchAt(fromNodeID, toNodeID, typ, candidates, candidateSources, handshake, 0)
}

// CreateSignalWithPunchAt queues a signaling message with an optional synchronized punch window.
func (db *DB) CreateSignalWithPunchAt(fromNodeID, toNodeID, typ string, candidates []string, candidateSources map[string]string, handshake string, punchAtMS int64) (*Signal, error) {
	return db.CreateSignalWithTraversalMetadata(fromNodeID, toNodeID, typ, candidates, candidateSources, handshake, punchAtMS, 0, 0)
}

// CreateSignalWithTraversalMetadata persists the candidate-set ordering metadata.
// Legacy callers use generation 0 and no explicit expiry.
func (db *DB) CreateSignalWithTraversalMetadata(fromNodeID, toNodeID, typ string, candidates []string, candidateSources map[string]string, handshake string, punchAtMS, candidateGeneration, candidatesExpiresAtMS int64) (*Signal, error) {
	return db.CreateSignalWithTraversalSession(fromNodeID, toNodeID, typ, SignalProtocolVersion, candidates, candidateSources, handshake, punchAtMS, candidateGeneration, candidatesExpiresAtMS, "", "")
}

// CreateSignalWithTraversalSession persists candidate-set metadata plus optional traversal session key material.
//
// Every signal is queued, never silently replaced: delivery order is the
// per-(from, to) monotonic server sequence assigned here, and the receiver's
// candidate-generation / fresh-prediction high-waters are the authority on
// supersession.  In particular an ordinary refresh must never overwrite a
// fresh-mapping prediction that arrived earlier, and a signal G1 arriving
// late (after G2 was already queued) must never delete G2.
//
// The sequence is persisted in the dedicated `signal_seqs` table, NOT derived
// from the queued rows: the queue is drained by polling, so MAX(signal_seq)
// over the live rows would restart from 1 after every drain and reorder
// delivery across polls.  The sequence table is updated and read inside this
// same write transaction, so concurrent writers serialize and can never hand
// the same sequence to two signals of one pair.
//
// The queue bounds are enforced inside this same write transaction: rows per
// pair, approximate bytes per pair, global rows, and the sender's per-minute
// create frequency.  The frequency is counted from the persistent
// `signal_send_events` table (one row per create, pruned only after the
// window), never from the queued rows: polling the queue empty must not let a
// sender bypass the limit.  Exceeding any bound fails with
// ErrSignalQueueLimit so the API can return 429 instead of silently dropping
// or unbounded growth.
func (db *DB) CreateSignalWithTraversalSession(fromNodeID, toNodeID, typ string, protocolVersion int64, candidates []string, candidateSources map[string]string, handshake string, punchAtMS, candidateGeneration, candidatesExpiresAtMS int64, sessionID, probeEphemeralPublicKey string) (*Signal, error) {
	if candidates == nil {
		candidates = []string{}
	}
	if protocolVersion == 0 {
		protocolVersion = SignalProtocolVersion
	}
	if candidateSources == nil {
		candidateSources = map[string]string{}
	}

	candidatesJSON, err := json.Marshal(candidates)
	if err != nil {
		return nil, err
	}
	candidateSourcesJSON, err := json.Marshal(candidateSources)
	if err != nil {
		return nil, err
	}

	id := fmt.Sprintf("signal-%d-%d", time.Now().UnixNano(), nextSignalID.Add(1))
	now := time.Now().Unix()
	tx, err := db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	if _, err = tx.Exec(`DELETE FROM signals WHERE created_at < ?`, now-signalTTLSeconds); err != nil {
		return nil, err
	}

	// Queue bounds, checked after the TTL cleanup so expired rows never count.
	if err := enforceSignalQueueBounds(tx, fromNodeID, toNodeID, len(candidatesJSON)+len(candidateSourcesJSON)+len(handshake), now); err != nil {
		return nil, err
	}

	// The per-pair sequence is a PERSISTED counter (signal_seqs), never a
	// MAX over the currently queued rows: the queue is drained by polling, so
	// a queued-row MAX would restart from 1 after every drain and reorder
	// delivery across polls.
	if _, err := tx.Exec(`INSERT INTO signal_seqs (from_node_id, to_node_id, seq) VALUES (?, ?, 1)
		ON CONFLICT(from_node_id, to_node_id) DO UPDATE SET seq = seq + 1`, fromNodeID, toNodeID); err != nil {
		return nil, err
	}
	var signalSeq int64
	if err := tx.QueryRow(`SELECT seq FROM signal_seqs WHERE from_node_id = ? AND to_node_id = ?`, fromNodeID, toNodeID).Scan(&signalSeq); err != nil {
		return nil, err
	}

	_, err = tx.Exec(`INSERT INTO signals (id, from_node_id, to_node_id, type, protocol_version, candidates, candidate_sources, candidate_generation, candidates_expires_at_ms, session_id, probe_ephemeral_public_key, handshake, punch_at_ms, signal_seq, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, id, fromNodeID, toNodeID, typ, protocolVersion, string(candidatesJSON), string(candidateSourcesJSON), candidateGeneration, candidatesExpiresAtMS, sessionID, probeEphemeralPublicKey, handshake, punchAtMS, signalSeq, now)
	if err != nil {
		return nil, err
	}

	// Record the create in the persistent rate table (pruned only after the
	// window) and return the REAL database sequence the transaction assigned.
	sendEventID := fmt.Sprintf("send-%d-%d", time.Now().UnixNano(), nextSignalID.Add(1))
	if _, err := tx.Exec(`INSERT INTO signal_send_events (id, from_node_id, created_at) VALUES (?, ?, ?)`, sendEventID, fromNodeID, now); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}

	return &Signal{
		ID: id, FromNodeID: fromNodeID, ToNodeID: toNodeID, Type: typ,
		ProtocolVersion: protocolVersion, Candidates: candidates, CandidateSources: candidateSources, CandidateGeneration: candidateGeneration, CandidatesExpiresAtMS: candidatesExpiresAtMS, SessionID: sessionID, ProbeEphemeralPublicKey: probeEphemeralPublicKey, Handshake: handshake, PunchAtMS: punchAtMS, CreatedAt: now, SignalSeq: signalSeq,
	}, nil
}

// enforceSignalQueueBounds rejects a queued signal when any queue bound is
// exceeded.  Runs inside the insert transaction so concurrent writers can
// never jointly exceed a limit.
func enforceSignalQueueBounds(tx *sql.Tx, fromNodeID, toNodeID string, payloadBytes int, now int64) error {
	var pairRows int64
	if err := tx.QueryRow(`SELECT COUNT(*) FROM signals WHERE from_node_id = ? AND to_node_id = ?`, fromNodeID, toNodeID).Scan(&pairRows); err != nil {
		return err
	}
	if pairRows >= MaxSignalsPerPair {
		return fmt.Errorf("%w: %d rows queued for pair %s -> %s (max %d)", ErrSignalQueueLimit, pairRows, fromNodeID, toNodeID, MaxSignalsPerPair)
	}

	var pairBytes int64
	if err := tx.QueryRow(`SELECT COALESCE(SUM(LENGTH(candidates) + LENGTH(candidate_sources) + LENGTH(handshake)), 0) FROM signals WHERE from_node_id = ? AND to_node_id = ?`, fromNodeID, toNodeID).Scan(&pairBytes); err != nil {
		return err
	}
	if pairBytes+int64(payloadBytes) > MaxSignalBytesPerPair {
		return fmt.Errorf("%w: %d payload bytes queued for pair %s -> %s (max %d)", ErrSignalQueueLimit, pairBytes+int64(payloadBytes), fromNodeID, toNodeID, MaxSignalBytesPerPair)
	}

	var globalRows int64
	if err := tx.QueryRow(`SELECT COUNT(*) FROM signals`).Scan(&globalRows); err != nil {
		return err
	}
	if globalRows >= MaxSignalsGlobal {
		return fmt.Errorf("%w: %d rows queued globally (max %d)", ErrSignalQueueLimit, globalRows, MaxSignalsGlobal)
	}

	// Sender frequency is counted from the PERSISTENT send-event table, which
	// polling never touches: a sender cannot bypass the limit by draining the
	// queue between creates.  Stale events outside the window are pruned here
	// so the table stays bounded by ~one window of creates.
	if _, err := tx.Exec(`DELETE FROM signal_send_events WHERE created_at < ?`, now-60); err != nil {
		return err
	}
	var senderRate int64
	if err := tx.QueryRow(`SELECT COUNT(*) FROM signal_send_events WHERE from_node_id = ? AND created_at >= ?`, fromNodeID, now-60).Scan(&senderRate); err != nil {
		return err
	}
	if senderRate >= MaxSignalCreatesPerSenderPerMinute {
		return fmt.Errorf("%w: %d signals created by %s in the last minute (max %d)", ErrSignalQueueLimit, senderRate, fromNodeID, MaxSignalCreatesPerSenderPerMinute)
	}
	return nil
}

// ListAndDeleteSignals returns up to MaxSignalBatch queued messages for a node
// and deletes exactly those rows atomically.
//
// Delivery order is the per-pair monotonic server sequence (`signal_seq`),
// never the wall clock: two signals created within the same second still
// arrive in send order.  The batch is bounded so a flooded queue is drained
// across consecutive polls instead of materializing an unbounded row count
// into memory, and only the delivered rows are deleted: a client that fails
// mid-processing loses at most one bounded batch and the rest is redelivered
// on the next poll.
func (db *DB) ListAndDeleteSignals(toNodeID string) ([]Signal, error) {
	tx, err := db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	now := time.Now().Unix()
	if _, err := tx.Exec(`DELETE FROM signals WHERE created_at < ?`, now-signalTTLSeconds); err != nil {
		return nil, err
	}

	rows, err := tx.Query(`SELECT id, from_node_id, to_node_id, type, protocol_version, candidates, candidate_sources, candidate_generation, candidates_expires_at_ms, session_id, probe_ephemeral_public_key, handshake, punch_at_ms, signal_seq, created_at
		FROM signals WHERE to_node_id = ? AND created_at >= ? ORDER BY signal_seq ASC, created_at ASC, id ASC LIMIT ?`, toNodeID, now-signalTTLSeconds, MaxSignalBatch)
	if err != nil {
		return nil, err
	}

	signals := []Signal{}
	deliveredIDs := make([]interface{}, 0, MaxSignalBatch)
	malformedIDs := make([]interface{}, 0, 8)
	placeholders := ""
	appendDeleteID := func(ids *[]interface{}, placeholders *string, id string) {
		*ids = append(*ids, id)
		if *placeholders != "" {
			*placeholders += ","
		}
		*placeholders += "?"
	}
	for rows.Next() {
		var s Signal
		var candidatesJSON string
		var candidateSourcesJSON string
		if err := rows.Scan(&s.ID, &s.FromNodeID, &s.ToNodeID, &s.Type, &s.ProtocolVersion, &candidatesJSON, &candidateSourcesJSON, &s.CandidateGeneration, &s.CandidatesExpiresAtMS, &s.SessionID, &s.ProbeEphemeralPublicKey, &s.Handshake, &s.PunchAtMS, &s.SignalSeq, &s.CreatedAt); err != nil {
			return nil, err
		}
		// One malformed row must never block the whole batch: the row is
		// skipped (it is not delivered) but still deleted, because keeping it
		// would poison every later poll forever.  A mixed-version fleet can
		// therefore always drain its queue.
		if err := json.Unmarshal([]byte(candidatesJSON), &s.Candidates); err != nil {
			appendDeleteID(&malformedIDs, &placeholders, s.ID)
			continue
		}
		if s.Candidates == nil {
			s.Candidates = []string{}
		}
		if err := json.Unmarshal([]byte(candidateSourcesJSON), &s.CandidateSources); err != nil {
			appendDeleteID(&malformedIDs, &placeholders, s.ID)
			continue
		}
		if s.CandidateSources == nil {
			s.CandidateSources = map[string]string{}
		}
		signals = append(signals, s)
		appendDeleteID(&deliveredIDs, &placeholders, s.ID)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}

	deliveredIDs = append(deliveredIDs, malformedIDs...)
	if len(deliveredIDs) > 0 {
		args := append([]interface{}{toNodeID}, deliveredIDs...)
		// Delete exactly the delivered AND the malformed rows: an
		// undelivered healthy tail stays queued and is redelivered by the
		// next poll.
		if _, err := tx.Exec(`DELETE FROM signals WHERE to_node_id = ? AND id IN (`+placeholders+`)`, args...); err != nil {
			return nil, err
		}
	}

	if err := tx.Commit(); err != nil {
		return nil, err
	}

	return signals, nil
}
