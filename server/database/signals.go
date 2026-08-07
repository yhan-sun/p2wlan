package database

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
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
	// SenderPublicKey is the sender's identity fingerprint (public key, hex)
	// AT SEND TIME, bound to the row so a receiver can tell which identity a
	// queued signal came from.  After the sender's key changes, still-queued
	// signals from the old identity must never enter the new identity's
	// fresh-prediction high-water space.
	SenderPublicKey string `json:"sender_public_key,omitempty"`
	// DeliveryToken is the per-delivery lease token assigned when the row is
	// handed to a polling client in ACK mode.  The row is NOT deleted at
	// delivery: the client must ACK it (idempotently) or the lease expires
	// and the row is redelivered.
	DeliveryToken string `json:"delivery_token,omitempty"`
	// LeaseExpiresAtMS is the server-clock instant (unix ms) the current
	// delivery lease expires; 0 means the row is free to deliver.
	LeaseExpiresAtMS int64 `json:"lease_expires_at_ms,omitempty"`
	// Server-assigned monotonic sequence per (from, to) pair.  Delivery
	// ordering is defined by this sequence, never by the wall clock, so two
	// signals created within the same second still arrive in send order and a
	// late-arriving older signal can never overtake a newer one.
	SignalSeq int64 `json:"signal_seq,omitempty"`
}

// SignalAck identifies one delivered signal for an idempotent ACK.
type SignalAck struct {
	ID            string `json:"id"`
	DeliveryToken string `json:"delivery_token"`
}

const (
	SignalProtocolVersion int64 = 1
	signalTTLSeconds      int64 = 120
	// How long a delivered (leased) signal stays reserved before it is
	// redelivered.  Bounded well below the TTL so a client that dies
	// mid-processing loses at most one lease window, never the signal.
	signalLeaseSeconds int64 = 15
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
	return db.CreateSignalWithTraversalSession(fromNodeID, toNodeID, typ, SignalProtocolVersion, candidates, candidateSources, handshake, punchAtMS, candidateGeneration, candidatesExpiresAtMS, "", "", "")
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
// `senderPublicKey` is the sender's identity fingerprint at send time and is
// persisted with the row: the receiver binds the signal to the identity that
// actually sent it, so old-identity queued signals cannot pollute a new
// identity's fresh high-water after a key change.
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
func (db *DB) CreateSignalWithTraversalSession(fromNodeID, toNodeID, typ string, protocolVersion int64, candidates []string, candidateSources map[string]string, handshake string, punchAtMS, candidateGeneration, candidatesExpiresAtMS int64, sessionID, probeEphemeralPublicKey, senderPublicKey string) (*Signal, error) {
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

	_, err = tx.Exec(`INSERT INTO signals (id, from_node_id, to_node_id, type, protocol_version, candidates, candidate_sources, candidate_generation, candidates_expires_at_ms, session_id, probe_ephemeral_public_key, handshake, punch_at_ms, sender_public_key, signal_seq, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, id, fromNodeID, toNodeID, typ, protocolVersion, string(candidatesJSON), string(candidateSourcesJSON), candidateGeneration, candidatesExpiresAtMS, sessionID, probeEphemeralPublicKey, handshake, punchAtMS, senderPublicKey, signalSeq, now)
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
		ProtocolVersion: protocolVersion, Candidates: candidates, CandidateSources: candidateSources, CandidateGeneration: candidateGeneration, CandidatesExpiresAtMS: candidatesExpiresAtMS, SessionID: sessionID, ProbeEphemeralPublicKey: probeEphemeralPublicKey, Handshake: handshake, PunchAtMS: punchAtMS, CreatedAt: now, SenderPublicKey: senderPublicKey, SignalSeq: signalSeq,
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
//
// Rows currently HELD by an ACK-mode delivery lease are never returned or
// deleted here: a legacy delete-on-GET poll must not steal a signal a
// lease-mode client already received but has not yet ACKed.
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

	rows, err := tx.Query(`SELECT id, from_node_id, to_node_id, type, protocol_version, candidates, candidate_sources, candidate_generation, candidates_expires_at_ms, session_id, probe_ephemeral_public_key, handshake, punch_at_ms, sender_public_key, signal_seq, created_at
		FROM signals WHERE to_node_id = ? AND created_at >= ? AND lease_expires_at <= ?
		ORDER BY signal_seq ASC, created_at ASC, id ASC LIMIT ?`, toNodeID, now-signalTTLSeconds, now, MaxSignalBatch)
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
		if err := rows.Scan(&s.ID, &s.FromNodeID, &s.ToNodeID, &s.Type, &s.ProtocolVersion, &candidatesJSON, &candidateSourcesJSON, &s.CandidateGeneration, &s.CandidatesExpiresAtMS, &s.SessionID, &s.ProbeEphemeralPublicKey, &s.Handshake, &s.PunchAtMS, &s.SenderPublicKey, &s.SignalSeq, &s.CreatedAt); err != nil {
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

// ListSignalsWithLease returns up to MaxSignalBatch queued messages for a
// node WITHOUT deleting them, assigning each a delivery lease instead.
//
// Delivery order is the per-pair monotonic server sequence.  A row is only
// delivered when it is free: no active lease (either never leased or the
// lease EXPIRED, so a client that died mid-processing gets a redelivery).
// The lease keeps the row invisible to every other poll — including the
// legacy delete-on-GET path — until the client ACKs it (idempotently) or the
// lease expires.
//
// Returns the delivered signals (each carrying its per-row delivery token)
// and the server-clock lease deadline in unix milliseconds.
func (db *DB) ListSignalsWithLease(toNodeID string) ([]Signal, int64, error) {
	tx, err := db.Begin()
	if err != nil {
		return nil, 0, err
	}
	defer tx.Rollback()

	now := time.Now().Unix()
	leaseExpires := now + signalLeaseSeconds
	if _, err := tx.Exec(`DELETE FROM signals WHERE created_at < ?`, now-signalTTLSeconds); err != nil {
		return nil, 0, err
	}

	rows, err := tx.Query(`SELECT id, from_node_id, to_node_id, type, protocol_version, candidates, candidate_sources, candidate_generation, candidates_expires_at_ms, session_id, probe_ephemeral_public_key, handshake, punch_at_ms, sender_public_key, signal_seq, created_at
		FROM signals WHERE to_node_id = ? AND created_at >= ? AND lease_expires_at <= ?
		ORDER BY signal_seq ASC, created_at ASC, id ASC LIMIT ?`, toNodeID, now-signalTTLSeconds, now, MaxSignalBatch)
	if err != nil {
		return nil, 0, err
	}

	signals := []Signal{}
	malformedIDs := make([]interface{}, 0, 8)
	malformedPlaceholders := ""
	for rows.Next() {
		var s Signal
		var candidatesJSON string
		var candidateSourcesJSON string
		if err := rows.Scan(&s.ID, &s.FromNodeID, &s.ToNodeID, &s.Type, &s.ProtocolVersion, &candidatesJSON, &candidateSourcesJSON, &s.CandidateGeneration, &s.CandidatesExpiresAtMS, &s.SessionID, &s.ProbeEphemeralPublicKey, &s.Handshake, &s.PunchAtMS, &s.SenderPublicKey, &s.SignalSeq, &s.CreatedAt); err != nil {
			return nil, 0, err
		}
		// One malformed row must never block the batch: it is skipped and
		// DELETED (keeping it would poison every later poll forever), like
		// the legacy path does.
		if err := json.Unmarshal([]byte(candidatesJSON), &s.Candidates); err != nil {
			appendID(&malformedIDs, &malformedPlaceholders, s.ID)
			continue
		}
		if s.Candidates == nil {
			s.Candidates = []string{}
		}
		if err := json.Unmarshal([]byte(candidateSourcesJSON), &s.CandidateSources); err != nil {
			appendID(&malformedIDs, &malformedPlaceholders, s.ID)
			continue
		}
		if s.CandidateSources == nil {
			s.CandidateSources = map[string]string{}
		}
		s.DeliveryToken = fmt.Sprintf("dlv-%d-%d", time.Now().UnixNano(), nextSignalID.Add(1))
		s.LeaseExpiresAtMS = leaseExpires * 1000
		signals = append(signals, s)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, err
	}
	if err := rows.Close(); err != nil {
		return nil, 0, err
	}

	if len(signals) > 0 {
		entries := make([]struct{ ID, Token string }, 0, len(signals))
		for _, signal := range signals {
			entries = append(entries, struct{ ID, Token string }{signal.ID, signal.DeliveryToken})
		}
		batchToken := BatchTokenFor(entries)
		// Assign the lease for exactly the delivered rows, in the same
		// transaction that read them: two concurrent polls can never lease
		// the same row, and the row stays visible to NO poll until the client
		// ACKs it or the lease expires.
		for _, signal := range signals {
			result, err := tx.Exec(`UPDATE signals
				SET delivery_token = ?, delivery_batch_token = ?, lease_expires_at = ?
				WHERE to_node_id = ? AND id = ? AND lease_expires_at <= ?`,
				signal.DeliveryToken, batchToken, leaseExpires, toNodeID, signal.ID, now)
			if err != nil {
				return nil, 0, err
			}
			if affected, err := result.RowsAffected(); err != nil {
				return nil, 0, err
			} else if affected != 1 {
				// A separate server process may have claimed the row after the
				// SELECT.  Never overwrite its lease; abort this transaction so
				// the caller retries from a fresh snapshot.
				return nil, 0, fmt.Errorf("signal lease changed while claiming %s", signal.ID)
			}
		}
	}
	if len(malformedIDs) > 0 {
		args := append([]interface{}{toNodeID}, malformedIDs...)
		if _, err := tx.Exec(`DELETE FROM signals WHERE to_node_id = ? AND id IN (`+malformedPlaceholders+`)`, args...); err != nil {
			return nil, 0, err
		}
	}

	if err := tx.Commit(); err != nil {
		return nil, 0, err
	}

	return signals, leaseExpires * 1000, nil
}

// AckSignals idempotently acknowledges delivered signals: each row is
// deleted only when its delivery token still matches the token the client
// received (the client proves it really got THAT delivery).  Already-deleted
// rows are no-ops, so a repeated ACK is harmless.  Returns the number of
// rows actually deleted.
func (db *DB) AckSignals(toNodeID string, acks []SignalAck) (int64, error) {
	if len(acks) == 0 {
		return 0, nil
	}
	tx, err := db.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()

	deleted := int64(0)
	for _, ack := range acks {
		result, err := tx.Exec(`DELETE FROM signals
			WHERE to_node_id = ? AND id = ? AND delivery_token = ? AND delivery_token != ''`,
			toNodeID, ack.ID, ack.DeliveryToken)
		if err != nil {
			return 0, err
		}
		count, err := result.RowsAffected()
		if err != nil {
			return 0, err
		}
		deleted += count
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return deleted, nil
}

// AckSignalBatch acknowledges every signal of one delivered batch using the
// server-generated batch token.  The batch token is a digest of the delivery
// tokens the batch was handed out with; it validates only while every row of
// that batch is still leased with those exact tokens, so a batch whose rows
// were partially ACKed or re-leased fails and the client must fall back to
// per-row ACKs.  Returns the number of rows deleted.
func (db *DB) AckSignalBatch(toNodeID, batchToken string) (int64, error) {
	if strings.TrimSpace(batchToken) == "" {
		return 0, nil
	}
	now := time.Now().Unix()
	tx, err := db.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()

	rows, err := tx.Query(`SELECT id, delivery_token FROM signals
		WHERE to_node_id = ? AND delivery_batch_token = ? AND delivery_token != '' AND lease_expires_at > ?`, toNodeID, batchToken, now)
	if err != nil {
		return 0, err
	}
	var leased []struct{ ID, Token string }
	for rows.Next() {
		var entry struct{ ID, Token string }
		if err := rows.Scan(&entry.ID, &entry.Token); err != nil {
			rows.Close()
			return 0, err
		}
		leased = append(leased, entry)
	}
	if err := rows.Close(); err != nil {
		return 0, err
	}
	if len(leased) == 0 {
		return 0, nil
	}
	if BatchTokenFor(leased) != batchToken {
		// The batch changed (partially ACKed, re-leased, or new rows
		// arrived): the client must retry with per-row ACKs.
		return 0, nil
	}
	args := make([]interface{}, 0, len(leased))
	placeholders := ""
	for _, entry := range leased {
		args = append(args, entry.ID)
		if placeholders != "" {
			placeholders += ","
		}
		placeholders += "?"
	}
	args = append([]interface{}{toNodeID}, args...)
	args = append(args, batchToken, now)
	result, err := tx.Exec(`DELETE FROM signals
		WHERE to_node_id = ? AND id IN (`+placeholders+`) AND delivery_batch_token = ? AND lease_expires_at > ?`, args...)
	if err != nil {
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return result.RowsAffected()
}

// BatchTokenFor deterministically digests one delivery batch: the tokens are
// sorted by row id and hashed, so the same batch always produces the same
// token and a changed batch never does.
func BatchTokenFor(entries []struct{ ID, Token string }) string {
	sorted := make([]string, 0, len(entries))
	for _, entry := range entries {
		sorted = append(sorted, entry.ID+":"+entry.Token)
	}
	sort.Strings(sorted)
	digest := sha256.Sum256([]byte(strings.Join(sorted, "|")))
	return hex.EncodeToString(digest[:])
}

func appendID(ids *[]interface{}, placeholders *string, id string) {
	*ids = append(*ids, id)
	if *placeholders != "" {
		*placeholders += ","
	}
	*placeholders += "?"
}
