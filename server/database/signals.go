package database

import (
	"encoding/json"
	"fmt"
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
}

const (
	SignalProtocolVersion int64 = 1
	signalTTLSeconds      int64 = 120
)

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

	id := fmt.Sprintf("signal-%d", time.Now().UnixNano())
	now := time.Now().Unix()
	tx, err := db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	if _, err = tx.Exec(`DELETE FROM signals WHERE created_at < ?`, now-signalTTLSeconds); err != nil {
		return nil, err
	}
	if _, err = tx.Exec(`DELETE FROM signals WHERE from_node_id = ? AND to_node_id = ? AND type = ?`, fromNodeID, toNodeID, typ); err != nil {
		return nil, err
	}
	_, err = tx.Exec(`INSERT INTO signals (id, from_node_id, to_node_id, type, protocol_version, candidates, candidate_sources, candidate_generation, candidates_expires_at_ms, session_id, probe_ephemeral_public_key, handshake, punch_at_ms, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, id, fromNodeID, toNodeID, typ, protocolVersion, string(candidatesJSON), string(candidateSourcesJSON), candidateGeneration, candidatesExpiresAtMS, sessionID, probeEphemeralPublicKey, handshake, punchAtMS, now)
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}

	return &Signal{
		ID: id, FromNodeID: fromNodeID, ToNodeID: toNodeID, Type: typ,
		ProtocolVersion: protocolVersion, Candidates: candidates, CandidateSources: candidateSources, CandidateGeneration: candidateGeneration, CandidatesExpiresAtMS: candidatesExpiresAtMS, SessionID: sessionID, ProbeEphemeralPublicKey: probeEphemeralPublicKey, Handshake: handshake, PunchAtMS: punchAtMS, CreatedAt: now,
	}, nil
}

// ListAndDeleteSignals returns queued messages for a node and deletes them atomically.
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

	rows, err := tx.Query(`SELECT id, from_node_id, to_node_id, type, protocol_version, candidates, candidate_sources, candidate_generation, candidates_expires_at_ms, session_id, probe_ephemeral_public_key, handshake, punch_at_ms, created_at
		FROM signals WHERE to_node_id = ? AND created_at >= ? ORDER BY created_at ASC`, toNodeID, now-signalTTLSeconds)
	if err != nil {
		return nil, err
	}

	signals := []Signal{}
	for rows.Next() {
		var s Signal
		var candidatesJSON string
		var candidateSourcesJSON string
		if err := rows.Scan(&s.ID, &s.FromNodeID, &s.ToNodeID, &s.Type, &s.ProtocolVersion, &candidatesJSON, &candidateSourcesJSON, &s.CandidateGeneration, &s.CandidatesExpiresAtMS, &s.SessionID, &s.ProbeEphemeralPublicKey, &s.Handshake, &s.PunchAtMS, &s.CreatedAt); err != nil {
			return nil, err
		}
		if err := json.Unmarshal([]byte(candidatesJSON), &s.Candidates); err != nil {
			return nil, err
		}
		if s.Candidates == nil {
			s.Candidates = []string{}
		}
		if err := json.Unmarshal([]byte(candidateSourcesJSON), &s.CandidateSources); err != nil {
			return nil, err
		}
		if s.CandidateSources == nil {
			s.CandidateSources = map[string]string{}
		}
		signals = append(signals, s)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}

	if _, err := tx.Exec(`DELETE FROM signals WHERE to_node_id = ?`, toNodeID); err != nil {
		return nil, err
	}

	if err := tx.Commit(); err != nil {
		return nil, err
	}

	return signals, nil
}
