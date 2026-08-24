package database

import (
	"fmt"
	"testing"
	"time"
)

func openSignalLeaseDB(t *testing.T) *DB {
	t.Helper()
	db, err := New("file::memory:?cache=shared")
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func createLeasePair(t *testing.T, db *DB) (string, string) {
	t.Helper()
	user, err := db.CreateUser("lease-sender@example.com", "passw0rd")
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	network, err := db.CreateNetwork(user.ID, "lease-net", "")
	if err != nil {
		t.Fatalf("create network: %v", err)
	}
	sender, err := db.CreateDevice(user.ID, network.ID, "sender-key", "lease-sender", "", "")
	if err != nil {
		t.Fatalf("create sender: %v", err)
	}
	target, err := db.CreateDevice(user.ID, network.ID, "target-key", "lease-target", "", "")
	if err != nil {
		t.Fatalf("create target: %v", err)
	}
	return sender.ID, target.ID
}

func TestSignalLeaseExclusiveUntilAckOrExpiry(t *testing.T) {
	db := openSignalLeaseDB(t)
	sender, target := createLeasePair(t, db)
	for i := 0; i < 3; i++ {
		if _, err := db.CreateSignalWithTraversalMetadata(sender, target, "peer_offer",
			[]string{fmt.Sprintf("203.0.113.10:%d", 40000+i)}, nil, fmt.Sprintf("h%d", i), 0, int64(i+1), 0); err != nil {
			t.Fatalf("create signal: %v", err)
		}
	}

	// First ACK-mode poll leases the batch and returns it with tokens.
	first, expiresAtMS, err := db.ListSignalsWithLease(target)
	if err != nil {
		t.Fatalf("lease poll: %v", err)
	}
	if len(first) != 3 {
		t.Fatalf("expected 3 leased signals, got %d", len(first))
	}
	if expiresAtMS <= time.Now().UnixMilli() {
		t.Fatalf("lease deadline must be in the future")
	}
	for _, signal := range first {
		if signal.DeliveryToken == "" {
			t.Fatalf("every leased signal must carry a delivery token")
		}
		// Per-pair seq must be 1..3 in delivery order (signal_seq ASC).
		if signal.SignalSeq != int64(indexOf(first, signal.ID))+1 {
			t.Fatalf("signal %s has seq %d", signal.ID, signal.SignalSeq)
		}
	}

	// A second poll (before the lease expires) must see nothing: neither the
	// ACK-mode poll nor the legacy delete-on-GET poll may steal leased rows.
	second, _, err := db.ListSignalsWithLease(target)
	if err != nil {
		t.Fatalf("second lease poll: %v", err)
	}
	if len(second) != 0 {
		t.Fatalf("leased rows must not be redelivered before expiry, got %d", len(second))
	}
	legacy, err := db.ListAndDeleteSignals(target)
	if err != nil {
		t.Fatalf("legacy poll: %v", err)
	}
	if len(legacy) != 0 {
		t.Fatalf("legacy delete-on-GET must never steal leased rows, got %d", len(legacy))
	}

	// ACK with a WRONG token must not delete.
	acked, err := db.AckSignals(target, []SignalAck{{ID: first[0].ID, DeliveryToken: "wrong"}})
	if err != nil {
		t.Fatalf("ack wrong token: %v", err)
	}
	if acked != 0 {
		t.Fatalf("wrong-token ACK must delete nothing, deleted %d", acked)
	}

	// ACK with the real tokens deletes exactly those rows; a repeated ACK is
	// a no-op.
	acked, err = db.AckSignals(target, []SignalAck{{ID: first[0].ID, DeliveryToken: first[0].DeliveryToken}})
	if err != nil {
		t.Fatalf("ack: %v", err)
	}
	if acked != 1 {
		t.Fatalf("expected 1 deletion, got %d", acked)
	}
	acked, err = db.AckSignals(target, []SignalAck{{ID: first[0].ID, DeliveryToken: first[0].DeliveryToken}})
	if err != nil {
		t.Fatalf("repeat ack: %v", err)
	}
	if acked != 0 {
		t.Fatalf("repeated ACK must be a no-op, deleted %d", acked)
	}

	// The remaining two rows are still held by their leases.
	remaining, _, err := db.ListSignalsWithLease(target)
	if err != nil {
		t.Fatalf("poll after partial ack: %v", err)
	}
	if len(remaining) != 0 {
		t.Fatalf("un-acked rows must stay leased, got %d", len(remaining))
	}
}

func TestSignalLeaseExpiryRedelivers(t *testing.T) {
	db := openSignalLeaseDB(t)
	sender, target := createLeasePair(t, db)
	if _, err := db.CreateSignalWithTraversalMetadata(sender, target, "peer_offer", []string{"203.0.113.10:41001"}, nil, "h", 0, 1, 0); err != nil {
		t.Fatalf("create signal: %v", err)
	}
	first, _, err := db.ListSignalsWithLease(target)
	if err != nil || len(first) != 1 {
		t.Fatalf("first lease poll: %v (len=%d)", err, len(first))
	}
	// Force the lease to expire, as if the client died mid-processing.
	now := time.Now().Unix()
	if _, err := db.Exec(`UPDATE signals SET lease_expires_at = ? WHERE id = ?`, now-1, first[0].ID); err != nil {
		t.Fatalf("expire lease: %v", err)
	}
	redelivered, _, err := db.ListSignalsWithLease(target)
	if err != nil {
		t.Fatalf("redelivery poll: %v", err)
	}
	if len(redelivered) != 1 {
		t.Fatalf("expired lease must redeliver the row, got %d", len(redelivered))
	}
	if redelivered[0].ID != first[0].ID {
		t.Fatalf("redelivered row must be the same signal")
	}
	if redelivered[0].DeliveryToken == first[0].DeliveryToken {
		t.Fatalf("a redelivery must carry a fresh token")
	}
}

func TestSignalBatchAckValidatesWholeBatch(t *testing.T) {
	db := openSignalLeaseDB(t)
	sender, target := createLeasePair(t, db)
	for i := 0; i < 2; i++ {
		if _, err := db.CreateSignalWithTraversalMetadata(sender, target, "peer_answer",
			[]string{fmt.Sprintf("203.0.113.10:%d", 42000+i)}, nil, fmt.Sprintf("a%d", i), 0, int64(i+1), 0); err != nil {
			t.Fatalf("create signal: %v", err)
		}
	}
	first, _, err := db.ListSignalsWithLease(target)
	if err != nil || len(first) != 2 {
		t.Fatalf("lease poll: %v (len=%d)", err, len(first))
	}
	entries := make([]struct{ ID, Token string }, 0, len(first))
	for _, signal := range first {
		entries = append(entries, struct{ ID, Token string }{signal.ID, signal.DeliveryToken})
	}
	validToken := BatchTokenFor(entries)

	// A stale/wrong batch token acknowledges nothing.
	deleted, err := db.AckSignalBatch(target, "stale-token")
	if err != nil {
		t.Fatalf("stale batch ack: %v", err)
	}
	if deleted != 0 {
		t.Fatalf("stale batch token must delete nothing, deleted %d", deleted)
	}
	// The valid batch token deletes the whole batch.
	deleted, err = db.AckSignalBatch(target, validToken)
	if err != nil {
		t.Fatalf("batch ack: %v", err)
	}
	if deleted != 2 {
		t.Fatalf("expected 2 deletions, got %d", deleted)
	}
	// A repeated batch ACK is a no-op.
	deleted, err = db.AckSignalBatch(target, validToken)
	if err != nil {
		t.Fatalf("repeat batch ack: %v", err)
	}
	if deleted != 0 {
		t.Fatalf("repeated batch ACK must be a no-op, deleted %d", deleted)
	}
}

func TestSignalLeaseBlocksLaterRowsPerPairButNotOtherSenders(t *testing.T) {
	db := openSignalLeaseDB(t)
	senderA, target := createLeasePair(t, db)
	targetDevice, err := db.GetDevice(target)
	if err != nil {
		t.Fatalf("get target device: %v", err)
	}
	senderB, err := db.CreateDevice(targetDevice.UserID, targetDevice.NetworkID, "sender-d-key", "lease-sender-d", "", "")
	if err != nil {
		t.Fatalf("create sender b: %v", err)
	}

	firstCreated, err := db.CreateSignalWithTraversalMetadata(
		senderA, target, "peer_offer", []string{"203.0.113.10:45000"}, nil,
		"g1", 0, 1, 0,
	)
	if err != nil {
		t.Fatalf("create first sender-a signal: %v", err)
	}
	first, _, err := db.ListSignalsWithLease(target)
	if err != nil {
		t.Fatalf("first lease poll: %v", err)
	}
	if len(first) != 1 || first[0].ID != firstCreated.ID {
		t.Fatalf("expected sender-a G1 as the first lease, got %+v", first)
	}

	// Create sender A's G2 only after G1 has an active lease. Sender B is an
	// independent pair and must remain deliverable while A's queue is fenced.
	secondCreated, err := db.CreateSignalWithTraversalMetadata(
		senderA, target, "peer_offer", []string{"203.0.113.10:45001"}, nil,
		"g2", 0, 2, 0,
	)
	if err != nil {
		t.Fatalf("create sender-a G2: %v", err)
	}
	otherCreated, err := db.CreateSignalWithTraversalMetadata(
		senderB.ID, target, "peer_offer", []string{"203.0.113.20:45000"}, nil,
		"b1", 0, 1, 0,
	)
	if err != nil {
		t.Fatalf("create sender-b G1: %v", err)
	}

	second, _, err := db.ListSignalsWithLease(target)
	if err != nil {
		t.Fatalf("second lease poll: %v", err)
	}
	if len(second) != 1 || second[0].ID != otherCreated.ID {
		t.Fatalf("sender B must progress while sender A G2 remains fenced; got %+v", second)
	}

	// Even the legacy delete-on-GET path must not overtake sender A's active G1.
	legacy, err := db.ListAndDeleteSignals(target)
	if err != nil {
		t.Fatalf("legacy poll while sender-a G1 is leased: %v", err)
	}
	if len(legacy) != 0 {
		t.Fatalf("legacy delivery must not overtake sender-a G1, got %+v", legacy)
	}

	deleted, err := db.AckSignals(target, []SignalAck{
		{ID: second[0].ID, DeliveryToken: second[0].DeliveryToken},
		{ID: first[0].ID, DeliveryToken: first[0].DeliveryToken},
	})
	if err != nil {
		t.Fatalf("ack independent heads: %v", err)
	}
	if deleted != 2 {
		t.Fatalf("expected two head deletions, got %d", deleted)
	}

	third, _, err := db.ListSignalsWithLease(target)
	if err != nil {
		t.Fatalf("poll after sender-a head ACK: %v", err)
	}
	if len(third) != 1 || third[0].ID != secondCreated.ID {
		t.Fatalf("sender-a G2 must become deliverable only after G1 ACK; got %+v", third)
	}
	if third[0].SignalSeq != 2 {
		t.Fatalf("sender-a G2 sequence changed: got %d", third[0].SignalSeq)
	}
}

func TestSignalLeaseBatchOfFiveHundredFromMultipleSenders(t *testing.T) {
	db := openSignalLeaseDB(t)
	senderA, target := createLeasePair(t, db)
	user, err := db.CreateUser("lease-sender-b@example.com", "passw0rd")
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	network, err := db.CreateNetwork(user.ID, "lease-net-2", "")
	if err != nil {
		t.Fatalf("create network: %v", err)
	}
	senderB, err := db.CreateDevice(user.ID, network.ID, "sender-b-key", "lease-sender-b", "", "")
	if err != nil {
		t.Fatalf("create sender b: %v", err)
	}
	senderC, err := db.CreateDevice(user.ID, network.ID, "sender-c-key", "lease-sender-c", "", "")
	if err != nil {
		t.Fatalf("create sender c: %v", err)
	}

	senders := []string{senderA, senderB.ID, senderC.ID}
	for i := 0; i < 500; i++ {
		if _, err := db.CreateSignalWithTraversalMetadata(senders[i%3], target, "peer_offer",
			[]string{fmt.Sprintf("203.0.113.10:%d", 43000+i)}, nil, fmt.Sprintf("h%d", i), 0, int64(i+1), 0); err != nil {
			t.Fatalf("create signal %d: %v", i, err)
		}
	}

	batch, expiresAtMS, err := db.ListSignalsWithLease(target)
	if err != nil {
		t.Fatalf("lease poll: %v", err)
	}
	if len(batch) != 500 {
		t.Fatalf("expected exactly the 500-row batch, got %d", len(batch))
	}
	if expiresAtMS <= time.Now().UnixMilli() {
		t.Fatalf("lease deadline must be in the future")
	}
	// Per-pair ordering across the three senders must be the per-sender
	// sequence (1..), never the wall clock.
	seqBySender := map[string]int64{}
	for _, signal := range batch {
		expected := seqBySender[signal.FromNodeID] + 1
		if signal.SignalSeq != expected {
			t.Fatalf("sender %s seq %d, expected %d (delivery order violated)", signal.FromNodeID, signal.SignalSeq, expected)
		}
		seqBySender[signal.FromNodeID] = expected
	}

	// ACK everything per-row, then confirm the queue is empty.
	acks := make([]SignalAck, 0, len(batch))
	for _, signal := range batch {
		acks = append(acks, SignalAck{ID: signal.ID, DeliveryToken: signal.DeliveryToken})
	}
	deleted, err := db.AckSignals(target, acks)
	if err != nil {
		t.Fatalf("ack batch: %v", err)
	}
	if deleted != 500 {
		t.Fatalf("expected 500 deletions, got %d", deleted)
	}
	legacy, err := db.ListAndDeleteSignals(target)
	if err != nil {
		t.Fatalf("final legacy poll: %v", err)
	}
	if len(legacy) != 0 {
		t.Fatalf("queue must be empty after the full ACK, got %d", len(legacy))
	}
}

func indexOf(signals []Signal, id string) int {
	for i, signal := range signals {
		if signal.ID == id {
			return i
		}
	}
	return -1
}
