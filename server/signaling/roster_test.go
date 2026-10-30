package signaling

import (
	"encoding/json"
	"sync"
	"testing"
)

func TestRoomRosterHintRejectsDifferentAuthenticatedNetwork(t *testing.T) {
	fixture := newWebSocketFixture(t)
	conn := fixture.dial(t, "")
	ready := readServerMessage(t, conn)
	if fixture.hub.NotifyRoomRoster(fixture.deviceID, "another-room") {
		t.Fatal("roster hint crossed authenticated network scope")
	}
	if fixture.hub.NotifyRoomRoster(fixture.deviceID, "") {
		t.Fatal("empty room hint was admitted")
	}
	if !fixture.hub.NotifyRoomRoster(fixture.deviceID, ready.NetworkID) {
		t.Fatal("same-network legacy notification was not admitted")
	}
	notification := readServerMessage(t, conn)
	if notification.Type != "signals_available" || notification.Sequence != 1 {
		t.Fatalf("invalid hints altered the original sequence or legacy transport: %+v", notification)
	}
}

// Sequence allocation and publication must stay together even when many
// independent HTTP handlers wake the same socket concurrently.
func TestConcurrentNotificationDeliveryPreservesSequenceOrder(t *testing.T) {
	const publishers = 32
	const perPublisher = 32
	hub := NewHub()
	client := &Client{
		nodeID: "node", networkID: "network",
		send: make(chan []byte, publishers*perPublisher),
		done: make(chan struct{}), closeReq: make(chan closeRequest, 1),
	}
	hub.clients[client.nodeID] = client
	var workers sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < publishers; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			<-start
			for j := 0; j < perPublisher; j++ {
				if !hub.Notify(client.nodeID) {
					t.Error("bounded queue unexpectedly rejected notification")
				}
			}
		}()
	}
	close(start)
	workers.Wait()
	for want := uint64(1); want <= publishers*perPublisher; want++ {
		var message serverMessage
		if err := json.Unmarshal(<-client.send, &message); err != nil {
			t.Fatal(err)
		}
		if message.Sequence != want {
			t.Fatalf("publication sequence = %d, want %d", message.Sequence, want)
		}
	}
}
