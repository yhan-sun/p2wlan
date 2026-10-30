package signaling

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/gorilla/websocket"
)

// RoomRosterWakeHeader negotiates a hint understood by current clients. Older
// clients keep receiving the existing signal wake and retain their HTTP poll.
const RoomRosterWakeHeader = "X-P2WLAN-Room-Roster-Wake"

func supportsRoomRosterWake(r *http.Request) bool {
	values := r.Header.Values(RoomRosterWakeHeader)
	return len(values) == 1 && values[0] == "1"
}

// NotifyRoomRoster wakes only the current device connection in this room.
// The message contains no membership or authority; clients must refresh HTTP.
func (h *Hub) NotifyRoomRoster(nodeID, roomID string) bool {
	if roomID == "" {
		return false
	}
	return h.notify(nodeID, roomID, "roster_changed")
}

func (h *Hub) notify(nodeID, networkID, kind string) bool {
	h.mu.RLock()
	client := h.clients[nodeID]
	h.mu.RUnlock()
	if client == nil || (networkID != "" && client.networkID != networkID) {
		return false
	}
	if kind == "roster_changed" && !client.roomRosterWake {
		kind = "signals_available"
	}
	// Counter order must be publication order: an atomic counter alone can
	// enqueue sequence N+1 before a paused publisher enqueues N.
	client.notifyMu.Lock()
	defer client.notifyMu.Unlock()
	client.sequence++
	frame := serverMessage{Type: kind, ProtocolVersion: ProtocolVersion,
		Sequence: client.sequence, ServerTimeMS: time.Now().UnixMilli()}
	if kind == "roster_changed" {
		frame.NodeID, frame.NetworkID = client.nodeID, client.networkID
	}
	message, err := json.Marshal(frame)
	if err != nil {
		return false
	}
	if client.enqueue(message) {
		return true
	}
	client.requestClose(websocket.ClosePolicyViolation, "signal notification backpressure")
	return false
}
