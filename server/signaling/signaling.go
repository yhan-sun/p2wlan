// Package signaling implements the WebSocket-based signaling hub.
//
// The hub coordinates real-time communication between nodes:
//   - Node presence (join/leave announcements)
//   - Endpoint updates after NAT detection
//   - Peer offers/answers for ICE hole punching
//   - Heartbeat keep-alive
package signaling

import (
	"encoding/json"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/websocket"

	"github.com/yhan-sun/p2wlan/server/auth"
	"github.com/yhan-sun/p2wlan/server/database"
)

var upgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
	CheckOrigin:     func(r *http.Request) bool { return true },
}

// Message is a signaling message exchanged over WebSocket.
type Message struct {
	Type string          `json:"type"` // register, peer_join, peer_leave, endpoint_update, peer_offer, peer_answer, heartbeat, error
	Data json.RawMessage `json:"data"`
}

// RegisterData is the payload for node registration.
type RegisterData struct {
	NodeID    string `json:"node_id"`
	PublicKey string `json:"public_key"`
	NetworkID string `json:"network_id"`
}

// PeerUpdateData is the payload for peer presence updates.
type PeerUpdateData struct {
	NodeID    string `json:"node_id"`
	PublicKey string `json:"public_key"`
	Endpoint  string `json:"endpoint"`
	NATType   string `json:"nat_type"`
	VirtualIP string `json:"virtual_ip"`
}

// EndpointUpdateData is the payload for endpoint changes.
type EndpointUpdateData struct {
	NodeID   string `json:"node_id"`
	Endpoint string `json:"endpoint"`
	NATType  string `json:"nat_type"`
}

// PeerOfferData is the payload for P2P connection offers.
type PeerOfferData struct {
	FromNodeID       string            `json:"from_node_id"`
	ToNodeID         string            `json:"to_node_id"`
	Candidates       []string          `json:"candidates"`
	CandidateSources map[string]string `json:"candidate_sources,omitempty"`
	HandshakeInit    []byte            `json:"handshake_init,omitempty"`
	PunchAtMS        int64             `json:"punch_at_ms,omitempty"`
}

// PeerAnswerData is the payload for P2P connection answers.
type PeerAnswerData struct {
	FromNodeID        string            `json:"from_node_id"`
	ToNodeID          string            `json:"to_node_id"`
	Candidates        []string          `json:"candidates"`
	CandidateSources  map[string]string `json:"candidate_sources,omitempty"`
	HandshakeResponse []byte            `json:"handshake_response,omitempty"`
	PunchAtMS         int64             `json:"punch_at_ms,omitempty"`
}

// PeerReflexiveData carries a relay-assisted UDP source observation.
type PeerReflexiveData struct {
	FromNodeID       string            `json:"from_node_id"`
	ToNodeID         string            `json:"to_node_id"`
	Candidates       []string          `json:"candidates"`
	CandidateSources map[string]string `json:"candidate_sources,omitempty"`
	PunchAtMS        int64             `json:"punch_at_ms,omitempty"`
}

// Client represents a connected node.
type Client struct {
	hub       *Hub
	conn      *websocket.Conn
	send      chan []byte
	nodeID    string
	networkID string
}

// Hub manages all connected clients.
type Hub struct {
	mu       sync.RWMutex
	clients  map[string]*Client         // nodeID → client
	networks map[string]map[string]bool // networkID → set of nodeIDs
	db       *database.DB
}

// NewHub creates a new signaling hub.
func NewHub(db *database.DB) *Hub {
	return &Hub{
		clients:  make(map[string]*Client),
		networks: make(map[string]map[string]bool),
		db:       db,
	}
}

// Run starts the hub's main loop.
func (h *Hub) Run() {
	// The hub is event-driven through client channels.
	// This goroutine just keeps the hub alive.
	select {}
}

// Register adds a client to the hub.
func (h *Hub) Register(client *Client, networkID string) {
	h.mu.Lock()
	defer h.mu.Unlock()

	h.clients[client.nodeID] = client
	client.networkID = networkID

	if h.networks[networkID] == nil {
		h.networks[networkID] = make(map[string]bool)
	}
	h.networks[networkID][client.nodeID] = true

	// Notify other nodes in the network about the new peer
	// (done by the caller after getting the peer list)
}

// Unregister removes a client from the hub.
func (h *Hub) Unregister(client *Client) {
	h.mu.Lock()
	defer h.mu.Unlock()

	if _, ok := h.clients[client.nodeID]; ok {
		delete(h.clients, client.nodeID)

		if nodes, ok := h.networks[client.networkID]; ok {
			delete(nodes, client.nodeID)

			// Notify remaining peers
			leaveMsg, _ := json.Marshal(Message{
				Type: "peer_leave",
				Data: mustMarshal(map[string]string{"node_id": client.nodeID}),
			})
			for nodeID := range nodes {
				if peer, ok := h.clients[nodeID]; ok {
					select {
					case peer.send <- leaveMsg:
					default:
					}
				}
			}
		}

		close(client.send)
	}
}

// SendToPeer sends a message to a specific node.
func (h *Hub) SendToPeer(fromNodeID, toNodeID string, msg Message) bool {
	h.mu.RLock()
	peer, ok := h.clients[toNodeID]
	h.mu.RUnlock()

	if !ok {
		return false
	}

	data, _ := json.Marshal(msg)
	select {
	case peer.send <- data:
		return true
	default:
		return false
	}
}

// GetNetworkPeers returns all peer node IDs in a network.
func (h *Hub) GetNetworkPeers(networkID string) []string {
	h.mu.RLock()
	defer h.mu.RUnlock()

	nodes := h.networks[networkID]
	if nodes == nil {
		return nil
	}

	peers := make([]string, 0, len(nodes))
	for nodeID := range nodes {
		peers = append(peers, nodeID)
	}
	return peers
}

// ServeWS handles WebSocket upgrade and client connection.
func ServeWS(hub *Hub, authService *auth.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Validate token from query parameter
		token := r.URL.Query().Get("token")
		if token == "" {
			http.Error(w, "missing token", http.StatusUnauthorized)
			return
		}

		claims, err := authService.ValidateToken(token)
		if err != nil {
			http.Error(w, "invalid token", http.StatusUnauthorized)
			return
		}

		_ = claims // Use claims for authorization

		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			log.Printf("WebSocket upgrade error: %v", err)
			return
		}

		client := &Client{
			hub:  hub,
			conn: conn,
			send: make(chan []byte, 256),
		}

		// Read and write pumps
		go client.writePump()
		client.readPump()
	}
}

// readPump reads messages from the WebSocket connection.
func (c *Client) readPump() {
	defer func() {
		c.hub.Unregister(c)
		c.conn.Close()
	}()

	c.conn.SetReadDeadline(time.Now().Add(60 * time.Second))
	c.conn.SetPongHandler(func(string) error {
		c.conn.SetReadDeadline(time.Now().Add(60 * time.Second))
		return nil
	})

	for {
		_, message, err := c.conn.ReadMessage()
		if err != nil {
			break
		}

		var msg Message
		if err := json.Unmarshal(message, &msg); err != nil {
			continue
		}

		switch msg.Type {
		case "register":
			var data RegisterData
			json.Unmarshal(msg.Data, &data)
			c.nodeID = data.NodeID
			c.hub.Register(c, data.NetworkID)

		case "endpoint_update":
			var data EndpointUpdateData
			json.Unmarshal(msg.Data, &data)
			// Broadcast to network peers
			c.hub.SendToPeer(data.NodeID, "", Message{Type: "endpoint_update", Data: msg.Data})

		case "peer_offer":
			var data PeerOfferData
			json.Unmarshal(msg.Data, &data)
			c.hub.SendToPeer(data.FromNodeID, data.ToNodeID, msg)

		case "peer_answer":
			var data PeerAnswerData
			json.Unmarshal(msg.Data, &data)
			c.hub.SendToPeer(data.FromNodeID, data.ToNodeID, msg)

		case "peer_reflexive":
			var data PeerReflexiveData
			json.Unmarshal(msg.Data, &data)
			c.hub.SendToPeer(data.FromNodeID, data.ToNodeID, msg)

		case "heartbeat":
			// Update last_seen
			if c.nodeID != "" {
				c.hub.db.UpdateDeviceEndpoint(c.nodeID, "", "")
			}
		}
	}
}

// writePump writes messages to the WebSocket connection.
func (c *Client) writePump() {
	ticker := time.NewTicker(30 * time.Second)
	defer func() {
		ticker.Stop()
		c.conn.Close()
	}()

	for {
		select {
		case message, ok := <-c.send:
			c.conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if !ok {
				c.conn.WriteMessage(websocket.CloseMessage, []byte{})
				return
			}
			if err := c.conn.WriteMessage(websocket.TextMessage, message); err != nil {
				return
			}

		case <-ticker.C:
			c.conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if err := c.conn.WriteMessage(websocket.PingMessage, nil); err != nil {
				return
			}
		}
	}
}

func mustMarshal(v interface{}) json.RawMessage {
	data, _ := json.Marshal(v)
	return data
}
