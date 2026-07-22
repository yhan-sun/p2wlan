// Package signaling provides the authenticated WebSocket wake-up channel for
// durable control-plane signals. Signal payloads remain in the database until
// clients consume them through the HTTP API; WebSocket messages only wake the
// intended device, so reconnects and process crashes cannot lose signals.
package signaling

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"

	"github.com/yhan-sun/p2wlan/server/auth"
)

const (
	ProtocolName          = "p2wlan.signaling.v1"
	ProtocolVersion       = 1
	DefaultMaxConnections = 10_000
	sendQueueCapacity     = 64
	readLimitBytes        = 4 << 10
	writeWait             = 5 * time.Second
	pongWait              = 45 * time.Second
	pingPeriod            = 20 * time.Second
)

var (
	ErrHubClosed       = errors.New("signaling hub is closed")
	ErrConnectionLimit = errors.New("signaling connection limit exceeded")
)

type serverMessage struct {
	Type            string `json:"type"`
	ProtocolVersion int    `json:"protocol_version"`
	NodeID          string `json:"node_id,omitempty"`
	NetworkID       string `json:"network_id,omitempty"`
	Sequence        uint64 `json:"sequence,omitempty"`
	ServerTimeMS    int64  `json:"server_time_ms"`
}

type closeRequest struct {
	code int
	text string
}

// Client is one authenticated device connection. Identity comes exclusively
// from device credential claims; clients never self-declare node or network.
type Client struct {
	hub        *Hub
	conn       *websocket.Conn
	send       chan []byte
	done       chan struct{}
	closeReq   chan closeRequest
	writerDone chan struct{}
	stopOnce   sync.Once
	nodeID     string
	networkID  string
	expiresAt  time.Time
	sequence   atomic.Uint64
}

// Hub keeps at most one live WebSocket per device. It intentionally contains
// no signal payloads; those remain durable in the database.
type Hub struct {
	mu             sync.RWMutex
	clients        map[string]*Client
	maxConnections int
	activeClients  int
	closed         bool
	connections    sync.WaitGroup
}

func NewHub() *Hub {
	return NewHubWithLimit(DefaultMaxConnections)
}

// NewHubFromEnv parses production configuration strictly so an invalid
// resource limit cannot silently turn into a different operational policy.
func NewHubFromEnv() (*Hub, error) {
	maxConnections := DefaultMaxConnections
	if raw := strings.TrimSpace(os.Getenv("SIGNAL_WS_MAX_CONNECTIONS")); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed <= 0 {
			return nil, fmt.Errorf("SIGNAL_WS_MAX_CONNECTIONS must be a positive integer")
		}
		maxConnections = parsed
	}
	return NewHubWithLimit(maxConnections), nil
}

func NewHubWithLimit(maxConnections int) *Hub {
	if maxConnections <= 0 {
		maxConnections = DefaultMaxConnections
	}
	return &Hub{
		clients:        make(map[string]*Client),
		maxConnections: maxConnections,
	}
}

func (h *Hub) register(client *Client) (*Client, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closed {
		return nil, ErrHubClosed
	}
	if h.activeClients >= h.maxConnections {
		return nil, ErrConnectionLimit
	}
	previous := h.clients[client.nodeID]
	h.clients[client.nodeID] = client
	h.activeClients++
	h.connections.Add(1)
	return previous, nil
}

func (h *Hub) connectionDone() {
	h.mu.Lock()
	if h.activeClients > 0 {
		h.activeClients--
	}
	h.mu.Unlock()
	h.connections.Done()
}

func (h *Hub) unregister(client *Client) {
	h.mu.Lock()
	if h.clients[client.nodeID] == client {
		delete(h.clients, client.nodeID)
	}
	h.mu.Unlock()
}

// Notify wakes the current connection for nodeID. False means the device is
// offline or backpressured; the durable HTTP signal remains available.
func (h *Hub) Notify(nodeID string) bool {
	h.mu.RLock()
	client := h.clients[nodeID]
	h.mu.RUnlock()
	if client == nil {
		return false
	}
	sequence := client.sequence.Add(1)
	message, err := json.Marshal(serverMessage{
		Type:            "signals_available",
		ProtocolVersion: ProtocolVersion,
		Sequence:        sequence,
		ServerTimeMS:    time.Now().UnixMilli(),
	})
	if err != nil {
		return false
	}
	if client.enqueue(message) {
		return true
	}
	client.requestClose(websocket.ClosePolicyViolation, "signal notification backpressure")
	return false
}

// Close disconnects all clients and prevents future registrations.
func (h *Hub) Close() {
	h.mu.Lock()
	if h.closed {
		h.mu.Unlock()
		h.connections.Wait()
		return
	}
	h.closed = true
	clients := make([]*Client, 0, len(h.clients))
	for _, client := range h.clients {
		clients = append(clients, client)
	}
	h.clients = make(map[string]*Client)
	h.mu.Unlock()
	for _, client := range clients {
		client.requestClose(websocket.CloseGoingAway, "server shutdown")
	}
	h.connections.Wait()
}

func (c *Client) enqueue(message []byte) bool {
	select {
	case <-c.done:
		return false
	default:
	}
	select {
	case c.send <- message:
		return true
	case <-c.done:
		return false
	default:
		return false
	}
}

func (c *Client) stop() {
	c.stopOnce.Do(func() { close(c.done) })
}

func (c *Client) requestClose(code int, text string) {
	select {
	case c.closeReq <- closeRequest{code: code, text: text}:
	default:
	}
}

// ServeWS upgrades a request already authenticated by RequireDeviceAuth.
func ServeWS(hub *Hub) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		claims, err := auth.GetDeviceClaims(r.Context())
		if err != nil {
			http.Error(w, `{"error":"device authentication required"}`, http.StatusUnauthorized)
			return
		}
		if claims.DeviceID == "" || claims.NetworkID == "" || claims.ExpiresAt <= time.Now().Unix() {
			http.Error(w, `{"error":"invalid device identity"}`, http.StatusUnauthorized)
			return
		}
		if !supportsProtocol(r.Header.Values("Sec-WebSocket-Protocol"), ProtocolName) {
			http.Error(w, `{"error":"required websocket subprotocol is missing"}`, http.StatusUpgradeRequired)
			return
		}

		upgrader := websocket.Upgrader{
			ReadBufferSize:  1024,
			WriteBufferSize: 1024,
			Subprotocols:    []string{ProtocolName},
			CheckOrigin:     checkOrigin,
		}
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}

		client := &Client{
			hub:        hub,
			conn:       conn,
			send:       make(chan []byte, sendQueueCapacity),
			done:       make(chan struct{}),
			closeReq:   make(chan closeRequest, 1),
			writerDone: make(chan struct{}),
			nodeID:     claims.DeviceID,
			networkID:  claims.NetworkID,
			expiresAt:  time.Unix(claims.ExpiresAt, 0),
		}
		previous, err := hub.register(client)
		if err != nil {
			_ = conn.WriteControl(
				websocket.CloseMessage,
				websocket.FormatCloseMessage(websocket.CloseTryAgainLater, err.Error()),
				time.Now().Add(writeWait),
			)
			_ = conn.Close()
			return
		}
		defer hub.connectionDone()
		if previous != nil {
			previous.requestClose(websocket.ClosePolicyViolation, "replaced by a newer device connection")
		}

		ready, _ := json.Marshal(serverMessage{
			Type:            "ready",
			ProtocolVersion: ProtocolVersion,
			NodeID:          client.nodeID,
			NetworkID:       client.networkID,
			ServerTimeMS:    time.Now().UnixMilli(),
		})
		if !client.enqueue(ready) {
			hub.unregister(client)
			_ = conn.Close()
			return
		}

		go client.writePump()
		client.readPump()
		<-client.writerDone
	}
}

func (c *Client) readPump() {
	defer func() {
		c.hub.unregister(c)
		c.stop()
		_ = c.conn.Close()
	}()
	c.conn.SetReadLimit(readLimitBytes)
	_ = c.conn.SetReadDeadline(c.readDeadline())
	c.conn.SetPongHandler(func(string) error {
		return c.conn.SetReadDeadline(c.readDeadline())
	})
	for {
		messageType, _, err := c.conn.ReadMessage()
		if err != nil {
			return
		}
		if messageType == websocket.TextMessage || messageType == websocket.BinaryMessage {
			c.requestClose(websocket.CloseUnsupportedData, "server-to-client notification channel")
			return
		}
	}
}

func (c *Client) writePump() {
	ticker := time.NewTicker(pingPeriod)
	defer func() {
		ticker.Stop()
		c.stop()
		_ = c.conn.Close()
		close(c.writerDone)
	}()
	for {
		select {
		case message := <-c.send:
			_ = c.conn.SetWriteDeadline(time.Now().Add(writeWait))
			if err := c.conn.WriteMessage(websocket.TextMessage, message); err != nil {
				return
			}
		case request := <-c.closeReq:
			_ = c.conn.WriteControl(
				websocket.CloseMessage,
				websocket.FormatCloseMessage(request.code, request.text),
				time.Now().Add(writeWait),
			)
			return
		case <-ticker.C:
			_ = c.conn.SetWriteDeadline(time.Now().Add(writeWait))
			if err := c.conn.WriteMessage(websocket.PingMessage, nil); err != nil {
				return
			}
		case <-c.done:
			return
		}
	}
}

func (c *Client) readDeadline() time.Time {
	deadline := time.Now().Add(pongWait)
	if c.expiresAt.Before(deadline) {
		return c.expiresAt
	}
	return deadline
}

func supportsProtocol(values []string, expected string) bool {
	for _, value := range values {
		for _, protocol := range strings.Split(value, ",") {
			if strings.TrimSpace(protocol) == expected {
				return true
			}
		}
	}
	return false
}

func checkOrigin(r *http.Request) bool {
	origin := strings.TrimSpace(r.Header.Get("Origin"))
	if origin == "" {
		return true
	}
	parsed, err := url.Parse(origin)
	if err == nil && strings.EqualFold(parsed.Host, r.Host) {
		return true
	}
	for _, allowed := range strings.Split(os.Getenv("CONTROL_ALLOWED_ORIGINS"), ",") {
		if strings.TrimSpace(allowed) == origin {
			return true
		}
	}
	return false
}
