package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

var magic = []byte{'D', 'E', 'R', 'P'}

const (
	version       = byte(1)
	frameHeader   = 8
	msgRegister   = byte(0x01)
	msgRegistered = byte(0x02)
	msgForward    = byte(0x03)
	msgReceived   = byte(0x04)
	msgPing       = byte(0x05)
	msgPong       = byte(0x06)
	msgError      = byte(0x07)
	msgClose      = byte(0x08)
)

var (
	ErrInvalidMagic    = fmt.Errorf("invalid magic")
	ErrUnsupportedVers = fmt.Errorf("unsupported version")
	ErrFrameTooLarge   = fmt.Errorf("frame too large")
)

type RelayConfig struct {
	Bind               string
	SendQueueCapacity  int
	RegisterTimeout    time.Duration
	IdleTimeout        time.Duration
	MaxConnections     int
	MaxFramePayload    int
}

type peer struct {
	id   string
	conn net.Conn
	send chan []byte
	done chan struct{}
}

type hub struct {
	mu    sync.RWMutex
	peers map[string]*peer
}

func newHub() *hub {
	return &hub{peers: map[string]*peer{}}
}

func (h *hub) register(p *peer, id string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if old := h.peers[id]; old != nil && old != p {
		_ = old.conn.Close()
	}
	p.id = id
	h.peers[id] = p
}

func (h *hub) unregister(p *peer) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if p.id != "" && h.peers[p.id] == p {
		delete(h.peers, p.id)
	}
}

// forward forwards payload and returns error code (0 for success).
func (h *hub) forward(srcID, dstID string, data []byte, maxFramePayload int) uint16 {
	h.mu.RLock()
	dst := h.peers[dstID]
	h.mu.RUnlock()
	if dst == nil {
		return 404
	}

	// Enforce max_frame_payload limit on outbound frames
	totalLen := 1 + len(srcID) + len(data)
	if totalLen > maxFramePayload {
		return 4006 // ERR_FRAME_TOO_LARGE
	}

	frame, err := receivedFrame(srcID, data)
	if err != nil {
		return 4000
	}
	select {
	case dst.send <- frame:
		return 0
	case <-dst.done:
		return 404
	default:
		// slow consumer backpressure: close target connection
		_ = dst.conn.Close()
		return 4008
	}
}

var activeConnections int64

func main() {
	config, err := parseConfig(os.Args[1:])
	if err != nil {
		log.Fatalf("config error: %v", err)
	}

	listener, err := net.Listen("tcp", config.Bind)
	if err != nil {
		log.Fatalf("listen %s: %v", config.Bind, err)
	}
	defer listener.Close()

	h := newHub()
	log.Printf("p2wlan relay listening on %s (limits: connections=%d, payload=%d)", listener.Addr(), config.MaxConnections, config.MaxFramePayload)

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-stop
		_ = listener.Close()
	}()

	for {
		conn, err := listener.Accept()
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			return
		}

		// Atomic connection limit check using atomic addition
		if atomic.AddInt64(&activeConnections, 1) > int64(config.MaxConnections) {
			atomic.AddInt64(&activeConnections, -1)
			_ = conn.SetWriteDeadline(time.Now().Add(1 * time.Second))
			_, _ = conn.Write(errorFrame(4005, "connection limit exceeded"))
			_ = conn.Close()
			continue
		}

		go handleConn(h, conn, config)
	}
}

func getenv(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}

func getIntEnv(key string, fallback int) int {
	val := os.Getenv(key)
	if val == "" {
		return fallback
	}
	i, err := strconv.Atoi(val)
	if err != nil {
		return fallback
	}
	return i
}

func getDurationEnv(key string, fallback time.Duration) time.Duration {
	val := os.Getenv(key)
	if val == "" {
		return fallback
	}
	d, err := time.ParseDuration(val)
	if err != nil {
		return fallback
	}
	return d
}

func parseConfig(args []string) (*RelayConfig, error) {
	fs := flag.NewFlagSet("relay", flag.ContinueOnError)
	bind := fs.String("bind", getenv("RELAY_BIND", ":18081"), "TCP listen address")
	sendQueue := fs.Int("send-queue", getIntEnv("RELAY_SEND_QUEUE", 128), "Send queue capacity")
	registerTimeout := fs.Duration("register-timeout", getDurationEnv("RELAY_REGISTER_TIMEOUT", 5*time.Second), "Register timeout")
	idleTimeout := fs.Duration("idle-timeout", getDurationEnv("RELAY_IDLE_TIMEOUT", 30*time.Second), "Idle timeout")
	maxConnections := fs.Int("max-connections", getIntEnv("RELAY_MAX_CONNECTIONS", 1000), "Maximum connections")
	maxFramePayload := fs.Int("max-frame-payload", getIntEnv("RELAY_MAX_FRAME_PAYLOAD", 65535), "Maximum frame payload")
	if err := fs.Parse(args); err != nil {
		return nil, err
	}

	config := &RelayConfig{
		Bind:               *bind,
		SendQueueCapacity:  *sendQueue,
		RegisterTimeout:    *registerTimeout,
		IdleTimeout:        *idleTimeout,
		MaxConnections:     *maxConnections,
		MaxFramePayload:    *maxFramePayload,
	}

	if config.SendQueueCapacity <= 0 {
		return nil, fmt.Errorf("send-queue capacity must be > 0")
	}
	if config.RegisterTimeout <= 0 {
		return nil, fmt.Errorf("register-timeout must be > 0")
	}
	if config.IdleTimeout <= 0 {
		return nil, fmt.Errorf("idle-timeout must be > 0")
	}
	if config.MaxConnections <= 0 {
		return nil, fmt.Errorf("max-connections must be > 0")
	}
	if config.MaxFramePayload <= 0 || config.MaxFramePayload > 65535 {
		return nil, fmt.Errorf("max-frame-payload must be between 1 and 65535")
	}

	return config, nil
}

func handleConn(h *hub, conn net.Conn, config *RelayConfig) {
	p := &peer{
		conn: conn,
		send: make(chan []byte, config.SendQueueCapacity),
		done: make(chan struct{}),
	}
	defer func() {
		h.unregister(p)
		close(p.done)
		_ = conn.Close()
		atomic.AddInt64(&activeConnections, -1)
	}()

	go func() {
		for {
			select {
			case frame, ok := <-p.send:
				if !ok {
					return
				}
				if _, err := conn.Write(frame); err != nil {
					_ = conn.Close()
					return
				}
			case <-p.done:
				return
			}
		}
	}()

	// Registration timeout
	_ = conn.SetReadDeadline(time.Now().Add(config.RegisterTimeout))
	typ, payload, err := readFrame(conn, config.MaxFramePayload)
	if err != nil {
		_ = conn.SetWriteDeadline(time.Now().Add(1 * time.Second))
		if ne, ok := err.(net.Error); ok && ne.Timeout() {
			_, _ = conn.Write(errorFrame(4003, "registration timed out"))
		} else if err == ErrInvalidMagic {
			_, _ = conn.Write(errorFrame(4000, "invalid magic"))
		} else if err == ErrUnsupportedVers {
			_, _ = conn.Write(errorFrame(4001, "unsupported version"))
		} else if err == ErrFrameTooLarge {
			_, _ = conn.Write(errorFrame(4006, "frame too large"))
		}
		return
	}

	if typ != msgRegister {
		_ = conn.SetWriteDeadline(time.Now().Add(1 * time.Second))
		_, _ = conn.Write(errorFrame(4002, "registration required"))
		return
	}

	nodeID := string(payload)
	if nodeID == "" || len(nodeID) > 255 {
		_ = conn.SetWriteDeadline(time.Now().Add(1 * time.Second))
		_, _ = conn.Write(errorFrame(4000, "invalid node ID"))
		return
	}

	h.register(p, nodeID)
	queue(p, makeFrame(msgRegistered, []byte(nodeID)))

	for {
		_ = conn.SetReadDeadline(time.Now().Add(config.IdleTimeout))
		typ, payload, err := readFrame(conn, config.MaxFramePayload)
		if err != nil {
			_ = conn.SetWriteDeadline(time.Now().Add(1 * time.Second))
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				_, _ = conn.Write(errorFrame(4009, "idle timeout"))
			} else if err == ErrInvalidMagic {
				_, _ = conn.Write(errorFrame(4000, "invalid magic"))
			} else if err == ErrUnsupportedVers {
				_, _ = conn.Write(errorFrame(4001, "unsupported version"))
			} else if err == ErrFrameTooLarge {
				_, _ = conn.Write(errorFrame(4006, "frame too large"))
			}
			return
		}

		switch typ {
		case msgRegister:
			newID := string(payload)
			if newID != p.id {
				queue(p, errorFrame(4004, "already registered with a different node ID"))
				time.Sleep(50 * time.Millisecond)
				return
			}
			queue(p, makeFrame(msgRegistered, []byte(newID)))

		case msgForward:
			dstID, data, ok := parsePeerPayload(payload)
			if !ok {
				queue(p, errorFrame(4000, "malformed forward payload"))
				continue
			}
			status := h.forward(p.id, dstID, data, config.MaxFramePayload)
			if status != 0 {
				queue(p, errorFrame(status, "forward failed"))
			}

		case msgPing:
			queue(p, makeFrame(msgPong, payload))

		case msgClose:
			return

		default:
			queue(p, errorFrame(4000, "unsupported frame type"))
		}
	}
}

func queue(p *peer, frame []byte) {
	select {
	case p.send <- frame:
	case <-p.done:
	default:
		_ = p.conn.Close()
	}
}

func readFrame(conn net.Conn, maxPayload int) (byte, []byte, error) {
	header := make([]byte, frameHeader)
	if _, err := io.ReadFull(conn, header); err != nil {
		return 0, nil, err
	}
	if string(header[:4]) != string(magic) {
		return 0, nil, ErrInvalidMagic
	}
	if header[4] != version {
		return 0, nil, ErrUnsupportedVers
	}
	length := int(binary.BigEndian.Uint16(header[6:8]))
	if length > maxPayload {
		return 0, nil, ErrFrameTooLarge
	}
	payload := make([]byte, length)
	if length > 0 {
		if _, err := io.ReadFull(conn, payload); err != nil {
			return 0, nil, err
		}
	}
	return header[5], payload, nil
}

func makeFrame(typ byte, payload []byte) []byte {
	frame := make([]byte, frameHeader+len(payload))
	copy(frame[:4], magic)
	frame[4] = version
	frame[5] = typ
	binary.BigEndian.PutUint16(frame[6:8], uint16(len(payload)))
	copy(frame[8:], payload)
	return frame
}

func receivedFrame(srcID string, data []byte) ([]byte, error) {
	if len(srcID) > 255 || len(data)+1+len(srcID) > 65535 {
		return nil, io.ErrShortBuffer
	}
	payload := make([]byte, 1+len(srcID)+len(data))
	payload[0] = byte(len(srcID))
	copy(payload[1:], srcID)
	copy(payload[1+len(srcID):], data)
	return makeFrame(msgReceived, payload), nil
}

func parsePeerPayload(payload []byte) (string, []byte, bool) {
	if len(payload) < 1 {
		return "", nil, false
	}
	idLen := int(payload[0])
	if len(payload) < 1+idLen {
		return "", nil, false
	}
	return string(payload[1 : 1+idLen]), payload[1+idLen:], true
}

func errorFrame(code uint16, message string) []byte {
	payload := make([]byte, 2+len(message))
	binary.BigEndian.PutUint16(payload[:2], code)
	copy(payload[2:], message)
	return makeFrame(msgError, payload)
}
