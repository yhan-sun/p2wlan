package main

import (
	"encoding/binary"
	"flag"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"
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

type peer struct {
	id   string
	conn net.Conn
	send chan []byte
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

func (h *hub) forward(srcID, dstID string, data []byte) bool {
	h.mu.RLock()
	dst := h.peers[dstID]
	h.mu.RUnlock()
	if dst == nil {
		return false
	}
	frame, err := receivedFrame(srcID, data)
	if err != nil {
		return false
	}
	select {
	case dst.send <- frame:
		return true
	default:
		return false
	}
}

func main() {
	bind := flag.String("bind", getenv("RELAY_BIND", ":18081"), "TCP listen address")
	flag.Parse()

	listener, err := net.Listen("tcp", *bind)
	if err != nil {
		log.Fatalf("listen %s: %v", *bind, err)
	}
	defer listener.Close()

	h := newHub()
	log.Printf("p2wlan relay listening on %s", listener.Addr())

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
		go handleConn(h, conn)
	}
}

func getenv(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}

func handleConn(h *hub, conn net.Conn) {
	p := &peer{conn: conn, send: make(chan []byte, 128)}
	defer func() {
		h.unregister(p)
		close(p.send)
		_ = conn.Close()
	}()

	go func() {
		for frame := range p.send {
			if _, err := conn.Write(frame); err != nil {
				_ = conn.Close()
				return
			}
		}
	}()

	for {
		typ, payload, err := readFrame(conn)
		if err != nil {
			if err != io.EOF {
				log.Printf("relay read error from %s: %v", conn.RemoteAddr(), err)
			}
			return
		}

		switch typ {
		case msgRegister:
			nodeID := string(payload)
			if nodeID == "" || len(nodeID) > 255 {
				queue(p, errorFrame(400, "invalid node id"))
				continue
			}
			h.register(p, nodeID)
			queue(p, makeFrame(msgRegistered, []byte(nodeID)))

		case msgForward:
			if p.id == "" {
				queue(p, errorFrame(401, "not registered"))
				continue
			}
			dstID, data, ok := parsePeerPayload(payload)
			if !ok {
				queue(p, errorFrame(400, "malformed forward payload"))
				continue
			}
			if !h.forward(p.id, dstID, data) {
				queue(p, errorFrame(404, "target peer not connected"))
			}

		case msgPing:
			queue(p, makeFrame(msgPong, payload))

		case msgClose:
			return

		default:
			queue(p, errorFrame(400, "unsupported frame type"))
		}
	}
}

func queue(p *peer, frame []byte) {
	select {
	case p.send <- frame:
	default:
		_ = p.conn.Close()
	}
}

func readFrame(conn net.Conn) (byte, []byte, error) {
	header := make([]byte, frameHeader)
	if _, err := io.ReadFull(conn, header); err != nil {
		return 0, nil, err
	}
	if string(header[:4]) != string(magic) || header[4] != version {
		return 0, nil, io.ErrUnexpectedEOF
	}
	length := int(binary.BigEndian.Uint16(header[6:8]))
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
