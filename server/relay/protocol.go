package main

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"unicode/utf8"
)

var magic = []byte{'D', 'E', 'R', 'P'}

const (
	version         = byte(1)
	frameHeader     = 8
	msgRegister     = byte(0x01)
	msgRegistered   = byte(0x02)
	msgForward      = byte(0x03)
	msgReceived     = byte(0x04)
	msgPing         = byte(0x05)
	msgPong         = byte(0x06)
	msgError        = byte(0x07)
	msgClose        = byte(0x08)
	msgAuthRegister = byte(0x09)
)

// A2 error codes (extending A1 codes)
const (
	errAuthRequired     = uint16(4011)
	errInvalidTicket    = uint16(4012)
	errTicketExpired    = uint16(4013)
	errAudienceMismatch = uint16(4014)
	errIdentityMismatch = uint16(4015)
	errNetworkMismatch  = uint16(4016)
	errTicketNotYetVal  = uint16(4017)
	errUnknownTicketKey = uint16(4018)
	errAuthRateLimited  = uint16(4019)
)

var (
	ErrInvalidMagic    = fmt.Errorf("invalid magic")
	ErrUnsupportedVers = fmt.Errorf("unsupported version")
	ErrFrameTooLarge   = fmt.Errorf("frame too large")
)

// parseAuthRegister parses the MSG_AUTH_REGISTER binary payload.
// Format: u8 node_id_len | node_id | u16 ticket_len (BE) | ticket
func parseAuthRegister(payload []byte) (nodeID, ticket string, err error) {
	if len(payload) < 1 {
		return "", "", fmt.Errorf("auth register payload empty")
	}
	nodeIDLen := int(payload[0])
	if nodeIDLen == 0 || nodeIDLen > 255 {
		return "", "", fmt.Errorf("invalid node_id_len: %d", nodeIDLen)
	}
	if len(payload) < 1+nodeIDLen+2 {
		return "", "", fmt.Errorf("auth register payload truncated")
	}
	nodeIDBytes := payload[1 : 1+nodeIDLen]
	if !utf8.Valid(nodeIDBytes) {
		return "", "", fmt.Errorf("node_id is not valid UTF-8")
	}
	nodeID = string(nodeIDBytes)

	ticketStart := 1 + nodeIDLen
	ticketLen := int(binary.BigEndian.Uint16(payload[ticketStart : ticketStart+2]))
	if ticketLen == 0 || ticketLen > 8192 {
		return "", "", fmt.Errorf("invalid ticket_len: %d", ticketLen)
	}
	ticketDataStart := ticketStart + 2
	if len(payload) != ticketDataStart+ticketLen {
		return "", "", fmt.Errorf("auth register payload has trailing bytes or is truncated")
	}
	ticket = string(payload[ticketDataStart : ticketDataStart+ticketLen])
	return nodeID, ticket, nil
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
