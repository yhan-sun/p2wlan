package main

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"io"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go"
)

const relayALPN = "p2wlan-relay-dgram/1"

func listenDatagrams(bind string, config *tls.Config) (*quic.Listener, error) {
	options := config.Clone()
	options.NextProtos = []string{relayALPN}
	return quic.ListenAddr(bind, options, &quic.Config{
		EnableDatagrams:       true,
		HandshakeIdleTimeout:  3 * time.Second,
		MaxIdleTimeout:        7 * time.Second,
		MaxIncomingStreams:    1,
		MaxIncomingUniStreams: -1,
	})
}

type quicInput struct {
	frame []byte
	err   error
}

// The existing relay session owns authorization, registration and the
// destination writer for both transports. QUIC opens one reliable control
// stream and carries only Forward/Received frames as unreliable datagrams.
type datagramConn struct {
	quic          *quic.Conn
	control       *quic.Stream
	streamFrames  chan quicInput
	datagrams     chan quicInput
	readBacklog   []byte
	readDeadline  time.Time    // single application reader
	writeDeadline atomic.Int64 // also set by the error/close path
	sequence      atomic.Uint64
	maxPayload    int
	readers       sync.WaitGroup
	controlWrite  sync.Mutex
	inputDrops    *uint64
}

func newDatagramConn(conn *quic.Conn, maxPayload int, inputDrops *uint64) *datagramConn {
	return &datagramConn{
		quic: conn, maxPayload: maxPayload, inputDrops: inputDrops,
		streamFrames: make(chan quicInput, 1),
		datagrams:    make(chan quicInput, 4),
	}
}

func (c *datagramConn) open(timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(c.quic.Context(), timeout)
	defer cancel()
	control, err := c.quic.AcceptStream(ctx)
	if err != nil {
		return err
	}
	c.control = control
	c.readers.Add(1)
	go c.readControl()
	return nil
}

func (c *datagramConn) readControl() {
	defer c.readers.Done()
	var header [frameHeader]byte
	for {
		_, err := io.ReadFull(c.control, header[:])
		if err != nil {
			c.deliver(c.streamFrames, quicInput{err: err})
			return
		}
		length := int(binary.BigEndian.Uint16(header[6:8]))
		if length > c.maxPayload {
			c.deliver(c.streamFrames, quicInput{err: ErrFrameTooLarge})
			return
		}
		if header[5] == msgForward {
			// Business traffic on this ALPN must use DATAGRAM.
			c.deliver(c.streamFrames, quicInput{err: ErrInvalidMagic})
			return
		}
		frame := make([]byte, frameHeader+length)
		copy(frame, header[:])
		_, err = io.ReadFull(c.control, frame[frameHeader:])
		if !c.deliver(c.streamFrames, quicInput{frame: frame, err: err}) || err != nil {
			return
		}
	}
}

func (c *datagramConn) enableBusiness() {
	c.readers.Add(1)
	go func() {
		defer c.readers.Done()
		reader := datagramReader{maxLength: frameHeader + c.maxPayload}
		for {
			chunk, err := c.quic.ReceiveDatagram(c.quic.Context())
			if err != nil {
				return
			}
			if frame := reader.push(chunk, time.Now()); frame != nil &&
				frame[5] == msgForward && int(binary.BigEndian.Uint16(frame[6:8])) == len(frame)-frameHeader {
				select {
				case c.datagrams <- quicInput{frame: frame}:
				case <-c.quic.Context().Done():
					return
				default:
					// Keep a congested app reader independent of QUIC control.
					atomic.AddUint64(c.inputDrops, 1)
				}
			}
		}
	}()
}

func (c *datagramConn) deliver(sink chan<- quicInput, input quicInput) bool {
	select {
	case sink <- input:
		return true
	case <-c.quic.Context().Done():
		return false
	}
}

func (c *datagramConn) nextInput() (quicInput, error) {
	select {
	case input := <-c.streamFrames:
		return input, input.err
	default:
	}
	ctx, cancel := context.WithDeadline(c.quic.Context(), c.readDeadline)
	defer cancel()
	select {
	case input := <-c.streamFrames:
		return input, input.err
	case input := <-c.datagrams:
		return input, input.err
	case <-ctx.Done():
		if c.quic.Context().Err() != nil {
			return quicInput{}, net.ErrClosed
		}
		return quicInput{}, os.ErrDeadlineExceeded
	}
}

func (c *datagramConn) Read(output []byte) (int, error) {
	if len(c.readBacklog) == 0 {
		input, err := c.nextInput()
		if err != nil {
			return 0, err
		}
		c.readBacklog = input.frame
	}
	copied := copy(output, c.readBacklog)
	c.readBacklog = c.readBacklog[copied:]
	return copied, nil
}

func (c *datagramConn) Write(input []byte) (int, error) {
	if len(input) < frameHeader || input[5] != msgReceived {
		c.controlWrite.Lock()
		defer c.controlWrite.Unlock()
		return c.control.Write(input)
	}
	// quic-go's send queue blocks when full. Closing the connection bounds
	// that wait and unblocks both readers and the one owner of these frames.
	wait := min(time.Until(time.Unix(0, c.writeDeadline.Load())), 500*time.Millisecond)
	if wait <= 0 {
		return 0, os.ErrDeadlineExceeded
	}
	timer := time.AfterFunc(wait, func() { _ = c.Close() })
	defer timer.Stop()
	id := c.sequence.Add(1)
	var wire [datagramHeader + datagramChunk]byte
	binary.BigEndian.PutUint64(wire[:8], id)
	binary.BigEndian.PutUint32(wire[8:12], uint32(len(input)))
	for start := 0; start < len(input); start += datagramChunk {
		wire[12] = byte(start / datagramChunk)
		copied := copy(wire[datagramHeader:], input[start:])
		if err := c.quic.SendDatagram(wire[:datagramHeader+copied]); err != nil {
			return 0, err
		}
	}
	return len(input), nil
}

func (c *datagramConn) LocalAddr() net.Addr  { return c.quic.LocalAddr() }
func (c *datagramConn) RemoteAddr() net.Addr { return c.quic.RemoteAddr() }
func (c *datagramConn) Close() error         { return c.quic.CloseWithError(0, "") }

func (c *datagramConn) SetReadDeadline(deadline time.Time) error {
	c.readDeadline = deadline
	return nil
}

func (c *datagramConn) SetWriteDeadline(deadline time.Time) error {
	c.writeDeadline.Store(deadline.UnixNano())
	return c.control.SetWriteDeadline(deadline)
}

func (c *datagramConn) SetDeadline(deadline time.Time) error {
	_ = c.SetReadDeadline(deadline)
	return c.SetWriteDeadline(deadline)
}
