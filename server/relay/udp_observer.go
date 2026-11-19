package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sync/atomic"
)

const (
	stunBindingRequest  uint16 = 0x0001
	stunBindingResponse uint16 = 0x0101
	stunXorMappedAddr   uint16 = 0x0020
	stunMagicCookie     uint32 = 0x2112A442
	stunHeaderLen              = 20
)

func openAlternateObserver(primary *net.UDPConn, bind string) (*net.UDPConn, error) {
	if bind == "" {
		return nil, nil
	}
	if primary == nil {
		return nil, errors.New("alternate UDP observer requires a primary observer")
	}
	address, err := net.ResolveUDPAddr("udp", bind)
	if err != nil {
		return nil, err
	}
	source := primary.LocalAddr().(*net.UDPAddr)
	if len(source.IP) == 0 || len(address.IP) == 0 || source.IP.IsUnspecified() || address.IP.IsUnspecified() || source.IP.Equal(address.IP) ||
		(source.IP.To4() == nil) != (address.IP.To4() == nil) {
		return nil, errors.New("alternate observer requires distinct explicit IPs of the same family")
	}
	alternate, err := net.ListenUDP("udp", address)
	if err != nil {
		return nil, fmt.Errorf("alternate UDP observer: %w", err)
	}
	if alternate.LocalAddr().(*net.UDPAddr).Port == source.Port {
		_ = alternate.Close()
		return nil, errors.New("alternate observer requires a different source port")
	}
	return alternate, nil
}

// A full CHANGE-REQUEST can only be answered from a registered second IP and port.
func observerChange(request []byte) (uint32, bool) {
	if len(request) < stunHeaderLen || int(binary.BigEndian.Uint16(request[2:4])) != len(request)-stunHeaderLen {
		return 0, false
	}
	var flags uint32
	found := false
	for attrs := request[stunHeaderLen:]; len(attrs) > 0; {
		if len(attrs) < 4 {
			return 0, false
		}
		length := int(binary.BigEndian.Uint16(attrs[2:4]))
		padded := (length + 3) &^ 3
		if padded > len(attrs)-4 {
			return 0, false
		}
		if binary.BigEndian.Uint16(attrs[:2]) == 3 {
			if length != 4 || found {
				return 0, false
			}
			found = true
			flags = binary.BigEndian.Uint32(attrs[4:8])
		}
		attrs = attrs[4+padded:]
	}
	return flags, flags == 0 || flags == 6
}

func (s *RelayServer) serveUDPObserver() {
	defer s.wg.Done()

	buf := make([]byte, 1500)
	for {
		n, addr, err := s.udpObserverConn.ReadFromUDP(buf)
		if err != nil {
			select {
			case <-s.shutdownChan:
				return
			default:
				if errors.Is(err, net.ErrClosed) {
					return
				}
				atomic.AddUint64(&s.stats.udpObserverErrorsTotal, 1)
				continue
			}
		}

		flags, valid := observerChange(buf[:n])
		writer := s.udpObserverConn
		if flags == 6 {
			writer = s.udpObserverAlternate
		}
		if !valid || writer == nil {
			continue
		}
		response, ok := buildUDPObserverSTUNResponse(buf[:n], addr)
		if !ok {
			atomic.AddUint64(&s.stats.udpObserverErrorsTotal, 1)
			continue
		}
		// Count a validated request before making the response observable to
		// the caller. Otherwise a client can receive the response and read the
		// metric before this goroutine is scheduled again.
		atomic.AddUint64(&s.stats.udpObserverRequestsTotal, 1)
		if _, err := writer.WriteToUDP(response, addr); err != nil {
			atomic.AddUint64(&s.stats.udpObserverErrorsTotal, 1)
			continue
		}
	}
}

func buildUDPObserverSTUNResponse(request []byte, clientAddr *net.UDPAddr) ([]byte, bool) {
	if len(request) < stunHeaderLen || clientAddr == nil || clientAddr.IP == nil {
		return nil, false
	}
	if binary.BigEndian.Uint16(request[0:2]) != stunBindingRequest {
		return nil, false
	}
	if binary.BigEndian.Uint32(request[4:8]) != stunMagicCookie {
		return nil, false
	}

	transactionID := request[8:20]
	value, ok := xorMappedAddressValue(clientAddr, transactionID)
	if !ok {
		return nil, false
	}

	attrs := make([]byte, 4+len(value))
	binary.BigEndian.PutUint16(attrs[0:2], stunXorMappedAddr)
	binary.BigEndian.PutUint16(attrs[2:4], uint16(len(value)))
	copy(attrs[4:], value)

	response := make([]byte, stunHeaderLen+len(attrs))
	binary.BigEndian.PutUint16(response[0:2], stunBindingResponse)
	binary.BigEndian.PutUint16(response[2:4], uint16(len(attrs)))
	binary.BigEndian.PutUint32(response[4:8], stunMagicCookie)
	copy(response[8:20], transactionID)
	copy(response[20:], attrs)
	return response, true
}

func xorMappedAddressValue(clientAddr *net.UDPAddr, transactionID []byte) ([]byte, bool) {
	xorPort := uint16(clientAddr.Port) ^ uint16(stunMagicCookie>>16)
	if ip4 := clientAddr.IP.To4(); ip4 != nil {
		value := make([]byte, 8)
		value[1] = 0x01
		binary.BigEndian.PutUint16(value[2:4], xorPort)
		cookie := make([]byte, 4)
		binary.BigEndian.PutUint32(cookie, stunMagicCookie)
		for i := 0; i < 4; i++ {
			value[4+i] = ip4[i] ^ cookie[i]
		}
		return value, true
	}

	ip16 := clientAddr.IP.To16()
	if ip16 == nil || len(transactionID) != 12 {
		return nil, false
	}
	value := make([]byte, 20)
	value[1] = 0x02
	binary.BigEndian.PutUint16(value[2:4], xorPort)
	cookieAndTransaction := make([]byte, 16)
	binary.BigEndian.PutUint32(cookieAndTransaction[0:4], stunMagicCookie)
	copy(cookieAndTransaction[4:], transactionID)
	for i := 0; i < 16; i++ {
		value[4+i] = ip16[i] ^ cookieAndTransaction[i]
	}
	return value, true
}
