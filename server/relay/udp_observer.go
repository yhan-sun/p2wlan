package main

import (
	"encoding/binary"
	"errors"
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

		response, ok := buildUDPObserverSTUNResponse(buf[:n], addr)
		if !ok {
			atomic.AddUint64(&s.stats.udpObserverErrorsTotal, 1)
			continue
		}
		if _, err := s.udpObserverConn.WriteToUDP(response, addr); err != nil {
			atomic.AddUint64(&s.stats.udpObserverErrorsTotal, 1)
			continue
		}
		atomic.AddUint64(&s.stats.udpObserverRequestsTotal, 1)
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
