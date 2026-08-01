package main

import (
	"bytes"
	"testing"
)

func TestRustGoErrorCodesCompatibility(t *testing.T) {
	// 1. peer-backpressure (4008)
	err4008 := errorFrame(4008, "backpressure")
	expected4008 := []byte{
		'D', 'E', 'R', 'P',
		1,
		msgError,
		0, 14,
		15, 168,
		'b', 'a', 'c', 'k', 'p', 'r', 'e', 's', 's', 'u', 'r', 'e',
	}
	if !bytes.Equal(err4008, expected4008) {
		t.Errorf("errorFrame 4008 mismatch\ngot:  %v\nwant: %v", err4008, expected4008)
	}

	// 2. peer-not-found (404)
	err404 := errorFrame(404, "peer not found")
	expected404 := []byte{
		'D', 'E', 'R', 'P',
		1,
		msgError,
		0, 16,
		1, 148,
		'p', 'e', 'e', 'r', ' ', 'n', 'o', 't', ' ', 'f', 'o', 'u', 'n', 'd',
	}
	if !bytes.Equal(err404, expected404) {
		t.Errorf("errorFrame 404 mismatch\ngot:  %v\nwant: %v", err404, expected404)
	}

	// 3. registered (msgRegistered 0x02)
	registered := makeFrame(msgRegistered, []byte("nodeA"))
	expectedRegistered := []byte{
		'D', 'E', 'R', 'P',
		1,
		msgRegistered,
		0, 5,
		'n', 'o', 'd', 'e', 'A',
	}
	if !bytes.Equal(registered, expectedRegistered) {
		t.Errorf("registered frame mismatch\ngot:  %v\nwant: %v", registered, expectedRegistered)
	}

	// 4. frame-too-large (4006)
	err4006 := errorFrame(4006, "frame too large")
	expected4006 := []byte{
		'D', 'E', 'R', 'P',
		1,
		msgError,
		0, 17,
		15, 166,
		'f', 'r', 'a', 'm', 'e', ' ', 't', 'o', 'o', ' ', 'l', 'a', 'r', 'g', 'e',
	}
	if !bytes.Equal(err4006, expected4006) {
		t.Errorf("errorFrame 4006 mismatch\ngot:  %v\nwant: %v", err4006, expected4006)
	}

	// 5. unknown error code (9999)
	err9999 := errorFrame(9999, "unknown")
	expected9999 := []byte{
		'D', 'E', 'R', 'P',
		1,
		msgError,
		0, 9,
		39, 15,
		'u', 'n', 'k', 'n', 'o', 'w', 'n',
	}
	if !bytes.Equal(err9999, expected9999) {
		t.Errorf("errorFrame 9999 mismatch\ngot:  %v\nwant: %v", err9999, expected9999)
	}
}
