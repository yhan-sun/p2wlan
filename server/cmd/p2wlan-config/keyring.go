package main

import (
	"encoding/json"
	"errors"
	"io"

	"github.com/yhan-sun/p2wlan/server/auth"
)

// Use the same loader and precedence as Control, including its previous key
// during rotation. Only verification keys leave this command; it never creates
// credentials or writes deployment files.
func printRelayKeyring(output io.Writer) error {
	signer, err := auth.LoadSignerFromEnv()
	if err != nil {
		return err
	}
	if signer == nil {
		return errors.New("no existing relay signer configured; set RELAY_TICKET_SIGNER_KEY_FILE with RELAY_TICKET_SIGNER_KID, or RELAY_TICKET_SIGNER_JSON")
	}
	return json.NewEncoder(output).Encode(signer.PublicKeyring())
}
