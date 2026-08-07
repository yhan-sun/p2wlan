// relay_keygen prints one ephemeral Ed25519 seed/public-key pair for local
// smoke harnesses. It intentionally depends only on the Go standard library.
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"os"
)

func main() {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		fmt.Fprintf(os.Stderr, "generate relay Ed25519 key: %v\n", err)
		os.Exit(1)
	}

	// The control server accepts a 32-byte Ed25519 seed, while the relay
	// verifier receives the corresponding 32-byte public key.
	fmt.Printf("%x %x\n", privateKey.Seed(), publicKey)
}
