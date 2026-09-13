// Package privatefile creates secret-bearing files without a permissive write window.
package privatefile

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
)

func WriteNew(path string, data []byte) error {
	file, err := OpenNew(path)
	if err != nil {
		return err
	}
	complete := false
	defer func() {
		file.Close()
		if !complete {
			os.Remove(path)
		}
	}()
	if _, err = file.Write(data); err != nil {
		return err
	}
	if err = file.Sync(); err != nil {
		return err
	}
	if err = file.Close(); err != nil {
		return err
	}
	complete = true
	return nil
}

func CreateTemp(directory string) (*os.File, error) {
	for attempt := 0; attempt < 10; attempt++ {
		var entropy [16]byte
		if _, err := rand.Read(entropy[:]); err != nil {
			return nil, err
		}
		name := filepath.Join(directory, ".p2wlan-private-"+hex.EncodeToString(entropy[:])+".tmp")
		file, err := OpenNew(name)
		if os.IsExist(err) {
			continue
		}
		return file, err
	}
	return nil, fmt.Errorf("could not allocate a unique private file in %q", directory)
}
