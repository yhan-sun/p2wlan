//go:build !windows

package privatefile

import (
	"fmt"
	"os"
)

func OpenNew(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0600)
}

func Verify(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
		return fmt.Errorf("private file %q has mode %v; expected regular 0600", path, info.Mode())
	}
	return nil
}
