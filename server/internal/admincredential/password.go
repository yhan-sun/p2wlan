package admincredential

import (
	"encoding/base64"
	"errors"
	"regexp"
	"unicode/utf8"

	"golang.org/x/crypto/bcrypt"
)

var usernamePattern = regexp.MustCompile("^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")

func ValidUsername(name string) bool {
	return usernamePattern.MatchString(name)
}

func EncodePassword(password []byte) (string, error) {
	if !utf8.Valid(password) || len(password) < 12 || len(password) > 72 {
		return "", errors.New("administrator password must contain 12 to 72 UTF-8 bytes")
	}
	hash, err := bcrypt.GenerateFromPassword(password, bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	// Compose and systemd can both read this representation literally.
	return base64.RawURLEncoding.EncodeToString(hash), nil
}

func DecodeHash(encoded string) ([]byte, error) {
	hash, err := base64.RawURLEncoding.Strict().DecodeString(encoded)
	if err != nil || len(hash) != 60 {
		return nil, errors.New("invalid CONTROL_ADMIN_PASSWORD_HASH")
	}
	if cost, err := bcrypt.Cost(hash); err != nil || cost != bcrypt.DefaultCost {
		return nil, errors.New("unsupported CONTROL_ADMIN_PASSWORD_HASH")
	}
	return hash, nil
}
