package database

import (
	"fmt"
	"time"
)

// ---- User operations ----

// User represents a registered user.
type User struct {
	ID           string `json:"id"`
	Email        string `json:"email"`
	PasswordHash string `json:"-"`
	CreatedAt    int64  `json:"created_at"`
}

// Network represents a virtual network.
type Network struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	CIDR      string `json:"cidr"`
	OwnerID   string `json:"owner_id"`
	CreatedAt int64  `json:"created_at"`
}

// CreateUser inserts a new user.
func (db *DB) CreateUser(email, passwordHash string) (*User, error) {
	id := fmt.Sprintf("user-%d", time.Now().UnixNano())
	now := time.Now().Unix()

	_, err := db.Exec(`INSERT INTO users (id, email, password_hash, created_at) VALUES (?, ?, ?, ?)`,
		id, email, passwordHash, now)
	if err != nil {
		return nil, err
	}

	// Auto-join the user to the default network (for backward compatibility)
	db.CreateNetworkMembership(id, "default", "member")
	return &User{ID: id, Email: email, PasswordHash: passwordHash, CreatedAt: now}, nil
}

// GetUserByEmail looks up a user by email.
func (db *DB) GetUserByEmail(email string) (*User, error) {
	var u User
	err := db.QueryRow(`SELECT id, email, password_hash, created_at FROM users WHERE email = ?`, email).
		Scan(&u.ID, &u.Email, &u.PasswordHash, &u.CreatedAt)
	if err != nil {
		return nil, err
	}
	return &u, nil
}
