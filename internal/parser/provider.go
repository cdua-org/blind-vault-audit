// Package parser provides interfaces and implementations for parsing vault files.
package parser

import (
	"context"
)

// PasswordEntry represents a single password and its last update timestamp.
type PasswordEntry struct {
	Value     string
	Label     string
	UpdatedAt int64
	Order     int
}

// VaultItem represents an entry in a password manager vault.
type VaultItem struct {
	Title     string
	Domains   []string
	Passwords []PasswordEntry
	HasTOTP   bool
}

// Provider defines the interface for parsing different password manager vaults.
type Provider interface {
	Parse(ctx context.Context, filePath string) ([]VaultItem, error)
}
