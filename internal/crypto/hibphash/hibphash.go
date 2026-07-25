// Package hibphash provides SHA-1 hashing specifically for HIBP k-Anonymity.
package hibphash

import (
	"crypto/sha1"
	"encoding/hex"
	"strings"
)

// HashPassword returns the uppercase SHA-1 hash of the given password.
// This is required by the HIBP k-Anonymity API.
func HashPassword(password string) string {
	hashBytes := sha1.Sum([]byte(password))
	return strings.ToUpper(hex.EncodeToString(hashBytes[:]))
}
