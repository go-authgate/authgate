package util

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"

	"golang.org/x/crypto/pbkdf2"
)

// CryptoRandomBytes generates cryptographically secure random bytes
func CryptoRandomBytes(length int64) ([]byte, error) {
	buf := make([]byte, length)
	_, err := rand.Read(buf)
	return buf, err
}

// CryptoRandomString generates a random hex string for salts
func CryptoRandomString(length int) (string, error) {
	bytes, err := CryptoRandomBytes(int64((length + 1) / 2))
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes)[:length], nil
}

// HashToken returns PBKDF2 hash of token with salt
// Parameters match Gitea's implementation for security consistency
func HashToken(token, salt string) string {
	hash := pbkdf2.Key([]byte(token), []byte(salt), 10000, 50, sha256.New)
	return hex.EncodeToString(hash)
}

// SHA256Hex returns the SHA-256 hash of s as a lowercase hex string.
// Intended for use with high-entropy, unguessable values (e.g., randomly
// generated tokens); for such inputs, a salt is not required for security.
func SHA256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}
