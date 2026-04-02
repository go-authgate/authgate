package util

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/crypto/pbkdf2"
)

// CryptoRandomBytes generates cryptographically secure random bytes
func CryptoRandomBytes(length int) ([]byte, error) {
	buf := make([]byte, length)
	_, err := rand.Read(buf)
	return buf, err
}

// CryptoRandomString generates a random hex string for salts
func CryptoRandomString(length int) (string, error) {
	randomBytes, err := CryptoRandomBytes((length + 1) / 2)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(randomBytes)[:length], nil
}

// HashToken returns PBKDF2 hash of token with salt
// Parameters match Gitea's implementation for security consistency
func HashToken(token, salt string) string {
	hash := pbkdf2.Key([]byte(token), []byte(salt), 10000, 50, sha256.New)
	return hex.EncodeToString(hash)
}

// WriteCredentialsFile writes initial credentials to a new file with 0600 permissions.
// Uses O_CREATE|O_EXCL to fail if the file already exists (prevents overwriting
// existing credentials and symlink attacks). Returns the file path on success.
func WriteCredentialsFile(dir, content string) (string, error) {
	filePath := filepath.Join(dir, "authgate-credentials.txt")

	// O_EXCL ensures we never overwrite an existing file or follow a symlink
	f, err := os.OpenFile(filePath, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0o600)
	if err != nil {
		return "", fmt.Errorf("failed to create credentials file: %w", err)
	}

	_, writeErr := f.WriteString(content)
	closeErr := f.Close()

	if writeErr != nil {
		return "", fmt.Errorf("failed to write credentials file: %w", writeErr)
	}
	if closeErr != nil {
		return "", fmt.Errorf("failed to close credentials file: %w", closeErr)
	}

	// Explicitly enforce 0600 even if umask was permissive
	if err := os.Chmod(filePath, 0o600); err != nil {
		return "", fmt.Errorf("failed to set credentials file permissions: %w", err)
	}

	return filePath, nil
}

// GenerateRandomPassword generates a random password of specified length.
// Uses base64url encoding and truncates to length printable characters.
func GenerateRandomPassword(length int) (string, error) {
	if length <= 0 {
		return "", fmt.Errorf("password length must be positive, got %d", length)
	}
	b, err := CryptoRandomBytes(length)
	if err != nil {
		return "", err
	}
	return base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(b)[:length], nil
}

// SHA256Hex returns the SHA-256 hash of s as a lowercase hex string.
// Intended for use with high-entropy, unguessable values (e.g., randomly
// generated tokens); for such inputs, a salt is not required for security.
func SHA256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}
