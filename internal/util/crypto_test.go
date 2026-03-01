package util

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCryptoRandomBytes(t *testing.T) {
	t.Run("Generate correct length", func(t *testing.T) {
		bytes, err := CryptoRandomBytes(20)
		require.NoError(t, err)
		assert.Len(t, bytes, 20)
	})

	t.Run("Generate unique values", func(t *testing.T) {
		bytes1, err := CryptoRandomBytes(20)
		require.NoError(t, err)

		bytes2, err := CryptoRandomBytes(20)
		require.NoError(t, err)

		assert.NotEqual(t, bytes1, bytes2, "Random bytes should not be identical")
	})
}

func TestCryptoRandomString(t *testing.T) {
	t.Run("Generate correct length", func(t *testing.T) {
		str, err := CryptoRandomString(20)
		require.NoError(t, err)
		assert.Len(t, str, 20)
	})

	t.Run("Generate hex characters only", func(t *testing.T) {
		str, err := CryptoRandomString(20)
		require.NoError(t, err)

		for _, c := range str {
			assert.True(t, (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'),
				"Character '%c' is not a valid hex digit", c)
		}
	})
}

func TestSHA256Hex(t *testing.T) {
	t.Run("Known vector", func(t *testing.T) {
		// echo -n "hello" | sha256sum → 2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824
		assert.Equal(t, "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824", SHA256Hex("hello"))
	})

	t.Run("Output is 64 lowercase hex characters", func(t *testing.T) {
		result := SHA256Hex("any input")
		assert.Len(t, result, 64)
		for _, c := range result {
			assert.True(t, (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'),
				"Character '%c' is not a lowercase hex digit", c)
		}
	})

	t.Run("Same input produces same hash", func(t *testing.T) {
		assert.Equal(t, SHA256Hex("token"), SHA256Hex("token"))
	})

	t.Run("Different inputs produce different hashes", func(t *testing.T) {
		assert.NotEqual(t, SHA256Hex("token-a"), SHA256Hex("token-b"))
	})

	t.Run("Empty string has known hash", func(t *testing.T) {
		// SHA-256 of empty string is well-defined
		assert.Equal(t, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", SHA256Hex(""))
	})
}

func TestHashToken(t *testing.T) {
	t.Run("Same input produces same hash", func(t *testing.T) {
		token := "test-device-code-12345"
		salt := "random-salt-abc"

		hash1 := HashToken(token, salt)
		hash2 := HashToken(token, salt)

		assert.Equal(t, hash1, hash2)
		assert.Len(t, hash1, 100) // 50 bytes = 100 hex chars
	})

	t.Run("Different salt produces different hash", func(t *testing.T) {
		token := "test-device-code-12345"
		salt1 := "salt1"
		salt2 := "salt2"

		hash1 := HashToken(token, salt1)
		hash2 := HashToken(token, salt2)

		assert.NotEqual(t, hash1, hash2)
	})

	t.Run("Different token produces different hash", func(t *testing.T) {
		token1 := "device-code-1"
		token2 := "device-code-2" //nolint:gosec // test value, not a credential
		salt := "same-salt"

		hash1 := HashToken(token1, salt)
		hash2 := HashToken(token2, salt)

		assert.NotEqual(t, hash1, hash2)
	})
}
