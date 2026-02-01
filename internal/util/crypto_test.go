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
