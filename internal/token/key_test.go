package token

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// writeTestPEM creates a temporary PEM file and returns its path.
func writeTestPEM(t *testing.T, blockType string, data []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "key.pem")
	buf := pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: data})
	require.NoError(t, os.WriteFile(path, buf, 0o600))
	return path
}

func TestLoadSigningKey_RSA(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	der := x509.MarshalPKCS1PrivateKey(rsaKey)
	path := writeTestPEM(t, "RSA PRIVATE KEY", der)

	key, err := LoadSigningKey(path)
	require.NoError(t, err)
	_, ok := key.(*rsa.PrivateKey)
	assert.True(t, ok, "expected *rsa.PrivateKey, got %T", key)
}

func TestLoadSigningKey_RSA_PKCS8(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	der, err := x509.MarshalPKCS8PrivateKey(rsaKey)
	require.NoError(t, err)
	path := writeTestPEM(t, "PRIVATE KEY", der)

	key, err := LoadSigningKey(path)
	require.NoError(t, err)
	_, ok := key.(*rsa.PrivateKey)
	assert.True(t, ok, "expected *rsa.PrivateKey, got %T", key)
}

func TestLoadSigningKey_ECDSA(t *testing.T) {
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	der, err := x509.MarshalECPrivateKey(ecKey)
	require.NoError(t, err)
	path := writeTestPEM(t, "EC PRIVATE KEY", der)

	key, err := LoadSigningKey(path)
	require.NoError(t, err)
	loaded, ok := key.(*ecdsa.PrivateKey)
	assert.True(t, ok, "expected *ecdsa.PrivateKey, got %T", key)
	assert.Equal(t, elliptic.P256(), loaded.Curve)
}

func TestLoadSigningKey_ECDSA_PKCS8(t *testing.T) {
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	der, err := x509.MarshalPKCS8PrivateKey(ecKey)
	require.NoError(t, err)
	path := writeTestPEM(t, "PRIVATE KEY", der)

	key, err := LoadSigningKey(path)
	require.NoError(t, err)
	_, ok := key.(*ecdsa.PrivateKey)
	assert.True(t, ok, "expected *ecdsa.PrivateKey, got %T", key)
}

func TestLoadSigningKey_FileNotFound(t *testing.T) {
	_, err := LoadSigningKey("/nonexistent/path/to/key.pem")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "read key file")
}

func TestLoadSigningKey_InvalidPEM(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bad.pem")
	require.NoError(t, os.WriteFile(path, []byte("not a pem file"), 0o600))

	_, err := LoadSigningKey(path)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no PEM block found")
}

func TestLoadSigningKey_UnsupportedFormat(t *testing.T) {
	// Write a PEM with garbage bytes that won't parse as any key format
	path := writeTestPEM(t, "UNKNOWN KEY", []byte("garbage-key-data"))

	_, err := LoadSigningKey(path)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no supported private key found")
}

func TestLoadSigningKey_MultiBlock_ECAfterUnknown(t *testing.T) {
	// PEM with a non-key block first (e.g. EC PARAMETERS), followed by the real EC key.
	// This mirrors OpenSSL's "traditional" EC format which emits two blocks.
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	ecDER, err := x509.MarshalECPrivateKey(ecKey)
	require.NoError(t, err)

	// Build two-block PEM: first an unknown block, then the real key.
	buf := pem.EncodeToMemory(&pem.Block{Type: "EC PARAMETERS", Bytes: []byte("params")})
	buf = append(buf, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: ecDER})...)

	path := filepath.Join(t.TempDir(), "key.pem")
	require.NoError(t, os.WriteFile(path, buf, 0o600))

	key, err := LoadSigningKey(path)
	require.NoError(t, err)
	_, ok := key.(*ecdsa.PrivateKey)
	assert.True(t, ok, "expected *ecdsa.PrivateKey from multi-block PEM")
}

func TestDeriveKeyID_RSA(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	kid, err := DeriveKeyID(rsaKey.Public())
	require.NoError(t, err)
	assert.NotEmpty(t, kid)
	// Must be deterministic
	kid2, err := DeriveKeyID(rsaKey.Public())
	require.NoError(t, err)
	assert.Equal(t, kid, kid2)
}

func TestDeriveKeyID_ECDSA(t *testing.T) {
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	kid, err := DeriveKeyID(ecKey.Public())
	require.NoError(t, err)
	assert.NotEmpty(t, kid)
	// Must be deterministic
	kid2, err := DeriveKeyID(ecKey.Public())
	require.NoError(t, err)
	assert.Equal(t, kid, kid2)
}

func TestDeriveKeyID_DifferentKeys(t *testing.T) {
	key1, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	key2, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	kid1, err := DeriveKeyID(key1.Public())
	require.NoError(t, err)
	kid2, err := DeriveKeyID(key2.Public())
	require.NoError(t, err)
	assert.NotEqual(t, kid1, kid2)
}

func TestDeriveKeyID_FullHashLength(t *testing.T) {
	// base64url of 32 bytes (full SHA-256) = 43 chars (no padding)
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	kid, err := DeriveKeyID(key.Public())
	require.NoError(t, err)
	assert.Len(t, kid, 43, "kid must be base64url-encoded full SHA-256 (43 chars)")
}
