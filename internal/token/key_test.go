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
	assert.Contains(t, err.Error(), "unsupported key format")
}

func TestDeriveKeyID_RSA(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	kid := DeriveKeyID(rsaKey.Public())
	assert.NotEmpty(t, kid)
	// Must be deterministic
	assert.Equal(t, kid, DeriveKeyID(rsaKey.Public()))
}

func TestDeriveKeyID_ECDSA(t *testing.T) {
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	kid := DeriveKeyID(ecKey.Public())
	assert.NotEmpty(t, kid)
	// Must be deterministic
	assert.Equal(t, kid, DeriveKeyID(ecKey.Public()))
}

func TestDeriveKeyID_DifferentKeys(t *testing.T) {
	key1, _ := rsa.GenerateKey(rand.Reader, 2048)
	key2, _ := rsa.GenerateKey(rand.Reader, 2048)

	kid1 := DeriveKeyID(key1.Public())
	kid2 := DeriveKeyID(key2.Public())
	assert.NotEqual(t, kid1, kid2)
}

func TestValidateKeyAlgorithm_RS256_RSAKey(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	err := ValidateKeyAlgorithm(key, "RS256")
	assert.NoError(t, err)
}

func TestValidateKeyAlgorithm_RS256_ECKey(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	err := ValidateKeyAlgorithm(key, "RS256")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "requires an RSA private key")
}

func TestValidateKeyAlgorithm_ES256_ECKey(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	err := ValidateKeyAlgorithm(key, "ES256")
	assert.NoError(t, err)
}

func TestValidateKeyAlgorithm_ES256_WrongCurve(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	err := ValidateKeyAlgorithm(key, "ES256")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "requires P-256 curve")
}

func TestValidateKeyAlgorithm_ES256_RSAKey(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	err := ValidateKeyAlgorithm(key, "ES256")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "requires an ECDSA private key")
}

func TestValidateKeyAlgorithm_Unsupported(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	err := ValidateKeyAlgorithm(key, "PS256")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported algorithm")
}
