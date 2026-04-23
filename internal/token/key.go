package token

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
)

// ParseSigningKey parses PEM-encoded data into a supported private key.
// Supports RSA (PKCS#1 / PKCS#8) and ECDSA (SEC1 / PKCS#8).
// All PEM blocks are tried in order until a supported key is found.
func ParseSigningKey(data []byte) (crypto.Signer, error) {
	rest := data
	foundBlocks := false
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		foundBlocks = true

		// Try PKCS#8 first (works for both RSA and ECDSA).
		// Only return supported key types; skip unsupported ones (e.g. Ed25519)
		// so that later PEM blocks can still be tried.
		if key, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
			switch k := key.(type) {
			case *rsa.PrivateKey:
				return k, nil
			case *ecdsa.PrivateKey:
				return k, nil
			}
			// Unsupported key type from PKCS#8 — continue scanning
		}

		// Try RSA PKCS#1
		if rsaKey, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
			return rsaKey, nil
		}

		// Try EC (SEC1)
		if ecKey, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
			return ecKey, nil
		}
	}

	if !foundBlocks {
		return nil, errors.New("no PEM block found in key data")
	}
	return nil, errors.New("no supported private key found in key data")
}

// LoadSigningKey reads a PEM file and returns the parsed private key.
// Supports RSA (PKCS#1 / PKCS#8) and ECDSA (SEC1 / PKCS#8).
func LoadSigningKey(path string) (crypto.Signer, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read key file: %w", err)
	}
	key, err := ParseSigningKey(data)
	if err != nil {
		return nil, fmt.Errorf("parse key file %s: %w", path, err)
	}
	return key, nil
}

// DeriveKeyID computes a deterministic kid from the SHA-256 hash of the
// DER-encoded public key (SPKI format). Returns a base64url-encoded string
// of the full 32-byte hash, suitable for JWKS key rotation.
func DeriveKeyID(pub crypto.PublicKey) (string, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", fmt.Errorf("DeriveKeyID: marshal public key: %w", err)
	}
	sum := sha256.Sum256(der)
	return base64.RawURLEncoding.EncodeToString(sum[:]), nil
}
