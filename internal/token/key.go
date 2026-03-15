package token

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
)

// LoadSigningKey reads a PEM file and returns the parsed private key.
// Supports RSA (PKCS#1 / PKCS#8) and ECDSA (SEC1 / PKCS#8).
func LoadSigningKey(path string) (crypto.Signer, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read key file: %w", err)
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found in %s", path)
	}

	// Try PKCS#8 first (works for both RSA and ECDSA)
	if key, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		signer, ok := key.(crypto.Signer)
		if !ok {
			return nil, errors.New("PKCS#8 key is not a crypto.Signer")
		}
		return signer, nil
	}

	// Try RSA PKCS#1
	if rsaKey, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return rsaKey, nil
	}

	// Try EC (SEC1)
	if ecKey, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
		return ecKey, nil
	}

	return nil, fmt.Errorf("unsupported key format in %s", path)
}

// DeriveKeyID computes a kid from the SHA-256 thumbprint of the DER-encoded public key.
// Returns a base64url-encoded string of the first 16 bytes of the hash.
func DeriveKeyID(pub crypto.PublicKey) string {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(der)
	return base64.RawURLEncoding.EncodeToString(sum[:16])
}

// ValidateKeyAlgorithm checks that the loaded key matches the configured algorithm.
func ValidateKeyAlgorithm(key crypto.Signer, algorithm string) error {
	switch algorithm {
	case "RS256":
		if _, ok := key.(*rsa.PrivateKey); !ok {
			return fmt.Errorf(
				"JWT_SIGNING_ALGORITHM=RS256 requires an RSA private key, got %T",
				key,
			)
		}
	case "ES256":
		ecKey, ok := key.(*ecdsa.PrivateKey)
		if !ok {
			return fmt.Errorf(
				"JWT_SIGNING_ALGORITHM=ES256 requires an ECDSA private key, got %T",
				key,
			)
		}
		if ecKey.Curve != elliptic.P256() {
			return fmt.Errorf(
				"JWT_SIGNING_ALGORITHM=ES256 requires P-256 curve, got %s",
				ecKey.Curve.Params().Name,
			)
		}
	default:
		return fmt.Errorf("unsupported algorithm: %s", algorithm)
	}
	return nil
}
