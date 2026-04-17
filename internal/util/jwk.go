package util

import (
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"math/big"
)

// Known JWK key types and curves (RFC 7517 §4.1, RFC 7518 §6).
const (
	JWKTypeRSA   = "RSA"
	JWKTypeEC    = "EC"
	JWKCurveP256 = "P-256"
)

// JWK represents a single JSON Web Key (RFC 7517).
// Only the fields required for RSA and EC P-256 signing keys are modelled; additional
// JWK fields (e.g. x5c, x5t) are ignored on parse and omitted on marshal.
type JWK struct {
	Kty string `json:"kty"`
	Use string `json:"use,omitempty"`
	Kid string `json:"kid,omitempty"`
	Alg string `json:"alg,omitempty"`
	// RSA
	N string `json:"n,omitempty"`
	E string `json:"e,omitempty"`
	// EC
	Crv string `json:"crv,omitempty"`
	X   string `json:"x,omitempty"`
	Y   string `json:"y,omitempty"`
}

// JWKSet is a set of JSON Web Keys (RFC 7517 §5).
type JWKSet struct {
	Keys []JWK `json:"keys"`
}

// Errors returned from this package.
var (
	ErrInvalidJWKS          = errors.New("invalid JWK Set")
	ErrUnsupportedKeyType   = errors.New("unsupported JWK key type")
	ErrJWKFieldMissing      = errors.New("JWK missing required field")
	ErrJWKInvalidEncoding   = errors.New("JWK contains invalid base64url encoding")
	ErrJWKNoMatchingKey     = errors.New("no JWK matches requested kid")
	ErrJWKAlgorithmMismatch = errors.New("JWK algorithm does not match requested algorithm")
)

// ParseJWKSet unmarshals a JWKS JSON document and validates that it contains
// at least one key. It does not verify individual keys — use ToPublicKey for that.
func ParseJWKSet(jsonBlob string) (*JWKSet, error) {
	var set JWKSet
	if err := json.Unmarshal([]byte(jsonBlob), &set); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidJWKS, err)
	}
	if len(set.Keys) == 0 {
		return nil, fmt.Errorf("%w: keys array is empty", ErrInvalidJWKS)
	}
	return &set, nil
}

// FindByKid returns the key whose Kid matches, or nil if not found.
// If kid is empty and there is exactly one key, that key is returned; otherwise nil.
func (s *JWKSet) FindByKid(kid string) *JWK {
	if kid == "" {
		if len(s.Keys) == 1 {
			return &s.Keys[0]
		}
		return nil
	}
	for i := range s.Keys {
		if s.Keys[i].Kid == kid {
			return &s.Keys[i]
		}
	}
	return nil
}

// ToPublicKey converts a JWK to a crypto.PublicKey. Only RSA and EC P-256 keys
// are supported. The returned key can be used with golang-jwt/jwt for signature
// verification.
func (k *JWK) ToPublicKey() (crypto.PublicKey, error) {
	switch k.Kty {
	case JWKTypeRSA:
		return rsaKeyFromJWK(k)
	case JWKTypeEC:
		return ecKeyFromJWK(k)
	default:
		return nil, fmt.Errorf("%w: kty=%q", ErrUnsupportedKeyType, k.Kty)
	}
}

func rsaKeyFromJWK(k *JWK) (*rsa.PublicKey, error) {
	if k.N == "" || k.E == "" {
		return nil, fmt.Errorf("%w: RSA key requires n and e", ErrJWKFieldMissing)
	}
	nBytes, err := base64.RawURLEncoding.DecodeString(k.N)
	if err != nil {
		return nil, fmt.Errorf("%w: n: %v", ErrJWKInvalidEncoding, err)
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(k.E)
	if err != nil {
		return nil, fmt.Errorf("%w: e: %v", ErrJWKInvalidEncoding, err)
	}
	n := new(big.Int).SetBytes(nBytes)
	e := new(big.Int).SetBytes(eBytes)
	if !e.IsInt64() {
		return nil, fmt.Errorf("%w: RSA exponent overflow", ErrInvalidJWKS)
	}
	// E must be an odd integer > 1 per PKCS#1; reject weak/degenerate exponents
	// (e.g. 0, 1, even values) that make signature verification trivially unsafe.
	eInt := e.Int64()
	if eInt < 3 || eInt&1 == 0 {
		return nil, fmt.Errorf(
			"%w: RSA exponent must be odd and >= 3 (got %d)",
			ErrInvalidJWKS, eInt,
		)
	}
	// rsa.PublicKey.E is an int, which is 32 bits on some platforms. Reject
	// exponents that would truncate when cast rather than silently producing
	// a corrupted key.
	if eInt > math.MaxInt {
		return nil, fmt.Errorf(
			"%w: RSA exponent %d exceeds platform int range",
			ErrInvalidJWKS, eInt,
		)
	}
	if n.BitLen() < 2048 {
		return nil, fmt.Errorf(
			"%w: RSA modulus must be >= 2048 bits (got %d)",
			ErrInvalidJWKS,
			n.BitLen(),
		)
	}
	return &rsa.PublicKey{N: n, E: int(eInt)}, nil
}

func ecKeyFromJWK(k *JWK) (*ecdsa.PublicKey, error) {
	if k.Crv == "" || k.X == "" || k.Y == "" {
		return nil, fmt.Errorf("%w: EC key requires crv, x, and y", ErrJWKFieldMissing)
	}
	var (
		curve   elliptic.Curve
		ecdhCrv ecdh.Curve
		byteLen int
	)
	switch k.Crv {
	case JWKCurveP256:
		curve = elliptic.P256()
		ecdhCrv = ecdh.P256()
		byteLen = 32
	default:
		return nil, fmt.Errorf(
			"%w: curve %q (only P-256 is supported)",
			ErrUnsupportedKeyType,
			k.Crv,
		)
	}
	xBytes, err := base64.RawURLEncoding.DecodeString(k.X)
	if err != nil {
		return nil, fmt.Errorf("%w: x: %v", ErrJWKInvalidEncoding, err)
	}
	yBytes, err := base64.RawURLEncoding.DecodeString(k.Y)
	if err != nil {
		return nil, fmt.Errorf("%w: y: %v", ErrJWKInvalidEncoding, err)
	}
	if len(xBytes) > byteLen || len(yBytes) > byteLen {
		return nil, fmt.Errorf("%w: EC coordinate exceeds curve byte length", ErrInvalidJWKS)
	}
	// Left-pad x/y to fixed width, then build SEC1 uncompressed point (0x04 || X || Y)
	// and delegate on-curve validation to crypto/ecdh.
	xPad := make([]byte, byteLen)
	yPad := make([]byte, byteLen)
	copy(xPad[byteLen-len(xBytes):], xBytes)
	copy(yPad[byteLen-len(yBytes):], yBytes)
	uncompressed := make([]byte, 0, 1+2*byteLen)
	uncompressed = append(uncompressed, 0x04)
	uncompressed = append(uncompressed, xPad...)
	uncompressed = append(uncompressed, yPad...)
	if _, err := ecdhCrv.NewPublicKey(uncompressed); err != nil {
		return nil, fmt.Errorf("%w: EC point is not on curve %s: %v", ErrInvalidJWKS, k.Crv, err)
	}
	return &ecdsa.PublicKey{
		Curve: curve,
		X:     new(big.Int).SetBytes(xPad),
		Y:     new(big.Int).SetBytes(yPad),
	}, nil
}
