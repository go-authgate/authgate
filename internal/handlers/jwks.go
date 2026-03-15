package handlers

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"encoding/base64"
	"math/big"
	"net/http"

	"github.com/gin-gonic/gin"
)

// JSONWebKey represents a single key in a JWKS response (RFC 7517).
type JSONWebKey struct {
	Kty string `json:"kty"`           // Key type: "RSA" or "EC"
	Use string `json:"use"`           // Key use: "sig"
	Kid string `json:"kid"`           // Key ID
	Alg string `json:"alg"`           // Algorithm: "RS256" or "ES256"
	N   string `json:"n,omitempty"`   // RSA modulus (base64url)
	E   string `json:"e,omitempty"`   // RSA exponent (base64url)
	Crv string `json:"crv,omitempty"` // EC curve: "P-256"
	X   string `json:"x,omitempty"`   // EC x coordinate (base64url)
	Y   string `json:"y,omitempty"`   // EC y coordinate (base64url)
}

// JWKSResponse is the top-level JWKS document (RFC 7517 §5).
type JWKSResponse struct {
	Keys []JSONWebKey `json:"keys"`
}

// JWKSHandler serves the JWKS endpoint.
type JWKSHandler struct {
	response JWKSResponse // built once at startup
}

// NewJWKSHandler builds a JWKSHandler from the token provider's public key.
// For HS256 (no public key), the keys array is empty.
func NewJWKSHandler(algorithm, kid string, publicKey any) *JWKSHandler {
	h := &JWKSHandler{
		response: JWKSResponse{Keys: []JSONWebKey{}},
	}

	switch key := publicKey.(type) {
	case *rsa.PublicKey:
		h.response.Keys = append(h.response.Keys, rsaPublicKeyToJWK(key, algorithm, kid))
	case *ecdsa.PublicKey:
		h.response.Keys = append(h.response.Keys, ecPublicKeyToJWK(key, algorithm, kid))
	}

	return h
}

// JWKS godoc
//
//	@Summary		JSON Web Key Set
//	@Description	Returns the public keys used to verify JWT signatures (RFC 7517)
//	@Tags			OIDC
//	@Produce		json
//	@Success		200	{object}	JWKSResponse	"JWKS document"
//	@Router			/.well-known/jwks.json [get]
func (h *JWKSHandler) JWKS(c *gin.Context) {
	c.JSON(http.StatusOK, h.response)
}

// rsaPublicKeyToJWK converts an RSA public key to a JWK.
func rsaPublicKeyToJWK(key *rsa.PublicKey, alg, kid string) JSONWebKey {
	return JSONWebKey{
		Kty: "RSA",
		Use: "sig",
		Kid: kid,
		Alg: alg,
		N:   base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
		E:   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes()),
	}
}

// ecPublicKeyToJWK converts an ECDSA public key to a JWK.
func ecPublicKeyToJWK(key *ecdsa.PublicKey, alg, kid string) JSONWebKey {
	// For P-256, coordinates must be exactly 32 bytes (zero-padded on the left)
	byteLen := (key.Curve.Params().BitSize + 7) / 8
	xBytes := key.X.Bytes()
	yBytes := key.Y.Bytes()

	// Pad to fixed length
	xPadded := make([]byte, byteLen)
	yPadded := make([]byte, byteLen)
	copy(xPadded[byteLen-len(xBytes):], xBytes)
	copy(yPadded[byteLen-len(yBytes):], yBytes)

	return JSONWebKey{
		Kty: "EC",
		Use: "sig",
		Kid: kid,
		Alg: alg,
		Crv: key.Curve.Params().Name,
		X:   base64.RawURLEncoding.EncodeToString(xPadded),
		Y:   base64.RawURLEncoding.EncodeToString(yPadded),
	}
}
