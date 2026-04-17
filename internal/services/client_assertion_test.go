package services

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-authgate/authgate/internal/cache"
	"github.com/go-authgate/authgate/internal/core"
	"github.com/go-authgate/authgate/internal/models"
	"github.com/go-authgate/authgate/internal/store"
	"github.com/go-authgate/authgate/internal/util"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

// --- helpers ------------------------------------------------------------

const testAudience = "https://authgate.test/oauth/token"

type rsaFixture struct {
	priv *rsa.PrivateKey
	jwk  util.JWK
}

func newRSAFixture(t *testing.T, kid string) rsaFixture {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	return rsaFixture{
		priv: priv,
		jwk: util.JWK{
			Kty: "RSA",
			Use: "sig",
			Kid: kid,
			Alg: "RS256",
			N:   base64.RawURLEncoding.EncodeToString(priv.PublicKey.N.Bytes()),
			E:   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(priv.PublicKey.E)).Bytes()),
		},
	}
}

type ecFixture struct {
	priv *ecdsa.PrivateKey
	jwk  util.JWK
}

func newECFixture(t *testing.T, kid string) ecFixture {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	byteLen := 32
	xBytes := make([]byte, byteLen)
	yBytes := make([]byte, byteLen)
	copy(xBytes[byteLen-len(priv.PublicKey.X.Bytes()):], priv.PublicKey.X.Bytes())
	copy(yBytes[byteLen-len(priv.PublicKey.Y.Bytes()):], priv.PublicKey.Y.Bytes())
	return ecFixture{
		priv: priv,
		jwk: util.JWK{
			Kty: "EC",
			Use: "sig",
			Kid: kid,
			Alg: "ES256",
			Crv: "P-256",
			X:   base64.RawURLEncoding.EncodeToString(xBytes),
			Y:   base64.RawURLEncoding.EncodeToString(yBytes),
		},
	}
}

func signRS256(t *testing.T, priv *rsa.PrivateKey, kid string, claims jwt.MapClaims) string {
	t.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["kid"] = kid
	out, err := tok.SignedString(priv)
	require.NoError(t, err)
	return out
}

func signES256(t *testing.T, priv *ecdsa.PrivateKey, kid string, claims jwt.MapClaims) string {
	t.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	tok.Header["kid"] = kid
	out, err := tok.SignedString(priv)
	require.NoError(t, err)
	return out
}

func signHS256(t *testing.T, secret []byte, claims jwt.MapClaims) string {
	t.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	out, err := tok.SignedString(secret)
	require.NoError(t, err)
	return out
}

type verifierFixture struct {
	verifier *ClientAssertionVerifier
	store    *store.Store
	cs       *ClientService
}

func newVerifierFixture(t *testing.T) *verifierFixture {
	t.Helper()
	s := setupTestStore(t)
	cs := NewClientService(s, nil, nil, 0, nil, 0)
	fetcher := NewJWKSFetcher(cache.NewMemoryCache[util.JWKSet](0), 2*time.Second, time.Minute)
	jtiCache := cache.NewMemoryCache[bool](0)
	t.Cleanup(func() { _ = jtiCache.Close() })
	v := NewClientAssertionVerifier(cs, fetcher, jtiCache, NewNoopAuditService(),
		ClientAssertionConfig{
			Enabled:           true,
			ExpectedAudiences: []string{testAudience},
			MaxLifetime:       5 * time.Minute,
			ClockSkew:         30 * time.Second,
		})
	return &verifierFixture{verifier: v, store: s, cs: cs}
}

func seedRSAClient(
	t *testing.T,
	s *store.Store,
	jwk util.JWK,
	alg string,
) *models.OAuthApplication {
	t.Helper()
	set := util.JWKSet{Keys: []util.JWK{jwk}}
	blob, err := json.Marshal(set)
	require.NoError(t, err)
	client := &models.OAuthApplication{
		ClientID:                    uuid.New().String(),
		ClientName:                  "pkjwt-client",
		UserID:                      uuid.New().String(),
		Scopes:                      "read write",
		GrantTypes:                  "client_credentials",
		ClientType:                  core.ClientTypeConfidential.String(),
		EnableClientCredentialsFlow: true,
		Status:                      models.ClientStatusActive,
		TokenEndpointAuthMethod:     models.TokenEndpointAuthPrivateKeyJWT,
		TokenEndpointAuthSigningAlg: alg,
		JWKS:                        string(blob),
	}
	require.NoError(t, s.CreateClient(client))
	return client
}

func baseClaims(clientID string) jwt.MapClaims {
	now := time.Now()
	return jwt.MapClaims{
		"iss": clientID,
		"sub": clientID,
		"aud": testAudience,
		"iat": now.Unix(),
		"exp": now.Add(time.Minute).Unix(),
		"jti": uuid.NewString(),
	}
}

// --- success paths ------------------------------------------------------

func TestClientAssertion_RS256_Success(t *testing.T) {
	f := newVerifierFixture(t)
	rsa := newRSAFixture(t, "k1")
	client := seedRSAClient(t, f.store, rsa.jwk, "RS256")

	token := signRS256(t, rsa.priv, "k1", baseClaims(client.ClientID))
	got, err := f.verifier.Verify(context.Background(), token, AssertionType)
	require.NoError(t, err)
	require.Equal(t, client.ClientID, got.ClientID)
}

func TestClientAssertion_ES256_Success(t *testing.T) {
	f := newVerifierFixture(t)
	ec := newECFixture(t, "ec1")
	set := util.JWKSet{Keys: []util.JWK{ec.jwk}}
	blob, err := json.Marshal(set)
	require.NoError(t, err)

	client := &models.OAuthApplication{
		ClientID:                    uuid.New().String(),
		ClientName:                  "pkjwt-ec",
		UserID:                      uuid.New().String(),
		Scopes:                      "read",
		GrantTypes:                  "client_credentials",
		ClientType:                  core.ClientTypeConfidential.String(),
		EnableClientCredentialsFlow: true,
		Status:                      models.ClientStatusActive,
		TokenEndpointAuthMethod:     models.TokenEndpointAuthPrivateKeyJWT,
		TokenEndpointAuthSigningAlg: "ES256",
		JWKS:                        string(blob),
	}
	require.NoError(t, f.store.CreateClient(client))

	token := signES256(t, ec.priv, "ec1", baseClaims(client.ClientID))
	got, err := f.verifier.Verify(context.Background(), token, AssertionType)
	require.NoError(t, err)
	require.Equal(t, client.ClientID, got.ClientID)
}

func TestClientAssertion_JWKSURI_Success(t *testing.T) {
	f := newVerifierFixture(t)
	rsa := newRSAFixture(t, "k1")

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		blob, _ := json.Marshal(util.JWKSet{Keys: []util.JWK{rsa.jwk}})
		_, _ = w.Write(blob)
	}))
	defer srv.Close()

	client := &models.OAuthApplication{
		ClientID:                    uuid.New().String(),
		ClientName:                  "pkjwt-uri",
		UserID:                      uuid.New().String(),
		Scopes:                      "read",
		GrantTypes:                  "client_credentials",
		ClientType:                  core.ClientTypeConfidential.String(),
		EnableClientCredentialsFlow: true,
		Status:                      models.ClientStatusActive,
		TokenEndpointAuthMethod:     models.TokenEndpointAuthPrivateKeyJWT,
		TokenEndpointAuthSigningAlg: "RS256",
		JWKSURI:                     srv.URL,
	}
	require.NoError(t, f.store.CreateClient(client))

	token := signRS256(t, rsa.priv, "k1", baseClaims(client.ClientID))
	got, err := f.verifier.Verify(context.Background(), token, AssertionType)
	require.NoError(t, err)
	require.Equal(t, client.ClientID, got.ClientID)
}

// --- failure paths ------------------------------------------------------

func TestClientAssertion_FeatureDisabled(t *testing.T) {
	f := newVerifierFixture(t)
	f.verifier.cfg.Enabled = false
	_, err := f.verifier.Verify(context.Background(), "anything", AssertionType)
	require.ErrorIs(t, err, ErrAssertionFeatureDisabled)
}

func TestClientAssertion_WrongAssertionType(t *testing.T) {
	f := newVerifierFixture(t)
	_, err := f.verifier.Verify(context.Background(), "anything", "urn:other")
	require.ErrorIs(t, err, ErrAssertionTypeInvalid)
}

func TestClientAssertion_Malformed(t *testing.T) {
	f := newVerifierFixture(t)
	_, err := f.verifier.Verify(context.Background(), "not.a.jwt", AssertionType)
	require.ErrorIs(t, err, ErrAssertionMalformed)
}

func TestClientAssertion_IssSubMismatch(t *testing.T) {
	f := newVerifierFixture(t)
	rsa := newRSAFixture(t, "k1")
	client := seedRSAClient(t, f.store, rsa.jwk, "RS256")

	claims := baseClaims(client.ClientID)
	claims["sub"] = "different"
	token := signRS256(t, rsa.priv, "k1", claims)
	_, err := f.verifier.Verify(context.Background(), token, AssertionType)
	require.ErrorIs(t, err, ErrAssertionIssuerMismatch)
}

func TestClientAssertion_UnknownClient(t *testing.T) {
	f := newVerifierFixture(t)
	rsa := newRSAFixture(t, "k1")
	claims := baseClaims("ghost-client")
	token := signRS256(t, rsa.priv, "k1", claims)
	_, err := f.verifier.Verify(context.Background(), token, AssertionType)
	require.ErrorIs(t, err, ErrAssertionClientUnknown)
}

func TestClientAssertion_MethodNotAllowed(t *testing.T) {
	f := newVerifierFixture(t)
	rsa := newRSAFixture(t, "k1")
	// Seed a client that registered as client_secret_basic, not private_key_jwt.
	client := &models.OAuthApplication{
		ClientID:                    uuid.New().String(),
		ClientName:                  "secret-client",
		UserID:                      uuid.New().String(),
		Scopes:                      "read",
		ClientType:                  core.ClientTypeConfidential.String(),
		EnableClientCredentialsFlow: true,
		Status:                      models.ClientStatusActive,
		TokenEndpointAuthMethod:     models.TokenEndpointAuthClientSecretBasic,
	}
	require.NoError(t, f.store.CreateClient(client))

	token := signRS256(t, rsa.priv, "k1", baseClaims(client.ClientID))
	_, err := f.verifier.Verify(context.Background(), token, AssertionType)
	require.ErrorIs(t, err, ErrAssertionMethodNotAllowed)
}

func TestClientAssertion_AlgorithmMismatch(t *testing.T) {
	f := newVerifierFixture(t)
	rsa := newRSAFixture(t, "k1")
	// Register the client as ES256, but sign as RS256 — mismatch.
	client := seedRSAClient(t, f.store, rsa.jwk, "ES256")

	token := signRS256(t, rsa.priv, "k1", baseClaims(client.ClientID))
	_, err := f.verifier.Verify(context.Background(), token, AssertionType)
	require.ErrorIs(t, err, ErrAssertionAlgorithmMismatch)
}

func TestClientAssertion_HS256Rejected(t *testing.T) {
	f := newVerifierFixture(t)
	rsa := newRSAFixture(t, "k1")
	client := seedRSAClient(t, f.store, rsa.jwk, "RS256")

	// Try to sign with HS256 — algorithm mismatch should reject it regardless.
	token := signHS256(t, []byte("shared-secret"), baseClaims(client.ClientID))
	_, err := f.verifier.Verify(context.Background(), token, AssertionType)
	require.ErrorIs(t, err, ErrAssertionAlgorithmMismatch)
}

func TestClientAssertion_BadSignature(t *testing.T) {
	f := newVerifierFixture(t)
	rsa1 := newRSAFixture(t, "k1")
	rsa2 := newRSAFixture(t, "k1")
	// Register rsa1's public key, but sign with rsa2's private key.
	client := seedRSAClient(t, f.store, rsa1.jwk, "RS256")

	token := signRS256(t, rsa2.priv, "k1", baseClaims(client.ClientID))
	_, err := f.verifier.Verify(context.Background(), token, AssertionType)
	require.ErrorIs(t, err, ErrAssertionSignatureInvalid)
}

func TestClientAssertion_WrongAudience(t *testing.T) {
	f := newVerifierFixture(t)
	rsa := newRSAFixture(t, "k1")
	client := seedRSAClient(t, f.store, rsa.jwk, "RS256")

	claims := baseClaims(client.ClientID)
	claims["aud"] = "https://other.example.com/token"
	token := signRS256(t, rsa.priv, "k1", claims)
	_, err := f.verifier.Verify(context.Background(), token, AssertionType)
	require.ErrorIs(t, err, ErrAssertionAudienceInvalid)
}

func TestClientAssertion_Expired(t *testing.T) {
	f := newVerifierFixture(t)
	rsa := newRSAFixture(t, "k1")
	client := seedRSAClient(t, f.store, rsa.jwk, "RS256")

	claims := baseClaims(client.ClientID)
	claims["iat"] = time.Now().Add(-2 * time.Minute).Unix()
	claims["exp"] = time.Now().Add(-time.Minute).Unix()
	token := signRS256(t, rsa.priv, "k1", claims)
	_, err := f.verifier.Verify(context.Background(), token, AssertionType)
	require.ErrorIs(t, err, ErrAssertionExpired)
}

func TestClientAssertion_LifetimeTooLong(t *testing.T) {
	f := newVerifierFixture(t)
	rsa := newRSAFixture(t, "k1")
	client := seedRSAClient(t, f.store, rsa.jwk, "RS256")

	now := time.Now()
	claims := jwt.MapClaims{
		"iss": client.ClientID,
		"sub": client.ClientID,
		"aud": testAudience,
		"iat": now.Unix(),
		"exp": now.Add(1 * time.Hour).Unix(), // exceeds MaxLifetime=5m
		"jti": uuid.NewString(),
	}
	token := signRS256(t, rsa.priv, "k1", claims)
	_, err := f.verifier.Verify(context.Background(), token, AssertionType)
	require.ErrorIs(t, err, ErrAssertionLifetimeTooLong)
}

func TestClientAssertion_MissingJTI(t *testing.T) {
	f := newVerifierFixture(t)
	rsa := newRSAFixture(t, "k1")
	client := seedRSAClient(t, f.store, rsa.jwk, "RS256")

	claims := baseClaims(client.ClientID)
	delete(claims, "jti")
	token := signRS256(t, rsa.priv, "k1", claims)
	_, err := f.verifier.Verify(context.Background(), token, AssertionType)
	require.ErrorIs(t, err, ErrAssertionMissingJTI)
}

func TestClientAssertion_JTIReplay(t *testing.T) {
	f := newVerifierFixture(t)
	rsa := newRSAFixture(t, "k1")
	client := seedRSAClient(t, f.store, rsa.jwk, "RS256")

	claims := baseClaims(client.ClientID)
	token := signRS256(t, rsa.priv, "k1", claims)

	// First use: accepted.
	_, err := f.verifier.Verify(context.Background(), token, AssertionType)
	require.NoError(t, err)
	// Second use of the same token: rejected as replay.
	_, err = f.verifier.Verify(context.Background(), token, AssertionType)
	require.ErrorIs(t, err, ErrAssertionJTIReplay)
}

func TestClientAssertion_UnknownKid(t *testing.T) {
	f := newVerifierFixture(t)
	rsa := newRSAFixture(t, "registered")
	client := seedRSAClient(t, f.store, rsa.jwk, "RS256")

	// Sign with a different kid — no matching JWK.
	token := signRS256(t, rsa.priv, "mystery", baseClaims(client.ClientID))
	_, err := f.verifier.Verify(context.Background(), token, AssertionType)
	require.ErrorIs(t, err, ErrAssertionKeyLookup)
}

func TestClientAssertion_InactiveClient(t *testing.T) {
	f := newVerifierFixture(t)
	rsa := newRSAFixture(t, "k1")
	client := seedRSAClient(t, f.store, rsa.jwk, "RS256")
	// Disable the client after registration.
	client.Status = models.ClientStatusInactive
	require.NoError(t, f.store.UpdateClient(client))
	// Clear any cached version.
	_ = f.cs.clientCache.Delete(context.Background(), client.ClientID)

	token := signRS256(t, rsa.priv, "k1", baseClaims(client.ClientID))
	_, err := f.verifier.Verify(context.Background(), token, AssertionType)
	require.ErrorIs(t, err, ErrAssertionClientInactive)
}
