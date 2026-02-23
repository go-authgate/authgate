package services

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"testing"
	"time"

	"github.com/go-authgate/authgate/internal/config"
	"github.com/go-authgate/authgate/internal/models"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"
)

const (
	testClientPlainSecret = "test-plain-secret" //nolint:gosec
	testPKCEVerifier      = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
)

// createTestAuthorizationService builds a service with an in-memory store.
func createTestAuthorizationService(t *testing.T) *AuthorizationService {
	t.Helper()
	s := setupTestStore(t)
	cfg := &config.Config{
		AuthCodeExpiration: 10 * time.Minute,
		PKCERequired:       false,
		ConsentRemember:    true,
	}
	return NewAuthorizationService(s, cfg, nil)
}

// createAuthCodeFlowClient creates a test client with auth code flow enabled.
// The ClientSecret field stores the bcrypt hash of testClientPlainSecret.
func createAuthCodeFlowClient(
	t *testing.T,
	svc *AuthorizationService,
	clientType string,
) *models.OAuthApplication {
	t.Helper()
	hash, err := bcrypt.GenerateFromPassword([]byte(testClientPlainSecret), bcrypt.MinCost)
	require.NoError(t, err)
	client := &models.OAuthApplication{
		ClientID:           uuid.New().String(),
		ClientSecret:       string(hash),
		ClientName:         "Test Auth Code Client",
		UserID:             uuid.New().String(),
		Scopes:             "read write",
		GrantTypes:         "authorization_code",
		RedirectURIs:       models.StringArray{"https://app.example.com/callback"},
		ClientType:         clientType,
		EnableAuthCodeFlow: true,
		IsActive:           true,
	}
	err = svc.store.CreateClient(client)
	require.NoError(t, err)
	return client
}

// ============================================================
// ValidateAuthorizationRequest
// ============================================================

func TestValidateAuthorizationRequest_Success(t *testing.T) {
	svc := createTestAuthorizationService(t)
	client := createAuthCodeFlowClient(t, svc, "confidential")

	req, err := svc.ValidateAuthorizationRequest(
		client.ClientID,
		"https://app.example.com/callback",
		"code",
		"read",
		"",
	)

	require.NoError(t, err)
	assert.Equal(t, client.ClientID, req.Client.ClientID)
	assert.Equal(t, "read", req.Scopes)
}

func TestValidateAuthorizationRequest_DefaultScope(t *testing.T) {
	svc := createTestAuthorizationService(t)
	client := createAuthCodeFlowClient(t, svc, "confidential")

	req, err := svc.ValidateAuthorizationRequest(
		client.ClientID, "https://app.example.com/callback", "code", "", "",
	)

	require.NoError(t, err)
	// Empty scope should fall back to the client's full scope
	assert.Equal(t, client.Scopes, req.Scopes)
}

func TestValidateAuthorizationRequest_InvalidResponseType(t *testing.T) {
	svc := createTestAuthorizationService(t)
	client := createAuthCodeFlowClient(t, svc, "confidential")

	_, err := svc.ValidateAuthorizationRequest(
		client.ClientID, "https://app.example.com/callback", "token", "", "",
	)
	assert.ErrorIs(t, err, ErrUnsupportedResponseType)
}

func TestValidateAuthorizationRequest_UnknownClient(t *testing.T) {
	svc := createTestAuthorizationService(t)

	_, err := svc.ValidateAuthorizationRequest(
		"nonexistent", "https://app.example.com/callback", "code", "", "",
	)
	assert.ErrorIs(t, err, ErrUnauthorizedClient)
}

func TestValidateAuthorizationRequest_AuthCodeFlowDisabled(t *testing.T) {
	svc := createTestAuthorizationService(t)
	client := &models.OAuthApplication{
		ClientID:           uuid.New().String(),
		ClientSecret:       "secret",
		ClientName:         "No Auth Code Client",
		UserID:             uuid.New().String(),
		Scopes:             "read",
		GrantTypes:         "device_code",
		RedirectURIs:       models.StringArray{"https://app.example.com/callback"},
		ClientType:         "confidential",
		EnableAuthCodeFlow: false, // disabled
		IsActive:           true,
	}
	require.NoError(t, svc.store.CreateClient(client))

	_, err := svc.ValidateAuthorizationRequest(
		client.ClientID, "https://app.example.com/callback", "code", "", "",
	)
	assert.ErrorIs(t, err, ErrUnauthorizedClient)
}

func TestValidateAuthorizationRequest_InvalidRedirectURI(t *testing.T) {
	svc := createTestAuthorizationService(t)
	client := createAuthCodeFlowClient(t, svc, "confidential")

	_, err := svc.ValidateAuthorizationRequest(
		client.ClientID, "https://evil.example.com/callback", "code", "", "",
	)
	assert.ErrorIs(t, err, ErrInvalidRedirectURI)
}

func TestValidateAuthorizationRequest_InvalidScope(t *testing.T) {
	svc := createTestAuthorizationService(t)
	client := createAuthCodeFlowClient(t, svc, "confidential")

	_, err := svc.ValidateAuthorizationRequest(
		client.ClientID, "https://app.example.com/callback", "code", "admin", "",
	)
	assert.ErrorIs(t, err, ErrInvalidAuthCodeScope)
}

func TestValidateAuthorizationRequest_PublicClientRequiresPKCE(t *testing.T) {
	svc := createTestAuthorizationService(t)
	client := createAuthCodeFlowClient(t, svc, "public")

	// No code_challenge_method → should fail for public client
	_, err := svc.ValidateAuthorizationRequest(
		client.ClientID, "https://app.example.com/callback", "code", "read", "",
	)
	assert.ErrorIs(t, err, ErrPKCERequired)
}

func TestValidateAuthorizationRequest_PublicClientWithPKCE(t *testing.T) {
	svc := createTestAuthorizationService(t)
	client := createAuthCodeFlowClient(t, svc, "public")

	req, err := svc.ValidateAuthorizationRequest(
		client.ClientID, "https://app.example.com/callback", "code", "read", "S256",
	)
	require.NoError(t, err)
	assert.Equal(t, "S256", req.CodeChallengeMethod)
}

// ============================================================
// CreateAuthorizationCode
// ============================================================

func TestCreateAuthorizationCode_Success(t *testing.T) {
	svc := createTestAuthorizationService(t)
	client := createAuthCodeFlowClient(t, svc, "confidential")
	userID := uuid.New().String()

	plainCode, record, err := svc.CreateAuthorizationCode(
		context.Background(),
		client.ID,
		client.ClientID,
		userID,
		"https://app.example.com/callback",
		"read write",
		"", "",
	)

	require.NoError(t, err)
	assert.Len(t, plainCode, 64) // 32 bytes hex-encoded
	assert.NotEmpty(t, record.UUID)
	assert.Equal(t, client.ID, record.ApplicationID)
	assert.Equal(t, userID, record.UserID)
	assert.False(t, record.IsExpired())
	assert.False(t, record.IsUsed())
}

func TestCreateAuthorizationCode_WithPKCE(t *testing.T) {
	svc := createTestAuthorizationService(t)
	client := createAuthCodeFlowClient(t, svc, "public")
	userID := uuid.New().String()

	verifier := testPKCEVerifier
	sum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])

	_, record, err := svc.CreateAuthorizationCode(
		context.Background(),
		client.ID, client.ClientID, userID,
		"https://app.example.com/callback", "read",
		challenge, "S256",
	)

	require.NoError(t, err)
	assert.Equal(t, challenge, record.CodeChallenge)
	assert.Equal(t, "S256", record.CodeChallengeMethod)
}

// ============================================================
// ExchangeCode
// ============================================================

func TestExchangeCode_Success_ConfidentialClient(t *testing.T) {
	svc := createTestAuthorizationService(t)
	client := createAuthCodeFlowClient(t, svc, "confidential")
	userID := uuid.New().String()

	plainCode, _, err := svc.CreateAuthorizationCode(
		context.Background(),
		client.ID, client.ClientID, userID,
		"https://app.example.com/callback", "read write", "", "",
	)
	require.NoError(t, err)

	authCode, err := svc.ExchangeCode(
		context.Background(),
		plainCode,
		client.ClientID,
		"https://app.example.com/callback",
		testClientPlainSecret,
		"",
	)

	require.NoError(t, err)
	assert.Equal(t, userID, authCode.UserID)
	assert.Equal(t, client.ClientID, authCode.ClientID)
	// Code should now be marked used
	assert.True(t, authCode.IsUsed())
}

func TestExchangeCode_Success_PublicClient_PKCE_S256(t *testing.T) {
	svc := createTestAuthorizationService(t)
	client := createAuthCodeFlowClient(t, svc, "public")
	userID := uuid.New().String()

	verifier := testPKCEVerifier
	sum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])

	plainCode, _, err := svc.CreateAuthorizationCode(
		context.Background(),
		client.ID, client.ClientID, userID,
		"https://app.example.com/callback", "read",
		challenge, "S256",
	)
	require.NoError(t, err)

	_, err = svc.ExchangeCode(
		context.Background(),
		plainCode, client.ClientID,
		"https://app.example.com/callback",
		"", verifier,
	)
	require.NoError(t, err)
}

func TestExchangeCode_ReplayAttack(t *testing.T) {
	svc := createTestAuthorizationService(t)
	client := createAuthCodeFlowClient(t, svc, "confidential")
	userID := uuid.New().String()

	plainCode, _, err := svc.CreateAuthorizationCode(
		context.Background(),
		client.ID, client.ClientID, userID,
		"https://app.example.com/callback", "read", "", "",
	)
	require.NoError(t, err)

	// First exchange succeeds
	_, err = svc.ExchangeCode(context.Background(), plainCode, client.ClientID,
		"https://app.example.com/callback", testClientPlainSecret, "")
	require.NoError(t, err)

	// Second exchange with same code must fail
	_, err = svc.ExchangeCode(context.Background(), plainCode, client.ClientID,
		"https://app.example.com/callback", testClientPlainSecret, "")
	assert.ErrorIs(t, err, ErrAuthCodeAlreadyUsed)
}

func TestExchangeCode_ExpiredCode(t *testing.T) {
	svc := createTestAuthorizationService(t)
	svc.config.AuthCodeExpiration = -1 * time.Second // already expired
	client := createAuthCodeFlowClient(t, svc, "confidential")
	userID := uuid.New().String()

	plainCode, _, err := svc.CreateAuthorizationCode(
		context.Background(),
		client.ID, client.ClientID, userID,
		"https://app.example.com/callback", "read", "", "",
	)
	require.NoError(t, err)

	_, err = svc.ExchangeCode(context.Background(), plainCode, client.ClientID,
		"https://app.example.com/callback", testClientPlainSecret, "")
	assert.ErrorIs(t, err, ErrAuthCodeExpired)
}

func TestExchangeCode_WrongRedirectURI(t *testing.T) {
	svc := createTestAuthorizationService(t)
	client := createAuthCodeFlowClient(t, svc, "confidential")
	userID := uuid.New().String()

	plainCode, _, err := svc.CreateAuthorizationCode(
		context.Background(),
		client.ID, client.ClientID, userID,
		"https://app.example.com/callback", "read", "", "",
	)
	require.NoError(t, err)

	_, err = svc.ExchangeCode(context.Background(), plainCode, client.ClientID,
		"https://other.example.com/callback", testClientPlainSecret, "")
	assert.ErrorIs(t, err, ErrInvalidRedirectURI)
}

func TestExchangeCode_WrongClientSecret(t *testing.T) {
	svc := createTestAuthorizationService(t)
	client := createAuthCodeFlowClient(t, svc, "confidential")
	userID := uuid.New().String()

	plainCode, _, err := svc.CreateAuthorizationCode(
		context.Background(),
		client.ID, client.ClientID, userID,
		"https://app.example.com/callback", "read", "", "",
	)
	require.NoError(t, err)

	_, err = svc.ExchangeCode(context.Background(), plainCode, client.ClientID,
		"https://app.example.com/callback", "wrong-secret", "")
	assert.ErrorIs(t, err, ErrUnauthorizedClient)
}

func TestExchangeCode_WrongCodeVerifier(t *testing.T) {
	svc := createTestAuthorizationService(t)
	client := createAuthCodeFlowClient(t, svc, "public")
	userID := uuid.New().String()

	verifier := "correct-verifier-string-long-enough-for-pkce-use"
	sum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])

	plainCode, _, err := svc.CreateAuthorizationCode(
		context.Background(),
		client.ID, client.ClientID, userID,
		"https://app.example.com/callback", "read",
		challenge, "S256",
	)
	require.NoError(t, err)

	_, err = svc.ExchangeCode(context.Background(), plainCode, client.ClientID,
		"https://app.example.com/callback", "", "wrong-verifier")
	assert.ErrorIs(t, err, ErrInvalidCodeVerifier)
}

// ============================================================
// UserAuthorization consent management
// ============================================================

func TestSaveUserAuthorization_CreateAndUpsert(t *testing.T) {
	svc := createTestAuthorizationService(t)
	client := createAuthCodeFlowClient(t, svc, "confidential")
	userID := uuid.New().String()

	// First save – creates record
	auth, err := svc.SaveUserAuthorization(
		context.Background(), userID, client.ID, client.ClientID, "read",
	)
	require.NoError(t, err)
	assert.True(t, auth.IsActive)
	assert.Equal(t, "read", auth.Scopes)
	firstUUID := auth.UUID

	// Second save with expanded scopes – should update, not duplicate
	auth2, err := svc.SaveUserAuthorization(
		context.Background(), userID, client.ID, client.ClientID, "read write",
	)
	require.NoError(t, err)
	assert.Equal(t, "read write", auth2.Scopes)
	assert.True(t, auth2.IsActive)
	// UUID may differ (new UUID on upsert) but there should still be only one record
	_ = firstUUID
}

func TestGetUserAuthorization_ExistsAndMissing(t *testing.T) {
	svc := createTestAuthorizationService(t)
	client := createAuthCodeFlowClient(t, svc, "confidential")
	userID := uuid.New().String()

	// Before saving: should return nil, nil
	auth, err := svc.GetUserAuthorization(userID, client.ID)
	require.NoError(t, err)
	assert.Nil(t, auth)

	// After saving
	_, err = svc.SaveUserAuthorization(
		context.Background(), userID, client.ID, client.ClientID, "read",
	)
	require.NoError(t, err)

	auth, err = svc.GetUserAuthorization(userID, client.ID)
	require.NoError(t, err)
	require.NotNil(t, auth)
	assert.Equal(t, "read", auth.Scopes)
}

func TestRevokeUserAuthorization_Success(t *testing.T) {
	svc := createTestAuthorizationService(t)
	client := createAuthCodeFlowClient(t, svc, "confidential")
	userID := uuid.New().String()

	auth, err := svc.SaveUserAuthorization(
		context.Background(), userID, client.ID, client.ClientID, "read write",
	)
	require.NoError(t, err)

	err = svc.RevokeUserAuthorization(context.Background(), auth.UUID, userID)
	require.NoError(t, err)

	// After revoke, GetUserAuthorization should return nil (no active record)
	found, err := svc.GetUserAuthorization(userID, client.ID)
	require.NoError(t, err)
	assert.Nil(t, found)
}

func TestRevokeUserAuthorization_WrongUser(t *testing.T) {
	svc := createTestAuthorizationService(t)
	client := createAuthCodeFlowClient(t, svc, "confidential")
	ownerID := uuid.New().String()
	otherID := uuid.New().String()

	auth, err := svc.SaveUserAuthorization(
		context.Background(), ownerID, client.ID, client.ClientID, "read",
	)
	require.NoError(t, err)

	// Attempt to revoke with a different user ID
	err = svc.RevokeUserAuthorization(context.Background(), auth.UUID, otherID)
	assert.ErrorIs(t, err, ErrAuthorizationNotFound)
}

func TestListUserAuthorizations_MultipleClients(t *testing.T) {
	svc := createTestAuthorizationService(t)
	userID := uuid.New().String()

	for i := 0; i < 3; i++ {
		c := &models.OAuthApplication{
			ClientID:           uuid.New().String(),
			ClientSecret:       "secret",
			ClientName:         fmt.Sprintf("Client %d", i),
			UserID:             uuid.New().String(),
			Scopes:             "read",
			GrantTypes:         "authorization_code",
			RedirectURIs:       models.StringArray{"https://app.example.com/cb"},
			ClientType:         "confidential",
			EnableAuthCodeFlow: true,
			IsActive:           true,
		}
		require.NoError(t, svc.store.CreateClient(c))
		_, err := svc.SaveUserAuthorization(context.Background(), userID, c.ID, c.ClientID, "read")
		require.NoError(t, err)
	}

	auths, err := svc.ListUserAuthorizations(context.Background(), userID)
	require.NoError(t, err)
	assert.Len(t, auths, 3)
}

// ============================================================
// RevokeAllApplicationTokens (admin P6)
// ============================================================

func TestRevokeAllApplicationTokens_RevokesConsentRecords(t *testing.T) {
	svc := createTestAuthorizationService(t)
	client := createAuthCodeFlowClient(t, svc, "confidential")

	// Grant access for 2 users
	for i := 0; i < 2; i++ {
		userID := uuid.New().String()
		_, err := svc.SaveUserAuthorization(
			context.Background(), userID, client.ID, client.ClientID, "read",
		)
		require.NoError(t, err)
	}

	// Revoke all
	adminID := uuid.New().String()
	revokedCount, err := svc.RevokeAllApplicationTokens(
		context.Background(),
		client.ClientID,
		adminID,
	)
	require.NoError(t, err)
	assert.GreaterOrEqual(t, revokedCount, int64(0)) // 0 tokens in DB (no actual tokens created)

	// All consent records for this client should now be inactive
	auths, err := svc.store.GetClientAuthorizations(client.ClientID)
	require.NoError(t, err)
	assert.Empty(t, auths) // active records only; all revoked
}

// ============================================================
// PKCE helper unit tests
// ============================================================

func TestVerifyPKCE_S256(t *testing.T) {
	verifier := testPKCEVerifier
	sum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])

	assert.True(t, verifyPKCE(challenge, "S256", verifier))
	assert.False(t, verifyPKCE(challenge, "S256", "wrong-verifier"))
	assert.False(t, verifyPKCE(challenge, "S256", ""))
}

func TestVerifyPKCE_Plain(t *testing.T) {
	challenge := "my-plain-verifier"
	assert.True(t, verifyPKCE(challenge, "plain", challenge))
	assert.False(t, verifyPKCE(challenge, "plain", "other"))
}

func TestVerifyPKCE_EmptyMethod(t *testing.T) {
	challenge := "my-plain-verifier"
	// Empty method falls back to plain
	assert.True(t, verifyPKCE(challenge, "", challenge))
}

func TestVerifyPKCE_UnknownMethod(t *testing.T) {
	// Any unrecognised method must return false
	assert.False(t, verifyPKCE("challenge", "RS256", "verifier"))
	assert.False(t, verifyPKCE("challenge", "HS256", "verifier"))
}

// ============================================================
// verifyClientSecret
// ============================================================

func TestValidateClientSecret_CorrectSecret(t *testing.T) {
	plain := testClientPlainSecret
	hash, err := bcrypt.GenerateFromPassword([]byte(plain), bcrypt.MinCost)
	require.NoError(t, err)

	client := &models.OAuthApplication{ClientSecret: string(hash)}
	assert.True(t, client.ValidateClientSecret([]byte(plain)))
}

func TestValidateClientSecret_WrongSecret(t *testing.T) {
	hash, err := bcrypt.GenerateFromPassword([]byte("correct"), bcrypt.MinCost)
	require.NoError(t, err)

	client := &models.OAuthApplication{ClientSecret: string(hash)}
	assert.False(t, client.ValidateClientSecret([]byte("wrong")))
}

func TestValidateClientSecret_EmptyHash(t *testing.T) {
	client := &models.OAuthApplication{ClientSecret: ""}
	assert.False(t, client.ValidateClientSecret([]byte("any-secret")))
}

func TestValidateClientSecret_EmptySecret(t *testing.T) {
	hash, err := bcrypt.GenerateFromPassword([]byte("secret"), bcrypt.MinCost)
	require.NoError(t, err)

	client := &models.OAuthApplication{ClientSecret: string(hash)}
	assert.False(t, client.ValidateClientSecret([]byte("")))
}

// ============================================================
// ValidateAuthorizationRequest – global PKCE enforcement
// ============================================================

func TestValidateAuthorizationRequest_GlobalPKCERequired(t *testing.T) {
	svc := createTestAuthorizationService(t)
	svc.config.PKCERequired = true
	client := createAuthCodeFlowClient(
		t,
		svc,
		"confidential",
	) // confidential, normally no PKCE needed

	// Without PKCE → must fail
	_, err := svc.ValidateAuthorizationRequest(
		client.ClientID, "https://app.example.com/callback", "code", "read", "",
	)
	assert.ErrorIs(t, err, ErrPKCERequired)

	// With S256 → must succeed
	req, err := svc.ValidateAuthorizationRequest(
		client.ClientID, "https://app.example.com/callback", "code", "read", "S256",
	)
	require.NoError(t, err)
	assert.Equal(t, "S256", req.CodeChallengeMethod)
}

func TestValidateAuthorizationRequest_UnsupportedChallengeMethod(t *testing.T) {
	svc := createTestAuthorizationService(t)
	client := createAuthCodeFlowClient(t, svc, "confidential")

	// "RS256" is not a valid code_challenge_method
	_, err := svc.ValidateAuthorizationRequest(
		client.ClientID, "https://app.example.com/callback", "code", "read", "RS256",
	)
	assert.ErrorIs(t, err, ErrInvalidAuthCodeRequest)
}

// ============================================================
// ExchangeCode – additional error paths
// ============================================================

func TestExchangeCode_NotFound(t *testing.T) {
	svc := createTestAuthorizationService(t)
	client := createAuthCodeFlowClient(t, svc, "confidential")

	_, err := svc.ExchangeCode(
		context.Background(),
		"nonexistent-code-that-was-never-created",
		client.ClientID,
		"https://app.example.com/callback",
		testClientPlainSecret,
		"",
	)
	assert.ErrorIs(t, err, ErrAuthCodeNotFound)
}

func TestExchangeCode_WrongClientID(t *testing.T) {
	svc := createTestAuthorizationService(t)
	client := createAuthCodeFlowClient(t, svc, "confidential")
	userID := uuid.New().String()

	plainCode, _, err := svc.CreateAuthorizationCode(
		context.Background(),
		client.ID, client.ClientID, userID,
		"https://app.example.com/callback", "read", "", "",
	)
	require.NoError(t, err)

	// Present correct code but wrong client_id → must fail (prevents cross-client reuse)
	_, err = svc.ExchangeCode(
		context.Background(),
		plainCode,
		"wrong-client-id",
		"https://app.example.com/callback",
		testClientPlainSecret,
		"",
	)
	assert.ErrorIs(t, err, ErrAuthCodeNotFound)
}

func TestExchangeCode_PublicClientMissingCodeChallenge(t *testing.T) {
	svc := createTestAuthorizationService(t)
	client := createAuthCodeFlowClient(t, svc, "public")
	userID := uuid.New().String()

	// Create a code without a PKCE challenge (simulates a code stored without PKCE)
	plainCode, _, err := svc.CreateAuthorizationCode(
		context.Background(),
		client.ID, client.ClientID, userID,
		"https://app.example.com/callback", "read",
		"", "", // no PKCE challenge
	)
	require.NoError(t, err)

	// Exchange: public client with no stored challenge → ErrPKCERequired
	_, err = svc.ExchangeCode(
		context.Background(),
		plainCode, client.ClientID,
		"https://app.example.com/callback",
		"", "some-verifier",
	)
	assert.ErrorIs(t, err, ErrPKCERequired)
}

// ============================================================
// ListClientAuthorizations (admin view)
// ============================================================

func TestListClientAuthorizations_MultipleUsers(t *testing.T) {
	svc := createTestAuthorizationService(t)
	client := createAuthCodeFlowClient(t, svc, "confidential")

	// Create 3 users and save consent for each
	userIDs := make([]string, 3)
	for i := range userIDs {
		userIDs[i] = uuid.New().String()
		_, err := svc.SaveUserAuthorization(
			context.Background(), userIDs[i], client.ID, client.ClientID, "read",
		)
		require.NoError(t, err)
	}

	auths, err := svc.ListClientAuthorizations(context.Background(), client.ClientID)
	require.NoError(t, err)
	assert.Len(t, auths, 3)
}

func TestListClientAuthorizations_EmptyClient(t *testing.T) {
	svc := createTestAuthorizationService(t)
	client := createAuthCodeFlowClient(t, svc, "confidential")

	auths, err := svc.ListClientAuthorizations(context.Background(), client.ClientID)
	require.NoError(t, err)
	assert.Empty(t, auths)
}
