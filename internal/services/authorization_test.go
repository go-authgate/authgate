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
	testClientPlainSecret = "test-plain-secret" //nolint:gosec // G101: false positive, this is a test secret string, not a hardcoded credential
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
	return NewAuthorizationService(
		s,
		cfg,
		NewNoopAuditService(),
		nil,
		NewClientService(s, NewNoopAuditService(), nil, 0, nil, 0),
	)
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
		Status:             models.ClientStatusActive,
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

	req, err := svc.ValidateAuthorizationRequest(context.Background(),
		client.ClientID,
		"https://app.example.com/callback",
		"code",
		"read",
		"", "", "")

	require.NoError(t, err)
	assert.Equal(t, client.ClientID, req.Client.ClientID)
	assert.Equal(t, "read", req.Scopes)
}

func TestValidateAuthorizationRequest_DefaultScope(t *testing.T) {
	svc := createTestAuthorizationService(t)
	client := createAuthCodeFlowClient(t, svc, "confidential")

	req, err := svc.ValidateAuthorizationRequest(context.Background(),
		client.ClientID, "https://app.example.com/callback", "code", "", "", "", "")

	require.NoError(t, err)
	// Empty scope should fall back to the client's full scope
	assert.Equal(t, client.Scopes, req.Scopes)
}

func TestValidateAuthorizationRequest_InvalidResponseType(t *testing.T) {
	svc := createTestAuthorizationService(t)
	client := createAuthCodeFlowClient(t, svc, "confidential")

	_, err := svc.ValidateAuthorizationRequest(context.Background(),
		client.ClientID, "https://app.example.com/callback", "token", "", "", "", "")
	assert.ErrorIs(t, err, ErrUnsupportedResponseType)
}

func TestValidateAuthorizationRequest_UnknownClient(t *testing.T) {
	svc := createTestAuthorizationService(t)

	_, err := svc.ValidateAuthorizationRequest(context.Background(),
		"nonexistent", "https://app.example.com/callback", "code", "", "", "", "")
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
		Status:             models.ClientStatusActive,
	}
	require.NoError(t, svc.store.CreateClient(client))

	_, err := svc.ValidateAuthorizationRequest(context.Background(),
		client.ClientID, "https://app.example.com/callback", "code", "", "", "", "")
	assert.ErrorIs(t, err, ErrUnauthorizedClient)
}

func TestValidateAuthorizationRequest_InvalidRedirectURI(t *testing.T) {
	svc := createTestAuthorizationService(t)
	client := createAuthCodeFlowClient(t, svc, "confidential")

	_, err := svc.ValidateAuthorizationRequest(context.Background(),
		client.ClientID, "https://evil.example.com/callback", "code", "", "", "", "")
	assert.ErrorIs(t, err, ErrInvalidRedirectURI)
}

func TestValidateAuthorizationRequest_InvalidScope(t *testing.T) {
	svc := createTestAuthorizationService(t)
	client := createAuthCodeFlowClient(t, svc, "confidential")

	_, err := svc.ValidateAuthorizationRequest(context.Background(),
		client.ClientID, "https://app.example.com/callback", "code", "admin", "", "", "")
	assert.ErrorIs(t, err, ErrInvalidAuthCodeScope)
}

func TestValidateAuthorizationRequest_PublicClientRequiresPKCE(t *testing.T) {
	svc := createTestAuthorizationService(t)
	client := createAuthCodeFlowClient(t, svc, "public")

	// No code_challenge_method → should fail for public client
	_, err := svc.ValidateAuthorizationRequest(context.Background(),
		client.ClientID, "https://app.example.com/callback", "code", "read", "", "", "")
	assert.ErrorIs(t, err, ErrPKCERequired)
}

func TestValidateAuthorizationRequest_PKCEPlainRejected(t *testing.T) {
	svc := createTestAuthorizationService(t)
	client := createAuthCodeFlowClient(t, svc, "public")

	// "plain" method must be rejected (only S256 is accepted)
	_, err := svc.ValidateAuthorizationRequest(context.Background(),
		client.ClientID, "https://app.example.com/callback", "code", "read", "", "plain", "")
	assert.ErrorIs(t, err, ErrInvalidAuthCodeRequest)
}

func TestValidateAuthorizationRequest_PublicClientWithPKCE(t *testing.T) {
	svc := createTestAuthorizationService(t)
	client := createAuthCodeFlowClient(t, svc, "public")

	req, err := svc.ValidateAuthorizationRequest(context.Background(),
		client.ClientID, "https://app.example.com/callback", "code", "read", "", "S256", "")
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
		CreateAuthorizationCodeParams{
			ApplicationID: client.ID,
			ClientID:      client.ClientID,
			UserID:        userID,
			RedirectURI:   "https://app.example.com/callback",
			Scopes:        "read write",
		},
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
		CreateAuthorizationCodeParams{
			ApplicationID:       client.ID,
			ClientID:            client.ClientID,
			UserID:              userID,
			RedirectURI:         "https://app.example.com/callback",
			Scopes:              "read",
			CodeChallenge:       challenge,
			CodeChallengeMethod: "S256",
		},
	)

	require.NoError(t, err)
	assert.Equal(t, challenge, record.CodeChallenge)
	assert.Equal(t, "S256", record.CodeChallengeMethod)
}

// ============================================================
// ExchangeCode
// ============================================================

// TestExchangeCode_Resource_SubsetAllowed asserts that a token-time resource
// that is a strict subset of the authorize-time grant is accepted and the
// code is consumed.
func TestExchangeCode_Resource_SubsetAllowed(t *testing.T) {
	svc := createTestAuthorizationService(t)
	client := createAuthCodeFlowClient(t, svc, "confidential")
	userID := uuid.New().String()

	plainCode, _, err := svc.CreateAuthorizationCode(
		context.Background(),
		CreateAuthorizationCodeParams{
			ApplicationID: client.ID,
			ClientID:      client.ClientID,
			UserID:        userID,
			RedirectURI:   "https://app.example.com/callback",
			Scopes:        "read",
			Resource: []string{
				"https://mcp1.example.com",
				"https://mcp2.example.com",
			},
		},
	)
	require.NoError(t, err)

	authCode, err := svc.ExchangeCode(
		context.Background(),
		plainCode,
		client.ClientID,
		"https://app.example.com/callback",
		testClientPlainSecret,
		"",
		[]string{"https://mcp1.example.com"},
	)
	require.NoError(t, err)
	require.NotNil(t, authCode)
	assert.True(t, authCode.IsUsed())
}

// TestExchangeCode_Resource_SupersetRejected asserts that a token-time
// resource not in the authorize-time grant is rejected with ErrInvalidTarget
// AND the authorization code is NOT consumed (so a typo doesn't burn the
// single-use code).
func TestExchangeCode_Resource_SupersetRejected(t *testing.T) {
	svc := createTestAuthorizationService(t)
	client := createAuthCodeFlowClient(t, svc, "confidential")
	userID := uuid.New().String()

	plainCode, record, err := svc.CreateAuthorizationCode(
		context.Background(),
		CreateAuthorizationCodeParams{
			ApplicationID: client.ID,
			ClientID:      client.ClientID,
			UserID:        userID,
			RedirectURI:   "https://app.example.com/callback",
			Scopes:        "read",
			Resource:      []string{"https://mcp.example.com"},
		},
	)
	require.NoError(t, err)

	_, err = svc.ExchangeCode(
		context.Background(),
		plainCode,
		client.ClientID,
		"https://app.example.com/callback",
		testClientPlainSecret,
		"",
		[]string{"https://forbidden.example.com"},
	)
	require.ErrorIs(t, err, ErrInvalidTarget)

	// The code must remain unconsumed: a malformed `resource` should never
	// burn the single-use authorization code.
	reloaded, err := svc.store.GetAuthorizationCodeByHash(record.CodeHash)
	require.NoError(t, err)
	assert.False(
		t, reloaded.IsUsed(),
		"authorization code must remain unconsumed after invalid_target",
	)
}

// TestExchangeCode_Resource_EmptyGrantRejectsRequest asserts that when
// /authorize bound no resource at all, /token cannot widen by passing one.
// This matches the refresh-grant rule and prevents quietly granting a
// specific audience after a no-audience consent.
func TestExchangeCode_Resource_EmptyGrantRejectsRequest(t *testing.T) {
	svc := createTestAuthorizationService(t)
	client := createAuthCodeFlowClient(t, svc, "confidential")
	userID := uuid.New().String()

	plainCode, _, err := svc.CreateAuthorizationCode(
		context.Background(),
		CreateAuthorizationCodeParams{
			ApplicationID: client.ID,
			ClientID:      client.ClientID,
			UserID:        userID,
			RedirectURI:   "https://app.example.com/callback",
			Scopes:        "read",
			// No Resource bound at authorize-time.
		},
	)
	require.NoError(t, err)

	_, err = svc.ExchangeCode(
		context.Background(),
		plainCode,
		client.ClientID,
		"https://app.example.com/callback",
		testClientPlainSecret,
		"",
		[]string{"https://mcp.example.com"},
	)
	require.ErrorIs(t, err, ErrInvalidTarget)
}

func TestExchangeCode_Success_ConfidentialClient(t *testing.T) {
	svc := createTestAuthorizationService(t)
	client := createAuthCodeFlowClient(t, svc, "confidential")
	userID := uuid.New().String()

	plainCode, _, err := svc.CreateAuthorizationCode(
		context.Background(),
		CreateAuthorizationCodeParams{
			ApplicationID: client.ID,
			ClientID:      client.ClientID,
			UserID:        userID,
			RedirectURI:   "https://app.example.com/callback",
			Scopes:        "read write",
		},
	)
	require.NoError(t, err)

	authCode, err := svc.ExchangeCode(
		context.Background(),
		plainCode,
		client.ClientID,
		"https://app.example.com/callback",
		testClientPlainSecret,
		"",
		nil,
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
		CreateAuthorizationCodeParams{
			ApplicationID:       client.ID,
			ClientID:            client.ClientID,
			UserID:              userID,
			RedirectURI:         "https://app.example.com/callback",
			Scopes:              "read",
			CodeChallenge:       challenge,
			CodeChallengeMethod: "S256",
		},
	)
	require.NoError(t, err)

	_, err = svc.ExchangeCode(
		context.Background(),
		plainCode, client.ClientID,
		"https://app.example.com/callback",
		"", verifier,
		nil,
	)
	require.NoError(t, err)
}

func TestExchangeCode_ReplayAttack(t *testing.T) {
	svc := createTestAuthorizationService(t)
	client := createAuthCodeFlowClient(t, svc, "confidential")
	userID := uuid.New().String()

	plainCode, _, err := svc.CreateAuthorizationCode(
		context.Background(),
		CreateAuthorizationCodeParams{
			ApplicationID: client.ID,
			ClientID:      client.ClientID,
			UserID:        userID,
			RedirectURI:   "https://app.example.com/callback",
			Scopes:        "read",
		},
	)
	require.NoError(t, err)

	// First exchange succeeds
	_, err = svc.ExchangeCode(context.Background(), plainCode, client.ClientID,
		"https://app.example.com/callback", testClientPlainSecret, "", nil)
	require.NoError(t, err)

	// Second exchange with same code must fail
	_, err = svc.ExchangeCode(context.Background(), plainCode, client.ClientID,
		"https://app.example.com/callback", testClientPlainSecret, "", nil)
	assert.ErrorIs(t, err, ErrAuthCodeAlreadyUsed)
}

func TestExchangeCode_ExpiredCode(t *testing.T) {
	svc := createTestAuthorizationService(t)
	svc.config.AuthCodeExpiration = -1 * time.Second // already expired
	client := createAuthCodeFlowClient(t, svc, "confidential")
	userID := uuid.New().String()

	plainCode, _, err := svc.CreateAuthorizationCode(
		context.Background(),
		CreateAuthorizationCodeParams{
			ApplicationID: client.ID,
			ClientID:      client.ClientID,
			UserID:        userID,
			RedirectURI:   "https://app.example.com/callback",
			Scopes:        "read",
		},
	)
	require.NoError(t, err)

	_, err = svc.ExchangeCode(context.Background(), plainCode, client.ClientID,
		"https://app.example.com/callback", testClientPlainSecret, "", nil)
	assert.ErrorIs(t, err, ErrAuthCodeExpired)
}

func TestExchangeCode_WrongRedirectURI(t *testing.T) {
	svc := createTestAuthorizationService(t)
	client := createAuthCodeFlowClient(t, svc, "confidential")
	userID := uuid.New().String()

	plainCode, _, err := svc.CreateAuthorizationCode(
		context.Background(),
		CreateAuthorizationCodeParams{
			ApplicationID: client.ID,
			ClientID:      client.ClientID,
			UserID:        userID,
			RedirectURI:   "https://app.example.com/callback",
			Scopes:        "read",
		},
	)
	require.NoError(t, err)

	_, err = svc.ExchangeCode(context.Background(), plainCode, client.ClientID,
		"https://other.example.com/callback", testClientPlainSecret, "", nil)
	assert.ErrorIs(t, err, ErrInvalidRedirectURI)
}

func TestExchangeCode_WrongClientSecret(t *testing.T) {
	svc := createTestAuthorizationService(t)
	client := createAuthCodeFlowClient(t, svc, "confidential")
	userID := uuid.New().String()

	plainCode, _, err := svc.CreateAuthorizationCode(
		context.Background(),
		CreateAuthorizationCodeParams{
			ApplicationID: client.ID,
			ClientID:      client.ClientID,
			UserID:        userID,
			RedirectURI:   "https://app.example.com/callback",
			Scopes:        "read",
		},
	)
	require.NoError(t, err)

	_, err = svc.ExchangeCode(context.Background(), plainCode, client.ClientID,
		"https://app.example.com/callback", "wrong-secret", "", nil)
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
		CreateAuthorizationCodeParams{
			ApplicationID:       client.ID,
			ClientID:            client.ClientID,
			UserID:              userID,
			RedirectURI:         "https://app.example.com/callback",
			Scopes:              "read",
			CodeChallenge:       challenge,
			CodeChallengeMethod: "S256",
		},
	)
	require.NoError(t, err)

	_, err = svc.ExchangeCode(context.Background(), plainCode, client.ClientID,
		"https://app.example.com/callback", "", "wrong-verifier", nil)
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
		context.Background(), userID, client.ID, client.ClientID, "read", nil,
	)
	require.NoError(t, err)
	assert.True(t, auth.IsActive)
	assert.Equal(t, "read", auth.Scopes)
	firstUUID := auth.UUID

	// Second save with expanded scopes – should update, not duplicate
	auth2, err := svc.SaveUserAuthorization(
		context.Background(), userID, client.ID, client.ClientID, "read write", nil,
	)
	require.NoError(t, err)
	assert.Equal(t, "read write", auth2.Scopes)
	assert.True(t, auth2.IsActive)
	// UUID may differ (new UUID on upsert) but there should still be only one record
	_ = firstUUID
}

// TestSaveUserAuthorization_PersistsResource confirms that the resource set
// supplied at consent time is persisted on the row and survives the upsert
// round-trip — this is what lets the GET-side remembered-consent shortcut do
// an exact resource-set match before auto-approving (and what gives
// resource-bound tokens an AuthorizationID for cascade-revoke).
func TestSaveUserAuthorization_PersistsResource(t *testing.T) {
	svc := createTestAuthorizationService(t)
	client := createAuthCodeFlowClient(t, svc, "confidential")
	userID := uuid.New().String()

	resource := []string{"https://mcp.example.com"}
	saved, err := svc.SaveUserAuthorization(
		context.Background(), userID, client.ID, client.ClientID, "read", resource,
	)
	require.NoError(t, err)
	assert.Equal(t, models.StringArray(resource), saved.Resource)

	// Re-load to confirm the resource survives the DB round-trip.
	loaded, err := svc.GetUserAuthorization(userID, client.ID)
	require.NoError(t, err)
	require.NotNil(t, loaded)
	assert.Equal(t, models.StringArray(resource), loaded.Resource)
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
		context.Background(), userID, client.ID, client.ClientID, "read", nil,
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
		context.Background(), userID, client.ID, client.ClientID, "read write", nil,
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
		context.Background(), ownerID, client.ID, client.ClientID, "read", nil,
	)
	require.NoError(t, err)

	// Attempt to revoke with a different user ID
	err = svc.RevokeUserAuthorization(context.Background(), auth.UUID, otherID)
	assert.ErrorIs(t, err, ErrAuthorizationNotFound)
}

func TestListUserAuthorizations_MultipleClients(t *testing.T) {
	svc := createTestAuthorizationService(t)
	userID := uuid.New().String()

	for i := range 3 {
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
			Status:             models.ClientStatusActive,
		}
		require.NoError(t, svc.store.CreateClient(c))
		_, err := svc.SaveUserAuthorization(
			context.Background(), userID, c.ID, c.ClientID, "read", nil,
		)
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
	for range 2 {
		userID := uuid.New().String()
		_, err := svc.SaveUserAuthorization(
			context.Background(), userID, client.ID, client.ClientID, "read", nil,
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

func TestVerifyPKCE_PlainMethodRejected(t *testing.T) {
	challenge := "my-plain-verifier"
	// "plain" method is now rejected (only S256 accepted)
	assert.False(t, verifyPKCE(challenge, "plain", challenge))
	assert.False(t, verifyPKCE(challenge, "PLAIN", challenge))
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
	_, err := svc.ValidateAuthorizationRequest(context.Background(),
		client.ClientID, "https://app.example.com/callback", "code", "read", "", "", "")
	require.ErrorIs(t, err, ErrPKCERequired)

	// With S256 → must succeed
	req, err := svc.ValidateAuthorizationRequest(context.Background(),
		client.ClientID, "https://app.example.com/callback", "code", "read", "", "S256", "")
	require.NoError(t, err)
	assert.Equal(t, "S256", req.CodeChallengeMethod)
}

func TestValidateAuthorizationRequest_UnsupportedChallengeMethod(t *testing.T) {
	svc := createTestAuthorizationService(t)
	client := createAuthCodeFlowClient(t, svc, "confidential")

	// "RS256" is not a valid code_challenge_method
	_, err := svc.ValidateAuthorizationRequest(context.Background(),
		client.ClientID, "https://app.example.com/callback", "code", "read", "", "RS256", "")
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
		nil,
	)
	assert.ErrorIs(t, err, ErrAuthCodeNotFound)
}

func TestExchangeCode_WrongClientID(t *testing.T) {
	svc := createTestAuthorizationService(t)
	client := createAuthCodeFlowClient(t, svc, "confidential")
	userID := uuid.New().String()

	plainCode, _, err := svc.CreateAuthorizationCode(
		context.Background(),
		CreateAuthorizationCodeParams{
			ApplicationID: client.ID,
			ClientID:      client.ClientID,
			UserID:        userID,
			RedirectURI:   "https://app.example.com/callback",
			Scopes:        "read",
		},
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
		nil,
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
		CreateAuthorizationCodeParams{
			ApplicationID: client.ID,
			ClientID:      client.ClientID,
			UserID:        userID,
			RedirectURI:   "https://app.example.com/callback",
			Scopes:        "read",
		},
	)
	require.NoError(t, err)

	// Exchange: public client with no stored challenge → ErrPKCERequired
	_, err = svc.ExchangeCode(
		context.Background(),
		plainCode, client.ClientID,
		"https://app.example.com/callback",
		"", "some-verifier",
		nil,
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
			context.Background(), userIDs[i], client.ID, client.ClientID, "read", nil,
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

// ============================================================
// ValidateClientRedirect (deny-path lightweight validator)
// ============================================================

// TestValidateClientRedirect_SkipsPKCEAndScope confirms the lightweight
// validator deliberately omits scope and PKCE checks (the Deny consent form
// posts neither). It must still validate client existence + redirect_uri
// registration to keep the open-redirect closure that the deny path relies on.
func TestValidateClientRedirect_SkipsPKCEAndScope(t *testing.T) {
	svc := createTestAuthorizationService(t)
	// Public client → full ValidateAuthorizationRequest demands PKCE; this
	// lightweight validator must NOT demand it.
	client := createAuthCodeFlowClient(t, svc, "public")

	uri, err := svc.ValidateClientRedirect(
		context.Background(),
		client.ClientID,
		"https://app.example.com/callback",
	)
	require.NoError(t, err)
	assert.Equal(t, "https://app.example.com/callback", uri)
}

func TestValidateClientRedirect_RejectsUnregisteredRedirectURI(t *testing.T) {
	svc := createTestAuthorizationService(t)
	client := createAuthCodeFlowClient(t, svc, "confidential")

	_, err := svc.ValidateClientRedirect(
		context.Background(),
		client.ClientID,
		"https://evil.example.com/exfil",
	)
	assert.ErrorIs(t, err, ErrInvalidRedirectURI)
}

func TestValidateClientRedirect_RejectsUnknownClient(t *testing.T) {
	svc := createTestAuthorizationService(t)

	_, err := svc.ValidateClientRedirect(
		context.Background(),
		"nonexistent-client",
		"https://app.example.com/callback",
	)
	assert.ErrorIs(t, err, ErrUnauthorizedClient)
}

// ============================================================
// SaveConsentAndAuthorizeDeviceCode (atomic save + authorize)
// ============================================================

// createTestDeviceCode persists a fresh, unauthorized DeviceCode for the given
// client. Returns the model with .ID populated for use in the orchestration
// test.
func createTestDeviceCode(
	t *testing.T,
	svc *AuthorizationService,
	clientID string,
) *models.DeviceCode {
	t.Helper()
	uc := "ABCD" + uuid.New().String()[:4]
	dc := &models.DeviceCode{
		DeviceCodeHash: "hash-" + uuid.New().String(),
		DeviceCodeSalt: "salt-" + uuid.New().String()[:8],
		DeviceCodeID:   uuid.New().String()[:8],
		UserCode:       uc,
		ClientID:       clientID,
		Scopes:         "read",
		ExpiresAt:      time.Now().Add(30 * time.Minute),
		Interval:       5,
	}
	require.NoError(t, svc.store.CreateDeviceCode(dc))
	return dc
}

// TestSaveConsentAndAuthorizeDeviceCode_HappyPath asserts the atomic
// orchestration commits both writes: the device code becomes authorized AND
// the user authorization is persisted.
func TestSaveConsentAndAuthorizeDeviceCode_HappyPath(t *testing.T) {
	svc := createTestAuthorizationService(t)
	client := createAuthCodeFlowClient(t, svc, "confidential")
	dc := createTestDeviceCode(t, svc, client.ClientID)

	userID := uuid.New().String()
	ua, err := svc.SaveConsentAndAuthorizeDeviceCode(
		context.Background(),
		userID, client.ID, client.ClientID,
		"read",
		[]string{"https://mcp.example.com"},
		dc,
		"user-alice",
	)
	require.NoError(t, err)
	require.NotNil(t, ua)
	assert.Equal(t, "read", ua.Scopes)
	assert.Equal(t, models.StringArray{"https://mcp.example.com"}, ua.Resource)

	// Device code is now authorized for this user.
	authorized, err := svc.store.GetDeviceCodeByUserCode(dc.UserCode)
	require.NoError(t, err)
	assert.True(t, authorized.Authorized)
	assert.Equal(t, userID, authorized.UserID)

	// Consent is queryable by (user, app).
	loaded, err := svc.GetUserAuthorization(userID, client.ID)
	require.NoError(t, err)
	require.NotNil(t, loaded)
	assert.Equal(t, ua.UUID, loaded.UUID)
}

// TestSaveConsentAndAuthorizeDeviceCode_RollsBackOnExpiry asserts the
// transactional expiry re-check: store.AuthorizeDeviceCode does not filter
// on expires_at, so a code that expires between the handler's
// GetClientByUserCode lookup and the transactional commit could otherwise
// be authorized + granted consent. The in-txn dc.IsExpired() check catches
// this and the entire transaction (including the consent upsert) rolls back.
func TestSaveConsentAndAuthorizeDeviceCode_RollsBackOnExpiry(t *testing.T) {
	svc := createTestAuthorizationService(t)
	client := createAuthCodeFlowClient(t, svc, "confidential")
	dc := createTestDeviceCode(t, svc, client.ClientID)

	// Backdate the expiry so the transactional check fires.
	dc.ExpiresAt = time.Now().Add(-1 * time.Second)

	userID := uuid.New().String()
	_, err := svc.SaveConsentAndAuthorizeDeviceCode(
		context.Background(),
		userID, client.ID, client.ClientID,
		"read", nil,
		dc,
		"user-carol",
	)
	require.ErrorIs(t, err, ErrDeviceCodeExpired)

	// Critical invariant: the upsert is rolled back — no stale consent left.
	leaked, err := svc.GetUserAuthorization(userID, client.ID)
	require.NoError(t, err)
	assert.Nil(t, leaked,
		"consent must roll back when expiry check inside the txn fails")

	// And the device code is NOT marked authorized.
	dcAfter, err := svc.store.GetDeviceCodeByUserCode(dc.UserCode)
	require.NoError(t, err)
	assert.False(t, dcAfter.Authorized,
		"expired device code must not be authorized")
}

// TestSaveConsentAndAuthorizeDeviceCode_RollsBackOnAlreadyAuthorized is the
// regression test for the stale-consent leak Copilot flagged: when
// AuthorizeDeviceCode fails (here, because a concurrent submit already
// authorized the code), the UserAuthorization upsert MUST roll back. Without
// the transactional wrapper, a stale consent row would persist and could be
// auto-approved on a later request (or shown at /account/authorizations as a
// grant the user never actually completed).
func TestSaveConsentAndAuthorizeDeviceCode_RollsBackOnAlreadyAuthorized(t *testing.T) {
	svc := createTestAuthorizationService(t)
	client := createAuthCodeFlowClient(t, svc, "confidential")
	dc := createTestDeviceCode(t, svc, client.ClientID)

	// Simulate a concurrent submit winning the AuthorizeDeviceCode race by
	// authorizing the code via the store directly. The next orchestrated call
	// MUST fail and leave NO consent behind.
	winnerID := uuid.New().String()
	require.NoError(t, svc.store.AuthorizeDeviceCode(dc.ID, winnerID))

	loserID := uuid.New().String()
	_, err := svc.SaveConsentAndAuthorizeDeviceCode(
		context.Background(),
		loserID, client.ID, client.ClientID,
		"read", nil,
		dc,
		"user-bob",
	)
	require.ErrorIs(t, err, ErrDeviceCodeAlreadyAuthorized)

	// Critical invariant: the loser's consent must NOT exist. If the upsert
	// were allowed to commit before AuthorizeDeviceCode failed, this lookup
	// would return a stale row.
	leaked, err := svc.GetUserAuthorization(loserID, client.ID)
	require.NoError(t, err)
	assert.Nil(t, leaked, "consent must roll back when AuthorizeDeviceCode fails")
}
