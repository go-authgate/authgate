package services

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/go-authgate/authgate/internal/auth"
	"github.com/go-authgate/authgate/internal/cache"
	"github.com/go-authgate/authgate/internal/models"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
)

func newOAuthUserService(t *testing.T) *UserService {
	t.Helper()
	db := setupTestStore(t)
	c := cache.NewMemoryCache[models.User]()
	return NewUserService(
		db,
		nil,
		nil,
		AuthModeLocal,
		true,
		NewNoopAuditService(),
		c,
		5*time.Minute,
	)
}

func newOAuthToken() *oauth2.Token {
	return &oauth2.Token{AccessToken: "test-access-token"}
}

// TestAuthenticateWithOAuth_NewUser verifies that a brand-new OAuth user is
// created and returned successfully.
func TestAuthenticateWithOAuth_NewUser(t *testing.T) {
	svc := newOAuthUserService(t)

	info := &auth.OAuthUserInfo{
		ProviderUserID: uuid.New().String(),
		Username:       "alice",
		Email:          "alice@example.com",
		FullName:       "Alice Example",
	}

	user, err := svc.AuthenticateWithOAuth(context.Background(), "github", info, newOAuthToken())
	require.NoError(t, err)
	require.NotNil(t, user)
	assert.Equal(t, "alice@example.com", user.Email)
	assert.True(t, strings.HasPrefix(user.Username, "alice"))
}

// TestCreateUserWithOAuth_DuplicateEmail verifies that calling createUserWithOAuth
// twice with the same email returns a clear "email already in use" error rather
// than a raw DB error. This requires TranslateError: true in the gorm.Config so
// that gorm.ErrDuplicatedKey is surfaced from the transaction.
//
// Note: AuthenticateWithOAuth itself guards against this via GetUserByEmail before
// reaching createUserWithOAuth, so the duplicate path is tested directly here to
// exercise the gorm.ErrDuplicatedKey handling inside the transaction.
func TestCreateUserWithOAuth_DuplicateEmail(t *testing.T) {
	svc := newOAuthUserService(t)
	email := "dup@example.com"

	info1 := &auth.OAuthUserInfo{
		ProviderUserID: uuid.New().String(),
		Username:       "dupuser",
		Email:          email,
	}
	_, err := svc.createUserWithOAuth(context.Background(), "github", info1, newOAuthToken())
	require.NoError(t, err)

	// Second call with the same email bypasses the GetUserByEmail guard and
	// hits the UNIQUE constraint on the users table inside the transaction.
	info2 := &auth.OAuthUserInfo{
		ProviderUserID: uuid.New().String(),
		Username:       "dupuser2",
		Email:          email,
	}
	_, err = svc.createUserWithOAuth(context.Background(), "github", info2, newOAuthToken())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "email already in use",
		"expected 'email already in use' error, got: %v", err)
}

// TestAuthenticateWithOAuth_ExistingConnection verifies that re-authenticating
// with an existing OAuth connection updates the token and returns the user.
func TestAuthenticateWithOAuth_ExistingConnection(t *testing.T) {
	svc := newOAuthUserService(t)

	providerUserID := uuid.New().String()
	info := &auth.OAuthUserInfo{
		ProviderUserID: providerUserID,
		Username:       "bob",
		Email:          "bob@example.com",
	}

	// First login — creates user + connection.
	user1, err := svc.AuthenticateWithOAuth(context.Background(), "github", info, newOAuthToken())
	require.NoError(t, err)

	// Second login with same provider user ID — should reuse the connection.
	user2, err := svc.AuthenticateWithOAuth(context.Background(), "github", info, newOAuthToken())
	require.NoError(t, err)
	assert.Equal(t, user1.ID, user2.ID)
}

// TestAuthenticateWithOAuth_AutoRegisterDisabled verifies that when
// oauthAutoRegister is false, a new user is rejected.
func TestAuthenticateWithOAuth_AutoRegisterDisabled(t *testing.T) {
	db := setupTestStore(t)
	c := cache.NewMemoryCache[models.User]()
	svc := NewUserService(
		db,
		nil,
		nil,
		AuthModeLocal,
		false, /* autoRegister */
		NewNoopAuditService(),
		c,
		5*time.Minute,
	)

	info := &auth.OAuthUserInfo{
		ProviderUserID: uuid.New().String(),
		Username:       "carol",
		Email:          "carol@example.com",
	}

	_, err := svc.AuthenticateWithOAuth(context.Background(), "github", info, newOAuthToken())
	assert.ErrorIs(t, err, ErrOAuthAutoRegisterDisabled)
}

// TestAuthenticateWithOAuth_LinkExistingUser_VerifiedEmail verifies that when
// EmailVerified is true and a local user with the same email exists, the OAuth
// identity is auto-linked to the existing account.
func TestAuthenticateWithOAuth_LinkExistingUser_VerifiedEmail(t *testing.T) {
	svc := newOAuthUserService(t)

	// Create an existing user first via a different provider.
	existingInfo := &auth.OAuthUserInfo{
		ProviderUserID: uuid.New().String(),
		Username:       "existing",
		Email:          "shared@example.com",
		EmailVerified:  true,
	}
	user1, err := svc.AuthenticateWithOAuth(
		context.Background(),
		"github",
		existingInfo,
		newOAuthToken(),
	)
	require.NoError(t, err)

	// Now authenticate via a different provider with a verified email matching
	// the existing user — should auto-link rather than create a new account.
	linkInfo := &auth.OAuthUserInfo{
		ProviderUserID: uuid.New().String(),
		Username:       "attacker",
		Email:          "shared@example.com",
		EmailVerified:  true,
	}
	user2, err := svc.AuthenticateWithOAuth(
		context.Background(),
		"microsoft",
		linkInfo,
		newOAuthToken(),
	)
	require.NoError(t, err)
	assert.Equal(t, user1.ID, user2.ID, "should link to existing user, not create a new one")
}

// TestAuthenticateWithOAuth_SkipLinkUnverifiedEmail verifies that when
// EmailVerified is false and a local user with the same email exists, the
// OAuth identity is NOT linked to the existing account. The attempt to create
// a new account also fails because of the UNIQUE email constraint, which is
// the correct security behaviour — the attacker cannot hijack the victim's
// account.
func TestAuthenticateWithOAuth_SkipLinkUnverifiedEmail(t *testing.T) {
	svc := newOAuthUserService(t)

	// Create an existing user.
	existingInfo := &auth.OAuthUserInfo{
		ProviderUserID: uuid.New().String(),
		Username:       "victim",
		Email:          "victim@example.com",
		EmailVerified:  true,
	}
	_, err := svc.AuthenticateWithOAuth(
		context.Background(),
		"github",
		existingInfo,
		newOAuthToken(),
	)
	require.NoError(t, err)

	// Attacker authenticates via a provider that does NOT verify email.
	attackerInfo := &auth.OAuthUserInfo{
		ProviderUserID: uuid.New().String(),
		Username:       "attacker",
		Email:          "victim@example.com",
		EmailVerified:  false,
	}
	_, err = svc.AuthenticateWithOAuth(context.Background(), "gitea", attackerInfo, newOAuthToken())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "email already in use",
		"unverified email must NOT auto-link; duplicate email prevents new account")
}

// TestAuthenticateWithOAuth_UnverifiedEmail_AutoRegisterDisabled verifies that
// when EmailVerified is false, a matching local user exists, and auto-register
// is disabled, the authentication returns ErrOAuthEmailNotVerified.
func TestAuthenticateWithOAuth_UnverifiedEmail_AutoRegisterDisabled(t *testing.T) {
	db := setupTestStore(t)
	c := cache.NewMemoryCache[models.User]()

	// First create a user with auto-register enabled.
	svcEnabled := NewUserService(
		db,
		nil,
		nil,
		AuthModeLocal,
		true,
		NewNoopAuditService(),
		c,
		5*time.Minute,
	)
	existingInfo := &auth.OAuthUserInfo{
		ProviderUserID: uuid.New().String(),
		Username:       "localuser",
		Email:          "local@example.com",
		EmailVerified:  true,
	}
	_, err := svcEnabled.AuthenticateWithOAuth(
		context.Background(),
		"github",
		existingInfo,
		newOAuthToken(),
	)
	require.NoError(t, err)

	// Now use a service with auto-register disabled.
	svcDisabled := NewUserService(
		db,
		nil,
		nil,
		AuthModeLocal,
		false,
		NewNoopAuditService(),
		c,
		5*time.Minute,
	)
	attackerInfo := &auth.OAuthUserInfo{
		ProviderUserID: uuid.New().String(),
		Username:       "attacker",
		Email:          "local@example.com",
		EmailVerified:  false,
	}
	_, err = svcDisabled.AuthenticateWithOAuth(
		context.Background(),
		"gitea",
		attackerInfo,
		newOAuthToken(),
	)
	assert.ErrorIs(t, err, ErrOAuthEmailNotVerified)
}
