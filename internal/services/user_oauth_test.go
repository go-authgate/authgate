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
	return NewUserService(db, nil, nil, AuthModeLocal, true, nil, c, 5*time.Minute)
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
		nil,
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
