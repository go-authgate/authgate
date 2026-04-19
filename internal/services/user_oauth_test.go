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
		EmailVerified:  true,
	}

	user, err := svc.AuthenticateWithOAuth(context.Background(), "github", info, newOAuthToken())
	require.NoError(t, err)
	require.NotNil(t, user)
	assert.Equal(t, "alice@example.com", user.Email)
	assert.True(t, strings.HasPrefix(user.Username, "alice"))
	assert.True(t, user.EmailVerified, "verified OAuth email must set User.EmailVerified")
}

// TestAuthenticateWithOAuth_NewUser_UnverifiedEmail verifies that a new OAuth
// user from a provider that doesn't verify email is stored with
// EmailVerified=false so ID tokens don't falsely assert verification.
func TestAuthenticateWithOAuth_NewUser_UnverifiedEmail(t *testing.T) {
	svc := newOAuthUserService(t)

	info := &auth.OAuthUserInfo{
		ProviderUserID: uuid.New().String(),
		Username:       "dan",
		Email:          "dan@example.com",
		EmailVerified:  false,
	}

	user, err := svc.AuthenticateWithOAuth(context.Background(), "gitea", info, newOAuthToken())
	require.NoError(t, err)
	assert.False(t, user.EmailVerified)
}

// TestAuthenticateWithOAuth_LinkPromotesEmailVerified verifies that when an
// unverified local user links to a provider that verifies the email, the
// User.EmailVerified flag is promoted to true.
func TestAuthenticateWithOAuth_LinkPromotesEmailVerified(t *testing.T) {
	svc := newOAuthUserService(t)

	// Start as an unverified-email local user created via a non-verifying provider.
	unverified := &auth.OAuthUserInfo{
		ProviderUserID: uuid.New().String(),
		Username:       "eve",
		Email:          "eve@example.com",
		EmailVerified:  false,
	}
	created, err := svc.AuthenticateWithOAuth(
		context.Background(),
		"gitea",
		unverified,
		newOAuthToken(),
	)
	require.NoError(t, err)
	require.False(t, created.EmailVerified)

	// Same email comes back via a verifying provider: link + promote.
	verified := &auth.OAuthUserInfo{
		ProviderUserID: uuid.New().String(),
		Username:       "eve",
		Email:          "eve@example.com",
		EmailVerified:  true,
	}
	linked, err := svc.AuthenticateWithOAuth(
		context.Background(),
		"github",
		verified,
		newOAuthToken(),
	)
	require.NoError(t, err)
	assert.Equal(t, created.ID, linked.ID)
	assert.True(t, linked.EmailVerified, "linking a verified provider must promote EmailVerified")
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

// TestAuthenticateWithOAuth_ExistingConnection_PromotesEmailVerified verifies
// that re-authenticating via an already-linked OAuth connection promotes
// User.EmailVerified to true when the provider reports a verified email that
// matches the stored address. This covers the migration and steady-state case
// where existing OAuth users default to EmailVerified=false (e.g., rows added
// before the column existed) and must self-heal on next login.
func TestAuthenticateWithOAuth_ExistingConnection_PromotesEmailVerified(t *testing.T) {
	svc := newOAuthUserService(t)

	providerUserID := uuid.New().String()
	info := &auth.OAuthUserInfo{
		ProviderUserID: providerUserID,
		Username:       "frank",
		Email:          "frank@example.com",
		EmailVerified:  true,
	}

	// Seed a user + connection as if created via a provider that didn't yet
	// expose verification, leaving EmailVerified=false.
	user, err := svc.AuthenticateWithOAuth(
		context.Background(),
		"github",
		&auth.OAuthUserInfo{
			ProviderUserID: providerUserID,
			Username:       "frank",
			Email:          "frank@example.com",
			EmailVerified:  false,
		},
		newOAuthToken(),
	)
	require.NoError(t, err)
	require.False(t, user.EmailVerified)

	// Re-authenticate via the same connection with a verified flag — the
	// stored flag must be promoted.
	promoted, err := svc.AuthenticateWithOAuth(
		context.Background(),
		"github",
		info,
		newOAuthToken(),
	)
	require.NoError(t, err)
	assert.Equal(t, user.ID, promoted.ID)
	assert.True(
		t,
		promoted.EmailVerified,
		"existing OAuth connection must promote EmailVerified when provider confirms the same email",
	)
}

// TestAuthenticateWithOAuth_ExistingConnection_LegacyWhitespaceEmail_Promotes
// verifies that a pre-existing user row whose stored Email carries incidental
// whitespace can still be promoted to EmailVerified=true when the (trimmed)
// provider email matches — i.e. normalization is applied on both sides of
// the comparison so legacy rows self-heal.
func TestAuthenticateWithOAuth_ExistingConnection_LegacyWhitespaceEmail_Promotes(
	t *testing.T,
) {
	svc := newOAuthUserService(t)

	providerUserID := uuid.New().String()
	// Seed user+connection via the normal (normalized) path.
	user, err := svc.AuthenticateWithOAuth(
		context.Background(),
		"github",
		&auth.OAuthUserInfo{
			ProviderUserID: providerUserID,
			Username:       "heidi",
			Email:          "heidi@example.com",
			EmailVerified:  false,
		},
		newOAuthToken(),
	)
	require.NoError(t, err)

	// Simulate a legacy row whose stored email carries incidental whitespace.
	user.Email = "  heidi@example.com  "
	require.NoError(t, svc.store.UpdateUser(user))

	// Re-authenticate with a verified flag; comparison must use trimmed
	// values so the promotion path still fires.
	promoted, err := svc.AuthenticateWithOAuth(
		context.Background(),
		"github",
		&auth.OAuthUserInfo{
			ProviderUserID: providerUserID,
			Username:       "heidi",
			Email:          "heidi@example.com",
			EmailVerified:  true,
		},
		newOAuthToken(),
	)
	require.NoError(t, err)
	assert.True(t, promoted.EmailVerified,
		"legacy whitespace in stored email must not block promotion when trimmed values match")
}

// TestAuthenticateWithOAuth_ExistingConnection_DoesNotPromoteOnEmailMismatch
// guards against a provider account whose email drifted away from the local
// user's email: verification of a different address must not promote the
// local user's EmailVerified flag.
func TestAuthenticateWithOAuth_ExistingConnection_DoesNotPromoteOnEmailMismatch(t *testing.T) {
	svc := newOAuthUserService(t)

	providerUserID := uuid.New().String()
	user, err := svc.AuthenticateWithOAuth(
		context.Background(),
		"github",
		&auth.OAuthUserInfo{
			ProviderUserID: providerUserID,
			Username:       "grace",
			Email:          "grace@example.com",
			EmailVerified:  false,
		},
		newOAuthToken(),
	)
	require.NoError(t, err)
	require.False(t, user.EmailVerified)

	// Provider now returns a verified flag but for a different email — the
	// stored user's EmailVerified must stay false.
	_, err = svc.AuthenticateWithOAuth(context.Background(), "github", &auth.OAuthUserInfo{
		ProviderUserID: providerUserID,
		Username:       "grace",
		Email:          "other@example.com",
		EmailVerified:  true,
	}, newOAuthToken())
	require.NoError(t, err)

	reloaded, err := svc.store.GetUserByID(user.ID)
	require.NoError(t, err)
	assert.False(t, reloaded.EmailVerified,
		"EmailVerified must not be promoted when the provider email drifted from the stored email")
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
