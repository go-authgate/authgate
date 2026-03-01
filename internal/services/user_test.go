package services

import (
	"context"
	"errors"
	"testing"
	"time"

	"go.uber.org/mock/gomock"

	"github.com/go-authgate/authgate/internal/core"
	"github.com/go-authgate/authgate/internal/mocks"
	"github.com/go-authgate/authgate/internal/models"
	"github.com/go-authgate/authgate/internal/store"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newUserServiceWithStore(db *store.Store, c core.Cache[models.User]) *UserService {
	return NewUserService(db, nil, nil, AuthModeLocal, false, nil, c, 5*time.Minute)
}

func makeTestUser(t *testing.T, db *store.Store) *models.User {
	t.Helper()
	u := &models.User{
		ID:           uuid.New().String(),
		Username:     "testuser-" + uuid.New().String()[:8],
		Email:        uuid.New().String() + "@example.com",
		PasswordHash: "hash",
		Role:         "user",
		AuthSource:   AuthModeLocal,
	}
	require.NoError(t, db.CreateUser(u))
	return u
}

// callFetchFn is a DoAndReturn helper that invokes the cache fetch function,
// simulating a cache miss where the real DB fetch is executed.
func callFetchFn[T any](
	ctx context.Context,
	key string,
	_ time.Duration,
	fn func(context.Context, string) (T, error),
) (T, error) {
	return fn(ctx, key)
}

func TestGetUserByID_CacheMiss(t *testing.T) {
	db := setupTestStore(t)
	ctrl := gomock.NewController(t)
	mockCache := mocks.NewMockCache[models.User](ctrl)
	u := makeTestUser(t, db)

	mockCache.EXPECT().
		GetWithFetch(gomock.Any(), "user:"+u.ID, gomock.Any(), gomock.Any()).
		DoAndReturn(callFetchFn[models.User]).Times(1)

	svc := newUserServiceWithStore(db, mockCache)
	result, err := svc.GetUserByID(u.ID)
	require.NoError(t, err)
	assert.Equal(t, u.ID, result.ID)
	assert.Equal(t, u.Username, result.Username)
}

func TestGetUserByID_CacheHit(t *testing.T) {
	db := setupTestStore(t)
	ctrl := gomock.NewController(t)
	mockCache := mocks.NewMockCache[models.User](ctrl)
	u := makeTestUser(t, db)

	gomock.InOrder(
		mockCache.EXPECT().
			GetWithFetch(gomock.Any(), "user:"+u.ID, gomock.Any(), gomock.Any()).
			DoAndReturn(callFetchFn[models.User]), // first call: cache miss → fetch from DB
		mockCache.EXPECT().
			GetWithFetch(gomock.Any(), "user:"+u.ID, gomock.Any(), gomock.Any()).
			Return(*u, nil), // second call: cache hit → return directly
	)

	svc := newUserServiceWithStore(db, mockCache)

	first, err := svc.GetUserByID(u.ID)
	require.NoError(t, err)
	assert.Equal(t, u.ID, first.ID)

	second, err := svc.GetUserByID(u.ID)
	require.NoError(t, err)
	assert.Equal(t, u.ID, second.ID)
}

func TestGetUserByID_CacheInvalidation(t *testing.T) {
	db := setupTestStore(t)
	ctrl := gomock.NewController(t)
	mockCache := mocks.NewMockCache[models.User](ctrl)
	u := makeTestUser(t, db)

	gomock.InOrder(
		mockCache.EXPECT().
			GetWithFetch(gomock.Any(), "user:"+u.ID, gomock.Any(), gomock.Any()).
			DoAndReturn(callFetchFn[models.User]), // first call: cache miss → fetch from DB
		mockCache.EXPECT().
			Delete(gomock.Any(), "user:"+u.ID).
			Return(nil), // invalidate cache entry
		mockCache.EXPECT().
			GetWithFetch(gomock.Any(), "user:"+u.ID, gomock.Any(), gomock.Any()).
			DoAndReturn(callFetchFn[models.User]), // re-fetch after invalidation: cache miss → fetch from DB
	)

	svc := newUserServiceWithStore(db, mockCache)

	// Populate (miss → DB fetch)
	_, err := svc.GetUserByID(u.ID)
	require.NoError(t, err)

	// Invalidate
	svc.InvalidateUserCache(u.ID)

	// Re-fetch after invalidation (miss again → DB fetch)
	result, err := svc.GetUserByID(u.ID)
	require.NoError(t, err)
	assert.Equal(t, u.ID, result.ID)
}

func TestGetUserByID_ErrUserNotFound(t *testing.T) {
	db := setupTestStore(t)
	ctrl := gomock.NewController(t)
	mockCache := mocks.NewMockCache[models.User](ctrl)

	id := uuid.New().String()
	mockCache.EXPECT().
		GetWithFetch(gomock.Any(), "user:"+id, gomock.Any(), gomock.Any()).
		DoAndReturn(callFetchFn[models.User]).Times(1) // fetchFn returns ErrUserNotFound

	svc := newUserServiceWithStore(db, mockCache)

	_, err := svc.GetUserByID(id)
	assert.ErrorIs(t, err, ErrUserNotFound)
}

func makeTestHTTPAPIUser(t *testing.T, db *store.Store) *models.User {
	t.Helper()
	u := &models.User{
		ID:         uuid.New().String(),
		Username:   "httpuser-" + uuid.New().String()[:8],
		Email:      uuid.New().String() + "@example.com",
		ExternalID: "ext-" + uuid.New().String()[:8],
		Role:       "user",
		AuthSource: AuthModeHTTPAPI,
	}
	require.NoError(t, db.CreateUser(u))
	return u
}

// newUserServiceForAuth builds a UserService with the given auth providers for authenticate tests.
func newUserServiceForAuth(
	db *store.Store,
	localProvider, httpAPIProvider core.AuthProvider,
	authMode string,
	c core.Cache[models.User],
) *UserService {
	return NewUserService(
		db, localProvider, httpAPIProvider, authMode, false, nil, c, 5*time.Minute,
	)
}

func TestAuthenticate_LocalSuccess(t *testing.T) {
	db := setupTestStore(t)
	ctrl := gomock.NewController(t)
	mockCache := mocks.NewMockCache[models.User](ctrl)
	mockLocalProvider := mocks.NewMockAuthProvider(ctrl)

	u := makeTestUser(t, db) // auth_source=local

	mockLocalProvider.EXPECT().
		Authenticate(gomock.Any(), u.Username, "correct-password").
		Return(&core.AuthResult{Username: u.Username, Success: true}, nil).
		Times(1)

	svc := newUserServiceForAuth(db, mockLocalProvider, nil, AuthModeLocal, mockCache)
	result, err := svc.Authenticate(context.Background(), u.Username, "correct-password")
	require.NoError(t, err)
	assert.Equal(t, u.ID, result.ID)
	assert.Equal(t, u.Username, result.Username)
}

func TestAuthenticate_LocalProviderNil(t *testing.T) {
	db := setupTestStore(t)
	ctrl := gomock.NewController(t)
	mockCache := mocks.NewMockCache[models.User](ctrl)

	u := makeTestUser(t, db) // auth_source=local, localProvider=nil

	svc := newUserServiceForAuth(db, nil, nil, AuthModeLocal, mockCache)
	_, err := svc.Authenticate(context.Background(), u.Username, "any")
	assert.ErrorIs(t, err, ErrAuthProviderFailed)
}

func TestAuthenticate_WrongPassword(t *testing.T) {
	db := setupTestStore(t)
	ctrl := gomock.NewController(t)
	mockCache := mocks.NewMockCache[models.User](ctrl)
	mockLocalProvider := mocks.NewMockAuthProvider(ctrl)

	u := makeTestUser(t, db)

	mockLocalProvider.EXPECT().
		Authenticate(gomock.Any(), u.Username, "wrong").
		Return(nil, errors.New("invalid credentials")).
		Times(1)

	svc := newUserServiceForAuth(db, mockLocalProvider, nil, AuthModeLocal, mockCache)
	_, err := svc.Authenticate(context.Background(), u.Username, "wrong")
	assert.ErrorIs(t, err, ErrInvalidCredentials)
}

func TestAuthenticate_HTTPAPIExistingUser(t *testing.T) {
	db := setupTestStore(t)
	ctrl := gomock.NewController(t)
	mockCache := mocks.NewMockCache[models.User](ctrl)
	mockHTTPAPIProvider := mocks.NewMockAuthProvider(ctrl)

	u := makeTestHTTPAPIUser(t, db)

	mockHTTPAPIProvider.EXPECT().
		Authenticate(gomock.Any(), u.Username, "pass").
		Return(&core.AuthResult{
			Username:   u.Username,
			ExternalID: u.ExternalID,
			Success:    true,
		}, nil).
		Times(1)

	// syncExternalUser calls InvalidateUserCache → cache.Delete
	mockCache.EXPECT().
		Delete(gomock.Any(), "user:"+u.ID).
		Return(nil).
		Times(1)

	svc := newUserServiceForAuth(db, nil, mockHTTPAPIProvider, AuthModeHTTPAPI, mockCache)
	result, err := svc.Authenticate(context.Background(), u.Username, "pass")
	require.NoError(t, err)
	assert.Equal(t, u.Username, result.Username)
}

func TestAuthenticate_HTTPAPIProviderNil(t *testing.T) {
	db := setupTestStore(t)
	ctrl := gomock.NewController(t)
	mockCache := mocks.NewMockCache[models.User](ctrl)

	u := makeTestHTTPAPIUser(t, db)

	svc := newUserServiceForAuth(db, nil, nil, AuthModeHTTPAPI, mockCache)
	_, err := svc.Authenticate(context.Background(), u.Username, "pass")
	assert.ErrorIs(t, err, ErrAuthProviderFailed)
}

func TestAuthenticate_UserNotFound_LocalMode(t *testing.T) {
	db := setupTestStore(t)
	ctrl := gomock.NewController(t)
	mockCache := mocks.NewMockCache[models.User](ctrl)

	svc := newUserServiceForAuth(db, nil, nil, AuthModeLocal, mockCache)
	_, err := svc.Authenticate(context.Background(), "nonexistent-user", "pass")
	assert.ErrorIs(t, err, ErrInvalidCredentials)
}

// TestAuthenticate_LocalSuccessFalse covers the if !authResult.Success branch in
// authenticateExistingUser when the provider returns a non-nil result with Success=false
// and a nil error (distinct from the error-return path).
func TestAuthenticate_LocalSuccessFalse(t *testing.T) {
	db := setupTestStore(t)
	ctrl := gomock.NewController(t)
	mockCache := mocks.NewMockCache[models.User](ctrl)
	mockLocalProvider := mocks.NewMockAuthProvider(ctrl)

	u := makeTestUser(t, db)

	mockLocalProvider.EXPECT().
		Authenticate(gomock.Any(), u.Username, "bad-pass").
		Return(&core.AuthResult{Username: u.Username, Success: false}, nil).
		Times(1)

	svc := newUserServiceForAuth(db, mockLocalProvider, nil, AuthModeLocal, mockCache)
	_, err := svc.Authenticate(context.Background(), u.Username, "bad-pass")
	assert.ErrorIs(t, err, ErrInvalidCredentials)
}

// TestAuthenticate_HTTPAPIExistingUser_SuccessFalse covers the if !authResult.Success branch
// for an existing HTTP API user (no sync occurs because Success=false).
func TestAuthenticate_HTTPAPIExistingUser_SuccessFalse(t *testing.T) {
	db := setupTestStore(t)
	ctrl := gomock.NewController(t)
	mockCache := mocks.NewMockCache[models.User](ctrl)
	mockHTTPAPIProvider := mocks.NewMockAuthProvider(ctrl)

	u := makeTestHTTPAPIUser(t, db)

	mockHTTPAPIProvider.EXPECT().
		Authenticate(gomock.Any(), u.Username, "bad-pass").
		Return(&core.AuthResult{Username: u.Username, ExternalID: u.ExternalID, Success: false}, nil).
		Times(1)

	// No cache.Delete call expected: sync only runs when Success=true.
	svc := newUserServiceForAuth(db, nil, mockHTTPAPIProvider, AuthModeHTTPAPI, mockCache)
	_, err := svc.Authenticate(context.Background(), u.Username, "bad-pass")
	assert.ErrorIs(t, err, ErrInvalidCredentials)
}

// TestAuthenticate_HTTPAPINewUser_Success covers authenticateAndCreateExternalUser when
// the user does not yet exist and the HTTP API provider returns a successful result,
// triggering new-user creation via syncExternalUser.
func TestAuthenticate_HTTPAPINewUser_Success(t *testing.T) {
	db := setupTestStore(t)
	ctrl := gomock.NewController(t)
	mockCache := mocks.NewMockCache[models.User](ctrl)
	mockHTTPAPIProvider := mocks.NewMockAuthProvider(ctrl)

	newUsername := "new-httpuser-" + uuid.New().String()[:8]
	newExtID := "ext-new-" + uuid.New().String()[:8]

	mockHTTPAPIProvider.EXPECT().
		Authenticate(gomock.Any(), newUsername, "pass").
		Return(&core.AuthResult{
			Username:   newUsername,
			ExternalID: newExtID,
			Email:      newUsername + "@example.com",
			Success:    true,
		}, nil).
		Times(1)

	// syncExternalUser calls InvalidateUserCache → cache.Delete for the new user.
	mockCache.EXPECT().
		Delete(gomock.Any(), gomock.Any()).
		Return(nil).
		Times(1)

	svc := newUserServiceForAuth(db, nil, mockHTTPAPIProvider, AuthModeHTTPAPI, mockCache)
	result, err := svc.Authenticate(context.Background(), newUsername, "pass")
	require.NoError(t, err)
	assert.Equal(t, newUsername, result.Username)
	assert.Equal(t, newExtID, result.ExternalID)
}

// TestAuthenticate_HTTPAPINewUser_SuccessFalse covers authenticateAndCreateExternalUser when
// the user does not exist and the HTTP API provider returns Success=false with a nil error.
func TestAuthenticate_HTTPAPINewUser_SuccessFalse(t *testing.T) {
	db := setupTestStore(t)
	ctrl := gomock.NewController(t)
	mockCache := mocks.NewMockCache[models.User](ctrl)
	mockHTTPAPIProvider := mocks.NewMockAuthProvider(ctrl)

	mockHTTPAPIProvider.EXPECT().
		Authenticate(gomock.Any(), "ghost-user", "bad-pass").
		Return(&core.AuthResult{Username: "ghost-user", Success: false}, nil).
		Times(1)

	svc := newUserServiceForAuth(db, nil, mockHTTPAPIProvider, AuthModeHTTPAPI, mockCache)
	_, err := svc.Authenticate(context.Background(), "ghost-user", "bad-pass")
	assert.ErrorIs(t, err, ErrInvalidCredentials)
}

// TestAuthenticate_HTTPAPINewUser_AuthError covers authenticateAndCreateExternalUser when
// the user does not exist and the HTTP API provider returns an error (distinct from Success=false).
func TestAuthenticate_HTTPAPINewUser_AuthError(t *testing.T) {
	db := setupTestStore(t)
	ctrl := gomock.NewController(t)
	mockCache := mocks.NewMockCache[models.User](ctrl)
	mockHTTPAPIProvider := mocks.NewMockAuthProvider(ctrl)

	mockHTTPAPIProvider.EXPECT().
		Authenticate(gomock.Any(), "ghost-user", "bad-pass").
		Return(nil, errors.New("provider unavailable")).
		Times(1)

	svc := newUserServiceForAuth(db, nil, mockHTTPAPIProvider, AuthModeHTTPAPI, mockCache)
	_, err := svc.Authenticate(context.Background(), "ghost-user", "bad-pass")
	assert.ErrorIs(t, err, ErrInvalidCredentials)
}
