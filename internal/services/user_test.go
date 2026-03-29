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
	return NewUserService(
		db,
		nil,
		nil,
		AuthModeLocal,
		false,
		NewNoopAuditService(),
		c,
		5*time.Minute,
	)
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

func TestGetUserByID_TransientDBError(t *testing.T) {
	db := setupTestStore(t)
	// Close the database to simulate a transient DB failure
	require.NoError(t, db.Close(context.Background()))

	ctrl := gomock.NewController(t)
	mockCache := mocks.NewMockCache[models.User](ctrl)

	id := uuid.New().String()
	mockCache.EXPECT().
		GetWithFetch(gomock.Any(), "user:"+id, gomock.Any(), gomock.Any()).
		DoAndReturn(callFetchFn[models.User]).Times(1)

	svc := newUserServiceWithStore(db, mockCache)

	_, err := svc.GetUserByID(id)
	require.Error(t, err)
	assert.NotErrorIs(
		t, err, ErrUserNotFound,
		"transient DB errors must not be wrapped as ErrUserNotFound",
	)
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
		db,
		localProvider,
		httpAPIProvider,
		authMode,
		false,
		NewNoopAuditService(),
		c,
		5*time.Minute,
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
		Return(&core.AuthResult{Username: u.Username}, nil).
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

// TestAuthenticate_LocalAuthError covers the error-return path in
// authenticateExistingUser when the local provider returns an error.
func TestAuthenticate_LocalAuthError(t *testing.T) {
	db := setupTestStore(t)
	ctrl := gomock.NewController(t)
	mockCache := mocks.NewMockCache[models.User](ctrl)
	mockLocalProvider := mocks.NewMockAuthProvider(ctrl)

	u := makeTestUser(t, db)

	mockLocalProvider.EXPECT().
		Authenticate(gomock.Any(), u.Username, "bad-pass").
		Return(nil, errors.New("invalid credentials")).
		Times(1)

	svc := newUserServiceForAuth(db, mockLocalProvider, nil, AuthModeLocal, mockCache)
	_, err := svc.Authenticate(context.Background(), u.Username, "bad-pass")
	assert.ErrorIs(t, err, ErrInvalidCredentials)
}

// TestAuthenticate_HTTPAPIExistingUser_AuthError covers the error-return path
// for an existing HTTP API user (no sync occurs because auth failed).
func TestAuthenticate_HTTPAPIExistingUser_AuthError(t *testing.T) {
	db := setupTestStore(t)
	ctrl := gomock.NewController(t)
	mockCache := mocks.NewMockCache[models.User](ctrl)
	mockHTTPAPIProvider := mocks.NewMockAuthProvider(ctrl)

	u := makeTestHTTPAPIUser(t, db)

	mockHTTPAPIProvider.EXPECT().
		Authenticate(gomock.Any(), u.Username, "bad-pass").
		Return(nil, errors.New("invalid credentials")).
		Times(1)

	// No cache.Delete call expected: sync only runs on success.
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

// TestAuthenticate_HTTPAPINewUser_AuthFailed covers authenticateAndCreateExternalUser when
// the user does not exist and the HTTP API provider returns an error.
func TestAuthenticate_HTTPAPINewUser_AuthFailed(t *testing.T) {
	db := setupTestStore(t)
	ctrl := gomock.NewController(t)
	mockCache := mocks.NewMockCache[models.User](ctrl)
	mockHTTPAPIProvider := mocks.NewMockAuthProvider(ctrl)

	mockHTTPAPIProvider.EXPECT().
		Authenticate(gomock.Any(), "ghost-user", "bad-pass").
		Return(nil, errors.New("invalid credentials")).
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

// ── Admin User Management Tests ────────────────────────────────────────

func TestUpdateUserProfile_Success(t *testing.T) {
	db := setupTestStore(t)
	ctrl := gomock.NewController(t)
	mockCache := mocks.NewMockCache[models.User](ctrl)
	u := makeTestUser(t, db)
	actor := makeTestUser(t, db)

	mockCache.EXPECT().Delete(gomock.Any(), "user:"+u.ID).Return(nil).Times(1)

	svc := newUserServiceWithStore(db, mockCache)
	err := svc.UpdateUserProfile(context.Background(), u.ID, actor.ID, UpdateUserProfileRequest{
		FullName: "New Name",
		Email:    u.Email, // keep same email
		Role:     models.UserRoleAdmin,
	})
	require.NoError(t, err)

	// Verify changes persisted
	updated, err := db.GetUserByID(u.ID)
	require.NoError(t, err)
	assert.Equal(t, "New Name", updated.FullName)
	assert.Equal(t, models.UserRoleAdmin, updated.Role)
}

func TestUpdateUserProfile_CannotChangeOwnRole(t *testing.T) {
	db := setupTestStore(t)
	ctrl := gomock.NewController(t)
	mockCache := mocks.NewMockCache[models.User](ctrl)
	u := makeTestUser(t, db)

	svc := newUserServiceWithStore(db, mockCache)
	err := svc.UpdateUserProfile(context.Background(), u.ID, u.ID, UpdateUserProfileRequest{
		FullName: "Self",
		Email:    u.Email,
		Role:     models.UserRoleAdmin, // trying to promote self
	})
	assert.ErrorIs(t, err, ErrCannotChangeOwnRole)
}

func TestUpdateUserProfile_EmailConflict(t *testing.T) {
	db := setupTestStore(t)
	ctrl := gomock.NewController(t)
	mockCache := mocks.NewMockCache[models.User](ctrl)
	u1 := makeTestUser(t, db)
	u2 := makeTestUser(t, db)
	actor := makeTestUser(t, db)

	svc := newUserServiceWithStore(db, mockCache)
	err := svc.UpdateUserProfile(context.Background(), u1.ID, actor.ID, UpdateUserProfileRequest{
		FullName: u1.FullName,
		Email:    u2.Email, // taken by u2
		Role:     u1.Role,
	})
	assert.ErrorIs(t, err, ErrEmailConflict)
}

func TestUpdateUserProfile_CannotDemoteLastAdmin(t *testing.T) {
	db := setupTestStore(t)
	ctrl := gomock.NewController(t)
	mockCache := mocks.NewMockCache[models.User](ctrl)

	// The seeded admin is the only admin; use a different user as actor.
	admin, err := db.GetUserByUsername("admin")
	require.NoError(t, err)
	actor := makeTestUser(t, db)

	svc := newUserServiceWithStore(db, mockCache)
	err = svc.UpdateUserProfile(context.Background(), admin.ID, actor.ID, UpdateUserProfileRequest{
		FullName: admin.FullName,
		Email:    admin.Email,
		Role:     models.UserRoleUser, // attempt to demote the only admin
	})
	assert.ErrorIs(t, err, ErrCannotRemoveLastAdmin)
}

func TestResetUserPassword_LocalSuccess(t *testing.T) {
	db := setupTestStore(t)
	ctrl := gomock.NewController(t)
	mockCache := mocks.NewMockCache[models.User](ctrl)
	u := makeTestUser(t, db) // auth_source=local

	mockCache.EXPECT().Delete(gomock.Any(), "user:"+u.ID).Return(nil).Times(1)

	svc := newUserServiceWithStore(db, mockCache)
	newPass, err := svc.ResetUserPassword(context.Background(), u.ID, uuid.New().String())
	require.NoError(t, err)
	assert.Len(t, newPass, 16)

	// Verify the password hash changed
	updated, err := db.GetUserByID(u.ID)
	require.NoError(t, err)
	assert.NotEqual(t, "hash", updated.PasswordHash)
}

func TestResetUserPassword_ExternalUserRejected(t *testing.T) {
	db := setupTestStore(t)
	ctrl := gomock.NewController(t)
	mockCache := mocks.NewMockCache[models.User](ctrl)
	u := makeTestHTTPAPIUser(t, db) // auth_source=http_api

	svc := newUserServiceWithStore(db, mockCache)
	_, err := svc.ResetUserPassword(context.Background(), u.ID, uuid.New().String())
	assert.ErrorIs(t, err, ErrPasswordResetNotAllowed)
}

func TestDeleteUserAdmin_Success(t *testing.T) {
	db := setupTestStore(t)
	ctrl := gomock.NewController(t)
	mockCache := mocks.NewMockCache[models.User](ctrl)
	u := makeTestUser(t, db)
	actor := makeTestUser(t, db)

	mockCache.EXPECT().Delete(gomock.Any(), "user:"+u.ID).Return(nil).Times(1)

	svc := newUserServiceWithStore(db, mockCache)
	err := svc.DeleteUserAdmin(context.Background(), u.ID, actor.ID)
	require.NoError(t, err)

	// Verify user is deleted
	_, err = db.GetUserByID(u.ID)
	require.Error(t, err)
}

func TestDeleteUserAdmin_CannotDeleteSelf(t *testing.T) {
	db := setupTestStore(t)
	ctrl := gomock.NewController(t)
	mockCache := mocks.NewMockCache[models.User](ctrl)
	u := makeTestUser(t, db)

	svc := newUserServiceWithStore(db, mockCache)
	err := svc.DeleteUserAdmin(context.Background(), u.ID, u.ID)
	assert.ErrorIs(t, err, ErrCannotDeleteSelf)
}

func TestDeleteUserAdmin_CannotDeleteLastAdmin(t *testing.T) {
	db := setupTestStore(t)
	ctrl := gomock.NewController(t)
	mockCache := mocks.NewMockCache[models.User](ctrl)

	// The seeded admin is the only admin; create a second user as actor
	admin, err := db.GetUserByUsername("admin")
	require.NoError(t, err)

	actor := makeTestUser(t, db)
	// Promote actor to admin so they can attempt deletion
	actor.Role = models.UserRoleAdmin
	require.NoError(t, db.UpdateUser(actor))

	svc := newUserServiceWithStore(db, mockCache)

	// Deleting actor should succeed (2 admins exist)
	mockCache.EXPECT().Delete(gomock.Any(), "user:"+actor.ID).Return(nil).Times(1)
	err = svc.DeleteUserAdmin(context.Background(), actor.ID, admin.ID)
	require.NoError(t, err)

	// Now deleting the only remaining admin should fail
	err = svc.DeleteUserAdmin(context.Background(), admin.ID, admin.ID)
	require.ErrorIs(t, err, ErrCannotDeleteSelf) // self-delete guard fires first

	// Create a non-admin actor to test the last-admin guard directly
	actor2 := makeTestUser(t, db)
	err = svc.DeleteUserAdmin(context.Background(), admin.ID, actor2.ID)
	assert.ErrorIs(t, err, ErrCannotRemoveLastAdmin)
}

func TestAdminGetUserByID_NotFound(t *testing.T) {
	db := setupTestStore(t)
	ctrl := gomock.NewController(t)
	mockCache := mocks.NewMockCache[models.User](ctrl)

	svc := newUserServiceWithStore(db, mockCache)
	_, err := svc.AdminGetUserByID(uuid.New().String())
	assert.ErrorIs(t, err, ErrUserNotFound)
}

func TestGetUserStats(t *testing.T) {
	db := setupTestStore(t)
	ctrl := gomock.NewController(t)
	mockCache := mocks.NewMockCache[models.User](ctrl)
	u := makeTestUser(t, db)

	svc := newUserServiceWithStore(db, mockCache)
	stats, err := svc.GetUserStats(u.ID)
	require.NoError(t, err)
	assert.Equal(t, int64(0), stats.ActiveTokenCount)
	assert.Equal(t, int64(0), stats.OAuthConnectionCount)
	assert.Equal(t, int64(0), stats.AuthorizationCount)
}
