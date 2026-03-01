package services

import (
	"context"
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

	mockCache.EXPECT().
		GetWithFetch(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
		DoAndReturn(callFetchFn[models.User]).Times(1) // fetchFn returns ErrUserNotFound

	svc := newUserServiceWithStore(db, mockCache)

	_, err := svc.GetUserByID(uuid.New().String())
	assert.ErrorIs(t, err, ErrUserNotFound)
}
