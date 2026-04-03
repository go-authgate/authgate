package services

import (
	"context"
	"testing"
	"time"

	"github.com/go-authgate/authgate/internal/models"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDashboardService_GetDashboardStats(t *testing.T) {
	db := setupTestStore(t)

	auditService := NewNoopAuditService()

	dashboardService := NewDashboardService(db, auditService)

	// Create a test user (admin is already seeded)
	user := &models.User{
		ID:       uuid.New().String(),
		Username: "dashtest",
		Email:    "dashtest@test.com",
		Role:     models.UserRoleUser,
	}
	require.NoError(t, db.CreateUser(user))

	// Create a client
	client := &models.OAuthApplication{
		ClientID:   uuid.New().String(),
		ClientName: "DashTestApp",
		UserID:     user.ID,
		Status:     models.ClientStatusActive,
	}
	require.NoError(t, db.CreateClient(client))

	// Create tokens
	accessTok := &models.AccessToken{
		ID:            uuid.New().String(),
		TokenHash:     uuid.New().String(),
		TokenCategory: models.TokenCategoryAccess,
		Status:        models.TokenStatusActive,
		UserID:        user.ID,
		ClientID:      client.ClientID,
		ExpiresAt:     time.Now().Add(1 * time.Hour),
	}
	require.NoError(t, db.CreateAccessToken(accessTok))

	refreshTok := &models.AccessToken{
		ID:            uuid.New().String(),
		TokenHash:     uuid.New().String(),
		TokenCategory: models.TokenCategoryRefresh,
		Status:        models.TokenStatusActive,
		UserID:        user.ID,
		ClientID:      client.ClientID,
		ExpiresAt:     time.Now().Add(24 * time.Hour),
	}
	require.NoError(t, db.CreateAccessToken(refreshTok))

	stats := dashboardService.GetDashboardStats(context.Background())

	// User counts (seeded admin + dashtest)
	assert.Equal(t, int64(2), stats.TotalUsers)
	assert.Equal(t, int64(1), stats.AdminUsers)
	assert.Equal(t, int64(1), stats.RegularUsers)

	// Client counts (seeded CLI client + DashTestApp)
	assert.GreaterOrEqual(t, stats.ActiveClients, int64(1))

	// Token counts
	assert.Equal(t, int64(1), stats.ActiveAccessTokens)
	assert.Equal(t, int64(1), stats.ActiveRefreshTokens)

	// Pending is 0
	assert.Equal(t, int64(0), stats.PendingClients)
}
