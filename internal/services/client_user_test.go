package services

import (
	"context"
	"testing"

	"github.com/go-authgate/authgate/internal/core"
	"github.com/go-authgate/authgate/internal/models"
	"github.com/go-authgate/authgate/internal/store"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ============================================================
// CreateClient – Client Credentials Flow validation
// ============================================================

func TestCreateClient_CCFlowConfidentialSuccess(t *testing.T) {
	s := setupTestStore(t)
	svc := NewClientService(s, nil, nil, 0)
	userID := uuid.New().String()

	resp, err := svc.CreateClient(context.Background(), CreateClientRequest{
		ClientName:                  "CC Confidential",
		UserID:                      userID,
		CreatedBy:                   userID,
		ClientType:                  core.ClientTypeConfidential,
		EnableClientCredentialsFlow: true,
		IsAdminCreated:              true,
	})
	require.NoError(t, err)
	assert.True(t, resp.EnableClientCredentialsFlow)
	assert.Contains(t, resp.GrantTypes, "client_credentials")
}

func TestCreateClient_CCFlowPublicRejected(t *testing.T) {
	s := setupTestStore(t)
	svc := NewClientService(s, nil, nil, 0)
	userID := uuid.New().String()

	_, err := svc.CreateClient(context.Background(), CreateClientRequest{
		ClientName:                  "CC Public",
		UserID:                      userID,
		CreatedBy:                   userID,
		ClientType:                  core.ClientTypePublic,
		EnableClientCredentialsFlow: true,
		IsAdminCreated:              true,
	})
	assert.ErrorIs(t, err, ErrClientCredentialsRequireConfidential)
}

// ============================================================
// CreateClient – IsAdminCreated flag
// ============================================================

func TestCreateClient_AdminCreated_IsActive(t *testing.T) {
	s := setupTestStore(t)
	svc := NewClientService(s, nil, nil, 0)
	userID := uuid.New().String()

	resp, err := svc.CreateClient(context.Background(), CreateClientRequest{
		ClientName:     "Admin Client",
		UserID:         userID,
		CreatedBy:      userID,
		IsAdminCreated: true,
	})
	require.NoError(t, err)
	assert.True(t, resp.IsActive())
	assert.Equal(t, models.ClientStatusActive, resp.Status)
}

func TestCreateClient_UserCreated_IsPendingAndInactive(t *testing.T) {
	s := setupTestStore(t)
	svc := NewClientService(s, nil, nil, 0)
	userID := uuid.New().String()

	resp, err := svc.CreateClient(context.Background(), CreateClientRequest{
		ClientName:     "User Client",
		UserID:         userID,
		CreatedBy:      userID,
		IsAdminCreated: false,
	})
	require.NoError(t, err)
	assert.False(t, resp.IsActive())
	assert.Equal(t, models.ClientStatusPending, resp.Status)
}

// ============================================================
// UserUpdateClient – ownership enforcement
// ============================================================

func TestUserUpdateClient_OwnershipEnforced(t *testing.T) {
	s := setupTestStore(t)
	svc := NewClientService(s, nil, nil, 0)
	ownerID := uuid.New().String()
	otherID := uuid.New().String()

	resp, err := svc.CreateClient(context.Background(), CreateClientRequest{
		ClientName:     "Owned Client",
		UserID:         ownerID,
		CreatedBy:      ownerID,
		IsAdminCreated: false,
	})
	require.NoError(t, err)

	err = svc.UserUpdateClient(
		context.Background(),
		resp.ClientID,
		otherID,
		UserUpdateClientRequest{
			ClientName:       "Renamed",
			EnableDeviceFlow: true,
		},
	)
	assert.ErrorIs(t, err, ErrClientOwnershipRequired)
}

func TestUserUpdateClient_OwnerCanUpdate(t *testing.T) {
	s := setupTestStore(t)
	svc := NewClientService(s, nil, nil, 0)
	ownerID := uuid.New().String()

	resp, err := svc.CreateClient(context.Background(), CreateClientRequest{
		ClientName:     "My App",
		UserID:         ownerID,
		CreatedBy:      ownerID,
		IsAdminCreated: false,
	})
	require.NoError(t, err)

	err = svc.UserUpdateClient(
		context.Background(),
		resp.ClientID,
		ownerID,
		UserUpdateClientRequest{
			ClientName:       "My App Updated",
			EnableDeviceFlow: true,
			Scopes:           "email profile",
		},
	)
	require.NoError(t, err)

	updated, err := svc.GetClient(resp.ClientID)
	require.NoError(t, err)
	assert.Equal(t, "My App Updated", updated.ClientName)
}

// ============================================================
// UserUpdateClient – scope validation
// ============================================================

func TestUserUpdateClient_InvalidScopeRejected(t *testing.T) {
	s := setupTestStore(t)
	svc := NewClientService(s, nil, nil, 0)
	ownerID := uuid.New().String()

	resp, err := svc.CreateClient(context.Background(), CreateClientRequest{
		ClientName:     "Scope App",
		UserID:         ownerID,
		CreatedBy:      ownerID,
		IsAdminCreated: false,
	})
	require.NoError(t, err)

	err = svc.UserUpdateClient(
		context.Background(),
		resp.ClientID,
		ownerID,
		UserUpdateClientRequest{
			ClientName:       "Scope App",
			EnableDeviceFlow: true,
			Scopes:           "admin superuser", // not allowed
		},
	)
	assert.ErrorIs(t, err, ErrInvalidScopeForUser)
}

func TestUserUpdateClient_AllowedScopesAccepted(t *testing.T) {
	s := setupTestStore(t)
	svc := NewClientService(s, nil, nil, 0)
	ownerID := uuid.New().String()

	resp, err := svc.CreateClient(context.Background(), CreateClientRequest{
		ClientName:     "Scope App OK",
		UserID:         ownerID,
		CreatedBy:      ownerID,
		IsAdminCreated: false,
	})
	require.NoError(t, err)

	err = svc.UserUpdateClient(
		context.Background(),
		resp.ClientID,
		ownerID,
		UserUpdateClientRequest{
			ClientName:       "Scope App OK",
			EnableDeviceFlow: true,
			Scopes:           "email profile openid offline_access",
		},
	)
	require.NoError(t, err)
}

// ============================================================
// UserUpdateClient – Client Credentials Flow
// ============================================================

func TestUserUpdateClient_CCFlowConfidentialClient(t *testing.T) {
	s := setupTestStore(t)
	svc := NewClientService(s, nil, nil, 0)
	ownerID := uuid.New().String()

	resp, err := svc.CreateClient(context.Background(), CreateClientRequest{
		ClientName:     "CC App",
		UserID:         ownerID,
		CreatedBy:      ownerID,
		ClientType:     core.ClientTypeConfidential,
		IsAdminCreated: false,
	})
	require.NoError(t, err)

	err = svc.UserUpdateClient(
		context.Background(),
		resp.ClientID,
		ownerID,
		UserUpdateClientRequest{
			ClientName:                  "CC App",
			ClientType:                  core.ClientTypeConfidential,
			EnableClientCredentialsFlow: true,
			Scopes:                      "email",
		},
	)
	require.NoError(t, err)

	updated, err := svc.GetClient(resp.ClientID)
	require.NoError(t, err)
	assert.True(t, updated.EnableClientCredentialsFlow)
	assert.Contains(t, updated.GrantTypes, "client_credentials")
}

func TestUserUpdateClient_CCFlowPublicClientRejected(t *testing.T) {
	s := setupTestStore(t)
	svc := NewClientService(s, nil, nil, 0)
	ownerID := uuid.New().String()

	resp, err := svc.CreateClient(context.Background(), CreateClientRequest{
		ClientName:     "Public CC App",
		UserID:         ownerID,
		CreatedBy:      ownerID,
		ClientType:     core.ClientTypePublic,
		IsAdminCreated: false,
	})
	require.NoError(t, err)

	err = svc.UserUpdateClient(
		context.Background(),
		resp.ClientID,
		ownerID,
		UserUpdateClientRequest{
			ClientName:                  "Public CC App",
			ClientType:                  core.ClientTypePublic,
			EnableClientCredentialsFlow: true,
			Scopes:                      "email",
		},
	)
	assert.ErrorIs(t, err, ErrClientCredentialsRequireConfidential)
}

func TestUserUpdateClient_CCOnlyConfidentialClient(t *testing.T) {
	s := setupTestStore(t)
	svc := NewClientService(s, nil, nil, 0)
	ownerID := uuid.New().String()

	resp, err := svc.CreateClient(context.Background(), CreateClientRequest{
		ClientName:     "CC Only App",
		UserID:         ownerID,
		CreatedBy:      ownerID,
		ClientType:     core.ClientTypeConfidential,
		IsAdminCreated: false,
	})
	require.NoError(t, err)

	// CC-only (no device, no auth code) should succeed for confidential
	err = svc.UserUpdateClient(
		context.Background(),
		resp.ClientID,
		ownerID,
		UserUpdateClientRequest{
			ClientName:                  "CC Only App",
			ClientType:                  core.ClientTypeConfidential,
			EnableClientCredentialsFlow: true,
			EnableDeviceFlow:            false,
			EnableAuthCodeFlow:          false,
			Scopes:                      "email",
		},
	)
	require.NoError(t, err)

	updated, err := svc.GetClient(resp.ClientID)
	require.NoError(t, err)
	assert.True(t, updated.EnableClientCredentialsFlow)
	assert.False(t, updated.EnableDeviceFlow)
	assert.False(t, updated.EnableAuthCodeFlow)
	assert.Equal(t, "client_credentials", updated.GrantTypes)
}

// ============================================================
// UserDeleteClient – ownership + active block
// ============================================================

func TestUserDeleteClient_OwnershipEnforced(t *testing.T) {
	s := setupTestStore(t)
	svc := NewClientService(s, nil, nil, 0)
	ownerID := uuid.New().String()
	otherID := uuid.New().String()

	resp, err := svc.CreateClient(context.Background(), CreateClientRequest{
		ClientName:     "Delete Target",
		UserID:         ownerID,
		CreatedBy:      ownerID,
		IsAdminCreated: false,
	})
	require.NoError(t, err)

	err = svc.UserDeleteClient(context.Background(), resp.ClientID, otherID)
	assert.ErrorIs(t, err, ErrClientOwnershipRequired)
}

func TestUserDeleteClient_ActiveClientBlocked(t *testing.T) {
	s := setupTestStore(t)
	svc := NewClientService(s, nil, nil, 0)
	ownerID := uuid.New().String()
	adminID := uuid.New().String()

	resp, err := svc.CreateClient(context.Background(), CreateClientRequest{
		ClientName:     "Active Client",
		UserID:         ownerID,
		CreatedBy:      ownerID,
		IsAdminCreated: false,
	})
	require.NoError(t, err)

	// Approve it first to make it active
	require.NoError(t, svc.ApproveClient(context.Background(), resp.ClientID, adminID))

	err = svc.UserDeleteClient(context.Background(), resp.ClientID, ownerID)
	assert.ErrorIs(t, err, ErrCannotDeleteActiveClient)
}

func TestUserDeleteClient_PendingClientAllowed(t *testing.T) {
	s := setupTestStore(t)
	svc := NewClientService(s, nil, nil, 0)
	ownerID := uuid.New().String()

	resp, err := svc.CreateClient(context.Background(), CreateClientRequest{
		ClientName:     "Pending Client",
		UserID:         ownerID,
		CreatedBy:      ownerID,
		IsAdminCreated: false,
	})
	require.NoError(t, err)
	assert.Equal(t, models.ClientStatusPending, resp.Status)

	err = svc.UserDeleteClient(context.Background(), resp.ClientID, ownerID)
	require.NoError(t, err)
}

// ============================================================
// ApproveClient / RejectClient
// ============================================================

func TestApproveClient_SetsActiveStatus(t *testing.T) {
	s := setupTestStore(t)
	svc := NewClientService(s, nil, nil, 0)
	ownerID := uuid.New().String()
	adminID := uuid.New().String()

	resp, err := svc.CreateClient(context.Background(), CreateClientRequest{
		ClientName:     "Pending",
		UserID:         ownerID,
		CreatedBy:      ownerID,
		IsAdminCreated: false,
	})
	require.NoError(t, err)
	assert.Equal(t, models.ClientStatusPending, resp.Status)
	assert.False(t, resp.IsActive())

	require.NoError(t, svc.ApproveClient(context.Background(), resp.ClientID, adminID))

	approved, err := svc.GetClient(resp.ClientID)
	require.NoError(t, err)
	assert.Equal(t, models.ClientStatusActive, approved.Status)
	assert.True(t, approved.IsActive())
}

func TestRejectClient_SetsInactiveStatus(t *testing.T) {
	s := setupTestStore(t)
	svc := NewClientService(s, nil, nil, 0)
	ownerID := uuid.New().String()
	adminID := uuid.New().String()

	resp, err := svc.CreateClient(context.Background(), CreateClientRequest{
		ClientName:     "To Reject",
		UserID:         ownerID,
		CreatedBy:      ownerID,
		IsAdminCreated: false,
	})
	require.NoError(t, err)

	require.NoError(t, svc.RejectClient(context.Background(), resp.ClientID, adminID))

	rejected, err := svc.GetClient(resp.ClientID)
	require.NoError(t, err)
	assert.Equal(t, models.ClientStatusInactive, rejected.Status)
	assert.False(t, rejected.IsActive())
}

// ============================================================
// CountPendingClients
// ============================================================

func TestCountPendingClients(t *testing.T) {
	s := setupTestStore(t)
	svc := NewClientService(s, nil, nil, 0)
	ownerID := uuid.New().String()
	adminID := uuid.New().String()

	// Initially zero pending (seeded default is active)
	initial, err := svc.CountPendingClients(context.Background())
	require.NoError(t, err)

	// Add two pending clients
	resp1, err := svc.CreateClient(context.Background(), CreateClientRequest{
		ClientName:     "Pending 1",
		UserID:         ownerID,
		CreatedBy:      ownerID,
		IsAdminCreated: false,
	})
	require.NoError(t, err)
	_, err = svc.CreateClient(context.Background(), CreateClientRequest{
		ClientName:     "Pending 2",
		UserID:         ownerID,
		CreatedBy:      ownerID,
		IsAdminCreated: false,
	})
	require.NoError(t, err)

	count, err := svc.CountPendingClients(context.Background())
	require.NoError(t, err)
	assert.Equal(t, initial+2, count)

	// Approve one → count goes back down
	require.NoError(t, svc.ApproveClient(context.Background(), resp1.ClientID, adminID))
	count, err = svc.CountPendingClients(context.Background())
	require.NoError(t, err)
	assert.Equal(t, initial+1, count)
}

// ============================================================
// ListClientsByUser
// ============================================================

func TestCountPendingClients_CacheInvalidation(t *testing.T) {
	s := setupTestStore(t)
	ctx := context.Background()
	svc := NewClientService(s, nil, nil, 0)
	ownerID := uuid.New().String()
	adminID := uuid.New().String()

	baseline, err := svc.CountPendingClients(ctx)
	require.NoError(t, err)

	// Create a pending client — should invalidate the cache.
	resp, err := svc.CreateClient(ctx, CreateClientRequest{
		ClientName:     "Cache Test",
		UserID:         ownerID,
		CreatedBy:      ownerID,
		IsAdminCreated: false,
	})
	require.NoError(t, err)

	// Second call must reflect the new pending client, not the stale cached value.
	count, err := svc.CountPendingClients(ctx)
	require.NoError(t, err)
	assert.Equal(t, baseline+1, count)

	// A third call with no mutations must return the same value (cache hit).
	countAgain, err := svc.CountPendingClients(ctx)
	require.NoError(t, err)
	assert.Equal(t, count, countAgain)

	// Approve the client — should invalidate the cache again.
	require.NoError(t, svc.ApproveClient(ctx, resp.ClientID, adminID))

	countAfterApprove, err := svc.CountPendingClients(ctx)
	require.NoError(t, err)
	assert.Equal(t, baseline, countAfterApprove)
}

func TestListClientsByUser(t *testing.T) {
	s := setupTestStore(t)
	svc := NewClientService(s, nil, nil, 0)
	user1ID := uuid.New().String()
	user2ID := uuid.New().String()

	_, err := svc.CreateClient(context.Background(), CreateClientRequest{
		ClientName: "App A", UserID: user1ID, CreatedBy: user1ID,
	})
	require.NoError(t, err)
	_, err = svc.CreateClient(context.Background(), CreateClientRequest{
		ClientName: "App B", UserID: user1ID, CreatedBy: user1ID,
	})
	require.NoError(t, err)
	_, err = svc.CreateClient(context.Background(), CreateClientRequest{
		ClientName: "Other", UserID: user2ID, CreatedBy: user2ID,
	})
	require.NoError(t, err)

	params := store.NewPaginationParams(1, 10, "")
	apps, pagination, err := svc.ListClientsByUser(user1ID, params)
	require.NoError(t, err)
	assert.Len(t, apps, 2)
	assert.Equal(t, int64(2), pagination.Total)
}
