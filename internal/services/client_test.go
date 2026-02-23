package services

import (
	"context"
	"testing"

	"github.com/go-authgate/authgate/internal/models"
	"github.com/go-authgate/authgate/internal/store"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestListClientsPaginatedWithCreator(t *testing.T) {
	s := setupTestStore(t)
	clientService := NewClientService(s, nil)

	// Create test users
	user1 := &models.User{
		ID:           uuid.New().String(),
		Username:     "alice",
		Email:        "alice@example.com",
		PasswordHash: "hashed_password",
		Role:         "user",
	}
	user2 := &models.User{
		ID:           uuid.New().String(),
		Username:     "bob",
		Email:        "bob@example.com",
		PasswordHash: "hashed_password",
		Role:         "user",
	}

	require.NoError(t, s.CreateUser(user1))
	require.NoError(t, s.CreateUser(user2))

	// Create test clients
	client1 := &models.OAuthApplication{
		ClientID:     uuid.New().String(),
		ClientSecret: "secret1",
		ClientName:   "Client 1",
		UserID:       user1.ID, // Created by alice
		GrantTypes:   "device_code",
		Scopes:       "read write",
		IsActive:     true,
	}
	client2 := &models.OAuthApplication{
		ClientID:     uuid.New().String(),
		ClientSecret: "secret2",
		ClientName:   "Client 2",
		UserID:       user2.ID, // Created by bob
		GrantTypes:   "device_code",
		Scopes:       "read",
		IsActive:     true,
	}
	client3 := &models.OAuthApplication{
		ClientID:     uuid.New().String(),
		ClientSecret: "secret3",
		ClientName:   "Client 3",
		UserID:       user1.ID, // Also created by alice
		GrantTypes:   "device_code",
		Scopes:       "write",
		IsActive:     false,
	}
	client4 := &models.OAuthApplication{
		ClientID:     uuid.New().String(),
		ClientSecret: "secret4",
		ClientName:   "Client 4",
		UserID:       "", // No creator (edge case)
		GrantTypes:   "device_code",
		Scopes:       "read",
		IsActive:     true,
	}

	require.NoError(t, s.CreateClient(client1))
	require.NoError(t, s.CreateClient(client2))
	require.NoError(t, s.CreateClient(client3))
	require.NoError(t, s.CreateClient(client4))

	t.Run("returns clients with creator usernames", func(t *testing.T) {
		params := store.NewPaginationParams(1, 10, "")
		clients, pagination, err := clientService.ListClientsPaginatedWithCreator(params)

		require.NoError(t, err)
		// Note: Store creates a default "AuthGate CLI" client, so we have 5 total
		assert.GreaterOrEqual(t, len(clients), 4)
		assert.GreaterOrEqual(t, int(pagination.Total), 4)

		// Find clients by name and verify creator
		clientMap := make(map[string]ClientWithCreator)
		for _, c := range clients {
			clientMap[c.ClientName] = c
		}

		assert.Equal(t, "alice", clientMap["Client 1"].CreatorUsername)
		assert.Equal(t, "bob", clientMap["Client 2"].CreatorUsername)
		assert.Equal(t, "alice", clientMap["Client 3"].CreatorUsername)
		assert.Equal(t, "", clientMap["Client 4"].CreatorUsername) // No creator
	})

	t.Run("handles pagination correctly", func(t *testing.T) {
		params := store.NewPaginationParams(1, 2, "")
		clients, pagination, err := clientService.ListClientsPaginatedWithCreator(params)

		require.NoError(t, err)
		assert.Equal(t, 2, len(clients))
		// Note: Store creates a default "AuthGate CLI" client, so we have 5 total
		assert.GreaterOrEqual(t, int(pagination.Total), 4)
		assert.Equal(t, 1, pagination.CurrentPage)
		assert.GreaterOrEqual(t, pagination.TotalPages, 2)
	})

	t.Run("handles search with creator", func(t *testing.T) {
		params := store.NewPaginationParams(1, 10, "Client 1")
		clients, pagination, err := clientService.ListClientsPaginatedWithCreator(params)

		require.NoError(t, err)
		assert.Equal(t, 1, len(clients))
		assert.Equal(t, "Client 1", clients[0].ClientName)
		assert.Equal(t, "alice", clients[0].CreatorUsername)
		assert.Equal(t, int64(1), pagination.Total)
	})

	t.Run("handles empty results", func(t *testing.T) {
		params := store.NewPaginationParams(1, 10, "NonExistent")
		clients, pagination, err := clientService.ListClientsPaginatedWithCreator(params)

		require.NoError(t, err)
		assert.Equal(t, 0, len(clients))
		assert.Equal(t, int64(0), pagination.Total)
	})

	t.Run("handles deleted user gracefully", func(t *testing.T) {
		// Create a client with a user, then delete the user
		deletedUser := &models.User{
			ID:           uuid.New().String(),
			Username:     "to-be-deleted",
			Email:        "deleted@example.com",
			PasswordHash: "hashed_password",
			Role:         "user",
		}
		require.NoError(t, s.CreateUser(deletedUser))

		clientWithDeletedUser := &models.OAuthApplication{
			ClientID:     uuid.New().String(),
			ClientSecret: "secret5",
			ClientName:   "Client With Deleted User",
			UserID:       deletedUser.ID,
			GrantTypes:   "device_code",
			Scopes:       "read",
			IsActive:     true,
		}
		require.NoError(t, s.CreateClient(clientWithDeletedUser))

		// Delete the user
		require.NoError(t, s.DeleteUser(deletedUser.ID))

		// Fetch clients with creator
		params := store.NewPaginationParams(1, 10, "Client With Deleted User")
		clients, _, err := clientService.ListClientsPaginatedWithCreator(params)

		require.NoError(t, err)
		assert.Equal(t, 1, len(clients))
		assert.Equal(t, "Client With Deleted User", clients[0].ClientName)
		assert.Equal(t, "", clients[0].CreatorUsername) // User deleted, so empty
	})
}

func TestGetUsersByIDs(t *testing.T) {
	s := setupTestStore(t)

	// Create test users
	user1 := &models.User{
		ID:           uuid.New().String(),
		Username:     "user1",
		Email:        "user1@example.com",
		PasswordHash: "hashed_password",
		Role:         "user",
	}
	user2 := &models.User{
		ID:           uuid.New().String(),
		Username:     "user2",
		Email:        "user2@example.com",
		PasswordHash: "hashed_password",
		Role:         "admin",
	}
	user3 := &models.User{
		ID:           uuid.New().String(),
		Username:     "user3",
		Email:        "user3@example.com",
		PasswordHash: "hashed_password",
		Role:         "user",
	}

	require.NoError(t, s.CreateUser(user1))
	require.NoError(t, s.CreateUser(user2))
	require.NoError(t, s.CreateUser(user3))

	t.Run("batch loads multiple users", func(t *testing.T) {
		userIDs := []string{user1.ID, user2.ID, user3.ID}
		userMap, err := s.GetUsersByIDs(userIDs)

		require.NoError(t, err)
		assert.Equal(t, 3, len(userMap))
		assert.Equal(t, "user1", userMap[user1.ID].Username)
		assert.Equal(t, "user2", userMap[user2.ID].Username)
		assert.Equal(t, "user3", userMap[user3.ID].Username)
	})

	t.Run("handles partial matches", func(t *testing.T) {
		nonExistentID := uuid.New().String()
		userIDs := []string{user1.ID, nonExistentID}
		userMap, err := s.GetUsersByIDs(userIDs)

		require.NoError(t, err)
		assert.Equal(t, 1, len(userMap))
		assert.Equal(t, "user1", userMap[user1.ID].Username)
		assert.Nil(t, userMap[nonExistentID])
	})

	t.Run("handles empty input", func(t *testing.T) {
		userMap, err := s.GetUsersByIDs([]string{})

		require.NoError(t, err)
		assert.Equal(t, 0, len(userMap))
	})

	t.Run("handles duplicate IDs efficiently", func(t *testing.T) {
		// Duplicate IDs should still result in single map entry
		userIDs := []string{user1.ID, user1.ID, user2.ID}
		userMap, err := s.GetUsersByIDs(userIDs)

		require.NoError(t, err)
		assert.Equal(t, 2, len(userMap))
		assert.Equal(t, "user1", userMap[user1.ID].Username)
		assert.Equal(t, "user2", userMap[user2.ID].Username)
	})
}

// ============================================================
// CreateClient – Authorization Code Flow fields
// ============================================================

func TestCreateClient_AuthCodeFlowEnabled(t *testing.T) {
	s := setupTestStore(t)
	svc := NewClientService(s, nil)
	userID := uuid.New().String()

	req := CreateClientRequest{
		ClientName:         "Auth Code Client",
		UserID:             userID,
		CreatedBy:          userID,
		Scopes:             "read write",
		EnableAuthCodeFlow: true,
		EnableDeviceFlow:   true, // both flows active
		RedirectURIs:       []string{"https://app.example.com/callback"},
	}

	resp, err := svc.CreateClient(context.Background(), req)
	require.NoError(t, err)

	assert.True(t, resp.EnableAuthCodeFlow)
	assert.True(t, resp.EnableDeviceFlow)
	assert.NotEmpty(t, resp.ClientID)
	assert.NotEmpty(t, resp.ClientSecretPlain) // Secret returned on creation only
}

func TestCreateClient_PublicClientType(t *testing.T) {
	s := setupTestStore(t)
	svc := NewClientService(s, nil)
	userID := uuid.New().String()

	req := CreateClientRequest{
		ClientName:         "Public SPA Client",
		UserID:             userID,
		CreatedBy:          userID,
		Scopes:             "read",
		ClientType:         ClientTypePublic,
		EnableAuthCodeFlow: true,
		RedirectURIs:       []string{"https://spa.example.com/callback"},
	}

	resp, err := svc.CreateClient(context.Background(), req)
	require.NoError(t, err)

	assert.Equal(t, ClientTypePublic, resp.ClientType)
}

func TestCreateClient_DefaultClientType(t *testing.T) {
	s := setupTestStore(t)
	svc := NewClientService(s, nil)
	userID := uuid.New().String()

	req := CreateClientRequest{
		ClientName: "Default Client",
		UserID:     userID,
		CreatedBy:  userID,
		Scopes:     "read",
		// ClientType not set → should default to "confidential"
	}

	resp, err := svc.CreateClient(context.Background(), req)
	require.NoError(t, err)

	assert.Equal(t, ClientTypeConfidential, resp.ClientType)
}

func TestCreateClient_OnlyAuthCodeFlow(t *testing.T) {
	// When only auth code flow is enabled, the service should not force device flow on.
	// The result depends on how the service handles the "neither enabled" default case.
	s := setupTestStore(t)
	svc := NewClientService(s, nil)
	userID := uuid.New().String()

	req := CreateClientRequest{
		ClientName:         "Auth-Code-Only Client",
		UserID:             userID,
		CreatedBy:          userID,
		Scopes:             "read write",
		EnableDeviceFlow:   false, // explicitly false
		EnableAuthCodeFlow: true,
		RedirectURIs:       []string{"https://app.example.com/callback"},
	}

	resp, err := svc.CreateClient(context.Background(), req)
	require.NoError(t, err)

	// Auth code flow must be enabled
	assert.True(t, resp.EnableAuthCodeFlow)
	// GrantTypes must include authorization_code
	assert.Contains(t, resp.GrantTypes, "authorization_code")
	assert.NotEmpty(t, resp.ClientID)
}

func TestCreateClient_NameRequired(t *testing.T) {
	s := setupTestStore(t)
	svc := NewClientService(s, nil)

	req := CreateClientRequest{
		ClientName: "", // Empty name
		UserID:     uuid.New().String(),
	}

	_, err := svc.CreateClient(context.Background(), req)
	assert.ErrorIs(t, err, ErrClientNameRequired)
}

func TestCreateClient_AuthCodeFlowRequiresRedirectURI(t *testing.T) {
	s := setupTestStore(t)
	svc := NewClientService(s, nil)
	userID := uuid.New().String()

	req := CreateClientRequest{
		ClientName:         "No Redirect Client",
		UserID:             userID,
		CreatedBy:          userID,
		EnableAuthCodeFlow: true,
		RedirectURIs:       []string{}, // empty → must be rejected
	}

	_, err := svc.CreateClient(context.Background(), req)
	assert.ErrorIs(t, err, ErrRedirectURIRequired)
}

func TestCreateClient_DeviceFlowOnlyNoRedirectURIRequired(t *testing.T) {
	s := setupTestStore(t)
	svc := NewClientService(s, nil)
	userID := uuid.New().String()

	req := CreateClientRequest{
		ClientName:       "Device Only Client",
		UserID:           userID,
		CreatedBy:        userID,
		EnableDeviceFlow: true,
		// No redirect URIs and no auth code flow → should succeed
	}

	resp, err := svc.CreateClient(context.Background(), req)
	require.NoError(t, err)
	assert.True(t, resp.EnableDeviceFlow)
	assert.False(t, resp.EnableAuthCodeFlow)
}

func TestUpdateClient_AuthCodeFlowRequiresRedirectURI(t *testing.T) {
	s := setupTestStore(t)
	svc := NewClientService(s, nil)
	userID := uuid.New().String()

	// Create a valid client first
	createReq := CreateClientRequest{
		ClientName:       "Update Target",
		UserID:           userID,
		CreatedBy:        userID,
		EnableDeviceFlow: true,
		RedirectURIs:     []string{"https://example.com/callback"},
	}
	resp, err := svc.CreateClient(context.Background(), createReq)
	require.NoError(t, err)

	updateReq := UpdateClientRequest{
		ClientName:         "Update Target",
		IsActive:           true,
		EnableAuthCodeFlow: true,
		RedirectURIs:       []string{}, // empty → must be rejected
	}

	err = svc.UpdateClient(context.Background(), resp.ClientID, userID, updateReq)
	assert.ErrorIs(t, err, ErrRedirectURIRequired)
}

func TestUpdateClient_AuthCodeFlowWithRedirectURISucceeds(t *testing.T) {
	s := setupTestStore(t)
	svc := NewClientService(s, nil)
	userID := uuid.New().String()

	createReq := CreateClientRequest{
		ClientName:       "Update Target",
		UserID:           userID,
		CreatedBy:        userID,
		EnableDeviceFlow: true,
		RedirectURIs:     []string{"https://example.com/callback"},
	}
	resp, err := svc.CreateClient(context.Background(), createReq)
	require.NoError(t, err)

	updateReq := UpdateClientRequest{
		ClientName:         "Update Target",
		IsActive:           true,
		EnableAuthCodeFlow: true,
		RedirectURIs:       []string{"https://example.com/callback"},
	}

	err = svc.UpdateClient(context.Background(), resp.ClientID, userID, updateReq)
	require.NoError(t, err)
}

func TestUpdateClient_BothGrantTypesDisabledRejected(t *testing.T) {
	s := setupTestStore(t)
	svc := NewClientService(s, nil)
	userID := uuid.New().String()

	createReq := CreateClientRequest{
		ClientName:       "Grant Type Client",
		UserID:           userID,
		CreatedBy:        userID,
		EnableDeviceFlow: true,
	}
	resp, err := svc.CreateClient(context.Background(), createReq)
	require.NoError(t, err)

	updateReq := UpdateClientRequest{
		ClientName:         "Grant Type Client",
		IsActive:           true,
		EnableDeviceFlow:   false, // both disabled → must be rejected
		EnableAuthCodeFlow: false,
	}

	err = svc.UpdateClient(context.Background(), resp.ClientID, userID, updateReq)
	assert.ErrorIs(t, err, ErrAtLeastOneGrantRequired)
}

func TestUpdateClient_GrantTypesReflectFlags(t *testing.T) {
	s := setupTestStore(t)
	svc := NewClientService(s, nil)
	userID := uuid.New().String()

	createReq := CreateClientRequest{
		ClientName:       "Grant Flags Client",
		UserID:           userID,
		CreatedBy:        userID,
		EnableDeviceFlow: true,
	}
	resp, err := svc.CreateClient(context.Background(), createReq)
	require.NoError(t, err)

	// Switch to auth code only
	updateReq := UpdateClientRequest{
		ClientName:         "Grant Flags Client",
		IsActive:           true,
		EnableDeviceFlow:   false,
		EnableAuthCodeFlow: true,
		RedirectURIs:       []string{"https://example.com/callback"},
	}
	err = svc.UpdateClient(context.Background(), resp.ClientID, userID, updateReq)
	require.NoError(t, err)

	updated, err := svc.GetClient(resp.ClientID)
	require.NoError(t, err)
	assert.False(t, updated.EnableDeviceFlow)
	assert.True(t, updated.EnableAuthCodeFlow)
	assert.Equal(t, "authorization_code", updated.GrantTypes)
}

// ============================================================
// validateRedirectURIs
// ============================================================

func TestValidateRedirectURIs(t *testing.T) {
	tests := []struct {
		name    string
		uris    []string
		wantErr bool
	}{
		{
			name:    "valid https URI",
			uris:    []string{"https://example.com/callback"},
			wantErr: false,
		},
		{
			name:    "valid http localhost URI",
			uris:    []string{"http://localhost:8080/callback"},
			wantErr: false,
		},
		{
			name:    "multiple valid URIs",
			uris:    []string{"https://app.example.com/cb", "https://staging.example.com/cb"},
			wantErr: false,
		},
		{
			name:    "empty list is allowed",
			uris:    []string{},
			wantErr: false,
		},
		{
			name:    "empty string URI",
			uris:    []string{""},
			wantErr: true,
		},
		{
			name:    "non-http scheme",
			uris:    []string{"ftp://example.com/callback"},
			wantErr: true,
		},
		{
			name:    "missing host",
			uris:    []string{"https:///callback"},
			wantErr: true,
		},
		{
			name:    "URI with fragment",
			uris:    []string{"https://example.com/callback#section"},
			wantErr: true,
		},
		{
			name:    "second URI invalid",
			uris:    []string{"https://valid.example.com/cb", "not-a-uri"},
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := validateRedirectURIs(tc.uris)
			if tc.wantErr {
				assert.ErrorIs(t, err, ErrInvalidRedirectURI)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestCreateClient_InvalidRedirectURIRejected(t *testing.T) {
	s := setupTestStore(t)
	svc := NewClientService(s, nil)
	userID := uuid.New().String()

	req := CreateClientRequest{
		ClientName:         "Bad URI Client",
		UserID:             userID,
		CreatedBy:          userID,
		EnableAuthCodeFlow: true,
		RedirectURIs:       []string{"ftp://evil.example.com/cb"},
	}

	_, err := svc.CreateClient(context.Background(), req)
	assert.ErrorIs(t, err, ErrInvalidRedirectURI)
}

func TestUpdateClient_InvalidRedirectURIRejected(t *testing.T) {
	s := setupTestStore(t)
	svc := NewClientService(s, nil)
	userID := uuid.New().String()

	createReq := CreateClientRequest{
		ClientName:       "URI Validation Client",
		UserID:           userID,
		CreatedBy:        userID,
		EnableDeviceFlow: true,
	}
	resp, err := svc.CreateClient(context.Background(), createReq)
	require.NoError(t, err)

	updateReq := UpdateClientRequest{
		ClientName:         "URI Validation Client",
		IsActive:           true,
		EnableAuthCodeFlow: true,
		RedirectURIs:       []string{"https://example.com/callback#fragment"},
	}

	err = svc.UpdateClient(context.Background(), resp.ClientID, userID, updateReq)
	assert.ErrorIs(t, err, ErrInvalidRedirectURI)
}
