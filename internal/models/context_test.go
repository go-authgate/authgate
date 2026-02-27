package models

import (
	"context"
	"testing"
)

func TestSetUserContext(t *testing.T) {
	tests := []struct {
		name     string
		user     *User
		expected bool
	}{
		{
			name: "Valid user",
			user: &User{
				ID:       "user-123",
				Username: "testuser",
			},
			expected: true,
		},
		{
			name:     "Nil user",
			user:     nil,
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			newCtx := SetUserContext(ctx, tt.user)

			if newCtx == nil {
				t.Fatal("SetUserContext returned nil context")
			}

			// Try to retrieve the user
			retrievedUser := GetUserFromContext(newCtx)
			if tt.expected {
				if retrievedUser == nil {
					t.Error("Expected user to be in context, but got nil")
				} else if retrievedUser.ID != tt.user.ID {
					t.Errorf("Expected user ID %s, got %s", tt.user.ID, retrievedUser.ID)
				}
			} else {
				if retrievedUser != nil {
					t.Error("Expected no user in context, but got one")
				}
			}
		})
	}
}

func TestGetUsernameFromContext(t *testing.T) {
	tests := []struct {
		name     string
		user     *User
		expected string
	}{
		{
			name: "Valid user",
			user: &User{
				ID:       "user-123",
				Username: "testuser",
			},
			expected: "testuser",
		},
		{
			name:     "Nil user",
			user:     nil,
			expected: "",
		},
		{
			name:     "Empty context",
			user:     nil,
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var ctx context.Context
			if tt.user != nil {
				ctx = SetUserContext(context.Background(), tt.user)
			} else {
				ctx = context.Background()
			}

			username := GetUsernameFromContext(ctx)
			if username != tt.expected {
				t.Errorf("Expected username %q, got %q", tt.expected, username)
			}
		})
	}
}

func TestGetUserIDFromContext(t *testing.T) {
	tests := []struct {
		name     string
		user     *User
		expected string
	}{
		{
			name: "Valid user",
			user: &User{
				ID:       "user-123",
				Username: "testuser",
			},
			expected: "user-123",
		},
		{
			name:     "Nil user",
			user:     nil,
			expected: "",
		},
		{
			name:     "Empty context",
			user:     nil,
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var ctx context.Context
			if tt.user != nil {
				ctx = SetUserContext(context.Background(), tt.user)
			} else {
				ctx = context.Background()
			}

			userID := GetUserIDFromContext(ctx)
			if userID != tt.expected {
				t.Errorf("Expected user ID %q, got %q", tt.expected, userID)
			}
		})
	}
}

func TestGetUserFromContext(t *testing.T) {
	tests := []struct {
		name     string
		user     *User
		expected bool
	}{
		{
			name: "Valid user",
			user: &User{
				ID:       "user-123",
				Username: "testuser",
				Email:    "test@example.com",
			},
			expected: true,
		},
		{
			name:     "Nil user",
			user:     nil,
			expected: false,
		},
		{
			name:     "Empty context",
			user:     nil,
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var ctx context.Context
			if tt.user != nil {
				ctx = SetUserContext(context.Background(), tt.user)
			} else {
				ctx = context.Background()
			}

			user := GetUserFromContext(ctx)
			if tt.expected {
				if user == nil {
					t.Error("Expected user to be in context, but got nil")
				} else {
					if user.ID != tt.user.ID {
						t.Errorf("Expected user ID %s, got %s", tt.user.ID, user.ID)
					}
					if user.Username != tt.user.Username {
						t.Errorf("Expected username %s, got %s", tt.user.Username, user.Username)
					}
					if user.Email != tt.user.Email {
						t.Errorf("Expected email %s, got %s", tt.user.Email, user.Email)
					}
				}
			} else {
				if user != nil {
					t.Error("Expected no user in context, but got one")
				}
			}
		})
	}
}

func TestContextChaining(t *testing.T) {
	// Test that context values are preserved when chaining
	user := &User{
		ID:       "user-123",
		Username: "testuser",
	}

	// Use a custom type for test key to avoid lint warnings
	type testKey int
	const testKeyOther testKey = 0

	ctx := context.Background()
	ctx = context.WithValue(ctx, testKeyOther, "other_value")
	ctx = SetUserContext(ctx, user)

	// Check user is accessible
	if GetUsernameFromContext(ctx) != "testuser" {
		t.Error("User context was not preserved")
	}

	// Check other values are accessible
	if val := ctx.Value(testKeyOther); val != "other_value" {
		t.Error("Other context values were not preserved")
	}
}
