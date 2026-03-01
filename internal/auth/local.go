package auth

import (
	"context"

	"github.com/go-authgate/authgate/internal/core"
	"github.com/go-authgate/authgate/internal/store"

	"golang.org/x/crypto/bcrypt"
)

var _ core.AuthProvider = (*LocalAuthProvider)(nil)

// LocalAuthProvider handles local database authentication
type LocalAuthProvider struct {
	store *store.Store
}

// NewLocalAuthProvider creates a new local authentication provider
func NewLocalAuthProvider(s *store.Store) *LocalAuthProvider {
	return &LocalAuthProvider{store: s}
}

// Authenticate verifies credentials against local database
func (p *LocalAuthProvider) Authenticate(
	ctx context.Context,
	username, password string,
) (*Result, error) {
	user, err := p.store.GetUserByUsername(username)
	if err != nil {
		return nil, ErrInvalidCredentials
	}

	if err := bcrypt.CompareHashAndPassword(
		[]byte(user.PasswordHash),
		[]byte(password),
	); err != nil {
		return nil, ErrInvalidCredentials
	}

	return &Result{
		Username:   user.Username,
		ExternalID: "", // Local users don't have external IDs
		Email:      user.Email,
		FullName:   user.FullName,
		Success:    true,
	}, nil
}

// Name returns provider name for logging
func (p *LocalAuthProvider) Name() string {
	return "local"
}
