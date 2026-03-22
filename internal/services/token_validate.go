package services

import (
	"context"
	"errors"
	"log"

	"github.com/go-authgate/authgate/internal/token"
	"github.com/go-authgate/authgate/internal/util"

	"gorm.io/gorm"
)

// ValidateToken validates a JWT token using the configured provider
func (s *TokenService) ValidateToken(
	ctx context.Context,
	tokenString string,
) (*token.ValidationResult, error) {
	result, err := s.tokenProvider.ValidateToken(ctx, tokenString)
	if err != nil {
		return nil, err
	}

	// Check token exists in database and validate its state (revocation, expiry, category)
	tok, err := s.store.GetAccessTokenByHash(util.SHA256Hex(tokenString))
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, errors.New("token not found or revoked")
		}
		log.Printf("[Token] token lookup failed: %v", err)
		return nil, errors.New("token not found or revoked")
	}
	if !tok.IsAccessToken() {
		return nil, errors.New("token is not an access token")
	}
	if !tok.IsActive() {
		return nil, errors.New("token not found or revoked")
	}
	if tok.IsExpired() {
		return nil, errors.New("token has expired")
	}

	return result, nil
}
