package token

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/appleboy/authgate/internal/config"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// LocalTokenProvider generates and validates JWT tokens locally
type LocalTokenProvider struct {
	config *config.Config
}

// NewLocalTokenProvider creates a new local token provider
func NewLocalTokenProvider(cfg *config.Config) *LocalTokenProvider {
	return &LocalTokenProvider{config: cfg}
}

// GenerateToken creates a JWT token using local signing
func (p *LocalTokenProvider) GenerateToken(
	ctx context.Context,
	userID, clientID, scopes string,
) (*TokenResult, error) {
	expiresAt := time.Now().Add(p.config.JWTExpiration)

	claims := jwt.MapClaims{
		"user_id":   userID,
		"client_id": clientID,
		"scope":     scopes,
		"exp":       expiresAt.Unix(),
		"iat":       time.Now().Unix(),
		"iss":       p.config.BaseURL,
		"sub":       userID,
		"jti":       uuid.New().String(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte(p.config.JWTSecret))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrTokenGeneration, err)
	}

	return &TokenResult{
		TokenString: tokenString,
		TokenType:   "Bearer",
		ExpiresAt:   expiresAt,
		Claims:      claims,
		Success:     true,
	}, nil
}

// ValidateToken verifies a JWT token using local verification
func (p *LocalTokenProvider) ValidateToken(
	ctx context.Context,
	tokenString string,
) (*TokenValidationResult, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (any, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(p.config.JWTSecret), nil
	})
	if err != nil {
		// Check if it's an expiration error
		if errors.Is(err, jwt.ErrTokenExpired) {
			return nil, ErrExpiredToken
		}
		return nil, fmt.Errorf("%w: %v", ErrInvalidToken, err)
	}

	if !token.Valid {
		return nil, ErrInvalidToken
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, ErrInvalidToken
	}

	// Extract and validate claims
	userID, _ := claims["user_id"].(string)
	clientID, _ := claims["client_id"].(string)
	scopes, _ := claims["scope"].(string)

	exp, ok := claims["exp"].(float64)
	if !ok {
		return nil, ErrInvalidToken
	}
	expiresAt := time.Unix(int64(exp), 0)

	return &TokenValidationResult{
		Valid:     true,
		UserID:    userID,
		ClientID:  clientID,
		Scopes:    scopes,
		ExpiresAt: expiresAt,
		Claims:    claims,
	}, nil
}

// Name returns provider name for logging
func (p *LocalTokenProvider) Name() string {
	return "local"
}
