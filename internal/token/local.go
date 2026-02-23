package token

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/go-authgate/authgate/internal/config"
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

// generateJWT creates a signed JWT token with the given claims and expiration
func (p *LocalTokenProvider) generateJWT(
	userID, clientID, scopes, tokenType string,
	expiresAt time.Time,
) (*TokenResult, error) {
	claims := jwt.MapClaims{
		"user_id":   userID,
		"client_id": clientID,
		"scope":     scopes,
		"type":      tokenType,
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
		TokenType:   TokenTypeBearer,
		ExpiresAt:   expiresAt,
		Claims:      claims,
		Success:     true,
	}, nil
}

// GenerateToken creates a JWT token using local signing
func (p *LocalTokenProvider) GenerateToken(
	ctx context.Context,
	userID, clientID, scopes string,
) (*TokenResult, error) {
	expiresAt := time.Now().Add(p.config.JWTExpiration)
	return p.generateJWT(userID, clientID, scopes, "access", expiresAt)
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

// GenerateRefreshToken creates a refresh token JWT with longer expiration
func (p *LocalTokenProvider) GenerateRefreshToken(
	ctx context.Context,
	userID, clientID, scopes string,
) (*TokenResult, error) {
	expiresAt := time.Now().Add(p.config.RefreshTokenExpiration)
	return p.generateJWT(userID, clientID, scopes, "refresh", expiresAt)
}

// ValidateRefreshToken verifies a refresh token JWT
func (p *LocalTokenProvider) ValidateRefreshToken(
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
			return nil, ErrExpiredRefreshToken
		}
		return nil, fmt.Errorf("%w: %v", ErrInvalidRefreshToken, err)
	}

	if !token.Valid {
		return nil, ErrInvalidRefreshToken
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, ErrInvalidRefreshToken
	}

	// Verify this is a refresh token
	tokenType, _ := claims["type"].(string)
	if tokenType != "refresh" {
		return nil, ErrInvalidRefreshToken
	}

	// Extract and validate claims
	userID, _ := claims["user_id"].(string)
	clientID, _ := claims["client_id"].(string)
	scopes, _ := claims["scope"].(string)

	exp, ok := claims["exp"].(float64)
	if !ok {
		return nil, ErrInvalidRefreshToken
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

// RefreshAccessToken generates new access token (and optionally new refresh token in rotation mode)
func (p *LocalTokenProvider) RefreshAccessToken(
	ctx context.Context,
	refreshToken string,
	enableRotation bool,
) (*RefreshResult, error) {
	// Validate the refresh token
	validationResult, err := p.ValidateRefreshToken(ctx, refreshToken)
	if err != nil {
		return nil, err
	}

	// Generate new access token
	accessTokenResult, err := p.GenerateToken(
		ctx,
		validationResult.UserID,
		validationResult.ClientID,
		validationResult.Scopes,
	)
	if err != nil {
		return nil, err
	}

	// Note: "type" claim already added in GenerateToken method

	result := &RefreshResult{
		AccessToken: accessTokenResult,
		Success:     true,
	}

	// Generate new refresh token only in rotation mode
	if enableRotation {
		newRefreshToken, err := p.GenerateRefreshToken(
			ctx,
			validationResult.UserID,
			validationResult.ClientID,
			validationResult.Scopes,
		)
		if err != nil {
			return nil, err
		}
		result.RefreshToken = newRefreshToken
	}

	return result, nil
}
