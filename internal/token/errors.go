package token

import "errors"

var (
	// ErrTokenGeneration indicates token generation failed
	ErrTokenGeneration = errors.New("failed to generate token")

	// ErrTokenValidation indicates token validation failed
	ErrTokenValidation = errors.New("failed to validate token")

	// ErrInvalidToken indicates the token is invalid
	ErrInvalidToken = errors.New("invalid token")

	// ErrExpiredToken indicates the token has expired
	ErrExpiredToken = errors.New("token expired")

	// Refresh token specific errors

	// ErrInvalidRefreshToken indicates the refresh token is invalid
	ErrInvalidRefreshToken = errors.New("invalid refresh token")

	// ErrExpiredRefreshToken indicates the refresh token has expired
	ErrExpiredRefreshToken = errors.New("refresh token expired")

	// ErrTokenReused indicates a refresh token was reused (security alert)
	ErrTokenReused = errors.New("token reuse detected")

	// ErrInvalidScope indicates scope validation failed
	ErrInvalidScope = errors.New("invalid scope")

	// HTTP API specific errors

	// ErrHTTPTokenConnection indicates failed connection to token API
	ErrHTTPTokenConnection = errors.New("failed to connect to token API")

	// ErrHTTPTokenAuthFailed indicates token API rejected request
	ErrHTTPTokenAuthFailed = errors.New("token API rejected request")

	// ErrHTTPTokenInvalidResp indicates invalid response from token API
	ErrHTTPTokenInvalidResp = errors.New("invalid response from token API")
)
