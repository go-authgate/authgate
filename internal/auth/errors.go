package auth

import "errors"

var (
	ErrInvalidCredentials = errors.New("invalid username or password")

	// HTTP API errors
	ErrHTTPAPIConnection  = errors.New("failed to connect to authentication API")
	ErrHTTPAPIAuthFailed  = errors.New("authentication API rejected credentials")
	ErrHTTPAPIInvalidResp = errors.New("invalid response from authentication API")
)
