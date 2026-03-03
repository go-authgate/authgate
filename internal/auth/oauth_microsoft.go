package auth

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/oauth2"
)

// microsoftUser is the Microsoft Graph API /me response
type microsoftUser struct {
	ID                string `json:"id"`                // Object ID (UUID)
	UserPrincipalName string `json:"userPrincipalName"` // user@domain.com
	DisplayName       string `json:"displayName"`       // Full name
	Mail              string `json:"mail"`              // Email (may be empty)
	GivenName         string `json:"givenName"`         // First name
	Surname           string `json:"surname"`           // Last name
}

func (p *OAuthProvider) getMicrosoftUserInfo(
	ctx context.Context,
	token *oauth2.Token,
) (*OAuthUserInfo, error) {
	client := p.config.Client(ctx, token)

	var user microsoftUser
	if err := fetchJSON(ctx, client, "https://graph.microsoft.com/v1.0/me", &user); err != nil {
		return nil, fmt.Errorf("failed to get Microsoft user info: %w", err)
	}

	// Prefer mail, fallback to userPrincipalName
	email := user.Mail
	if email == "" {
		email = user.UserPrincipalName
	}
	if email == "" {
		return nil, errors.New("microsoft account has no email address")
	}

	fullName := user.DisplayName
	if fullName == "" && (user.GivenName != "" || user.Surname != "") {
		fullName = strings.TrimSpace(user.GivenName + " " + user.Surname)
	}

	return &OAuthUserInfo{
		ProviderUserID: user.ID,
		Username:       strings.Split(email, "@")[0],
		Email:          email,
		FullName:       fullName,
		AvatarURL:      "", // Microsoft Graph /me doesn't include photo by default
	}, nil
}
