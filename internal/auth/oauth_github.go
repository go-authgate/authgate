package auth

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strconv"

	"golang.org/x/oauth2"
)

type githubUser struct {
	ID        int64  `json:"id"`
	Login     string `json:"login"`
	Name      string `json:"name"`
	Email     string `json:"email"`
	AvatarURL string `json:"avatar_url"`
}

type githubEmail struct {
	Email      string `json:"email"`
	Primary    bool   `json:"primary"`
	Verified   bool   `json:"verified"`
	Visibility string `json:"visibility"`
}

func (p *OAuthProvider) getGitHubUserInfo(
	ctx context.Context,
	token *oauth2.Token,
) (*OAuthUserInfo, error) {
	client := p.config.Client(ctx, token)

	var user githubUser
	if err := fetchJSON(ctx, client, "https://api.github.com/user", &user); err != nil {
		return nil, fmt.Errorf("failed to get GitHub user info: %w", err)
	}

	// If email is not public, fetch from emails endpoint
	if user.Email == "" {
		email, err := p.getGitHubPrimaryEmail(ctx, client)
		if err != nil {
			return nil, fmt.Errorf("failed to get user email: %w", err)
		}
		user.Email = email
	}

	if user.Email == "" {
		return nil, errors.New("GitHub account has no email address")
	}

	return &OAuthUserInfo{
		ProviderUserID: strconv.FormatInt(user.ID, 10),
		Username:       user.Login,
		Email:          user.Email,
		FullName:       user.Name,
		AvatarURL:      user.AvatarURL,
	}, nil
}

func (p *OAuthProvider) getGitHubPrimaryEmail(
	ctx context.Context,
	client *http.Client,
) (string, error) {
	var emails []githubEmail
	if err := fetchJSON(ctx, client, "https://api.github.com/user/emails", &emails); err != nil {
		return "", fmt.Errorf("failed to get GitHub emails: %w", err)
	}

	// Find primary verified email
	for _, email := range emails {
		if email.Primary && email.Verified {
			return email.Email, nil
		}
	}

	// Fallback to first verified email
	for _, email := range emails {
		if email.Verified {
			return email.Email, nil
		}
	}

	return "", errors.New("no verified email found")
}
