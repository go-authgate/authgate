package auth

import (
	"context"
	"errors"
	"fmt"
	"strconv"

	"golang.org/x/oauth2"
)

type gitlabUser struct {
	ID        int64  `json:"id"`
	Username  string `json:"username"`
	Name      string `json:"name"`
	Email     string `json:"email"`
	AvatarURL string `json:"avatar_url"`
}

func (p *OAuthProvider) getGitLabUserInfo(
	ctx context.Context,
	token *oauth2.Token,
) (*OAuthUserInfo, error) {
	client := p.config.Client(ctx, token)

	var user gitlabUser
	if err := fetchJSON(ctx, client, p.apiURL, &user); err != nil {
		return nil, fmt.Errorf("failed to get GitLab user info: %w", err)
	}

	if user.Email == "" {
		return nil, errors.New("gitlab account has no email address")
	}

	return &OAuthUserInfo{
		ProviderUserID: strconv.FormatInt(user.ID, 10),
		Username:       user.Username,
		Email:          user.Email,
		FullName:       user.Name,
		AvatarURL:      user.AvatarURL,
		EmailVerified:  false, // GitLab API does not expose email verification status
	}, nil
}
