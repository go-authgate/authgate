package auth

import (
	"context"
	"errors"
	"fmt"
	"strconv"

	"golang.org/x/oauth2"
)

type giteaUser struct {
	ID        int64  `json:"id"`
	Login     string `json:"login"`
	FullName  string `json:"full_name"`
	Email     string `json:"email"`
	AvatarURL string `json:"avatar_url"`
}

func (p *OAuthProvider) getGiteaUserInfo(
	ctx context.Context,
	token *oauth2.Token,
) (*OAuthUserInfo, error) {
	client := p.config.Client(ctx, token)

	var user giteaUser
	if err := fetchJSON(ctx, client, p.apiURL, &user); err != nil {
		return nil, fmt.Errorf("failed to get Gitea user info: %w", err)
	}

	if user.Email == "" {
		return nil, errors.New("gitea account has no email address")
	}

	return &OAuthUserInfo{
		ProviderUserID: strconv.FormatInt(user.ID, 10),
		Username:       user.Login,
		Email:          user.Email,
		FullName:       user.FullName,
		AvatarURL:      user.AvatarURL,
		EmailVerified:  false, // Gitea API does not expose email verification status
	}, nil
}
