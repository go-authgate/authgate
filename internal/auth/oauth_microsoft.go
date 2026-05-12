package auth

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/oauth2"
)

// microsoftUser is the Microsoft Graph API /me response. The on-prem fields
// are only populated for tenants that sync from Active Directory via Entra
// Connect; cloud-only and guest accounts leave them empty/null. They're not
// in Graph's default property set — the request must use $select.
type microsoftUser struct {
	ID                       string `json:"id"`
	UserPrincipalName        string `json:"userPrincipalName"`
	DisplayName              string `json:"displayName"`
	Mail                     string `json:"mail"`
	GivenName                string `json:"givenName"`
	Surname                  string `json:"surname"`
	OnPremisesSamAccountName string `json:"onPremisesSamAccountName"`
	// Pointer because Graph omits this field for cloud-only directories,
	// which is semantically distinct from sync=false on hybrid directories.
	OnPremisesSyncEnabled *bool  `json:"onPremisesSyncEnabled"`
	MailNickname          string `json:"mailNickname"`
}

// pickMicrosoftUsername returns the canonical local username for a Microsoft
// account: AD sAMAccountName when the directory is hybrid-synced, otherwise
// mailNickname, otherwise the email local-part.
func pickMicrosoftUsername(u *microsoftUser, email string) string {
	if u.OnPremisesSyncEnabled != nil && *u.OnPremisesSyncEnabled &&
		u.OnPremisesSamAccountName != "" {
		return u.OnPremisesSamAccountName
	}
	if u.MailNickname != "" {
		return u.MailNickname
	}
	return strings.Split(email, "@")[0]
}

func (p *OAuthProvider) getMicrosoftUserInfo(
	ctx context.Context,
	token *oauth2.Token,
) (*OAuthUserInfo, error) {
	client := p.config.Client(ctx, token)

	var user microsoftUser
	if err := fetchJSON(ctx, client, p.apiURL, &user); err != nil {
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
		Username:       pickMicrosoftUsername(&user, email),
		Email:          email,
		FullName:       fullName,
		AvatarURL:      "",   // Microsoft Graph /me doesn't include photo by default
		EmailVerified:  true, // Microsoft Entra ID email is tenant-controlled and admin-managed
	}, nil
}
