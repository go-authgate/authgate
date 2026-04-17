package handlers

import (
	"context"
	"errors"
	"strings"

	"github.com/go-authgate/authgate/internal/models"
	"github.com/go-authgate/authgate/internal/services"

	"github.com/gin-gonic/gin"
)

// Form parameters defined in RFC 7521 §4.2 for assertion-based client authentication.
const (
	formClientAssertion     = "client_assertion"
	formClientAssertionType = "client_assertion_type"
)

// Errors returned by the shared client authenticator. All map to OAuth
// invalid_client; the distinction is for logs/tests and for choosing the
// correct WWW-Authenticate header.
var (
	ErrClientAuthRequired    = errors.New("client authentication required")
	ErrClientAuthMismatch    = errors.New("client_id mismatch between parameters and assertion")
	ErrClientAuthMethodUnmet = errors.New(
		"client authentication method does not match client registration",
	)
	ErrClientAuthSecretBad = errors.New("invalid client secret")
)

// AuthenticatedClient carries the outcome of a successful authentication at the
// token endpoint.
type AuthenticatedClient struct {
	Client *models.OAuthApplication
	Method string // client_secret_basic | client_secret_post | private_key_jwt | none
}

// ClientAuthenticator performs RFC 6749 §2.3 + RFC 7521 §4.2 authentication at
// the token endpoint. It supports client_secret_basic, client_secret_post,
// private_key_jwt, and none (public clients). Assertion-audience validation
// lives on ClientAssertionVerifier; this type only dispatches.
type ClientAuthenticator struct {
	clientService     *services.ClientService
	assertionVerifier *services.ClientAssertionVerifier
}

// NewClientAuthenticator wires a new authenticator. assertionVerifier may be
// nil, in which case private_key_jwt assertions are rejected.
func NewClientAuthenticator(
	cs *services.ClientService,
	av *services.ClientAssertionVerifier,
) *ClientAuthenticator {
	return &ClientAuthenticator{
		clientService:     cs,
		assertionVerifier: av,
	}
}

// Authenticate inspects the request and returns the authenticated client.
// requireConfidential=true forces the caller to present credentials (for grants
// like client_credentials that are restricted to confidential clients);
// requireConfidential=false still verifies credentials when they are supplied,
// but allows public clients to pass with only a client_id.
func (a *ClientAuthenticator) Authenticate(
	c *gin.Context,
	requireConfidential bool,
) (*AuthenticatedClient, error) {
	assertion := c.PostForm(formClientAssertion)
	assertionType := c.PostForm(formClientAssertionType)
	if assertion != "" || assertionType != "" {
		return a.authenticateViaAssertion(c.Request.Context(), c, assertion, assertionType)
	}

	clientID, secret, cameFromHeader := parseClientCredentials(c)
	if clientID == "" {
		return nil, ErrClientAuthRequired
	}

	client, err := a.clientService.GetClientWithSecret(c.Request.Context(), clientID)
	if err != nil {
		return nil, ErrClientAuthRequired
	}
	if !client.IsActive() {
		return nil, ErrClientAuthRequired
	}

	// Enforce registration consistency: a private_key_jwt client must use an
	// assertion (which takes the branch above), not a shared secret.
	if client.UsesPrivateKeyJWT() {
		return nil, ErrClientAuthMethodUnmet
	}

	if client.UsesClientSecret() {
		if secret == "" || !client.ValidateClientSecret([]byte(secret)) {
			return nil, ErrClientAuthSecretBad
		}
		observed := models.TokenEndpointAuthClientSecretBasic
		if !cameFromHeader {
			observed = models.TokenEndpointAuthClientSecretPost
		}
		// Enforce the registered method contract: a client registered as
		// client_secret_basic must use Basic Auth, and client_secret_post
		// must use form-body credentials. Accepting either mode would let a
		// stolen secret be presented through whichever channel happens to
		// be easier for the attacker.
		if client.TokenEndpointAuthMethod != observed {
			return nil, ErrClientAuthMethodUnmet
		}
		return &AuthenticatedClient{
			Client: client,
			Method: observed,
		}, nil
	}

	// Public client (method=none). Only allowed when requireConfidential=false.
	if requireConfidential {
		return nil, ErrClientAuthRequired
	}
	return &AuthenticatedClient{
		Client: client,
		Method: models.TokenEndpointAuthNone,
	}, nil
}

func (a *ClientAuthenticator) authenticateViaAssertion(
	ctx context.Context,
	c *gin.Context,
	assertion, assertionType string,
) (*AuthenticatedClient, error) {
	if a.assertionVerifier == nil {
		return nil, ErrClientAuthRequired
	}
	client, err := a.assertionVerifier.Verify(ctx, assertion, assertionType)
	if err != nil {
		return nil, err
	}
	// RFC 7521 §4.2: if client_id is also sent as a form param, it must match
	// the authenticated client.
	if formID := strings.TrimSpace(
		c.PostForm("client_id"),
	); formID != "" &&
		formID != client.ClientID {
		return nil, ErrClientAuthMismatch
	}
	return &AuthenticatedClient{
		Client: client,
		Method: models.TokenEndpointAuthPrivateKeyJWT,
	}, nil
}
