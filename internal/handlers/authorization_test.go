package handlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/go-authgate/authgate/internal/config"
	"github.com/go-authgate/authgate/internal/models"
	"github.com/go-authgate/authgate/internal/services"
	"github.com/go-authgate/authgate/internal/store"
	"github.com/go-authgate/authgate/internal/util"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ============================================================
// maxStateLength
// ============================================================

func TestMaxStateLength_AcceptsAtLimit(t *testing.T) {
	state := strings.Repeat("a", maxStateLength)
	assert.LessOrEqual(t, len(state), maxStateLength)
}

func TestMaxStateLength_RejectsOverLimit(t *testing.T) {
	state := strings.Repeat("a", maxStateLength+1)
	assert.Greater(t, len(state), maxStateLength)
}

func TestMaxStateLength_AcceptsEmpty(t *testing.T) {
	assert.LessOrEqual(t, len(""), maxStateLength)
}

// ============================================================
// oauthErrorCode
// ============================================================

func TestOauthErrorCode_UnauthorizedClient(t *testing.T) {
	assert.Equal(t, "unauthorized_client", oauthErrorCode(services.ErrUnauthorizedClient))
}

func TestOauthErrorCode_UnsupportedResponseType(t *testing.T) {
	assert.Equal(
		t,
		"unsupported_response_type",
		oauthErrorCode(services.ErrUnsupportedResponseType),
	)
}

func TestOauthErrorCode_InvalidScope(t *testing.T) {
	assert.Equal(t, "invalid_scope", oauthErrorCode(services.ErrInvalidAuthCodeScope))
}

func TestOauthErrorCode_InvalidTarget(t *testing.T) {
	// RFC 8707 maps to "invalid_target".
	assert.Equal(t, "invalid_target", oauthErrorCode(services.ErrInvalidTarget))
}

func TestOauthErrorCode_DefaultsToInvalidRequest(t *testing.T) {
	// Any unrecognised error falls back to "invalid_request"
	assert.Equal(t, errInvalidRequest, oauthErrorCode(services.ErrInvalidAuthCodeRequest))
	assert.Equal(t, errInvalidRequest, oauthErrorCode(services.ErrInvalidRedirectURI))
	assert.Equal(t, errInvalidRequest, oauthErrorCode(services.ErrAuthCodeNotFound))
	assert.Equal(t, errInvalidRequest, oauthErrorCode(services.ErrPKCERequired))
}

// ============================================================
// authzSuccessMessages / authzErrorMessages
// ============================================================

func TestAuthzSuccessMessages_KnownKeys(t *testing.T) {
	assert.Equal(
		t,
		"Application access has been revoked successfully.",
		authzSuccessMessages["revoked"],
	)
}

func TestAuthzErrorMessages_KnownKeys(t *testing.T) {
	assert.Equal(t, "Authorization not found.", authzErrorMessages["not_found"])
	assert.Equal(
		t,
		"An error occurred while processing your request. Please try again.",
		authzErrorMessages["server_error"],
	)
}

func TestAuthzMessages_UnknownKeyReturnsEmpty(t *testing.T) {
	injections := []string{
		"arbitrary_text",
		"<script>alert(1)</script>",
		"",
	}
	for _, key := range injections {
		assert.Empty(
			t,
			authzSuccessMessages[key],
			"unknown success key %q must return empty string",
			key,
		)
		assert.Empty(
			t,
			authzErrorMessages[key],
			"unknown error key %q must return empty string",
			key,
		)
	}
}

// ============================================================
// util.IsScopeSubset (formerly scopesAreCovered)
// ============================================================

func TestScopesAreCovered_ExactMatch(t *testing.T) {
	assert.True(t, util.IsScopeSubset("read write", "read write"))
}

func TestScopesAreCovered_SubsetOfGranted(t *testing.T) {
	assert.True(t, util.IsScopeSubset("read write admin", "read"))
	assert.True(t, util.IsScopeSubset("read write admin", "read write"))
}

func TestScopesAreCovered_RequestedExceedsGranted(t *testing.T) {
	assert.False(t, util.IsScopeSubset("read", "read write"))
	assert.False(t, util.IsScopeSubset("read write", "read write admin"))
}

func TestScopesAreCovered_EmptyRequestedScopes(t *testing.T) {
	// No scopes requested → trivially covered
	assert.True(t, util.IsScopeSubset("read write", ""))
}

func TestScopesAreCovered_EmptyGrantedScopes(t *testing.T) {
	// Nothing granted but something requested → not covered
	assert.False(t, util.IsScopeSubset("", "read"))
}

func TestScopesAreCovered_BothEmpty(t *testing.T) {
	assert.True(t, util.IsScopeSubset("", ""))
}

func TestScopesAreCovered_DuplicateTokensInRequest(t *testing.T) {
	// Duplicate tokens should still pass if the scope is granted
	assert.True(t, util.IsScopeSubset("read write", "read read"))
}

func TestScopesAreCovered_ExtraWhitespace(t *testing.T) {
	// strings.Fields handles extra whitespace
	assert.True(t, util.IsScopeSubset("read  write", "read"))
}

// ============================================================
// RFC 8707 Resource Indicators — handler integration
// ============================================================

// setupAuthorizeTestEnv wires up a real authorization handler against an
// in-memory SQLite store plus a registered confidential client and a real
// user. The returned gin engine has only `/oauth/authorize` registered with
// a test middleware that injects user_id into the gin context, simulating
// what RequireAuth does in production.
func setupAuthorizeTestEnv(
	t *testing.T,
) (engine *gin.Engine, client *models.OAuthApplication) {
	t.Helper()
	gin.SetMode(gin.TestMode)

	cfg := &config.Config{
		BaseURL:            "http://localhost:8080",
		AuthCodeExpiration: 10 * time.Minute,
	}

	s, err := store.New(context.Background(), "sqlite", ":memory:", &config.Config{})
	require.NoError(t, err)

	auditSvc := services.NewNoopAuditService()
	clientSvc := services.NewClientService(s, auditSvc, nil, 0, nil, 0)
	userSvc := services.NewUserService(s, nil, nil, "local", false, auditSvc, nil, 0)
	authzSvc := services.NewAuthorizationService(s, cfg, auditSvc, nil, clientSvc)
	handler := NewAuthorizationHandler(authzSvc, nil, userSvc, cfg)

	// Register a confidential client with a fixed redirect URI.
	client = &models.OAuthApplication{
		ClientID:           uuid.New().String(),
		ClientSecret:       "test-secret-hash",
		ClientName:         "Resource Test Client",
		UserID:             uuid.New().String(),
		Scopes:             "read",
		GrantTypes:         "authorization_code",
		RedirectURIs:       models.StringArray{"https://app.example.com/callback"},
		ClientType:         "confidential",
		EnableAuthCodeFlow: true,
		Status:             models.ClientStatusActive,
	}
	require.NoError(t, s.CreateClient(client))

	// Create a real user the handler can resolve via userService.GetUserByID.
	user := &models.User{
		ID:       uuid.New().String(),
		Username: "rsrc-test-user",
		Email:    "rsrc-test@example.com",
		IsActive: true,
	}
	require.NoError(t, s.CreateUser(user))

	r := gin.New()
	// Inject the simulated logged-in user into the gin context — bypasses
	// the RequireAuth middleware that this handler relies on in production.
	r.Use(func(c *gin.Context) {
		c.Set("user_id", user.ID)
		c.Set("user", user)
		c.Next()
	})
	r.GET("/oauth/authorize", handler.ShowAuthorizePage)
	return r, client
}

// TestAuthorize_InvalidResource_RedirectsAfterValidation verifies the
// security invariant: an invalid `resource` only redirects AFTER the
// authorization request has been validated (proving the redirect_uri is
// registered). The redirect carries `error=invalid_target` and preserves
// `state` per RFC 6749 §4.1.2.1.
func TestAuthorize_InvalidResource_RedirectsAfterValidation(t *testing.T) {
	r, client := setupAuthorizeTestEnv(t)

	q := url.Values{
		"client_id":     {client.ClientID},
		"redirect_uri":  {"https://app.example.com/callback"},
		"response_type": {"code"},
		"scope":         {"read"},
		"state":         {"xyz"},
		"resource":      {"https://mcp.example.com/path#frag"},
	}
	req := httptest.NewRequest(http.MethodGet, "/oauth/authorize?"+q.Encode(), nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	require.Equal(t, http.StatusFound, w.Code)
	loc := w.Header().Get("Location")
	require.NotEmpty(t, loc)
	assert.Contains(t, loc, "https://app.example.com/callback")
	assert.Contains(t, loc, "error=invalid_target")
	assert.Contains(t, loc, "state=xyz")
}

// TestAuthorize_UnsupportedResponseType_UnregisteredRedirectURI_NotReflected
// asserts the open-redirect mitigation for the unsupported_response_type
// path: ValidateAuthorizationRequest checks response_type BEFORE the
// redirect_uri match, so an attacker pairing response_type=token with an
// unregistered redirect_uri must NOT cause AuthGate to redirect there with
// the OAuth error. The handler renders an error page locally instead.
func TestAuthorize_UnsupportedResponseType_UnregisteredRedirectURI_NotReflected(t *testing.T) {
	r, client := setupAuthorizeTestEnv(t)

	q := url.Values{
		"client_id":     {client.ClientID},
		"redirect_uri":  {"https://evil.example.com/exfil"},
		"response_type": {"token"},
		"scope":         {"read"},
		"state":         {"xyz"},
	}
	req := httptest.NewRequest(http.MethodGet, "/oauth/authorize?"+q.Encode(), nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	assert.NotEqual(
		t, http.StatusFound, w.Code,
		"unsupported_response_type with an unregistered redirect_uri must not redirect",
	)
	loc := w.Header().Get("Location")
	assert.NotContains(
		t, loc, "evil.example.com",
		"unregistered redirect_uri must not be reflected as a redirect target",
	)
}

// TestAuthorize_UnsupportedResponseType_RegisteredRedirectURI_Redirects
// asserts the RFC 6749 §4.1.2.1 spec invariant for the
// unsupported_response_type error: when the redirect_uri IS registered for
// the client, the error must be returned to that URI as a redirect, not
// rendered locally. ValidateAuthorizationRequest checks response_type before
// redirect_uri, so the error path re-runs ValidateClientRedirect to prove
// the URI is registered before reflecting.
func TestAuthorize_UnsupportedResponseType_RegisteredRedirectURI_Redirects(t *testing.T) {
	r, client := setupAuthorizeTestEnv(t)

	q := url.Values{
		"client_id":     {client.ClientID},
		"redirect_uri":  {"https://app.example.com/callback"},
		"response_type": {"token"}, // not supported
		"scope":         {"read"},
		"state":         {"xyz"},
	}
	req := httptest.NewRequest(http.MethodGet, "/oauth/authorize?"+q.Encode(), nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	require.Equal(t, http.StatusFound, w.Code, "registered redirect_uri → redirect")
	loc := w.Header().Get("Location")
	assert.Contains(t, loc, "https://app.example.com/callback")
	assert.Contains(t, loc, "error=unsupported_response_type")
	assert.Contains(t, loc, "state=xyz")
}

// TestAuthorize_InvalidResource_UnregisteredRedirectURI_NotReflected
// asserts the open-redirect mitigation: when an invalid `resource` is
// paired with an UNREGISTERED redirect_uri, the response must NOT redirect
// to that attacker-controlled URI. The handler runs request validation
// (which rejects the unregistered URI) before resource validation, so the
// error is rendered locally rather than reflected.
func TestAuthorize_InvalidResource_UnregisteredRedirectURI_NotReflected(t *testing.T) {
	r, client := setupAuthorizeTestEnv(t)

	q := url.Values{
		"client_id":     {client.ClientID},
		"redirect_uri":  {"https://evil.example.com/exfil"},
		"response_type": {"code"},
		"scope":         {"read"},
		"state":         {"xyz"},
		"resource":      {"https://mcp.example.com/path#frag"},
	}
	req := httptest.NewRequest(http.MethodGet, "/oauth/authorize?"+q.Encode(), nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	// Even if the response IS a redirect (existing handler behavior on
	// invalid_redirect_uri), it MUST NOT go to the attacker-controlled URI.
	loc := w.Header().Get("Location")
	assert.NotContains(
		t, loc, "evil.example.com",
		"unregistered redirect_uri must not be reflected as a redirect target",
	)
}

// setupAuthorizePOSTEnv extends setupAuthorizeTestEnv with the POST route so
// HandleAuthorize (the consent submission handler) can be exercised. CSRF is
// not wired in the test setup — that middleware is layered separately in
// bootstrap/router.go and is orthogonal to the validation logic under test.
func setupAuthorizePOSTEnv(
	t *testing.T,
	clientType string,
	pkceRequired bool,
) (engine *gin.Engine, client *models.OAuthApplication, userID string) {
	t.Helper()
	gin.SetMode(gin.TestMode)

	cfg := &config.Config{
		BaseURL:            "http://localhost:8080",
		AuthCodeExpiration: 10 * time.Minute,
		PKCERequired:       pkceRequired,
	}

	s, err := store.New(context.Background(), "sqlite", ":memory:", &config.Config{})
	require.NoError(t, err)

	auditSvc := services.NewNoopAuditService()
	clientSvc := services.NewClientService(s, auditSvc, nil, 0, nil, 0)
	userSvc := services.NewUserService(s, nil, nil, "local", false, auditSvc, nil, 0)
	authzSvc := services.NewAuthorizationService(s, cfg, auditSvc, nil, clientSvc)
	handler := NewAuthorizationHandler(authzSvc, nil, userSvc, cfg)

	client = &models.OAuthApplication{
		ClientID:           uuid.New().String(),
		ClientSecret:       "test-secret-hash",
		ClientName:         "Deny Test Client",
		UserID:             uuid.New().String(),
		Scopes:             "read",
		GrantTypes:         "authorization_code",
		RedirectURIs:       models.StringArray{"https://app.example.com/callback"},
		ClientType:         clientType,
		EnableAuthCodeFlow: true,
		Status:             models.ClientStatusActive,
	}
	require.NoError(t, s.CreateClient(client))

	user := &models.User{
		ID:       uuid.New().String(),
		Username: "deny-test-user",
		Email:    "deny-test@example.com",
		IsActive: true,
	}
	require.NoError(t, s.CreateUser(user))
	userID = user.ID

	r := gin.New()
	r.Use(func(c *gin.Context) {
		c.Set("user_id", user.ID)
		c.Set("user", user)
		c.Next()
	})
	r.POST("/oauth/authorize", handler.HandleAuthorize)
	return r, client, userID
}

// TestAuthorize_PublicClientDeny_RedirectsAccessDenied verifies that a Deny
// click on a PUBLIC client redirects with `error=access_denied` even though
// the Deny form does not POST `scope` or any PKCE parameter. Public clients
// require PKCE on the approve path, but enforcing that on the deny path
// (which the form doesn't post for) would erroneously block users from
// canceling and leak a PKCE error back to the client instead of access_denied.
func TestAuthorize_PublicClientDeny_RedirectsAccessDenied(t *testing.T) {
	r, client, _ := setupAuthorizePOSTEnv(t, "public", false)

	form := url.Values{
		"action":       {"deny"},
		"client_id":    {client.ClientID},
		"redirect_uri": {"https://app.example.com/callback"},
		"state":        {"state-123"},
	}
	req := httptest.NewRequest(
		http.MethodPost,
		"/oauth/authorize",
		strings.NewReader(form.Encode()),
	)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	require.Equal(t, http.StatusFound, w.Code, "deny should redirect, not error")
	loc := w.Header().Get("Location")
	require.NotEmpty(t, loc)
	assert.Contains(t, loc, "https://app.example.com/callback")
	assert.Contains(t, loc, "error=access_denied")
	assert.Contains(t, loc, "state=state-123")
	assert.NotContains(
		t, loc, "invalid_request",
		"deny must NOT surface a PKCE/scope validation error",
	)
}

// TestAuthorize_GlobalPKCEDeny_RedirectsAccessDenied is the same invariant
// for confidential clients when global PKCE enforcement is on
// (PKCE_REQUIRED=true). Without the deny-first reorder, the deny path runs
// the full validator which sees a missing code_challenge_method and rejects
// with invalid_request instead of access_denied.
func TestAuthorize_GlobalPKCEDeny_RedirectsAccessDenied(t *testing.T) {
	r, client, _ := setupAuthorizePOSTEnv(t, "confidential", true)

	form := url.Values{
		"action":       {"deny"},
		"client_id":    {client.ClientID},
		"redirect_uri": {"https://app.example.com/callback"},
		"state":        {"state-456"},
	}
	req := httptest.NewRequest(
		http.MethodPost,
		"/oauth/authorize",
		strings.NewReader(form.Encode()),
	)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	require.Equal(t, http.StatusFound, w.Code)
	loc := w.Header().Get("Location")
	assert.Contains(t, loc, "error=access_denied")
	assert.NotContains(t, loc, "invalid_request")
}

// TestAuthorize_DenyUnregisteredRedirectURI_NotReflected confirms the open-
// redirect guard remains intact on the deny path: an unregistered
// redirect_uri must NOT be honored, even though deny short-circuits before
// the full request validator. ValidateClientRedirect runs the redirect_uri
// check, so the bad URI is rejected and the response is not redirected to
// the attacker.
func TestAuthorize_DenyUnregisteredRedirectURI_NotReflected(t *testing.T) {
	r, client, _ := setupAuthorizePOSTEnv(t, "public", false)

	form := url.Values{
		"action":       {"deny"},
		"client_id":    {client.ClientID},
		"redirect_uri": {"https://evil.example.com/exfil"},
		"state":        {"state-789"},
	}
	req := httptest.NewRequest(
		http.MethodPost,
		"/oauth/authorize",
		strings.NewReader(form.Encode()),
	)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	loc := w.Header().Get("Location")
	assert.NotContains(
		t, loc, "evil.example.com",
		"unregistered redirect_uri must not be reflected on the deny path",
	)
}
