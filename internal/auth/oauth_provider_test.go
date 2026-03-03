package auth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"golang.org/x/oauth2"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newTestToken returns a minimal oauth2.Token shared across provider tests.
func newTestToken() *oauth2.Token {
	return &oauth2.Token{AccessToken: "test-access-token"}
}

// mockTransport is an http.RoundTripper that dispatches to an http.Handler.
// Inject it via contextWithMock to intercept calls from p.config.Client(ctx, token).
type mockTransport struct {
	handler http.Handler
}

func (m *mockTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	w := httptest.NewRecorder()
	m.handler.ServeHTTP(w, req)
	return w.Result(), nil
}

// contextWithMock returns a context that injects handler as the HTTP transport
// used by oauth2 clients, enabling tests of providers with hardcoded API URLs.
func contextWithMock(handler http.Handler) context.Context {
	return context.WithValue(
		context.Background(),
		oauth2.HTTPClient,
		&http.Client{Transport: &mockTransport{handler: handler}},
	)
}

func TestGetDisplayName(t *testing.T) {
	tests := []struct {
		provider string
		want     string
	}{
		{"github", "GitHub"},
		{"gitea", "Gitea"},
		{"gitlab", "GitLab"},
		{"microsoft", "Microsoft"},
		{"custom", "Custom"},
		{"", ""},
	}
	for _, tt := range tests {
		p := &OAuthProvider{provider: tt.provider}
		assert.Equal(t, tt.want, p.GetDisplayName(), "provider=%q", tt.provider)
	}
}

func TestGetUserInfo_UnsupportedProvider(t *testing.T) {
	p := &OAuthProvider{provider: "unsupported"}
	info, err := p.GetUserInfo(context.Background(), newTestToken())

	require.Error(t, err)
	assert.Nil(t, info)
	assert.Contains(t, err.Error(), "unsupported provider")
}
