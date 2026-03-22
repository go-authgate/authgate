package models

import (
	"testing"
)

func TestUser_IsAdmin(t *testing.T) {
	tests := []struct {
		name string
		role string
		want bool
	}{
		{name: "admin role", role: UserRoleAdmin, want: true},
		{name: "user role", role: UserRoleUser, want: false},
		{name: "empty role", role: "", want: false},
		{name: "unknown role", role: "moderator", want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u := &User{Role: tt.role}
			if got := u.IsAdmin(); got != tt.want {
				t.Errorf("User.IsAdmin() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestUser_IsExternal(t *testing.T) {
	tests := []struct {
		name       string
		authSource string
		want       bool
	}{
		{name: "http_api is external", authSource: AuthSourceHTTPAPI, want: true},
		{name: "local is not external", authSource: AuthSourceLocal, want: false},
		{name: "empty is not external", authSource: "", want: false},
		{name: "oauth provider is external", authSource: "github", want: true},
		{name: "gitea provider is external", authSource: "gitea", want: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u := &User{AuthSource: tt.authSource}
			if got := u.IsExternal(); got != tt.want {
				t.Errorf("User.IsExternal() = %v, want %v", got, tt.want)
			}
		})
	}
}
