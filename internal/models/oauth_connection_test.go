package models

import (
	"testing"
)

func TestOAuthConnection_TableName(t *testing.T) {
	c := OAuthConnection{}
	if got := c.TableName(); got != "oauth_connections" {
		t.Errorf("OAuthConnection.TableName() = %v, want %v", got, "oauth_connections")
	}
}
