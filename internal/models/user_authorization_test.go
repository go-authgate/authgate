package models

import (
	"testing"
)

func TestUserAuthorization_TableName(t *testing.T) {
	ua := UserAuthorization{}
	if got := ua.TableName(); got != "user_authorizations" {
		t.Errorf("UserAuthorization.TableName() = %v, want %v", got, "user_authorizations")
	}
}
