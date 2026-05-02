package config_test

import (
	"sort"
	"testing"

	"github.com/go-authgate/authgate/internal/config"
	"github.com/go-authgate/authgate/internal/token"

	"github.com/stretchr/testify/assert"
)

// TestPrivateClaimRegistryDrift ensures that config.jwtPrivateClaimLogicalNames
// (exposed via PrivateClaimLogicalNames) stays in sync with the canonical
// privateClaims registry in the token package (exposed via PrivateClaimRegistry).
// If this test fails, you added/removed a PrivateClaim entry in token/types.go
// without updating jwtPrivateClaimLogicalNames in config/config.go (or vice versa).
func TestPrivateClaimRegistryDrift(t *testing.T) {
	configNames := config.PrivateClaimLogicalNames()

	registry := token.PrivateClaimRegistry()
	tokenNames := make([]string, len(registry))
	for i, pc := range registry {
		tokenNames[i] = pc.LogicalName
	}

	sort.Strings(configNames)
	sort.Strings(tokenNames)

	assert.Equal(t, tokenNames, configNames,
		"config.jwtPrivateClaimLogicalNames is out of sync with token.privateClaims — "+
			"update the list in internal/config/config.go to match internal/token/types.go")
}
