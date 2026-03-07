//go:build tools

package tools

// Tool dependencies that are used via "go run" but not imported directly.
// This file ensures "go mod tidy" does not remove them.
import (
	_ "github.com/evanw/esbuild/pkg/api"
)
