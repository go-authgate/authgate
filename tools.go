//go:build tools

package main

import (
	_ "github.com/a-h/templ/cmd/templ"
	_ "github.com/golangci/golangci-lint/v2/cmd/golangci-lint"
	_ "github.com/swaggo/swag/cmd/swag"
	_ "go.uber.org/mock/mockgen"
)
