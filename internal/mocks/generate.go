package mocks

// Mock generation directives. Run `make mocks` or `go generate ./internal/mocks/` to regenerate.

//go:generate go tool -modfile ../../go.tools.mod mockgen -source=../core/cache.go -destination=mock_cache.go -package=mocks
//go:generate go tool -modfile ../../go.tools.mod mockgen -source=../core/metrics.go -destination=mock_metrics.go -package=mocks
//go:generate go tool -modfile ../../go.tools.mod mockgen -source=../core/auth.go -destination=mock_auth.go -package=mocks
//go:generate go tool -modfile ../../go.tools.mod mockgen -source=../core/token.go -destination=mock_token.go -package=mocks
