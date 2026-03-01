package mocks

// Mock generation directives. Run `make mocks` or `go generate ./internal/mocks/` to regenerate.

//go:generate go run go.uber.org/mock/mockgen -source=../core/cache.go -destination=mock_cache.go -package=mocks
//go:generate go run go.uber.org/mock/mockgen -source=../core/metrics.go -destination=mock_metrics.go -package=mocks
