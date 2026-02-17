package cache

import "errors"

var (
	// ErrCacheMiss indicates the requested key was not found in cache
	ErrCacheMiss = errors.New("cache: key not found")

	// ErrCacheUnavailable indicates the cache backend is unavailable
	ErrCacheUnavailable = errors.New("cache: backend unavailable")

	// ErrInvalidValue indicates the cached value cannot be parsed
	ErrInvalidValue = errors.New("cache: invalid value")
)
