package cache

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/redis/rueidis"
)

// prefixedKey prepends prefix to key.
func prefixedKey(prefix, key string) string {
	return prefix + key
}

// prefixedKeys returns a new slice with prefix prepended to each key.
func prefixedKeys(prefix string, keys []string) []string {
	full := make([]string, len(keys))
	for i, k := range keys {
		full[i] = prefix + k
	}
	return full
}

// marshalValue encodes a value to its JSON string representation.
func marshalValue[T any](value T) (string, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrInvalidValue, err)
	}
	return string(encoded), nil
}

// unmarshalValue decodes a JSON string into a value.
func unmarshalValue[T any](str string) (T, error) {
	var value T
	if err := json.Unmarshal([]byte(str), &value); err != nil {
		var zero T
		return zero, fmt.Errorf("%w: %v", ErrInvalidValue, err)
	}
	return value, nil
}

// fetchThrough implements the cache-aside pattern: try Get, on miss call
// fetchFunc and store the result via Set. Used by MemoryCache and RueidisCache.
func fetchThrough[T any](
	ctx context.Context,
	key string,
	ttl time.Duration,
	get func(context.Context, string) (T, error),
	set func(context.Context, string, T, time.Duration) error,
	fetchFunc func(context.Context, string) (T, error),
) (T, error) {
	if value, err := get(ctx, key); err == nil {
		return value, nil
	}
	value, err := fetchFunc(ctx, key)
	if err != nil {
		var zero T
		return zero, err
	}
	_ = set(ctx, key, value, ttl)
	return value, nil
}

// parseMultiGetResponse maps Redis MGET results back to their original keys,
// skipping nil or unparseable entries.
//
// Note: rueidis.RedisMessage has unexported fields and cannot be constructed
// outside the rueidis package, so this function is not directly unit-testable.
// The decode path (unmarshalValue) is covered by TestMarshalValue/TestUnmarshalValue,
// and the full MGet behaviour is exercised by Redis integration tests.
func parseMultiGetResponse[T any](keys []string, values []rueidis.RedisMessage) map[string]T {
	result := make(map[string]T, len(keys))
	for i, val := range values {
		if val.IsNil() {
			continue
		}
		str, err := val.ToString()
		if err != nil {
			continue
		}
		item, err := unmarshalValue[T](str)
		if err != nil {
			continue
		}
		result[keys[i]] = item
	}
	return result
}
