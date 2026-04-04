package services

// fetchErr wraps a store error returned inside GetWithFetch's fetchFunc,
// so callers can distinguish a store/DB error from a cache-backend error.
// Used by GetClient and getAccessTokenByHash to decide whether to fall back
// to a direct DB lookup.
type fetchErr struct{ cause error }

func (e *fetchErr) Error() string { return e.cause.Error() }
func (e *fetchErr) Unwrap() error { return e.cause }
