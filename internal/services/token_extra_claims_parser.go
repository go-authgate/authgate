package services

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/go-authgate/authgate/internal/config"
	"github.com/go-authgate/authgate/internal/token"
)

// ErrExtraClaimsDisabled is returned when a caller supplies extra_claims but
// the feature has not been enabled in the server configuration.
var ErrExtraClaimsDisabled = errors.New("extra_claims feature is not enabled")

// ErrExtraClaimsTooLarge is returned when caller-supplied extra_claims exceed
// any of the configured size limits (raw bytes, key count, value size).
var ErrExtraClaimsTooLarge = errors.New("extra_claims exceeds configured size limits")

// ExtraClaimsParser decodes the caller-supplied extra_claims payload from
// /oauth/token, applying size limits and the reserved-key guard.
type ExtraClaimsParser struct {
	cfg *config.Config
}

// NewExtraClaimsParser returns a parser bound to the given config.
func NewExtraClaimsParser(cfg *config.Config) *ExtraClaimsParser {
	return &ExtraClaimsParser{cfg: cfg}
}

// Parse decodes the raw JSON payload, enforces size limits, and rejects
// reserved JWT/OIDC claim keys. (nil, nil) signals "no extras supplied"
// (empty input or JSON null) — the no-op path that keeps existing clients
// working when EXTRA_CLAIMS_ENABLED is left at its default.
//
//nolint:nilnil // (nil, nil) is the documented "no extras supplied" signal.
func (p *ExtraClaimsParser) Parse(raw string) (map[string]any, error) {
	if raw == "" {
		return nil, nil
	}
	if p.cfg == nil || !p.cfg.ExtraClaimsEnabled {
		return nil, ErrExtraClaimsDisabled
	}
	if limit := p.cfg.ExtraClaimsMaxRawSize; limit > 0 && len(raw) > limit {
		return nil, fmt.Errorf("%w: raw payload %d bytes (limit %d)",
			ErrExtraClaimsTooLarge, len(raw), limit)
	}

	var out map[string]any
	dec := json.NewDecoder(strings.NewReader(raw))
	dec.UseNumber() // preserve int-vs-float distinction for downstream validation
	if err := dec.Decode(&out); err != nil {
		return nil, fmt.Errorf("extra_claims: invalid JSON: %w", err)
	}
	if out == nil {
		// JSON "null" decodes to a nil map — treat as no-op rather than error.
		return nil, nil
	}

	if limit := p.cfg.ExtraClaimsMaxKeys; limit > 0 && len(out) > limit {
		return nil, fmt.Errorf("%w: %d keys (limit %d)",
			ErrExtraClaimsTooLarge, len(out), limit)
	}

	if err := token.ValidateExtraClaims(out); err != nil {
		return nil, err
	}

	if limit := p.cfg.ExtraClaimsMaxValSize; limit > 0 {
		for k, v := range out {
			size, err := approxValueSize(v)
			if err != nil {
				return nil, fmt.Errorf("extra_claims[%q]: %w", k, err)
			}
			if size > limit {
				return nil, fmt.Errorf("%w: value for %q is %d bytes (limit %d)",
					ErrExtraClaimsTooLarge, k, size, limit)
			}
		}
	}

	return out, nil
}

// approxValueSize measures the JSON-encoded size of v. Re-encoding (rather
// than scanning the raw input) makes per-value limits robust to whitespace
// and key ordering in the caller's payload.
func approxValueSize(v any) (int, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return 0, err
	}
	return len(b), nil
}
