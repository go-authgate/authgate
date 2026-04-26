package services

import (
	"errors"
	"strings"
	"testing"

	"github.com/go-authgate/authgate/internal/config"
	"github.com/go-authgate/authgate/internal/token"
)

// newTestExtraClaimsParser builds a parser with the feature enabled and
// generous default limits so each test can override only the field it cares
// about. The defaults match Load()'s production defaults so behaviour is
// representative of a real deployment with EXTRA_CLAIMS_ENABLED=true.
func newTestExtraClaimsParser(t *testing.T, override func(*config.Config)) *ExtraClaimsParser {
	t.Helper()
	cfg := &config.Config{
		ExtraClaimsEnabled:    true,
		ExtraClaimsMaxRawSize: 4096,
		ExtraClaimsMaxKeys:    16,
		ExtraClaimsMaxValSize: 512,
	}
	if override != nil {
		override(cfg)
	}
	return NewExtraClaimsParser(cfg)
}

func TestExtraClaimsParser_EmptyInput(t *testing.T) {
	// Empty parameter is the happy path even when the feature is disabled —
	// existing clients that never set extra_claims must keep working.
	p := NewExtraClaimsParser(&config.Config{ExtraClaimsEnabled: false})
	got, err := p.Parse("")
	if err != nil {
		t.Fatalf("expected nil error on empty input, got %v", err)
	}
	if got != nil {
		t.Fatalf("expected nil claims on empty input, got %v", got)
	}
}

func TestExtraClaimsParser_DisabledFeatureRejectsNonEmpty(t *testing.T) {
	p := NewExtraClaimsParser(&config.Config{ExtraClaimsEnabled: false})
	_, err := p.Parse(`{"tenant":"acme"}`)
	if !errors.Is(err, ErrExtraClaimsDisabled) {
		t.Fatalf("expected ErrExtraClaimsDisabled, got %v", err)
	}
}

func TestExtraClaimsParser_HappyPath(t *testing.T) {
	p := newTestExtraClaimsParser(t, nil)
	got, err := p.Parse(`{"tenant":"acme","trace_id":"abc-123","feature_flags":["beta","ai"]}`)
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if got["tenant"] != "acme" {
		t.Errorf("expected tenant=acme, got %v", got["tenant"])
	}
	if got["trace_id"] != "abc-123" {
		t.Errorf("expected trace_id=abc-123, got %v", got["trace_id"])
	}
	flags, ok := got["feature_flags"].([]any)
	if !ok || len(flags) != 2 {
		t.Errorf("expected feature_flags=[beta ai], got %v", got["feature_flags"])
	}
}

func TestExtraClaimsParser_NullPayload(t *testing.T) {
	// JSON `null` decodes to a nil map. Treat as no-op rather than error so
	// callers can pass through whatever their HTTP framework gave them
	// without special-casing.
	p := newTestExtraClaimsParser(t, nil)
	got, err := p.Parse("null")
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if got != nil {
		t.Fatalf("expected nil claims, got %v", got)
	}
}

func TestExtraClaimsParser_InvalidJSON(t *testing.T) {
	p := newTestExtraClaimsParser(t, nil)
	_, err := p.Parse(`{not valid`)
	if err == nil {
		t.Fatalf("expected error on invalid JSON, got nil")
	}
	if !strings.Contains(err.Error(), "invalid JSON") {
		t.Errorf("expected 'invalid JSON' in error, got %v", err)
	}
}

func TestExtraClaimsParser_ReservedKeyRejected(t *testing.T) {
	p := newTestExtraClaimsParser(t, nil)
	_, err := p.Parse(`{"iss":"evil","tenant":"acme"}`)
	if !errors.Is(err, token.ErrReservedClaimKey) {
		t.Fatalf("expected ErrReservedClaimKey, got %v", err)
	}
}

func TestExtraClaimsParser_RawSizeLimit(t *testing.T) {
	p := newTestExtraClaimsParser(t, func(c *config.Config) {
		c.ExtraClaimsMaxRawSize = 32
	})
	// Payload longer than 32 bytes should be rejected before JSON parsing.
	_, err := p.Parse(`{"tenant":"some-very-long-value-here"}`)
	if !errors.Is(err, ErrExtraClaimsTooLarge) {
		t.Fatalf("expected ErrExtraClaimsTooLarge, got %v", err)
	}
}

func TestExtraClaimsParser_KeyCountLimit(t *testing.T) {
	p := newTestExtraClaimsParser(t, func(c *config.Config) {
		c.ExtraClaimsMaxKeys = 2
	})
	_, err := p.Parse(`{"a":"1","b":"2","c":"3"}`)
	if !errors.Is(err, ErrExtraClaimsTooLarge) {
		t.Fatalf("expected ErrExtraClaimsTooLarge, got %v", err)
	}
}

func TestExtraClaimsParser_ValueSizeLimit(t *testing.T) {
	p := newTestExtraClaimsParser(t, func(c *config.Config) {
		c.ExtraClaimsMaxValSize = 8
	})
	// Value over 8 bytes when JSON-encoded should be rejected.
	_, err := p.Parse(`{"tenant":"this-is-too-long"}`)
	if !errors.Is(err, ErrExtraClaimsTooLarge) {
		t.Fatalf("expected ErrExtraClaimsTooLarge, got %v", err)
	}
}

func TestExtraClaimsParser_ZeroLimitsDisableChecks(t *testing.T) {
	// All limits set to zero must mean "no enforcement" rather than
	// "everything fails immediately".
	p := newTestExtraClaimsParser(t, func(c *config.Config) {
		c.ExtraClaimsMaxRawSize = 0
		c.ExtraClaimsMaxKeys = 0
		c.ExtraClaimsMaxValSize = 0
	})
	_, err := p.Parse(`{"tenant":"acme","trace_id":"abc"}`)
	if err != nil {
		t.Fatalf("expected nil error with limits disabled, got %v", err)
	}
}
