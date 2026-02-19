package main

import (
	"crypto/sha256"
	"encoding/base64"
	"strings"
	"testing"
)

func TestGeneratePKCE_VerifierLength(t *testing.T) {
	p, err := GeneratePKCE()
	if err != nil {
		t.Fatalf("GeneratePKCE() error: %v", err)
	}

	// RFC 7636 §4.1: verifier must be between 43 and 128 chars.
	if len(p.Verifier) < 43 || len(p.Verifier) > 128 {
		t.Errorf("verifier length %d is outside [43, 128]", len(p.Verifier))
	}
}

func TestGeneratePKCE_VerifierCharset(t *testing.T) {
	p, err := GeneratePKCE()
	if err != nil {
		t.Fatalf("GeneratePKCE() error: %v", err)
	}

	allowed := func(c rune) bool {
		return (c >= 'A' && c <= 'Z') ||
			(c >= 'a' && c <= 'z') ||
			(c >= '0' && c <= '9') ||
			c == '-' || c == '_'
	}
	for _, c := range p.Verifier {
		if !allowed(c) {
			t.Errorf("verifier contains disallowed character: %q", c)
		}
	}
}

func TestGeneratePKCE_ChallengeIsS256(t *testing.T) {
	p, err := GeneratePKCE()
	if err != nil {
		t.Fatalf("GeneratePKCE() error: %v", err)
	}

	sum := sha256.Sum256([]byte(p.Verifier))
	expected := base64.RawURLEncoding.EncodeToString(sum[:])

	if p.Challenge != expected {
		t.Errorf("challenge mismatch\n  got:  %s\n  want: %s", p.Challenge, expected)
	}
}

func TestGeneratePKCE_ChallengeNoPadding(t *testing.T) {
	p, err := GeneratePKCE()
	if err != nil {
		t.Fatalf("GeneratePKCE() error: %v", err)
	}

	if strings.Contains(p.Challenge, "=") {
		t.Errorf("challenge must not contain padding, got: %s", p.Challenge)
	}
	if strings.Contains(p.Challenge, "+") || strings.Contains(p.Challenge, "/") {
		t.Errorf("challenge must use URL-safe base64, got: %s", p.Challenge)
	}
}

func TestGeneratePKCE_MethodIsS256(t *testing.T) {
	p, err := GeneratePKCE()
	if err != nil {
		t.Fatalf("GeneratePKCE() error: %v", err)
	}
	if p.Method != "S256" {
		t.Errorf("method = %q, want S256", p.Method)
	}
}

func TestGeneratePKCE_Uniqueness(t *testing.T) {
	const iterations = 100
	seen := make(map[string]bool, iterations)

	for i := 0; i < iterations; i++ {
		p, err := GeneratePKCE()
		if err != nil {
			t.Fatalf("GeneratePKCE() error on iteration %d: %v", i, err)
		}
		if seen[p.Verifier] {
			t.Fatalf("duplicate verifier generated on iteration %d: %s", i, p.Verifier)
		}
		seen[p.Verifier] = true
	}
}

func TestGenerateState_Length(t *testing.T) {
	s, err := generateState()
	if err != nil {
		t.Fatalf("generateState() error: %v", err)
	}
	if len(s) < 20 {
		t.Errorf("state is too short: %d chars", len(s))
	}
}

func TestGenerateState_Uniqueness(t *testing.T) {
	const iterations = 50
	seen := make(map[string]bool, iterations)
	for i := 0; i < iterations; i++ {
		s, err := generateState()
		if err != nil {
			t.Fatalf("generateState() error: %v", err)
		}
		if seen[s] {
			t.Fatalf("duplicate state on iteration %d", i)
		}
		seen[s] = true
	}
}
