package util

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestTruncateString(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		maxLen int
		want   string
	}{
		{"short string unchanged", "hello", 10, "hello"},
		{"exact length unchanged", "hello", 5, "hello"},
		{"truncated with ellipsis", "hello world", 5, "hello..."},
		{"empty string", "", 5, ""},
		{"zero max length", "hello", 0, "..."},
		{"long string", strings.Repeat("a", 300), 200, strings.Repeat("a", 200) + "..."},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, TruncateString(tt.input, tt.maxLen))
		})
	}
}
