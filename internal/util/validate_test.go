package util

import (
	"strings"
	"testing"
)

func TestIsValidProjectIdentifier(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  bool
	}{
		{name: "empty", input: "", want: false},
		{name: "single alnum", input: "a", want: true},
		{name: "single digit", input: "9", want: true},
		{name: "lowercase word", input: "oa", want: true},
		{name: "mixed case", input: "MyProject", want: true},
		{name: "with underscore", input: "my_project", want: true},
		{name: "with dot", input: "my.project", want: true},
		{name: "with hyphen", input: "my-project", want: true},
		{name: "alnum digits", input: "project123", want: true},
		{name: "max length 64", input: "a" + strings.Repeat("b", 62) + "c", want: true},

		{name: "leading hyphen", input: "-foo", want: false},
		{name: "trailing hyphen", input: "foo-", want: false},
		{name: "leading underscore", input: "_foo", want: false},
		{name: "trailing dot", input: "foo.", want: false},
		{name: "contains space", input: "bad value with spaces", want: false},
		{name: "contains slash", input: "foo/bar", want: false},
		{name: "contains at-sign", input: "foo@bar", want: false},
		{name: "too long 65", input: "a" + strings.Repeat("b", 63) + "c", want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsValidProjectIdentifier(tt.input); got != tt.want {
				t.Errorf("IsValidProjectIdentifier(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}
