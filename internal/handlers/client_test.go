package handlers

import (
	"reflect"
	"testing"
)

func Test_parseRedirectURIs(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name:  "empty string",
			input: "",
			want:  []string{},
		},
		{
			name:  "whitespace only",
			input: "   ",
			want:  []string{},
		},
		{
			name:  "single URI",
			input: "https://example.com/callback",
			want:  []string{"https://example.com/callback"},
		},
		{
			name:  "single URI with leading/trailing spaces",
			input: "  https://example.com/callback  ",
			want:  []string{"https://example.com/callback"},
		},
		{
			name:  "multiple URIs",
			input: "https://example.com/callback,https://app.example.com/oauth",
			want:  []string{"https://example.com/callback", "https://app.example.com/oauth"},
		},
		{
			name:  "multiple URIs with spaces",
			input: "https://example.com/callback, https://app.example.com/oauth",
			want:  []string{"https://example.com/callback", "https://app.example.com/oauth"},
		},
		{
			name:  "multiple URIs with extra spaces",
			input: "  https://example.com/callback  ,  https://app.example.com/oauth  ,  http://localhost:8080  ",
			want: []string{
				"https://example.com/callback",
				"https://app.example.com/oauth",
				"http://localhost:8080",
			},
		},
		{
			name:  "URIs with empty elements",
			input: "https://example.com/callback, , https://app.example.com/oauth",
			want:  []string{"https://example.com/callback", "https://app.example.com/oauth"},
		},
		{
			name:  "URIs with trailing comma",
			input: "https://example.com/callback,https://app.example.com/oauth,",
			want:  []string{"https://example.com/callback", "https://app.example.com/oauth"},
		},
		{
			name:  "URIs with leading comma",
			input: ",https://example.com/callback,https://app.example.com/oauth",
			want:  []string{"https://example.com/callback", "https://app.example.com/oauth"},
		},
		{
			name:  "localhost URIs",
			input: "http://localhost:8080,http://127.0.0.1:3000",
			want:  []string{"http://localhost:8080", "http://127.0.0.1:3000"},
		},
		{
			name:  "newline separated",
			input: "https://a.example.com/cb\nhttps://b.example.com/cb",
			want:  []string{"https://a.example.com/cb", "https://b.example.com/cb"},
		},
		{
			name:  "CRLF separated",
			input: "https://a.example.com/cb\r\nhttps://b.example.com/cb",
			want:  []string{"https://a.example.com/cb", "https://b.example.com/cb"},
		},
		{
			name:  "mixed comma and newline",
			input: "https://a.example.com/cb,\nhttps://b.example.com/cb\nhttps://c.example.com/cb",
			want: []string{
				"https://a.example.com/cb",
				"https://b.example.com/cb",
				"https://c.example.com/cb",
			},
		},
		{
			name:  "newline with surrounding spaces",
			input: "  https://a.example.com/cb  \n  https://b.example.com/cb  \n",
			want:  []string{"https://a.example.com/cb", "https://b.example.com/cb"},
		},
		{
			name:  "blank lines between URIs",
			input: "https://a.example.com/cb\n\n\nhttps://b.example.com/cb",
			want:  []string{"https://a.example.com/cb", "https://b.example.com/cb"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseRedirectURIs(tt.input)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("parseRedirectURIs() = %v, want %v", got, tt.want)
			}
		})
	}
}
