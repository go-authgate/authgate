package models

import (
	"context"
	"database/sql/driver"
	"testing"
)

func TestStringArray_Join(t *testing.T) {
	tests := []struct {
		name      string
		array     StringArray
		separator string
		want      string
	}{
		{
			name:      "empty array",
			array:     StringArray{},
			separator: ", ",
			want:      "",
		},
		{
			name:      "single element",
			array:     StringArray{"https://example.com/callback"},
			separator: ", ",
			want:      "https://example.com/callback",
		},
		{
			name:      "multiple elements with comma separator",
			array:     StringArray{"https://example.com/callback", "https://app.example.com/oauth"},
			separator: ", ",
			want:      "https://example.com/callback, https://app.example.com/oauth",
		},
		{
			name: "multiple elements with newline separator",
			array: StringArray{
				"http://localhost:8080",
				"http://localhost:3000",
				"http://127.0.0.1:8080",
			},
			separator: "\n",
			want:      "http://localhost:8080\nhttp://localhost:3000\nhttp://127.0.0.1:8080",
		},
		{
			name:      "multiple elements with pipe separator",
			array:     StringArray{"read", "write", "delete"},
			separator: " | ",
			want:      "read | write | delete",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.array.Join(tt.separator)
			if got != tt.want {
				t.Errorf("StringArray.Join() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestStringArray_Scan(t *testing.T) {
	tests := []struct {
		name    string
		value   any
		want    StringArray
		wantErr bool
	}{
		{
			name:    "nil value",
			value:   nil,
			want:    StringArray{},
			wantErr: false,
		},
		{
			name:    "valid JSON array",
			value:   []byte(`["https://example.com","https://app.example.com"]`),
			want:    StringArray{"https://example.com", "https://app.example.com"},
			wantErr: false,
		},
		{
			name:    "empty JSON array",
			value:   []byte(`[]`),
			want:    StringArray{},
			wantErr: false,
		},
		{
			name:    "single element JSON array",
			value:   []byte(`["http://localhost:8080"]`),
			want:    StringArray{"http://localhost:8080"},
			wantErr: false,
		},
		{
			name:    "invalid type (not []byte)",
			value:   "not a byte slice",
			want:    StringArray(nil),
			wantErr: true,
		},
		{
			name:    "invalid JSON",
			value:   []byte(`{"invalid": "json"}`),
			want:    StringArray(nil),
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var s StringArray
			err := s.Scan(tt.value)
			if (err != nil) != tt.wantErr {
				t.Errorf("StringArray.Scan() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				if len(s) != len(tt.want) {
					t.Errorf("StringArray.Scan() length = %v, want %v", len(s), len(tt.want))
					return
				}
				for i := range s {
					if s[i] != tt.want[i] {
						t.Errorf("StringArray.Scan()[%d] = %v, want %v", i, s[i], tt.want[i])
					}
				}
			}
		})
	}
}

func TestStringArray_Value(t *testing.T) {
	tests := []struct {
		name    string
		array   StringArray
		want    driver.Value
		wantErr bool
	}{
		{
			name:    "empty array",
			array:   StringArray{},
			want:    []byte(`[]`),
			wantErr: false,
		},
		{
			name:    "nil array",
			array:   nil,
			want:    []byte(`[]`),
			wantErr: false,
		},
		{
			name:    "single element",
			array:   StringArray{"https://example.com"},
			want:    []byte(`["https://example.com"]`),
			wantErr: false,
		},
		{
			name: "multiple elements",
			array: StringArray{
				"https://example.com",
				"https://app.example.com",
				"http://localhost:8080",
			},
			want: []byte(
				`["https://example.com","https://app.example.com","http://localhost:8080"]`,
			),
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.array.Value()
			if (err != nil) != tt.wantErr {
				t.Errorf("StringArray.Value() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				gotBytes, ok := got.([]byte)
				if !ok {
					t.Errorf("StringArray.Value() returned non-[]byte type")
					return
				}
				wantBytes, _ := tt.want.([]byte)
				if string(gotBytes) != string(wantBytes) {
					t.Errorf(
						"StringArray.Value() = %s, want %s",
						string(gotBytes),
						string(wantBytes),
					)
				}
			}
		})
	}
}

func TestOAuthApplication_GenerateClientSecret(t *testing.T) {
	app := &OAuthApplication{}
	secret, err := app.GenerateClientSecret(context.Background())
	if err != nil {
		t.Fatalf("GenerateClientSecret() unexpected error: %v", err)
	}

	if len(secret) < 4 || secret[:4] != "ago_" {
		t.Errorf("GenerateClientSecret() secret missing 'ago_' prefix: %v", secret)
	}
	if app.ClientSecret == "" {
		t.Error("GenerateClientSecret() did not set ClientSecret hash")
	}
	if app.ClientSecret == secret {
		t.Error("GenerateClientSecret() stored plaintext instead of hash")
	}
}

func TestOAuthApplication_ValidateClientSecret(t *testing.T) {
	app := &OAuthApplication{}
	secret, err := app.GenerateClientSecret(context.Background())
	if err != nil {
		t.Fatalf("GenerateClientSecret() unexpected error: %v", err)
	}

	if !app.ValidateClientSecret([]byte(secret)) {
		t.Error("ValidateClientSecret() returned false for correct secret")
	}
	if app.ValidateClientSecret([]byte("wrong_secret")) {
		t.Error("ValidateClientSecret() returned true for wrong secret")
	}
}

func TestOAuthApplication_TableName(t *testing.T) {
	app := OAuthApplication{}
	if got := app.TableName(); got != "oauth_applications" {
		t.Errorf("OAuthApplication.TableName() = %v, want %v", got, "oauth_applications")
	}
}

func TestOAuthApplication_IsActive(t *testing.T) {
	tests := []struct {
		name   string
		status string
		want   bool
	}{
		{name: "active", status: ClientStatusActive, want: true},
		{name: "pending", status: ClientStatusPending, want: false},
		{name: "inactive", status: ClientStatusInactive, want: false},
		{name: "empty", status: "", want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			app := &OAuthApplication{Status: tt.status}
			if got := app.IsActive(); got != tt.want {
				t.Errorf("OAuthApplication.IsActive() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIsValidTokenProfile(t *testing.T) {
	tests := []struct {
		in   string
		want bool
	}{
		{in: TokenProfileShort, want: true},
		{in: TokenProfileStandard, want: true},
		{in: TokenProfileLong, want: true},
		{in: "", want: false},
		{in: "SHORT", want: false}, // case-sensitive
		{in: "custom", want: false},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			if got := IsValidTokenProfile(tt.in); got != tt.want {
				t.Errorf("IsValidTokenProfile(%q) = %v, want %v", tt.in, got, tt.want)
			}
		})
	}
}
