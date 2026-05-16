package util

import "testing"

func TestIsStringSliceSubset(t *testing.T) {
	tests := []struct {
		name  string
		super []string
		sub   []string
		want  bool
	}{
		{"empty sub is always subset", []string{"a"}, nil, true},
		{"empty sub against empty super", nil, nil, true},
		{"non-empty sub against empty super", nil, []string{"a"}, false},
		{"single match", []string{"a"}, []string{"a"}, true},
		{"single non-match", []string{"a"}, []string{"b"}, false},
		{"sub fully covered", []string{"a", "b", "c"}, []string{"a", "c"}, true},
		{"sub partially covered", []string{"a", "b"}, []string{"a", "c"}, false},
		{"duplicates in sub still covered", []string{"a"}, []string{"a", "a"}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsStringSliceSubset(tt.super, tt.sub); got != tt.want {
				t.Fatalf("got %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIsStringSliceSetEqual(t *testing.T) {
	tests := []struct {
		name string
		a, b []string
		want bool
	}{
		{"both empty are equal", nil, nil, true},
		{"empty vs nil are equal", []string{}, nil, true},
		{"empty vs non-empty differs", nil, []string{"a"}, false},
		{"identical single", []string{"a"}, []string{"a"}, true},
		{"identical multiple, same order", []string{"a", "b"}, []string{"a", "b"}, true},
		{"identical multiple, different order", []string{"a", "b"}, []string{"b", "a"}, true},
		{"superset vs subset differs", []string{"a", "b"}, []string{"a"}, false},
		{"duplicates collapse to set equality", []string{"a", "a", "b"}, []string{"a", "b"}, true},
		{"different elements differs", []string{"a"}, []string{"b"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsStringSliceSetEqual(tt.a, tt.b); got != tt.want {
				t.Fatalf("got %v, want %v", got, tt.want)
			}
		})
	}
}
