package middleware

import (
	"testing"
)

func TestParseRate(t *testing.T) {
	tests := []struct {
		input      string
		wantMax    int
		wantWindow string
		wantErr    bool
	}{
		{"100/min", 100, "1m0s", false},
		{"50/second", 50, "1s", false},
		{"10/s", 10, "1s", false},
		{"200/hour", 200, "1h0m0s", false},
		{"invalid", 0, "", true},
		{"abc/min", 0, "", true},
		{"100/x", 0, "", true},
		{"100", 0, "", true},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			max, window, err := ParseRate(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseRate(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				if max != tt.wantMax {
					t.Errorf("max = %d, want %d", max, tt.wantMax)
				}
				if window.String() != tt.wantWindow {
					t.Errorf("window = %v, want %v", window, tt.wantWindow)
				}
			}
		})
	}
}
