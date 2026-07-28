package middleware

import "testing"

func TestScoreJA4(t *testing.T) {
	tests := []struct {
		name  string
		ja4   string
		ja4h  string
		want  float64
		above float64
		below float64
	}{
		{
			name: "known-bad python-requests",
			ja4:  "ja4-13010000h2",
			ja4h: "ja4h-abcdef012345",
			want: 0.95,
		},
		{
			name: "known-bad curl",
			ja4:  "ja4-13020000h2",
			want: 0.95,
		},
		{
			name: "normal browser",
			ja4:  "ja4-1303ff00h2",
			ja4h: "ja4h-112233445566",
			want: 0.5,
		},
		{
			name: "empty both",
			ja4:  "",
			ja4h: "",
			want: 0.5,
		},
		{
			name: "ja4 only with no match",
			ja4:  "ja4-9999xxxxxx",
			want: 0.5,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ScoreJA4(tt.ja4, tt.ja4h)
			if got != tt.want {
				t.Errorf("ScoreJA4(%q, %q) = %v, want %v", tt.ja4, tt.ja4h, got, tt.want)
			}
		})
	}
}