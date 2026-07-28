package tlsmw

import (
	"bytes"
	"errors"
	"testing"
)

func TestValidatePreface(t *testing.T) {
	if err := ValidatePreface([]byte(H2Preface)); err != nil {
		t.Fatalf("valid preface should pass: %v", err)
	}
	if err := ValidatePreface([]byte("PRI * HTTP/1.1\r\n\r\n")); err == nil {
		t.Fatalf("HTTP/1.1 preface must fail")
	}
	if err := ValidatePreface([]byte{}); err == nil {
		t.Fatalf("empty must fail")
	}
}

func TestParseFrameValid(t *testing.T) {
	// Build a minimal SETTINGS frame (length=0, type=4, flags=0, stream=0)
	frame := []byte{
		0x00, 0x00, 0x00, // length=0
		0x04,             // SETTINGS
		0x00,             // flags
		0x00, 0x00, 0x00, 0x00, // stream id
	}
	buf := append([]byte{}, frame...)
	f, n, err := ParseFrame(buf, 1<<14)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if n != 9 {
		t.Fatalf("consumed %d, want 9", n)
	}
	if f.Type != FrameSettings {
		t.Fatalf("frame type = %d, want SETTINGS", f.Type)
	}
}

func TestParseFrameInvalidType(t *testing.T) {
	frame := []byte{
		0x00, 0x00, 0x00,
		0x7F, // invalid frame type
		0x00,
		0x00, 0x00, 0x00, 0x00,
	}
	_, _, err := ParseFrame(frame, 1<<14)
	if err == nil {
		t.Fatalf("want reject for invalid frame type")
	}
}

func TestParseFrameSettingsBadLength(t *testing.T) {
	// SETTINGS body must be multiple of 6 bytes. 7 bytes is bad.
	body := []byte{1, 2, 3, 4, 5, 6, 7}
	header := []byte{
		byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body)),
		0x04, 0x00,
		0x00, 0x00, 0x00, 0x00,
	}
	buf := append(header, body...)
	_, _, err := ParseFrame(buf, 1<<14)
	var h2err *H2Err
	if !errors.As(err, &h2err) {
		t.Fatalf("want H2Err, got %T %v", err, err)
	}
}

func TestSettingsEntryValidation(t *testing.T) {
	cases := []struct {
		id   uint16
		val  uint32
		want bool
	}{
		{0x2, 2, false},  // ENABLE_PUSH must be 0 or 1
		{0x2, 0, true},
		{0x2, 1, true},
		{0x5, 100, false}, // MAX_FRAME_SIZE must be 2^14..2^24-1
		{0x5, 1 << 14, true},
		{0x5, 1<<24 - 1, true},
		{0x5, 1 << 24, false},
		{0x999, 0xFFFFFFFF, true}, // unknown setting — allow
	}
	for _, tc := range cases {
		if got := validSettingsEntry(tc.id, tc.val); got != tc.want {
			t.Errorf("validSettingsEntry(%#x, %d) = %v, want %v", tc.id, tc.val, got, tc.want)
		}
	}
}

func TestParseFramePingValidatesBody(t *testing.T) {
	// PING requires exactly 8 bytes of opaque data
	body := []byte{1, 2, 3, 4} // only 4 bytes — invalid
	header := []byte{
		0x00, 0x00, 0x04,
		0x06, 0x00,
		0x00, 0x00, 0x00, 0x00,
	}
	buf := append(header, body...)
	_, _, err := ParseFrame(buf, 1<<14)
	if err == nil {
		t.Fatalf("want reject for bad PING body")
	}
}

func TestPingLengthTooLarge(t *testing.T) {
	header := []byte{
		0x00, 0x00, 0x09, // length=9 — exceeds maxBody=8
		0x06, 0x00,
		0x00, 0x00, 0x00, 0x00,
	}
	buf := append(header, make([]byte, 9)...)
	_, _, err := ParseFrame(buf, 8)
	if err == nil {
		t.Fatalf("want reject for body-too-large")
	}
}

// silence unused
var _ = bytes.NewBuffer
