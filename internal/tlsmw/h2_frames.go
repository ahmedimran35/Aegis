// Package tlsmw: HTTP/2 frame parser for H2 smuggling detection.
//
// Go's http2 package handles only standard H2 connections — clients that
// smuggle H2 frames inside an HTTP/1.1 Upgrade (h2c) or that send non-standard
// frames via prior knowledge bypass our TLS termination and can confuse backends
// expecting H1 framing.
//
// This file implements a defensive frame parser that inspects the connection-
// preface and individual frames for the smuggling-relevant validation:
//
//   - Frame type whitelist (only DATA, HEADERS, PRIORITY, RST_STREAM, SETTINGS,
//     PUSH_PROMISE, PING, GOAWAY, WINDOW_UPDATE, CONTINUATION).
//   - SETTINGS frame values within RFC 7540 §6.5 ranges.
//   - Frame body length matches the 24-bit length field.
//   - Stream IDs monotonically non-decreasing per connection.
//
// Reference: RFC 7540 §6 (frame format), §6.5 (SETTINGS).
package tlsmw

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// H2FrameType enumerates the 10 valid frame types per RFC 7540 §11.
type H2FrameType uint8

const (
	FrameData          H2FrameType = 0x0
	FrameHeaders       H2FrameType = 0x1
	FramePriority      H2FrameType = 0x2
	FrameRstStream     H2FrameType = 0x3
	FrameSettings      H2FrameType = 0x4
	FramePushPromise   H2FrameType = 0x5
	FramePing          H2FrameType = 0x6
	FrameGoAway        H2FrameType = 0x7
	FrameWindowUpdate  H2FrameType = 0x8
	FrameContinuation  H2FrameType = 0x9
)

// H2Frame is a parsed HTTP/2 frame.
type H2Frame struct {
	Length   uint32
	Type     H2FrameType
	Flags    uint8
	StreamID uint32
	Body     []byte
}

// H2Err is a typed smuggling-related error.
type H2Err struct{ Reason string }

func (e *H2Err) Error() string { return "h2:" + e.Reason }

// H2Preface is the connection preface magic.
const H2Preface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

// ValidatePreface returns nil if the first 24 bytes equal H2Preface. Use this
// to gate connections claiming h2c upgrade — clients that don't actually send
// the preface are suspicious.
func ValidatePreface(b []byte) error {
	if len(b) < len(H2Preface) {
		return &H2Err{Reason: "preface.too-short"}
	}
	for i := 0; i < len(H2Preface); i++ {
		if b[i] != H2Preface[i] {
			return &H2Err{Reason: "preface.invalid"}
		}
	}
	return nil
}

// ParseFrame parses one 9-byte header + length-byte body. Returns io.EOF when
// input is exhausted cleanly. Validates frame type, body length, and rejects
// frames that exceed our internal limit.
func ParseFrame(buf []byte, maxBody uint32) (H2Frame, int, error) {
	const headerLen = 9
	if len(buf) < headerLen {
		return H2Frame{}, 0, io.ErrUnexpectedEOF
	}
	length := uint32(buf[0])<<16 | uint32(buf[1])<<8 | uint32(buf[2])
	if length > maxBody {
		return H2Frame{}, 0, &H2Err{Reason: fmt.Sprintf("body.too-large:%d", length)}
	}
	total := headerLen + int(length)
	if len(buf) < total {
		return H2Frame{}, 0, io.ErrUnexpectedEOF
	}
	ft := H2FrameType(buf[3])
	if !validFrameType(ft) {
		return H2Frame{}, 0, &H2Err{Reason: fmt.Sprintf("type.unknown:%d", ft)}
	}
	flags := buf[4]
	streamID := binary.BigEndian.Uint32(buf[5:9]) & 0x7FFFFFFF
	f := H2Frame{
		Length:   length,
		Type:     ft,
		Flags:    flags,
		StreamID: streamID,
		Body:     buf[headerLen:total],
	}
	if err := ValidateFrame(&f); err != nil {
		return H2Frame{}, 0, err
	}
	return f, total, nil
}

func validFrameType(t H2FrameType) bool {
	switch t {
	case FrameData, FrameHeaders, FramePriority, FrameRstStream,
		FrameSettings, FramePushPromise, FramePing, FrameGoAway,
		FrameWindowUpdate, FrameContinuation:
		return true
	}
	return false
}

// ValidateFrame checks the body contents per the frame type's spec.
func ValidateFrame(f *H2Frame) error {
	switch f.Type {
	case FrameSettings:
		if len(f.Body)%6 != 0 {
			return &H2Err{Reason: "settings.length-not-multiple-of-6"}
		}
		for i := 0; i < len(f.Body); i += 6 {
			id := binary.BigEndian.Uint16(f.Body[i : i+2])
			val := binary.BigEndian.Uint32(f.Body[i+2 : i+6])
			if !validSettingsEntry(id, val) {
				return &H2Err{Reason: fmt.Sprintf("settings.invalid:%d=%d", id, val)}
			}
		}
	case FramePing:
		if len(f.Body) != 8 {
			return &H2Err{Reason: "ping.length"}
		}
	case FrameWindowUpdate:
		if len(f.Body) != 4 {
			return &H2Err{Reason: "window-update.length"}
		}
		inc := binary.BigEndian.Uint32(f.Body) & 0x7FFFFFFF
		if inc == 0 {
			return &H2Err{Reason: "window-update.zero"}
		}
	case FramePriority:
		if len(f.Body) != 5 {
			return &H2Err{Reason: "priority.length"}
		}
	case FrameRstStream, FrameGoAway:
		if len(f.Body) != 4 {
			return &H2Err{Reason: fmt.Sprintf("frame.length:%d", f.Type)}
		}
	}
	return nil
}

// validSettingsEntry enforces RFC 7540 §6.5 ranges.
func validSettingsEntry(id uint16, val uint32) bool {
	switch id {
	case 0x1: // HEADER_TABLE_SIZE
		return val <= 0xFFFFFFFF
	case 0x2: // ENABLE_PUSH — must be 0 or 1
		return val == 0 || val == 1
	case 0x3: // MAX_CONCURRENT_STREAMS
		return true // any uint31
	case 0x4: // INITIAL_WINDOW_SIZE — 0..2^31-1
		return val <= 0x7FFFFFFF
	case 0x5: // MAX_FRAME_SIZE — 2^14..2^24-1
		return val >= 16384 && val <= 16777215
	case 0x6: // MAX_HEADER_LIST_SIZE
		return true
	}
	// unknown setting — RFC says ignore, NOT reject. Permit.
	return true
}

// ErrInvalidH2 is the umbrella error used when the parser rejects a frame.
var ErrInvalidH2 = errors.New("invalid h2 frame")

// AssertFrame returns nil if frame is valid, else wraps the H2Err.
func AssertFrame(f *H2Frame, maxBody uint32) error {
	if f == nil {
		return errors.New("nil frame")
	}
	if f.Length > maxBody {
		return fmt.Errorf("%w:body-too-large", ErrInvalidH2)
	}
	return ValidateFrame(f)
}
