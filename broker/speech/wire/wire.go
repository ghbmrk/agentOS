// Package wire is the framing between the box and the speech process
// (VOICE-ro-b, briefs/VOICE-ro.md). A frame is one type byte, a 4-byte
// big-endian payload length and the payload. Both ends parse with the same
// functions, and every parse refuses rather than repairs: a frame that fails
// here ends the session (rule 1).
//
// Box to process: Audio (8 kHz S16_LE mono PCM) and Speak (sentence id,
// then the checked sentence). Process to box: Heard (final flag, the sample
// at which speech ended, then the transcript), Spoken (sentence id, then a
// chunk of PCM) and Done (sentence id, then a status byte).
package wire

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"unicode"
	"unicode/utf8"
)

// Frame types.
const (
	Audio  byte = 1
	Speak  byte = 2
	Heard  byte = 3
	Spoken byte = 4
	Done   byte = 5
)

// Done statuses.
const (
	OK     byte = 0
	Failed byte = 1
)

const (
	// MaxPayload bounds every frame, so a reader never allocates more.
	MaxPayload = 64 << 10
	// MaxText bounds a transcript and a sentence, in bytes.
	MaxText = 2048
	// Rate is the line's sample rate; a sample is two bytes.
	Rate = 8000
)

// ErrFrame is any frame that does not parse.
var ErrFrame = errors.New("speech wire: bad frame")

func bad(format string, a ...any) error {
	return fmt.Errorf("%w: "+format, append([]any{ErrFrame}, a...)...)
}

// Write writes one frame.
func Write(w io.Writer, typ byte, payload []byte) error {
	if len(payload) > MaxPayload {
		return bad("payload %d bytes", len(payload))
	}
	b := make([]byte, 5+len(payload))
	b[0] = typ
	binary.BigEndian.PutUint32(b[1:5], uint32(len(payload)))
	copy(b[5:], payload)
	_, err := w.Write(b)
	return err
}

// Read reads one frame. io.EOF before the first byte is a clean end.
func Read(r io.Reader) (byte, []byte, error) {
	var h [5]byte
	if _, err := io.ReadFull(r, h[:]); err != nil {
		if errors.Is(err, io.ErrUnexpectedEOF) {
			return 0, nil, bad("cut header")
		}
		return 0, nil, err
	}
	n := binary.BigEndian.Uint32(h[1:])
	if n > MaxPayload {
		return 0, nil, bad("payload %d bytes", n)
	}
	p := make([]byte, n)
	if _, err := io.ReadFull(r, p); err != nil {
		return 0, nil, bad("cut payload")
	}
	return h[0], p, nil
}

// Text checks a transcript or sentence: UTF-8, at most MaxText bytes, and
// no control, format or line-breaking character (C0, C1, bidi overrides,
// zero-width, U+2028, U+2029), so what one end sends is what the other
// reads. The predicate is edgelink's and the kernel's.
func Text(b []byte) (string, error) {
	if len(b) > MaxText || !utf8.Valid(b) {
		return "", bad("text not UTF-8 or over %d bytes", MaxText)
	}
	s := string(b)
	for _, r := range s {
		if unicode.IsControl(r) || unicode.In(r, unicode.Cf, unicode.Zl, unicode.Zp) {
			return "", bad("control character %U", r)
		}
	}
	return s, nil
}

// PCM checks audio: whole samples.
func PCM(b []byte) error {
	if len(b)%2 != 0 {
		return bad("odd PCM length %d", len(b))
	}
	return nil
}

// HeardFrame is a parsed Heard payload.
type HeardFrame struct {
	Final bool
	// End is the sample, counted from the session's first, at which the
	// owner stopped speaking; 0 means the recognizer did not say.
	End  uint64
	Text string
}

// EncodeHeard builds a Heard payload.
func EncodeHeard(h HeardFrame) []byte {
	b := make([]byte, 9, 9+len(h.Text))
	if h.Final {
		b[0] = 1
	}
	binary.BigEndian.PutUint64(b[1:9], h.End)
	return append(b, h.Text...)
}

// DecodeHeard parses a Heard payload.
func DecodeHeard(p []byte) (HeardFrame, error) {
	if len(p) < 9 || p[0] > 1 {
		return HeardFrame{}, bad("heard header")
	}
	t, err := Text(p[9:])
	if err != nil {
		return HeardFrame{}, err
	}
	return HeardFrame{Final: p[0] == 1, End: binary.BigEndian.Uint64(p[1:9]), Text: t}, nil
}

// EncodeID prefixes a payload with a sentence id.
func EncodeID(id uint32, rest []byte) []byte {
	b := make([]byte, 4, 4+len(rest))
	binary.BigEndian.PutUint32(b, id)
	return append(b, rest...)
}

// DecodeID splits a sentence id from the rest of a Speak, Spoken or Done
// payload.
func DecodeID(p []byte) (uint32, []byte, error) {
	if len(p) < 4 {
		return 0, nil, bad("no sentence id")
	}
	return binary.BigEndian.Uint32(p[:4]), p[4:], nil
}
