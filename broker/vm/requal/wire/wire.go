// Package wire is the frame format on the requalification sandbox's one
// case channel (UPD-5r-b2): the host's end in package requal and the
// in-image case driver's end in package driver speak it over the
// sandbox's stdin and stdout, the only channel the sandbox has.
//
// A frame is one kind byte, a 4-byte big-endian body length and the body.
// The host sends a case and answers model calls; the driver sends model
// calls and ends each case with an answer or a case error.
package wire

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// Frame kinds.
const (
	Case        byte = 'C' // host → driver: one case's input
	ModelCall   byte = 'M' // driver → host: a model call's request
	ModelResult byte = 'R' // host → driver: the model's answer
	ModelRefuse byte = 'X' // host → driver: the call was refused; the body says why
	Answer      byte = 'A' // driver → host: the case's output
	CaseError   byte = 'E' // driver → host: the case could not run; the body says why
)

// MaxBody bounds any frame's body on either end. Each end may hold a
// smaller bound of its own.
const MaxBody = 4 << 20

// ErrTooLarge is a frame whose body passes the reader's bound.
var ErrTooLarge = errors.New("wire: frame too large")

// Write writes one frame.
func Write(w io.Writer, kind byte, body []byte) error {
	if len(body) > MaxBody {
		return ErrTooLarge
	}
	var h [5]byte
	h[0] = kind
	binary.BigEndian.PutUint32(h[1:], uint32(len(body)))
	if _, err := w.Write(append(h[:], body...)); err != nil {
		return fmt.Errorf("wire: %w", err)
	}
	return nil
}

// Read reads one frame whose body is at most max bytes (at most MaxBody).
// A longer frame is ErrTooLarge and nothing of its body is read.
func Read(r io.Reader, max int) (byte, []byte, error) {
	max = min(max, MaxBody)
	var h [5]byte
	if _, err := io.ReadFull(r, h[:]); err != nil {
		return 0, nil, err
	}
	n := binary.BigEndian.Uint32(h[1:])
	if max < 0 || uint64(n) > uint64(max) {
		return 0, nil, ErrTooLarge
	}
	body := make([]byte, n)
	if _, err := io.ReadFull(r, body); err != nil {
		if err == io.EOF {
			err = io.ErrUnexpectedEOF
		}
		return 0, nil, err
	}
	return h[0], body, nil
}
