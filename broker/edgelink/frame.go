// Package edgelink is the core's end of the edge link's wire (EDGE-link-core
// c1, #3296; SPEC HW-15, HW-17, PLN-3): the strict frame codec, the kind
// table that fixes each kind's direction, cap and label, the hello an
// unknown edge sends, and the TLS 1.3 configurations both ends run.
//
// It opens no socket, starts no process and imports no kernel package: the
// link process (agentos-link, c2) owns the listener and asks the kernel which
// edge key is live. It imports the standard library only.
package edgelink

import (
	"encoding/binary"
	"errors"
	"io"
	"unicode"
	"unicode/utf8"
)

// Version is the only frame version.
const Version = 1

// HeaderLen is a frame's fixed header: version, kind, origin length (2
// bytes) and body length (4 bytes), big-endian.
const HeaderLen = 8

// MaxOrigin bounds a frame's origin in bytes.
const MaxOrigin = 1024

// Frame is one decoded item. Its label is its kind's (Kind.Label), never a
// field the sender sets.
type Frame struct {
	Kind   Kind
	Origin string
	Body   []byte
}

// The codec's errors. Each is fixed text and carries no content from the
// frame, so a caller may count it but has nothing of the edge's to log.
var (
	ErrVersion      = errors.New("edgelink: unknown frame version")
	ErrKind         = errors.New("edgelink: unknown frame kind")
	ErrDirection    = errors.New("edgelink: frame kind not allowed on this stream")
	ErrOriginLength = errors.New("edgelink: frame origin length out of bounds")
	ErrBodyLength   = errors.New("edgelink: frame body length out of bounds")
	ErrOrigin       = errors.New("edgelink: frame origin is not printable UTF-8")
	ErrShort        = errors.New("edgelink: frame truncated")
)

// ReadFrame reads exactly one frame sent on stream s. On any error it has
// read no further than the field that failed, and the caller closes the
// connection: the codec never resynchronises or skips (HW-15). A stream
// that ends cleanly before a frame's first byte returns io.EOF.
func ReadFrame(r io.Reader, s Stream) (Frame, error) {
	var h [HeaderLen]byte
	if n, err := io.ReadFull(r, h[:]); err != nil {
		if n == 0 && err == io.EOF {
			return Frame{}, io.EOF
		}
		return Frame{}, ErrShort
	}
	k := Kind(h[1])
	olen := int(binary.BigEndian.Uint16(h[2:4]))
	blen := uint64(binary.BigEndian.Uint32(h[4:8]))
	if err := checkHeader(s, h[0], k, olen, blen); err != nil {
		return Frame{}, err
	}
	origin := make([]byte, olen)
	if _, err := io.ReadFull(r, origin); err != nil {
		return Frame{}, ErrShort
	}
	if !printable(origin) {
		return Frame{}, ErrOrigin
	}
	// The body is read through a limit, not into a buffer of the declared
	// length, so a header that lies costs only the bytes actually sent.
	body, err := io.ReadAll(io.LimitReader(r, int64(blen)))
	if err != nil || uint64(len(body)) != blen {
		return Frame{}, ErrShort
	}
	return Frame{Kind: k, Origin: string(origin), Body: body}, nil
}

// AppendFrame appends f's encoding on stream s to dst. It refuses exactly
// what ReadFrame refuses, so what one end writes the other reads.
func AppendFrame(dst []byte, s Stream, f Frame) ([]byte, error) {
	if uint64(len(f.Body)) > 1<<32-1 {
		return dst, ErrBodyLength
	}
	if err := checkHeader(s, Version, f.Kind, len(f.Origin), uint64(len(f.Body))); err != nil {
		return dst, err
	}
	if !printable([]byte(f.Origin)) {
		return dst, ErrOrigin
	}
	dst = append(dst, Version, byte(f.Kind))
	dst = binary.BigEndian.AppendUint16(dst, uint16(len(f.Origin)))
	dst = binary.BigEndian.AppendUint32(dst, uint32(len(f.Body)))
	dst = append(dst, f.Origin...)
	return append(dst, f.Body...), nil
}

// WriteFrame writes f on stream s in one Write.
func WriteFrame(w io.Writer, s Stream, f Frame) error {
	b, err := AppendFrame(nil, s, f)
	if err != nil {
		return err
	}
	_, err = w.Write(b)
	return err
}

// checkHeader holds every rule the header alone decides.
func checkHeader(s Stream, v byte, k Kind, olen int, blen uint64) error {
	if v != Version {
		return ErrVersion
	}
	spec, ok := kinds[k]
	if !ok {
		return ErrKind
	}
	if spec.streams&s.bit() == 0 {
		return ErrDirection
	}
	// The hello carries no origin; every other kind names one.
	if olen > MaxOrigin || (k == KindHello) != (olen == 0) {
		return ErrOriginLength
	}
	if blen > spec.cap || (spec.exact && blen != spec.cap) {
		return ErrBodyLength
	}
	return nil
}

// printable reports whether b is valid UTF-8 with no control character
// (C0, DEL or C1).
func printable(b []byte) bool {
	if !utf8.Valid(b) {
		return false
	}
	for len(b) > 0 {
		r, n := utf8.DecodeRune(b)
		if unicode.IsControl(r) {
			return false
		}
		b = b[n:]
	}
	return true
}
