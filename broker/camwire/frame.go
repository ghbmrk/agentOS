// Package camwire is the camera node's wire (CAM-node part a, #3513; SPEC
// DEV-3, NET-2 Cameras, NET-4, NET-7): the frame codec both ends of a
// camera stream run, the owner-signed settings bundle and the image
// manifest, and their verification, including the WebAuthn assertion check
// the node makes itself.
//
// The node (agentos-camnode) and the core's camera clerk (CAM-clerk) both
// link it, so both sides frame and verify the same way. It does no I/O of
// its own beyond the reader and writer it is handed, holds no key, and
// imports the standard library only (TestImportsStandardLibraryOnly).
package camwire

import (
	"encoding/binary"
	"errors"
	"io"
)

// HeaderLen is a frame's fixed header: type (1 byte) and payload length
// (4 bytes, big-endian).
const HeaderLen = 5

// Type is a frame's type. Its direction and cap come from the table below,
// never from the sender.
type Type byte

const (
	// TypeVideo is one H.264 access unit in Annex B byte-stream form
	// (node to core).
	TypeVideo Type = 1
	// TypeThermal is one thermal frame: a ThermalHeaderLen header (width,
	// height, frame counter) and width×height 16-bit samples (node to core).
	TypeThermal Type = 2
	// TypeStatus is the node's fixed status record (node to core, node to
	// enforcer).
	TypeStatus Type = 3
	// TypeBundle is a signed settings bundle (enforcer to node).
	TypeBundle Type = 4
	// TypeManifest is a signed image manifest, which opens an update
	// (enforcer to node).
	TypeManifest Type = 5
	// TypeImage is one chunk of the image a manifest names (enforcer to
	// node).
	TypeImage Type = 6
)

// Caps. A frame over its type's cap ends the connection.
const (
	MaxVideo    = 2 << 20 // one access unit
	MaxThermal  = 1 << 20 // the largest declared shape must fit (Shape.valid)
	MaxSigned   = 4096    // a signed bundle or manifest
	MaxImage    = 1 << 20 // one image chunk
	StatusLen   = 8 + 32 + 8 + 2
	thermalHead = ThermalHeaderLen
)

// ThermalHeaderLen is a thermal frame's header: width and height (2 bytes
// each) and the frame counter (4 bytes), big-endian.
const ThermalHeaderLen = 8

// Direction is one side of one channel: what a reader on it accepts.
type Direction byte

const (
	// ToCore is the stream channel as the core reads it.
	ToCore Direction = 1
	// FromEnforcer is the settings channel as the node reads it.
	FromEnforcer Direction = 2
	// ToEnforcer is the settings channel as the enforcer reads it.
	ToEnforcer Direction = 3
)

// spec is one type's row: the directions it may travel and its cap. An
// exact type's payload is always its cap (thermal's cap comes from the
// declared shape instead).
type spec struct {
	dirs  []Direction
	cap   uint32
	exact bool
}

var types = map[Type]spec{
	TypeVideo:    {[]Direction{ToCore}, MaxVideo, false},
	TypeThermal:  {[]Direction{ToCore}, MaxThermal, false},
	TypeStatus:   {[]Direction{ToCore, ToEnforcer}, StatusLen, true},
	TypeBundle:   {[]Direction{FromEnforcer}, MaxSigned, false},
	TypeManifest: {[]Direction{FromEnforcer}, MaxSigned, false},
	TypeImage:    {[]Direction{FromEnforcer}, MaxImage, false},
}

// Shape is a thermal core's declared frame shape. The zero Shape declares
// no thermal core, and a thermal frame is then refused.
type Shape struct{ Width, Height uint16 }

// valid reports whether s is a shape whose frames fit MaxThermal. The size
// is computed in 64 bits, where two 16-bit sides cannot wrap.
func (s Shape) valid() bool {
	return s.Width > 0 && s.Height > 0 &&
		thermalHead+2*uint64(s.Width)*uint64(s.Height) <= MaxThermal
}

// payload is a thermal frame's exact payload length for s, which valid has
// bounded first.
func (s Shape) payload() uint32 {
	return thermalHead + 2*uint32(s.Width)*uint32(s.Height)
}

// Frame is one decoded frame.
type Frame struct {
	Type    Type
	Payload []byte
}

// The codec's errors. Each is fixed text and carries nothing from the
// frame, so a caller may count it but has nothing of the peer's to log.
var (
	ErrType      = errors.New("camwire: frame type unknown or not allowed on this channel")
	ErrLength    = errors.New("camwire: frame length out of bounds")
	ErrShort     = errors.New("camwire: frame truncated")
	ErrPayload   = errors.New("camwire: frame payload malformed")
	ErrShape     = errors.New("camwire: thermal shape not declared or out of bounds")
	ErrDirection = errors.New("camwire: unknown direction")
)

// ReadFrame reads exactly one frame on direction d. thermal is the thermal
// core the node declared (the zero Shape for none). On any error it has
// read no further than the field that failed, and the caller ends the
// connection: the codec never resynchronises or skips. A stream that ends
// cleanly before a frame's first byte returns io.EOF.
func ReadFrame(r io.Reader, d Direction, thermal Shape) (Frame, error) {
	var h [HeaderLen]byte
	if n, err := io.ReadFull(r, h[:]); err != nil {
		if n == 0 && err == io.EOF {
			return Frame{}, io.EOF
		}
		return Frame{}, ErrShort
	}
	t := Type(h[0])
	n := binary.BigEndian.Uint32(h[1:])
	if err := checkHeader(d, t, n, thermal); err != nil {
		return Frame{}, err
	}
	// Read through a limit rather than into a buffer of the declared
	// length, so a header that lies costs only the bytes actually sent.
	p, err := io.ReadAll(io.LimitReader(r, int64(n)))
	if err != nil || uint32(len(p)) != n {
		return Frame{}, ErrShort
	}
	if err := checkPayload(t, p, thermal); err != nil {
		return Frame{}, err
	}
	return Frame{Type: t, Payload: p}, nil
}

// AppendFrame appends f's encoding on direction d to dst. It refuses
// exactly what ReadFrame refuses, so what one end writes the other reads.
func AppendFrame(dst []byte, d Direction, thermal Shape, f Frame) ([]byte, error) {
	if uint64(len(f.Payload)) > 1<<32-1 {
		return dst, ErrLength
	}
	n := uint32(len(f.Payload))
	if err := checkHeader(d, f.Type, n, thermal); err != nil {
		return dst, err
	}
	if err := checkPayload(f.Type, f.Payload, thermal); err != nil {
		return dst, err
	}
	dst = append(dst, byte(f.Type))
	dst = binary.BigEndian.AppendUint32(dst, n)
	return append(dst, f.Payload...), nil
}

// WriteFrame writes f on direction d in one Write.
func WriteFrame(w io.Writer, d Direction, thermal Shape, f Frame) error {
	b, err := AppendFrame(nil, d, thermal, f)
	if err != nil {
		return err
	}
	_, err = w.Write(b)
	return err
}

// checkHeader holds every rule the header alone decides.
func checkHeader(d Direction, t Type, n uint32, thermal Shape) error {
	if d < ToCore || d > ToEnforcer {
		return ErrDirection
	}
	s, ok := types[t]
	if !ok || !allowed(s.dirs, d) {
		return ErrType
	}
	if n == 0 || n > s.cap || (s.exact && n != s.cap) {
		return ErrLength
	}
	if t == TypeThermal {
		if !thermal.valid() {
			return ErrShape
		}
		if n != thermal.payload() {
			return ErrLength
		}
	}
	return nil
}

func allowed(dirs []Direction, d Direction) bool {
	for _, x := range dirs {
		if x == d {
			return true
		}
	}
	return false
}

// checkPayload holds the rules a payload's own bytes decide. Bundles and
// manifests are checked by their verifiers, which the receiver runs next.
func checkPayload(t Type, p []byte, thermal Shape) error {
	switch t {
	case TypeVideo:
		if !annexB(p) {
			return ErrPayload
		}
	case TypeThermal:
		if _, err := ParseThermal(p, thermal); err != nil {
			return err
		}
	case TypeStatus:
		if _, err := ParseStatus(p); err != nil {
			return err
		}
	}
	return nil
}

// annexB reports whether p opens with an Annex B start code (three or four
// bytes). The payload past it is decoded only by CAM-clerk's sandbox.
func annexB(p []byte) bool {
	return len(p) > 3 && p[0] == 0 && p[1] == 0 &&
		(p[2] == 1 || (len(p) > 4 && p[2] == 0 && p[3] == 1))
}

// Thermal is one decoded thermal frame. Samples holds Width×Height
// big-endian 16-bit samples, row by row.
type Thermal struct {
	Width, Height uint16
	Counter       uint32
	Samples       []byte
}

// ParseThermal decodes a thermal payload of the declared shape. A frame of
// any other shape is refused.
func ParseThermal(p []byte, shape Shape) (Thermal, error) {
	if !shape.valid() {
		return Thermal{}, ErrShape
	}
	if uint32(len(p)) != shape.payload() {
		return Thermal{}, ErrLength
	}
	th := Thermal{
		Width:   binary.BigEndian.Uint16(p[0:2]),
		Height:  binary.BigEndian.Uint16(p[2:4]),
		Counter: binary.BigEndian.Uint32(p[4:8]),
		Samples: p[thermalHead:],
	}
	if th.Width != shape.Width || th.Height != shape.Height {
		return Thermal{}, ErrPayload
	}
	return th, nil
}

// AppendThermal appends th's payload to dst.
func AppendThermal(dst []byte, th Thermal) []byte {
	dst = binary.BigEndian.AppendUint16(dst, th.Width)
	dst = binary.BigEndian.AppendUint16(dst, th.Height)
	dst = binary.BigEndian.AppendUint32(dst, th.Counter)
	return append(dst, th.Samples...)
}

// Status is the node's fixed status record.
type Status struct {
	Uptime      uint64   // seconds since boot
	Image       [32]byte // SHA-256 of the running image
	Settings    uint64   // the settings counter in the secure element
	Temperature int16    // board temperature, hundredths of a degree Celsius
}

// ParseStatus decodes a status payload.
func ParseStatus(p []byte) (Status, error) {
	if len(p) != StatusLen {
		return Status{}, ErrLength
	}
	var s Status
	s.Uptime = binary.BigEndian.Uint64(p[0:8])
	copy(s.Image[:], p[8:40])
	s.Settings = binary.BigEndian.Uint64(p[40:48])
	s.Temperature = int16(binary.BigEndian.Uint16(p[48:50]))
	return s, nil
}

// AppendStatus appends s's payload to dst.
func AppendStatus(dst []byte, s Status) []byte {
	dst = binary.BigEndian.AppendUint64(dst, s.Uptime)
	dst = append(dst, s.Image[:]...)
	dst = binary.BigEndian.AppendUint64(dst, s.Settings)
	return binary.BigEndian.AppendUint16(dst, uint16(s.Temperature))
}
