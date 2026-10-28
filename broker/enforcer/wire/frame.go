// Package wire is the enforcer channel's frame and message schema (SPEC
// NET-2 Channel, DEV-2; briefs/ENF.md slice d): what the kernel's channel
// client (slice o) writes and the enforcer's channel (broker/enforcer/
// channel) reads, and back. Both ends link it, so both frame and parse the
// same way.
//
// The core may send only what moves nothing in the home beyond NET-2's
// three kinds: a device command, a closed-list tightening or a read, plus
// the records that are not requests at all (its hello, the log heads and
// key-change entries the enforcer anchors, a proposal link it announces for
// counting, and the answer to a device challenge). No type, verb or field
// spells an unlock, a disarm, an arm, an open, a turn-on of a safety-list
// device or a rule change: there is nothing to parse them into. Every
// message has one encoding, and Encode refuses what Decode refuses.
//
// It imports the standard library only, does no I/O beyond the reader and
// writer it is handed and holds no key (TestImportsStandardLibraryOnly).
// Its assumptions are in ASSUMPTIONS.md.
package wire

import (
	"encoding/binary"
	"errors"
	"io"
)

// HeaderLen is a frame's fixed header: type (1 byte) and payload length
// (4 bytes, big-endian).
const HeaderLen = 5

// Type is a frame's type. Which direction it may travel and its cap come
// from the table below, never from the sender.
type Type byte

const (
	// THello opens a connection on both sides: the sender's role, its
	// pinned public key and its signature over the TLS exporter.
	THello Type = 1
	// TCommand is a device command (core to enforcer).
	TCommand Type = 2
	// TTighten is one closed-list tightening (core to enforcer).
	TTighten Type = 3
	// TRead asks for a read (core to enforcer).
	TRead Type = 4
	// TAnnounce counts a proposal link the core texted (core to enforcer).
	TAnnounce Type = 5
	// THead is one kernel log head for the enforcer to keep (core to
	// enforcer; STO-1).
	THead Type = 6
	// TEntry is one key-change or erase entry for the enforcer to keep
	// (core to enforcer; STO-1, KEY-7).
	TEntry Type = 7
	// TAnswer is the core's answer to a device challenge, in the fixed
	// challenge frame (core to enforcer).
	TAnswer Type = 8
	// TResult is the enforcer's verdict on one request (enforcer to core).
	TResult Type = 9
	// TReadReply carries what a read returned (enforcer to core).
	TReadReply Type = 10
	// TChallenge is a device's challenge for the core to answer, in the
	// fixed challenge frame (enforcer to core).
	TChallenge Type = 11
	// TAlert is a text or call the enforcer composed, for the kernel to
	// send on the owner line unchanged (enforcer to core).
	TAlert Type = 12
)

// Direction is one side of the channel: what a reader on it accepts.
type Direction byte

const (
	// ToEnforcer is the channel as the enforcer reads it.
	ToEnforcer Direction = 1
	// ToCore is the channel as the kernel's client reads it.
	ToCore Direction = 2
)

// Field sizes and caps.
const (
	// MaxName is a device, host or rule name's longest spelling: a DNS
	// name's limit, as the policy's names are.
	MaxName = 253
	// KeyLen and SigLen are an Ed25519 public key and signature.
	KeyLen = 32
	SigLen = 64
	// HashLen is a SHA-256.
	HashLen = 32
	// ChallengeData is the fixed challenge frame's data area. A device's
	// challenge or the core's answer is at most this long and the frame is
	// always full: the length byte says how much is data, the rest is
	// zero (DEV-withings-ble part s).
	ChallengeData = 64
	// MaxEntry is one log entry's largest encoding.
	MaxEntry = 4096
	// MaxReply is a read reply's largest body: the policy export
	// (slice a) is the largest read.
	MaxReply = 1 << 20
	// MaxAlert is an alert's longest text.
	MaxAlert = 1024

	idLen        = 8
	helloLen     = 1 + KeyLen + SigLen
	commandMax   = idLen + 1 + 1 + 1 + MaxName
	tightenMax   = idLen + 1 + 5*(1+MaxName) + 8 + 8
	readMax      = idLen + 1 + 1 + MaxName
	announceLen  = idLen + HashLen
	headLen      = idLen + 8 + HashLen + SigLen
	entryMax     = idLen + MaxEntry
	challengeLen = idLen + 1 + ChallengeData
	resultLen    = idLen + 1
	replyMax     = idLen + MaxReply
	alertMax     = 1 + MaxAlert
)

// spec is one type's row: its cap, and whether its payload is always
// exactly the cap.
type spec struct {
	cap   uint32
	exact bool
}

// types has one row per type and direction. THello travels both ways, so
// it is keyed with its direction; every other type travels one way only.
var types = map[Direction]map[Type]spec{
	ToEnforcer: {
		THello:    {helloLen, true},
		TCommand:  {commandMax, false},
		TTighten:  {tightenMax, false},
		TRead:     {readMax, false},
		TAnnounce: {announceLen, true},
		THead:     {headLen, true},
		TEntry:    {entryMax, false},
		TAnswer:   {challengeLen, true},
	},
	ToCore: {
		THello:     {helloLen, true},
		TResult:    {resultLen, true},
		TReadReply: {replyMax, false},
		TChallenge: {challengeLen, true},
		TAlert:     {alertMax, false},
	},
}

// Frame is one frame: its type and its payload.
type Frame struct {
	Type    Type
	Payload []byte
}

// The codec's errors. Each is fixed text and carries nothing from the
// frame, so a caller may log it with nothing of the peer's in the line.
var (
	ErrType      = errors.New("wire: frame type unknown or not allowed on this side")
	ErrLength    = errors.New("wire: frame length out of bounds")
	ErrShort     = errors.New("wire: frame truncated")
	ErrPayload   = errors.New("wire: payload malformed or not canonical")
	ErrDirection = errors.New("wire: unknown direction")
)

// ReadFrame reads exactly one frame on direction d. On any error the
// caller ends the connection: the codec never resynchronises or skips. A
// stream that ends cleanly before a frame's first byte returns io.EOF.
// The payload is checked by Decode, not here.
func ReadFrame(r io.Reader, d Direction) (Frame, error) {
	var h [HeaderLen]byte
	if n, err := io.ReadFull(r, h[:]); err != nil {
		if n == 0 && err == io.EOF {
			return Frame{}, io.EOF
		}
		return Frame{}, ErrShort
	}
	t := Type(h[0])
	n := binary.BigEndian.Uint32(h[1:])
	if err := checkHeader(d, t, n); err != nil {
		return Frame{}, err
	}
	// Read through a limit rather than into a buffer of the declared
	// length, so a header that lies costs only the bytes actually sent.
	p, err := io.ReadAll(io.LimitReader(r, int64(n)))
	if err != nil || uint32(len(p)) != n {
		return Frame{}, ErrShort
	}
	return Frame{Type: t, Payload: p}, nil
}

// WriteFrame writes f on direction d in one Write. It refuses a frame
// ReadFrame or Decode would refuse, so what one end writes the other reads.
func WriteFrame(w io.Writer, d Direction, f Frame) error {
	if uint64(len(f.Payload)) > 1<<32-1 {
		return ErrLength
	}
	if _, err := Decode(d, f); err != nil {
		return err
	}
	b := make([]byte, 0, HeaderLen+len(f.Payload))
	b = append(b, byte(f.Type))
	b = binary.BigEndian.AppendUint32(b, uint32(len(f.Payload)))
	_, err := w.Write(append(b, f.Payload...))
	return err
}

// checkHeader holds every rule the header alone decides.
func checkHeader(d Direction, t Type, n uint32) error {
	row, ok := types[d]
	if !ok {
		return ErrDirection
	}
	s, ok := row[t]
	if !ok {
		return ErrType
	}
	if n == 0 || n > s.cap || (s.exact && n != s.cap) {
		return ErrLength
	}
	return nil
}
