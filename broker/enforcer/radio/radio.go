// Package radio is the enforcer's confined radio host (NET-2 Confined radio
// stacks; briefs/ENF.md slice k): each radio stack runs as its own
// unprivileged process (package confine), and the enforcer reaches it only
// through one narrow command interface, a socket carrying the requests this
// file declares. The channel's device commands (channel.Radio), slice s's
// asserted actions and slice q's lock rules all go through Host, so a stack
// can be asked for nothing its stack does not declare.
//
// The radio process is untrusted: it parses what anyone in radio range
// sends. Host therefore parses its replies as strictly as the channel
// parses the core: a frame that does not decode, or a reply nobody asked
// for, ends that stack's link.
package radio

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
)

// Stack names one radio stack, and so one confined process.
type Stack string

// StackBLE is Bluetooth Low Energy on BlueZ (ENF decision 6). StackThread
// is OpenThread's ot-daemon behind its adapter (package thread; D-231).
// Slice t adds Matter.
const (
	StackBLE    Stack = "ble"
	StackThread Stack = "thread"
)

// Op is one operation a stack may be asked for.
type Op string

const (
	// OpRead reads a device's state or last reading. Every stack declares it.
	OpRead Op = "read"

	// The channel's device verbs (wire.Verb), one op each.
	OpOn           Op = "on"
	OpOff          Op = "off"
	OpLevel        Op = "level"
	OpLock         Op = "lock"
	OpShut         Op = "shut"
	OpClose        Op = "close"
	OpReturnToDock Op = "return-to-dock"

	// BLE's GATT session ops: connect to a declared device, write to or
	// subscribe to one of its declared characteristics, disconnect. There
	// is no raw HCI op and no scan that returns other devices.
	OpConnect    Op = "connect"
	OpDisconnect Op = "disconnect"
	OpWrite      Op = "write"
	OpSubscribe  Op = "subscribe"
)

// Declared is the closed set of ops each stack serves. Host refuses any
// other op before a byte reaches the stack, and Server refuses it again on
// the stack's side. Slices q and t add their stacks' ops here, each with
// its acceptance test.
var Declared = map[Stack][]Op{
	StackBLE: {OpRead, OpConnect, OpDisconnect, OpWrite, OpSubscribe},
	// Thread serves one device, the network itself, and only its read:
	// Thread devices are commanded through Matter.
	StackThread: {OpRead},
}

// Code is a stack's answer to one request.
type Code uint8

const (
	CodeOK          Code = 1
	CodeRefused     Code = 2 // the stack refused the request
	CodeFailed      Code = 3 // the radio tried and failed
	CodeUnreachable Code = 4 // the device did not answer
)

const (
	// MaxFrame bounds one frame's body in either direction.
	MaxFrame = 4096
	// MaxData bounds a request's or an answer's payload.
	MaxData = 512
	// MaxName bounds a device or characteristic name.
	MaxName = 64
	// MaxLevel is OpLevel's highest level, as wire.MaxLevel.
	MaxLevel = 100
)

// Request is one request from the enforcer to a stack.
type Request struct {
	ID     uint64
	Op     Op
	Device string
	Char   string `json:",omitempty"` // OpWrite and OpSubscribe only
	Level  uint8  `json:",omitempty"` // OpLevel only
	Data   []byte `json:",omitempty"` // OpWrite only
}

// Up is one message from a stack: the answer to request ID, or, with ID
// zero, a notification from a subscribed characteristic.
type Up struct {
	ID     uint64 `json:",omitempty"`
	Code   Code   `json:",omitempty"` // answers only
	Device string
	Char   string `json:",omitempty"` // notifications only
	Data   []byte `json:",omitempty"`
}

var (
	ErrNotDeclared = errors.New("radio: op not declared for this stack")
	ErrMalformed   = errors.New("radio: malformed message")
	ErrFrame       = errors.New("radio: frame out of bounds")
)

// Declares reports whether stack s serves op.
func Declares(s Stack, op Op) bool { return slices.Contains(Declared[s], op) }

// Check holds a request to its stack's declaration and to the fields its op
// uses: an op the stack does not declare is ErrNotDeclared, and any field
// the op does not use, or out of bounds, is ErrMalformed.
func (r Request) Check(s Stack) error {
	if !Declares(s, r.Op) {
		return fmt.Errorf("%w: %s on %s", ErrNotDeclared, r.Op, s)
	}
	if r.ID == 0 || !name(r.Device) {
		return ErrMalformed
	}
	char := r.Op == OpWrite || r.Op == OpSubscribe
	switch {
	case char != (r.Char != ""), char && !name(r.Char):
		return ErrMalformed
	case r.Op != OpLevel && r.Level != 0, r.Level > MaxLevel:
		return ErrMalformed
	case r.Op != OpWrite && r.Data != nil, len(r.Data) > MaxData:
		return ErrMalformed
	}
	return nil
}

// check holds an Up to its bounds. Whether it answers a request, or names a
// device and characteristic the stack may notify, is Host's to check.
func (u Up) check() error {
	answer := u.ID != 0
	switch {
	case !name(u.Device), len(u.Data) > MaxData:
		return ErrMalformed
	case answer && (u.Code < CodeOK || u.Code > CodeUnreachable || u.Char != ""):
		return ErrMalformed
	case !answer && (u.Code != 0 || !name(u.Char)):
		return ErrMalformed
	}
	return nil
}

// name is a device or characteristic name: printable ASCII, no space.
func name(s string) bool {
	if s == "" || len(s) > MaxName {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] <= ' ' || s[i] > '~' {
			return false
		}
	}
	return true
}

// write sends v as one frame: a four-byte big-endian length, then JSON.
func write(w io.Writer, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	if len(b) > MaxFrame {
		return ErrFrame
	}
	return writeFull(w, binary.BigEndian.AppendUint32(nil, uint32(len(b))), b)
}

func writeFull(w io.Writer, parts ...[]byte) error {
	_, err := w.Write(slices.Concat(parts...))
	return err
}

// read takes one frame and decodes it into v strictly: no unknown field,
// nothing after the value, and never more than MaxFrame bytes read.
func read(r io.Reader, v any) error {
	var n [4]byte
	if _, err := io.ReadFull(r, n[:]); err != nil {
		return err
	}
	size := binary.BigEndian.Uint32(n[:])
	if size == 0 || size > MaxFrame {
		return ErrFrame
	}
	b := make([]byte, size)
	if _, err := io.ReadFull(r, b); err != nil {
		return err
	}
	return decode(b, v)
}

func decode(b []byte, v any) error {
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if err := d.Decode(v); err != nil {
		return fmt.Errorf("%w: %v", ErrMalformed, err)
	}
	if d.More() {
		return ErrMalformed
	}
	if _, err := d.Token(); err != io.EOF {
		return ErrMalformed
	}
	return nil
}
