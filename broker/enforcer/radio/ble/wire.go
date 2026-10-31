package ble

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"strings"
	"unicode/utf8"
)

// The D-Bus wire format, as far as the BLE stack needs it (D-Bus
// specification, "Message Protocol"). Messages from the bus carry values a
// Bluetooth device controls (GATT values, UUIDs, names), so the decoder
// takes nothing on trust: both byte orders, every padding byte zero, bools
// 0 or 1, strings valid UTF-8 with no NUL, object paths and signatures
// well formed, no unix fds, a message at most MaxMessage bytes, and
// nesting bounded by maxDepth.

// ObjectPath is a D-Bus object path ('o').
type ObjectPath string

// Signature is a D-Bus type signature ('g').
type Signature string

// Variant is a value with its own signature ('v').
type Variant struct {
	Sig   Signature
	Value any
}

// Entry is one dict entry ('{..}'); a dict is an []any of Entry.
type Entry struct {
	Key, Value any
}

// Message types.
const (
	typeCall   = 1
	typeReturn = 2
	typeError  = 3
	typeSignal = 4
)

// flagNoReply is NO_REPLY_EXPECTED.
const flagNoReply = 1

// Message is one D-Bus message. Values decode as uint8, bool, int16,
// uint16, int32, uint32, int64, uint64, float64, string, ObjectPath,
// Signature, Variant, []byte (an array of bytes), []any (any other array,
// or a struct) and Entry.
type Message struct {
	Type        byte
	Flags       byte
	Serial      uint32
	Path        ObjectPath
	Interface   string
	Member      string
	ErrorName   string
	ReplySerial uint32
	Destination string
	Sender      string
	Sig         Signature
	Body        []any
}

const (
	// MaxMessage bounds one message, header and body. BlueZ's largest
	// answer the stack asks for is GetManagedObjects, a few KiB per device.
	MaxMessage = 1 << 20
	// maxHeader bounds a message's header fields, which are decoded before
	// the reader knows who sent the message: a few names and a path, each
	// short, plus the bus's own fields.
	maxHeader = 1 << 12
	// maxDepth bounds a signature's container nesting, and variants
	// nested in variants, each below the specification's 64.
	maxDepth = 32
	maxSig   = 255
)

var ErrWire = errors.New("ble: malformed bus message")

// errTooLong is a message longer than MaxMessage, or with header fields
// longer than maxHeader; frameLen still says how long, so the reader can
// step over it.
var errTooLong = fmt.Errorf("%w: message too long", ErrWire)

func wireErr(format string, a ...any) error {
	return fmt.Errorf("%w: "+format, append([]any{ErrWire}, a...)...)
}

// typ is one complete type of a signature.
type typ struct {
	code   byte
	elem   *typ   // 'a'
	fields []*typ // '(' and '{'
}

// parseSig parses a signature into complete types.
func parseSig(s string) ([]*typ, error) {
	if len(s) > maxSig {
		return nil, wireErr("signature too long")
	}
	var out []*typ
	for i := 0; i < len(s); {
		t, n, err := parseType(s, i, 0, false)
		if err != nil {
			return nil, err
		}
		out = append(out, t)
		i = n
	}
	return out, nil
}

// parseType parses one complete type at s[i:], returning the index after
// it. inArray says a dict entry may start here.
func parseType(s string, i, depth int, inArray bool) (*typ, int, error) {
	if i >= len(s) {
		return nil, 0, wireErr("signature ends early")
	}
	if depth > maxDepth {
		return nil, 0, wireErr("signature nested too deep")
	}
	c := s[i]
	switch c {
	case 'y', 'b', 'n', 'q', 'i', 'u', 'x', 't', 'd', 's', 'o', 'g', 'v':
		return &typ{code: c}, i + 1, nil
	case 'a':
		e, n, err := parseType(s, i+1, depth+1, true)
		if err != nil {
			return nil, 0, err
		}
		return &typ{code: c, elem: e}, n, nil
	case '(', '{':
		if c == '{' && !inArray {
			return nil, 0, wireErr("dict entry outside an array")
		}
		end := byte(')')
		if c == '{' {
			end = '}'
		}
		t := &typ{code: c}
		j := i + 1
		for j < len(s) && s[j] != end {
			f, n, err := parseType(s, j, depth+1, false)
			if err != nil {
				return nil, 0, err
			}
			t.fields = append(t.fields, f)
			j = n
		}
		if j >= len(s) {
			return nil, 0, wireErr("unclosed %c", c)
		}
		switch {
		case len(t.fields) == 0:
			return nil, 0, wireErr("empty struct")
		case c == '{' && (len(t.fields) != 2 || !basic(t.fields[0].code)):
			return nil, 0, wireErr("dict entry needs a basic key and one value")
		}
		return t, j + 1, nil
	}
	// 'h' (unix fd) is refused: the stack never negotiates fd passing.
	return nil, 0, wireErr("type %q", c)
}

func basic(c byte) bool {
	switch c {
	case 'y', 'b', 'n', 'q', 'i', 'u', 'x', 't', 'd', 's', 'o', 'g':
		return true
	}
	return false
}

func align(c byte) int {
	switch c {
	case 'n', 'q':
		return 2
	case 'b', 'i', 'u', 's', 'o', 'a':
		return 4
	case 'x', 't', 'd', '(', '{':
		return 8
	}
	return 1 // y, g, v
}

// validPath reports whether p is a well-formed object path: "/", or
// non-empty segments of [A-Za-z0-9_] each after a slash.
func validPath(p string) bool {
	if p == "/" {
		return true
	}
	segs := strings.Split(p, "/")
	if segs[0] != "" || len(segs) < 2 {
		return false
	}
	for _, seg := range segs[1:] {
		if seg == "" || strings.Trim(seg, pathChars) != "" {
			return false
		}
	}
	return true
}

const pathChars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_"

// decoder reads values from one message buffer; offsets are from the
// message's start, which alignment is relative to.
type decoder struct {
	b     []byte
	off   int
	order binary.ByteOrder
}

func (d *decoder) pad(n int) error {
	for d.off%n != 0 {
		if d.off >= len(d.b) {
			return wireErr("truncated")
		}
		if d.b[d.off] != 0 {
			return wireErr("nonzero padding")
		}
		d.off++
	}
	return nil
}

func (d *decoder) take(n int) ([]byte, error) {
	rest := d.b[d.off:]
	if n > len(rest) {
		return nil, wireErr("truncated")
	}
	d.off += n
	return rest[:n:n], nil
}

func (d *decoder) u32() (uint32, error) {
	b, err := d.take(4)
	if err != nil {
		return 0, err
	}
	return d.order.Uint32(b), nil
}

func (d *decoder) str(n int) (string, error) {
	b, err := d.take(n + 1)
	if err != nil {
		return "", err
	}
	s := b[:n]
	if b[n] != 0 || !utf8.Valid(s) {
		return "", wireErr("bad string")
	}
	for _, c := range s {
		if c == 0 {
			return "", wireErr("NUL in string")
		}
	}
	return string(s), nil
}

func (d *decoder) value(t *typ, depth int) (any, error) {
	if depth > maxDepth {
		return nil, wireErr("nested too deep")
	}
	if err := d.pad(align(t.code)); err != nil {
		return nil, err
	}
	switch t.code {
	case 'y':
		b, err := d.take(1)
		if err != nil {
			return nil, err
		}
		return b[0], nil
	case 'b':
		v, err := d.u32()
		if err != nil {
			return nil, err
		}
		if v > 1 {
			return nil, wireErr("bool %d", v)
		}
		return v == 1, nil
	case 'n', 'q':
		b, err := d.take(2)
		if err != nil {
			return nil, err
		}
		if t.code == 'n' {
			return int16(d.order.Uint16(b)), nil
		}
		return d.order.Uint16(b), nil
	case 'i', 'u':
		v, err := d.u32()
		if err != nil {
			return nil, err
		}
		if t.code == 'i' {
			return int32(v), nil
		}
		return v, nil
	case 'x', 't', 'd':
		b, err := d.take(8)
		if err != nil {
			return nil, err
		}
		v := d.order.Uint64(b)
		switch t.code {
		case 'x':
			return int64(v), nil
		case 'd':
			return math.Float64frombits(v), nil
		}
		return v, nil
	case 's', 'o':
		n, err := d.u32()
		if err != nil {
			return nil, err
		}
		s, err := d.str(int(n))
		if err != nil {
			return nil, err
		}
		if t.code == 'o' {
			if !validPath(s) {
				return nil, wireErr("bad object path")
			}
			return ObjectPath(s), nil
		}
		return s, nil
	case 'g', 'v':
		b, err := d.take(1)
		if err != nil {
			return nil, err
		}
		s, err := d.str(int(b[0]))
		if err != nil {
			return nil, err
		}
		ts, err := parseSig(s)
		if err != nil {
			return nil, err
		}
		if t.code == 'g' {
			return Signature(s), nil
		}
		if len(ts) != 1 {
			return nil, wireErr("variant needs one complete type")
		}
		v, err := d.value(ts[0], depth+1)
		if err != nil {
			return nil, err
		}
		return Variant{Sig: Signature(s), Value: v}, nil
	case 'a':
		n, err := d.u32()
		if err != nil {
			return nil, err
		}
		if err := d.pad(align(t.elem.code)); err != nil {
			return nil, err
		}
		if t.elem.code == 'y' {
			b, err := d.take(int(n))
			if err != nil {
				return nil, err
			}
			return append([]byte{}, b...), nil
		}
		// No bound check before the loop: every element takes at least a
		// byte, so a length past the message fails in take.
		end := d.off + int(n)
		out := []any{}
		for d.off < end {
			v, err := d.value(t.elem, depth)
			if err != nil {
				return nil, err
			}
			out = append(out, v)
		}
		if d.off != end {
			return nil, wireErr("array length")
		}
		return out, nil
	case '(':
		out := make([]any, len(t.fields))
		for i, f := range t.fields {
			v, err := d.value(f, depth)
			if err != nil {
				return nil, err
			}
			out[i] = v
		}
		return out, nil
	case '{':
		k, err := d.value(t.fields[0], depth)
		if err != nil {
			return nil, err
		}
		v, err := d.value(t.fields[1], depth)
		if err != nil {
			return nil, err
		}
		return Entry{Key: k, Value: v}, nil
	}
	return nil, wireErr("type %q", t.code)
}

// encoder writes values little-endian; offsets are from the message's
// start.
type encoder struct {
	b []byte
}

// le is the order the encoder writes; tests swap it to make big-endian
// messages.
var le interface {
	binary.ByteOrder
	binary.AppendByteOrder
} = binary.LittleEndian

func (e *encoder) pad(n int) {
	for len(e.b)%n != 0 {
		e.b = append(e.b, 0)
	}
}

func (e *encoder) str(s string) error {
	if !utf8.ValidString(s) {
		return wireErr("bad string")
	}
	for i := 0; i < len(s); i++ {
		if s[i] == 0 {
			return wireErr("NUL in string")
		}
	}
	e.b = append(append(e.b, s...), 0)
	return nil
}

func (e *encoder) value(t *typ, v any) error {
	e.pad(align(t.code))
	bad := func() error { return wireErr("value %T for type %q", v, t.code) }
	switch t.code {
	case 'y':
		x, ok := v.(uint8)
		if !ok {
			return bad()
		}
		e.b = append(e.b, x)
	case 'b':
		x, ok := v.(bool)
		if !ok {
			return bad()
		}
		var u uint32
		if x {
			u = 1
		}
		e.b = le.AppendUint32(e.b, u)
	case 'n':
		x, ok := v.(int16)
		if !ok {
			return bad()
		}
		e.b = le.AppendUint16(e.b, uint16(x))
	case 'q':
		x, ok := v.(uint16)
		if !ok {
			return bad()
		}
		e.b = le.AppendUint16(e.b, x)
	case 'i':
		x, ok := v.(int32)
		if !ok {
			return bad()
		}
		e.b = le.AppendUint32(e.b, uint32(x))
	case 'u':
		x, ok := v.(uint32)
		if !ok {
			return bad()
		}
		e.b = le.AppendUint32(e.b, x)
	case 'x':
		x, ok := v.(int64)
		if !ok {
			return bad()
		}
		e.b = le.AppendUint64(e.b, uint64(x))
	case 't':
		x, ok := v.(uint64)
		if !ok {
			return bad()
		}
		e.b = le.AppendUint64(e.b, x)
	case 'd':
		x, ok := v.(float64)
		if !ok {
			return bad()
		}
		e.b = le.AppendUint64(e.b, math.Float64bits(x))
	case 's', 'o':
		var s string
		switch x := v.(type) {
		case string:
			s = x
			if t.code == 'o' {
				return bad()
			}
		case ObjectPath:
			s = string(x)
			if t.code == 's' || !validPath(s) {
				return bad()
			}
		default:
			return bad()
		}
		e.b = le.AppendUint32(e.b, uint32(len(s)))
		return e.str(s)
	case 'g':
		x, ok := v.(Signature)
		if !ok {
			return bad()
		}
		if _, err := parseSig(string(x)); err != nil {
			return err
		}
		e.b = append(e.b, byte(len(x)))
		return e.str(string(x))
	case 'v':
		x, ok := v.(Variant)
		if !ok {
			return bad()
		}
		ts, err := parseSig(string(x.Sig))
		if err != nil {
			return err
		}
		if len(ts) != 1 {
			return wireErr("variant needs one complete type")
		}
		e.b = append(e.b, byte(len(x.Sig)))
		if err := e.str(string(x.Sig)); err != nil {
			return err
		}
		return e.value(ts[0], x.Value)
	case 'a':
		at := len(e.b)
		e.b = append(e.b, 0, 0, 0, 0)
		e.pad(align(t.elem.code))
		start := len(e.b)
		if t.elem.code == 'y' {
			x, ok := v.([]byte)
			if !ok {
				return bad()
			}
			e.b = append(e.b, x...)
		} else {
			xs, ok := v.([]any)
			if !ok {
				return bad()
			}
			for _, x := range xs {
				if err := e.value(t.elem, x); err != nil {
					return err
				}
			}
		}
		le.PutUint32(e.b[at:], uint32(len(e.b)-start))
	case '(':
		xs, ok := v.([]any)
		if !ok || len(xs) != len(t.fields) {
			return bad()
		}
		for i, f := range t.fields {
			if err := e.value(f, xs[i]); err != nil {
				return err
			}
		}
	case '{':
		x, ok := v.(Entry)
		if !ok {
			return bad()
		}
		if err := e.value(t.fields[0], x.Key); err != nil {
			return err
		}
		return e.value(t.fields[1], x.Value)
	default:
		return bad()
	}
	return nil
}

// Header field codes and the type each must carry.
var fieldSig = [...]Signature{1: "o", 2: "s", 3: "s", 4: "s", 5: "u", 6: "s", 7: "s", 8: "g", 9: "u"}

var headerTyp = &typ{code: 'a', elem: &typ{code: '(', fields: []*typ{{code: 'y'}, {code: 'v'}}}}

// Encode returns m on the wire, little-endian.
func (m *Message) Encode() ([]byte, error) {
	if m.Type < typeCall || m.Type > typeSignal || m.Serial == 0 {
		return nil, wireErr("header")
	}
	var fields []any
	add := func(code byte, sig Signature, v any) {
		fields = append(fields, []any{code, Variant{Sig: sig, Value: v}})
	}
	if m.Path != "" {
		add(1, "o", m.Path)
	}
	for _, f := range []struct {
		code byte
		v    string
	}{{2, m.Interface}, {3, m.Member}, {4, m.ErrorName}} {
		if f.v != "" {
			add(f.code, "s", f.v)
		}
	}
	if m.ReplySerial != 0 {
		add(5, "u", m.ReplySerial)
	}
	if m.Destination != "" {
		add(6, "s", m.Destination)
	}
	if m.Sender != "" {
		add(7, "s", m.Sender)
	}
	if m.Sig != "" {
		add(8, "g", m.Sig)
	}
	if err := m.required(); err != nil {
		return nil, err
	}
	ts, err := parseSig(string(m.Sig))
	if err != nil {
		return nil, err
	}
	if len(ts) != len(m.Body) {
		return nil, wireErr("body has %d values for signature %q", len(m.Body), m.Sig)
	}
	e := &encoder{b: []byte{'l', m.Type, m.Flags, 1, 0, 0, 0, 0}}
	e.b = le.AppendUint32(e.b, m.Serial)
	if err := e.value(headerTyp, fields); err != nil {
		return nil, err
	}
	e.pad(8)
	start := len(e.b)
	for i, t := range ts {
		if err := e.value(t, m.Body[i]); err != nil {
			return nil, err
		}
	}
	le.PutUint32(e.b[4:], uint32(len(e.b)-start))
	if len(e.b) > MaxMessage {
		return nil, wireErr("message too long")
	}
	return e.b, nil
}

// required holds a message to the header fields its type needs.
func (m *Message) required() error {
	ok := true
	switch m.Type {
	case typeCall:
		ok = m.Path != "" && m.Member != ""
	case typeReturn:
		ok = m.ReplySerial != 0
	case typeError:
		ok = m.ReplySerial != 0 && m.ErrorName != ""
	case typeSignal:
		ok = m.Path != "" && m.Interface != "" && m.Member != ""
	}
	if !ok {
		return wireErr("type %d lacks a required header field", m.Type)
	}
	return nil
}

// frameLen reads, from a message's first 16 bytes, the length of its
// header (fields and padding included) and of the whole message. The
// lengths are int64: two declared uint32 lengths sum past 1<<32, which an
// int would wrap on a 32-bit build, so the reader would skip the wrong
// number of bytes and lose the stream.
func frameLen(h []byte) (head, n int64, err error) {
	var order binary.ByteOrder
	switch h[0] {
	case 'l':
		order = binary.LittleEndian
	case 'B':
		order = binary.BigEndian
	default:
		return 0, 0, wireErr("byte order %q", h[0])
	}
	body, fields := uint64(order.Uint32(h[4:])), uint64(order.Uint32(h[12:]))
	hl := 16 + fields
	hl += (8 - hl%8) % 8
	if hl+body > MaxMessage || fields > maxHeader {
		return int64(hl), int64(hl + body), errTooLong
	}
	return int64(hl), int64(hl + body), nil
}

// Decode parses one whole message, refusing anything malformed, trailing
// bytes included.
func Decode(b []byte) (*Message, error) {
	var h [16]byte
	copy(h[:], b)
	_, n, err := frameLen(h[:]) // at least 16, so a shorter b fails below
	if err != nil {
		return nil, err
	}
	if n != int64(len(b)) {
		return nil, wireErr("length %d, header says %d", len(b), n)
	}
	m, d, err := header(b)
	if err != nil {
		return nil, err
	}
	if err := m.body(d); err != nil {
		return nil, err
	}
	return m, nil
}

// header parses the header of the message b starts with, which frameLen
// has measured: b holds at least the header, and the body is not read.
// The decoder it returns stands at the body's start.
func header(b []byte) (*Message, *decoder, error) {
	d := &decoder{b: b, off: 12, order: binary.LittleEndian}
	if b[0] == 'B' {
		d.order = binary.BigEndian
	}
	m := &Message{Type: b[1], Flags: b[2], Serial: d.order.Uint32(b[8:])}
	if m.Type < typeCall || m.Type > typeSignal || b[3] != 1 || m.Serial == 0 {
		return nil, nil, wireErr("header")
	}
	fs, err := d.value(headerTyp, 0)
	if err != nil {
		return nil, nil, err
	}
	seen := map[byte]bool{}
	for _, f := range fs.([]any) {
		f := f.([]any)
		code, v := f[0].(uint8), f[1].(Variant)
		if int(code) >= len(fieldSig) || fieldSig[code] == "" {
			continue // unknown fields are ignored (the specification)
		}
		if seen[code] || v.Sig != fieldSig[code] {
			return nil, nil, wireErr("header field %d", code)
		}
		seen[code] = true
		switch code {
		case 1:
			m.Path = v.Value.(ObjectPath)
		case 2:
			m.Interface = v.Value.(string)
		case 3:
			m.Member = v.Value.(string)
		case 4:
			m.ErrorName = v.Value.(string)
		case 5:
			m.ReplySerial = v.Value.(uint32)
		case 6:
			m.Destination = v.Value.(string)
		case 7:
			m.Sender = v.Value.(string)
		case 8:
			m.Sig = v.Value.(Signature)
		case 9:
			if v.Value.(uint32) != 0 {
				return nil, nil, wireErr("unix fds")
			}
		}
	}
	if err := m.required(); err != nil {
		return nil, nil, err
	}
	if err := d.pad(8); err != nil {
		return nil, nil, err
	}
	return m, d, nil
}

// body decodes m's body from d, which header left at the body's start and
// whose buffer has since been made the whole message.
func (m *Message) body(d *decoder) error {
	ts, err := parseSig(string(m.Sig))
	if err != nil {
		return err
	}
	for _, t := range ts {
		v, err := d.value(t, 0)
		if err != nil {
			return err
		}
		m.Body = append(m.Body, v)
	}
	if d.off != len(d.b) {
		return wireErr("body length")
	}
	return nil
}
