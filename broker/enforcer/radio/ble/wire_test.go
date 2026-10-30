package ble

import (
	"bytes"
	"encoding/binary"
	"errors"
	"reflect"
	"strings"
	"testing"
)

// REQ: NET-2

// propsChanged is the signal BlueZ sends for a notification.
func propsChanged(serial uint32, sender string, path ObjectPath, value []byte) *Message {
	return &Message{Type: typeSignal, Serial: serial, Sender: sender, Path: path,
		Interface: ifaceProps, Member: "PropertiesChanged", Sig: "sa{sv}as",
		Body: []any{ifaceChar, []any{Entry{Key: "Value", Value: Variant{Sig: "ay", Value: value}}}, []any{}}}
}

func mustEncode(t testing.TB, m *Message) []byte {
	t.Helper()
	b, err := m.Encode()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestWireKnownBytes: the encoder produces the specification's layout,
// checked against a hand-assembled Hello call, so the codec is not only
// consistent with itself.
func TestWireKnownBytes(t *testing.T) {
	m := &Message{Type: typeCall, Serial: 1, Path: "/org/freedesktop/DBus", Interface: busDriver,
		Member: "Hello", Destination: busDriver}
	got := mustEncode(t, m)
	var want []byte
	want = append(want, 'l', 1, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0) // header, empty body, serial 1
	var f []byte
	field := func(code byte, sig byte, s string) {
		for len(f)%8 != 0 {
			f = append(f, 0)
		}
		f = append(f, code, 1, sig, 0)
		f = binary.LittleEndian.AppendUint32(f, uint32(len(s)))
		f = append(append(f, s...), 0)
	}
	field(1, 'o', "/org/freedesktop/DBus")
	field(2, 's', busDriver)
	field(3, 's', "Hello")
	field(6, 's', busDriver)
	want = binary.LittleEndian.AppendUint32(want, uint32(len(f)))
	want = append(want, f...)
	for len(want)%8 != 0 {
		want = append(want, 0)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("Hello encodes as\n%x\nwant\n%x", got, want)
	}
}

// TestWireRoundTrip: every type the stack meets survives encode and
// decode, in both byte orders.
func TestWireRoundTrip(t *testing.T) {
	body := []any{
		uint8(7), true, int16(-2), uint16(3), int32(-4), uint32(5), int64(-6), uint64(7), 1.5,
		"text", ObjectPath("/org/bluez/hci0"), Signature("a{sv}"),
		Variant{Sig: "ay", Value: []byte{1, 2}},
		[]any{Entry{Key: ObjectPath("/a"), Value: []any{Entry{Key: "k", Value: Variant{Sig: "(yu)", Value: []any{uint8(1), uint32(2)}}}}}},
		[]byte{},
		[]any{},
	}
	m := &Message{Type: typeSignal, Serial: 9, Sender: ":1.4", Path: "/x", Interface: "a.b", Member: "C",
		Sig: "ybnqiuxtdsogva{oa{sv}}ayas", Body: body}
	b := mustEncode(t, m)
	got, err := Decode(b)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, m) {
		t.Fatalf("round trip:\n%#v\nwant\n%#v", got, m)
	}
	// The same message big-endian: re-encode the values by hand is the
	// encoder's job, so flip only what the order changes and decode.
	be := bigEndian(t, m)
	got, err = Decode(be)
	if err != nil {
		t.Fatalf("big-endian: %v", err)
	}
	if !reflect.DeepEqual(got, m) {
		t.Fatalf("big-endian round trip:\n%#v", got)
	}
}

// bigEndian encodes m in the big-endian order, by encoding it with a
// big-endian encoder (test only: the stack sends little-endian).
func bigEndian(t *testing.T, m *Message) []byte {
	t.Helper()
	old := le
	defer func() { le = old }()
	le = bigOrder{}
	b := mustEncode(t, m)
	b[0] = 'B'
	return b
}

type bigOrder struct{ binary.ByteOrder }

func (bigOrder) Uint16(b []byte) uint16                 { return binary.BigEndian.Uint16(b) }
func (bigOrder) Uint32(b []byte) uint32                 { return binary.BigEndian.Uint32(b) }
func (bigOrder) Uint64(b []byte) uint64                 { return binary.BigEndian.Uint64(b) }
func (bigOrder) PutUint16(b []byte, v uint16)           { binary.BigEndian.PutUint16(b, v) }
func (bigOrder) PutUint32(b []byte, v uint32)           { binary.BigEndian.PutUint32(b, v) }
func (bigOrder) PutUint64(b []byte, v uint64)           { binary.BigEndian.PutUint64(b, v) }
func (bigOrder) AppendUint16(b []byte, v uint16) []byte { return binary.BigEndian.AppendUint16(b, v) }
func (bigOrder) AppendUint32(b []byte, v uint32) []byte { return binary.BigEndian.AppendUint32(b, v) }
func (bigOrder) AppendUint64(b []byte, v uint64) []byte { return binary.BigEndian.AppendUint64(b, v) }
func (bigOrder) String() string                         { return "big" }

// TestWireRefusesMalformed: each fault a hostile or broken peer could put
// on the bus is refused, not decoded into something else.
func TestWireRefusesMalformed(t *testing.T) {
	good := mustEncode(t, propsChanged(3, ":1.0", "/org/bluez/hci0/dev_AA/char0001", []byte{0xAB}))
	if _, err := Decode(good); err != nil {
		t.Fatalf("the good message: %v", err)
	}
	at := func(sub []byte) int {
		i := bytes.Index(good, sub)
		if i < 0 {
			t.Fatalf("%q not in the message", sub)
		}
		return i
	}
	edit := func(f func(b []byte) []byte) []byte { return f(bytes.Clone(good)) }
	bodyStart := len(good) - int(binary.LittleEndian.Uint32(good[4:]))
	cases := map[string][]byte{
		"truncated":          good[:len(good)-1],
		"trailing byte":      append(bytes.Clone(good), 0),
		"byte order":         edit(func(b []byte) []byte { b[0] = 'x'; return b }),
		"version":            edit(func(b []byte) []byte { b[3] = 2; return b }),
		"type":               edit(func(b []byte) []byte { b[1] = 5; return b }),
		"serial zero":        edit(func(b []byte) []byte { copy(b[8:], []byte{0, 0, 0, 0}); return b }),
		"NUL in string":      edit(func(b []byte) []byte { b[at([]byte("PropertiesChanged"))+3] = 0; return b }),
		"bad UTF-8":          edit(func(b []byte) []byte { b[at([]byte("PropertiesChanged"))+3] = 0xff; return b }),
		"bad object path":    edit(func(b []byte) []byte { b[at([]byte("/org/bluez"))+4] = '-'; return b }),
		"nonzero padding":    edit(func(b []byte) []byte { b[bodyStart-1] = 1; return b }),
		"string past end":    edit(func(b []byte) []byte { binary.LittleEndian.PutUint32(b[bodyStart:], 1<<30); return b }),
		"header says long":   edit(func(b []byte) []byte { binary.LittleEndian.PutUint32(b[4:], 1<<30); return b }),
		"signature mismatch": edit(func(b []byte) []byte { b[at([]byte("sa{sv}as"))] = 'u'; return b }),
		"unknown type code":  edit(func(b []byte) []byte { b[at([]byte("sa{sv}as"))+7] = 'h'; return b }),
	}
	for name, b := range cases {
		if m, err := Decode(b); err == nil {
			t.Errorf("%s: decoded %+v", name, m)
		}
	}

	// A bool other than 0 or 1, unix fds, a dict entry outside an array,
	// too deep a nesting: built rather than edited.
	boolMsg := mustEncode(t, &Message{Type: typeSignal, Serial: 1, Path: "/", Interface: "a.b", Member: "C", Sig: "b", Body: []any{true}})
	boolMsg[len(boolMsg)-4] = 2
	fds := &Message{Type: typeSignal, Serial: 1, Path: "/", Interface: "a.b", Member: "C"}
	fdsRaw := withField(t, fds, 9, "u", uint32(1))
	deep := strings.Repeat("a", maxDepth+1) + "y"
	for name, b := range map[string][]byte{"bool 2": boolMsg, "unix fds": fdsRaw} {
		if _, err := Decode(b); err == nil {
			t.Errorf("%s: decoded", name)
		}
	}
	for _, sig := range []string{"{sv}", deep, "(", "()", "a{vs}", "a{s}", "h", "v)"} {
		if _, err := parseSig(sig); !errors.Is(err, ErrWire) {
			t.Errorf("signature %q: %v", sig, err)
		}
	}
	// Variants nested past maxDepth.
	var v any = Variant{Sig: "y", Value: uint8(1)}
	nest := &Message{Type: typeSignal, Serial: 1, Path: "/", Interface: "a.b", Member: "C", Sig: "v", Body: []any{v}}
	for i := 0; i <= maxDepth; i++ {
		nest.Body[0] = Variant{Sig: "v", Value: nest.Body[0]}
	}
	if _, err := nest.Encode(); err == nil {
		t.Error("encoded variants nested past maxDepth")
	}
}

// withField encodes m with one extra header field.
func withField(t *testing.T, m *Message, code byte, sig Signature, v any) []byte {
	t.Helper()
	e := &encoder{b: []byte{'l', m.Type, 0, 1, 0, 0, 0, 0}}
	e.b = le.AppendUint32(e.b, m.Serial)
	fields := []any{
		[]any{uint8(1), Variant{Sig: "o", Value: m.Path}},
		[]any{uint8(2), Variant{Sig: "s", Value: m.Interface}},
		[]any{uint8(3), Variant{Sig: "s", Value: m.Member}},
		[]any{code, Variant{Sig: sig, Value: v}},
	}
	if err := e.value(headerTyp, fields, 0); err != nil {
		t.Fatal(err)
	}
	e.pad(8)
	return e.b
}

// FuzzDecode: the decoder never panics, and whatever it accepts encodes to
// a message it decodes again to the same bytes; the stack's signal path
// takes any decoded message without panicking.
func FuzzDecode(f *testing.F) {
	f.Add(mustEncode(f, propsChanged(3, ":1.0", "/org/bluez/hci0/dev_AA_BB_CC_DD_EE_FF/service0010/char0011", []byte{1, 2, 3})))
	f.Add(mustEncode(f, &Message{Type: typeReturn, Serial: 2, ReplySerial: 1, Sig: "a{oa{sa{sv}}}", Body: []any{managed("/org/bluez/hci0/dev_AA_BB_CC_DD_EE_FF", map[string]string{"char0011": testUUID})}}))
	f.Add(mustEncode(f, &Message{Type: typeError, Serial: 2, ReplySerial: 1, ErrorName: "org.bluez.Error.Failed", Sig: "s", Body: []any{"no"}}))
	f.Add(mustEncode(f, &Message{Type: typeSignal, Serial: 4, Sender: busDriver, Path: "/org/freedesktop/DBus", Interface: busDriver, Member: "NameOwnerChanged", Sig: "sss", Body: []any{bluez, ":1.0", ":1.7"}}))
	f.Fuzz(func(t *testing.T, b []byte) {
		m, err := Decode(b)
		if err != nil {
			return
		}
		e1, err := m.Encode()
		if err != nil {
			t.Fatalf("decoded but does not encode: %v", err)
		}
		m2, err := Decode(e1)
		if err != nil {
			t.Fatalf("re-encoding does not decode: %v", err)
		}
		e2, err := m2.Encode()
		if err != nil || !bytes.Equal(e1, e2) {
			t.Fatalf("round trip differs: %v", err)
		}
		s := newFuzzStack()
		s.signal(m)
	})
}
