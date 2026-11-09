package wire

// REQ: CH-5, CH-21

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"
)

func TestFrameRoundTrip(t *testing.T) {
	var b bytes.Buffer
	if err := Write(&b, Speak, EncodeID(7, []byte("Hi."))); err != nil {
		t.Fatal(err)
	}
	if err := Write(&b, Audio, make([]byte, MaxPayload)); err != nil {
		t.Fatal(err)
	}
	if b.Len() != 5+7+5+MaxPayload {
		t.Fatalf("framed %d bytes", b.Len())
	}
	typ, p, err := Read(&b)
	id, rest, err2 := DecodeID(p)
	if err != nil || err2 != nil || typ != Speak || id != 7 || string(rest) != "Hi." {
		t.Fatalf("read %d %v %q %v %v", typ, id, rest, err, err2)
	}
	if typ, p, err := Read(&b); err != nil || typ != Audio || len(p) != MaxPayload {
		t.Fatalf("read %d, %d bytes, %v", typ, len(p), err)
	}
	if _, _, err := Read(&b); err != io.EOF {
		t.Fatalf("clean end = %v, want io.EOF", err)
	}
}

func TestFrameBounds(t *testing.T) {
	if err := Write(io.Discard, Audio, make([]byte, MaxPayload+1)); !errors.Is(err, ErrFrame) {
		t.Fatalf("oversize write = %v", err)
	}
	for name, s := range map[string][]byte{
		"oversize": {Audio, 0, 1, 0, 1},
		"cut head": {Audio, 0, 0},
		"cut body": {Audio, 0, 0, 0, 4, 0, 0},
	} {
		if _, _, err := Read(bytes.NewReader(s)); !errors.Is(err, ErrFrame) {
			t.Errorf("%s: Read = %v, want ErrFrame", name, err)
		}
	}
	// The length is checked before anything is allocated for it.
	if _, _, err := Read(bytes.NewReader([]byte{Audio, 0xff, 0xff, 0xff, 0xff})); !errors.Is(err, ErrFrame) {
		t.Fatalf("4 GiB length = %v", err)
	}
	if _, _, err := Read(bytes.NewReader(append([]byte{Audio, 0, 1, 0, 0}, make([]byte, MaxPayload)...))); err != nil {
		t.Fatalf("a frame at MaxPayload = %v", err)
	}
}

func TestText(t *testing.T) {
	for _, ok := range []string{"", "What is due today?", "Café at nine — £4.", strings.Repeat("a", MaxText)} {
		if s, err := Text([]byte(ok)); err != nil || s != ok {
			t.Errorf("Text(%q) = %q, %v", ok, s, err)
		}
	}
	for _, bad := range []string{"\t", "a\nb", "\x7f", "\u0085", "\u200b", "\u202e", "\ufeff", "\u2028", "\u2029", "\xff", strings.Repeat("a", MaxText+1)} {
		if _, err := Text([]byte(bad)); !errors.Is(err, ErrFrame) {
			t.Errorf("Text(%q) = %v, want ErrFrame", bad, err)
		}
	}
	if PCM([]byte{1}) == nil || PCM([]byte{1, 2}) != nil || PCM(nil) != nil {
		t.Fatal("PCM does not count whole samples")
	}
}

func TestHeardRoundTrip(t *testing.T) {
	for _, h := range []HeardFrame{{}, {Final: true, End: 1<<63 + 5, Text: "read my mail"}, {End: 1, Text: "r"}} {
		got, err := DecodeHeard(EncodeHeard(h))
		if err != nil || got != h {
			t.Fatalf("round trip of %+v = %+v, %v", h, got, err)
		}
	}
	for _, p := range [][]byte{nil, make([]byte, 8), append([]byte{2}, make([]byte, 8)...), append(make([]byte, 9), '\n')} {
		if _, err := DecodeHeard(p); !errors.Is(err, ErrFrame) {
			t.Errorf("DecodeHeard(%v) = %v", p, err)
		}
	}
	if _, _, err := DecodeID([]byte{0, 0, 0}); !errors.Is(err, ErrFrame) {
		t.Fatal("a 3-byte id parsed")
	}
	if id, rest, err := DecodeID([]byte{0, 0, 1, 2}); err != nil || id != 258 || len(rest) != 0 {
		t.Fatalf("DecodeID = %d %v %v", id, rest, err)
	}
}
