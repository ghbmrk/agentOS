package edgelink

import (
	"bytes"
	"testing"
)

// REQ: HW-15

// FuzzReadFrame: on any input and any stream the codec never panics, and a
// frame it returns re-encodes to exactly the bytes it consumed, so nothing
// the edge sends is reinterpreted or skipped. Revert mutant: ReadFrame
// dropping the origin's printable check (a re-encode then fails).
func FuzzReadFrame(f *testing.F) {
	seed := func(s Stream, fr Frame) {
		b, err := AppendFrame(nil, s, fr)
		if err != nil {
			f.Fatal(err)
		}
		f.Add(b)
	}
	seed(ToEdge, Frame{KindFetch, "https://example.org/", []byte("x")})
	seed(FromEdge, Frame{KindFetched, "https://example.org/", []byte("<html>")})
	seed(FromEdge, Frame{KindText, "+15550100", []byte("hi")})
	seed(FromEdge, Frame{KindDevice, "tv", nil})
	seed(Hello, Frame{KindHello, "", make([]byte, HelloLen)})
	f.Add([]byte{1, 3, 0, 1, 0, 0, 0, 0, 0x7F})
	f.Add([]byte{1, 2, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF})
	f.Fuzz(func(t *testing.T, data []byte) {
		for _, s := range []Stream{ToEdge, FromEdge, Hello} {
			r := bytes.NewReader(data)
			fr, err := ReadFrame(r, s)
			if err != nil {
				continue
			}
			used := data[:len(data)-r.Len()]
			enc, err := AppendFrame(nil, s, fr)
			if err != nil {
				t.Fatalf("stream %d: a frame read back does not encode: %v", s, err)
			}
			if !bytes.Equal(enc, used) {
				t.Fatalf("stream %d: re-encoding differs from the bytes consumed", s)
			}
		}
	})
}
