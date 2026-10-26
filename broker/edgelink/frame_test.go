package edgelink

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"strings"
	"testing"
)

// REQ: HW-15, HW-17

// countingReader records how many bytes the codec took, so a refusal can be
// shown to read no further than the field that failed.
type countingReader struct {
	r io.Reader
	n int
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += n
	return n, err
}

func header(v byte, k Kind, olen int, blen uint32) []byte {
	h := []byte{v, byte(k)}
	h = binary.BigEndian.AppendUint16(h, uint16(olen))
	return binary.BigEndian.AppendUint32(h, blen)
}

func encode(t *testing.T, s Stream, f Frame) []byte {
	t.Helper()
	b, err := AppendFrame(nil, s, f)
	if err != nil {
		t.Fatalf("AppendFrame(%v): %v", f.Kind, err)
	}
	return b
}

// TestFramesRoundTripAndRefuseEveryBadField: every kind round-trips on each
// stream it may travel on, and each bad field closes with its fixed error
// having read no further than that field. Revert mutants: dropping the
// direction check (ErrDirection cases pass), or `blen > spec.cap` becoming
// `>=`/removed (the cap cases), or skipping printable (the origin cases).
func TestFramesRoundTripAndRefuseEveryBadField(t *testing.T) {
	sig := bytes.Repeat([]byte{7}, HelloLen)
	good := []struct {
		s Stream
		f Frame
	}{
		{ToEdge, Frame{KindFetch, "https://example.org/a", []byte("GET")}},
		{FromEdge, Frame{KindFetched, "https://example.org/a", bytes.Repeat([]byte{1}, 16<<20)}},
		{FromEdge, Frame{KindText, "+15550100", []byte("hello")}},
		{FromEdge, Frame{KindCall, "+15550100", bytes.Repeat([]byte{2}, 64<<10)}},
		{FromEdge, Frame{KindDevice, "living room tv", nil}},
		{ToEdge, Frame{KindDevice, "living room tv", []byte("{}")}},
		{Hello, Frame{KindHello, "", sig}},
		{FromEdge, Frame{KindText, strings.Repeat("é", MaxOrigin/2), nil}},
	}
	for _, g := range good {
		b := encode(t, g.s, g.f)
		cr := &countingReader{r: bytes.NewReader(append(b, 0xEE))}
		got, err := ReadFrame(cr, g.s)
		if err != nil {
			t.Fatalf("%v on %v: %v", g.f.Kind, g.s, err)
		}
		if got.Kind != g.f.Kind || got.Origin != g.f.Origin || !bytes.Equal(got.Body, g.f.Body) || cr.n != len(b) {
			t.Fatalf("%v: round trip differs or read %d of %d", g.f.Kind, cr.n, len(b))
		}
	}

	bad := []struct {
		name string
		s    Stream
		in   []byte
		want error
		read int // bytes the codec may take before refusing
	}{
		{"version 0", FromEdge, header(0, KindText, 1, 0), ErrVersion, HeaderLen},
		{"version 2", FromEdge, header(2, KindText, 1, 0), ErrVersion, HeaderLen},
		{"kind 0", FromEdge, header(1, 0, 1, 0), ErrKind, HeaderLen},
		{"kind 7", FromEdge, header(1, 7, 1, 0), ErrKind, HeaderLen},
		{"kind 255", FromEdge, header(1, 255, 1, 0), ErrKind, HeaderLen},
		{"fetch from the edge", FromEdge, header(1, KindFetch, 1, 0), ErrDirection, HeaderLen},
		{"fetched to the edge", ToEdge, header(1, KindFetched, 1, 0), ErrDirection, HeaderLen},
		{"text to the edge", ToEdge, header(1, KindText, 1, 0), ErrDirection, HeaderLen},
		{"call to the edge", ToEdge, header(1, KindCall, 1, 0), ErrDirection, HeaderLen},
		{"hello on a served connection", FromEdge, header(1, KindHello, 0, HelloLen), ErrDirection, HeaderLen},
		{"text in hello mode", Hello, header(1, KindText, 1, 0), ErrDirection, HeaderLen},
		{"device in hello mode", Hello, header(1, KindDevice, 1, 0), ErrDirection, HeaderLen},
		{"unknown stream", Stream(0), header(1, KindText, 1, 0), ErrDirection, HeaderLen},
		{"origin one over", FromEdge, header(1, KindText, MaxOrigin+1, 0), ErrOriginLength, HeaderLen},
		{"origin max uint16", FromEdge, header(1, KindText, 65535, 0), ErrOriginLength, HeaderLen},
		{"empty origin", FromEdge, header(1, KindText, 0, 0), ErrOriginLength, HeaderLen},
		{"hello with an origin", Hello, header(1, KindHello, 1, HelloLen), ErrOriginLength, HeaderLen},
		{"fetch one over", ToEdge, header(1, KindFetch, 1, 64<<10+1), ErrBodyLength, HeaderLen},
		{"fetched one over", FromEdge, header(1, KindFetched, 1, 16<<20+1), ErrBodyLength, HeaderLen},
		{"text one over", FromEdge, header(1, KindText, 1, 64<<10+1), ErrBodyLength, HeaderLen},
		{"call one over", FromEdge, header(1, KindCall, 1, 64<<10+1), ErrBodyLength, HeaderLen},
		{"device one over", FromEdge, header(1, KindDevice, 1, 64<<10+1), ErrBodyLength, HeaderLen},
		{"device to the edge one over", ToEdge, header(1, KindDevice, 1, 64<<10+1), ErrBodyLength, HeaderLen},
		{"hello one short", Hello, header(1, KindHello, 0, HelloLen-1), ErrBodyLength, HeaderLen},
		{"hello one over", Hello, header(1, KindHello, 0, HelloLen+1), ErrBodyLength, HeaderLen},
		{"body max uint32", FromEdge, header(1, KindFetched, 1, 1<<32-1), ErrBodyLength, HeaderLen},
		{"empty stream mid-header", FromEdge, header(1, KindText, 1, 0)[:3], ErrShort, 3},
		{"truncated origin", FromEdge, append(header(1, KindText, 4, 0), "ab"...), ErrShort, HeaderLen + 2},
		{"truncated body", FromEdge, append(append(header(1, KindText, 1, 5), 'a'), "abc"...), ErrShort, HeaderLen + 4},
		{"invalid UTF-8", FromEdge, append(header(1, KindText, 2, 0), 0xC3, 0x28), ErrOrigin, HeaderLen + 2},
		{"NUL in origin", FromEdge, append(header(1, KindText, 2, 0), 'a', 0), ErrOrigin, HeaderLen + 2},
		{"newline in origin", FromEdge, append(header(1, KindText, 2, 0), 'a', '\n'), ErrOrigin, HeaderLen + 2},
		{"DEL in origin", FromEdge, append(header(1, KindText, 1, 0), 0x7F), ErrOrigin, HeaderLen + 1},
		{"C1 control in origin", FromEdge, append(header(1, KindText, 2, 0), 0xC2, 0x85), ErrOrigin, HeaderLen + 2},
	}
	for _, c := range bad {
		// Trailing bytes stand for whatever the peer sends next: none may be read.
		cr := &countingReader{r: bytes.NewReader(append(append([]byte{}, c.in...), bytes.Repeat([]byte{'x'}, 32)...))}
		if c.want == ErrShort {
			cr = &countingReader{r: bytes.NewReader(c.in)}
		}
		_, err := ReadFrame(cr, c.s)
		if !errors.Is(err, c.want) {
			t.Errorf("%s: got %v, want %v", c.name, err, c.want)
		}
		if cr.n > c.read {
			t.Errorf("%s: read %d bytes, want at most %d", c.name, cr.n, c.read)
		}
	}

	// A clean end before a frame is io.EOF, not a fault.
	if _, err := ReadFrame(bytes.NewReader(nil), FromEdge); err != io.EOF {
		t.Fatalf("empty stream: %v", err)
	}
}

// TestWriteRefusesWhatReadRefuses: the writer holds the same table, so the
// core never sends what the edge must refuse. Revert mutant: AppendFrame
// skipping checkHeader.
func TestWriteRefusesWhatReadRefuses(t *testing.T) {
	cases := []struct {
		s    Stream
		f    Frame
		want error
	}{
		{ToEdge, Frame{KindText, "+1", nil}, ErrDirection},
		{ToEdge, Frame{Kind(9), "x", nil}, ErrKind},
		{ToEdge, Frame{KindFetch, strings.Repeat("a", MaxOrigin+1), nil}, ErrOriginLength},
		{ToEdge, Frame{KindFetch, "", nil}, ErrOriginLength},
		{ToEdge, Frame{KindFetch, "a\tb", nil}, ErrOrigin},
		{ToEdge, Frame{KindFetch, "u", make([]byte, 64<<10+1)}, ErrBodyLength},
		{Hello, Frame{KindHello, "", make([]byte, 63)}, ErrBodyLength},
	}
	for _, c := range cases {
		var buf bytes.Buffer
		if err := WriteFrame(&buf, c.s, c.f); !errors.Is(err, c.want) || buf.Len() != 0 {
			t.Errorf("%v %q: got %v (wrote %d), want %v", c.f.Kind, c.f.Origin, err, buf.Len(), c.want)
		}
	}
}
