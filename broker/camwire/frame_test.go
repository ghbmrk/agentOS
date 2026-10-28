package camwire

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"testing"
)

// REQ: NET-2, DEV-7

var lepton = Shape{Width: 160, Height: 120}

// header is a frame header declaring type t and length n.
func header(t Type, n uint32) []byte {
	return binary.BigEndian.AppendUint32([]byte{byte(t)}, n)
}

// countingReader counts what the codec reads.
type countingReader struct {
	r io.Reader
	n int
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += n
	return n, err
}

func au(n int) []byte {
	p := make([]byte, n)
	p[2], p[3] = 0, 1
	return p
}

// TestFrameCaps: each type over its cap, an unknown type, a truncated
// header and a zero-length access unit end the read; an over-cap header is
// refused with nothing past it read. Revert mutant: checkHeader skipping
// the cap reads the body.
func TestFrameCaps(t *testing.T) {
	over := map[Type]struct {
		d Direction
		n uint32
	}{
		TypeVideo:    {ToCore, MaxVideo + 1},
		TypeThermal:  {ToCore, lepton.payload() + 1},
		TypeStatus:   {ToCore, StatusLen + 1},
		TypeBundle:   {FromEnforcer, MaxSigned + 1},
		TypeManifest: {FromEnforcer, MaxSigned + 1},
		TypeImage:    {FromEnforcer, MaxImage + 1},
	}
	for typ, c := range over {
		// The stream behind the header holds the whole declared length,
		// so only the cap stops the read.
		r := &countingReader{r: io.MultiReader(bytes.NewReader(header(typ, c.n)), bytes.NewReader(make([]byte, c.n)))}
		if _, err := ReadFrame(r, c.d, lepton); !errors.Is(err, ErrLength) {
			t.Errorf("type %d over its cap: %v", typ, err)
		}
		if r.n != HeaderLen {
			t.Errorf("type %d over its cap: read %d bytes, want the header only", typ, r.n)
		}
	}
	for name, c := range map[string]struct {
		in   []byte
		d    Direction
		want error
	}{
		"unknown type":            {append(header(9, 1), 0), ToCore, ErrType},
		"type 0":                  {append(header(0, 1), 0), ToCore, ErrType},
		"bundle on the stream":    {append(header(TypeBundle, 1), 0), ToCore, ErrType},
		"video to the node":       {append(header(TypeVideo, 5), au(5)...), FromEnforcer, ErrType},
		"thermal to the enforcer": {header(TypeThermal, lepton.payload()), ToEnforcer, ErrType},
		"truncated header":        {header(TypeVideo, 5)[:3], ToCore, ErrShort},
		"truncated body":          {append(header(TypeVideo, 9), au(5)...), ToCore, ErrShort},
		"zero-length access unit": {header(TypeVideo, 0), ToCore, ErrLength},
		"zero-length image chunk": {header(TypeImage, 0), FromEnforcer, ErrLength},
		"short status":            {append(header(TypeStatus, StatusLen-1), make([]byte, StatusLen-1)...), ToCore, ErrLength},
		"no start code":           {append(header(TypeVideo, 5), 1, 2, 3, 4, 5), ToCore, ErrPayload},
		"unknown direction":       {append(header(TypeVideo, 5), au(5)...), 0, ErrDirection},
	} {
		if _, err := ReadFrame(bytes.NewReader(c.in), c.d, lepton); !errors.Is(err, c.want) {
			t.Errorf("%s: got %v, want %v", name, err, c.want)
		}
	}
	if _, err := ReadFrame(bytes.NewReader(nil), ToCore, lepton); err != io.EOF {
		t.Errorf("clean end: %v", err)
	}
}

// TestThermalShape: a thermal frame is taken only at the declared shape,
// and never when no thermal core is declared.
func TestThermalShape(t *testing.T) {
	th := Thermal{Width: 160, Height: 120, Counter: 3, Samples: make([]byte, 160*120*2)}
	p := AppendThermal(nil, th)
	in := append(header(TypeThermal, uint32(len(p))), p...)
	f, err := ReadFrame(bytes.NewReader(in), ToCore, lepton)
	if err != nil {
		t.Fatalf("declared shape: %v", err)
	}
	if got, _ := ParseThermal(f.Payload, lepton); got.Counter != 3 {
		t.Fatalf("counter %d", got.Counter)
	}
	if _, err := ReadFrame(bytes.NewReader(in), ToCore, Shape{}); !errors.Is(err, ErrShape) {
		t.Errorf("no thermal core declared: %v", err)
	}
	if _, err := ReadFrame(bytes.NewReader(in), ToCore, Shape{Width: 120, Height: 160}); !errors.Is(err, ErrPayload) {
		t.Errorf("same size, other shape: %v", err)
	}
	if (Shape{Width: 1024, Height: 1024}).valid() {
		t.Error("a shape over MaxThermal is valid")
	}
	// 8 + 2×65535×32769 wraps to 65542 in 32 bits.
	wrap := Shape{Width: 65535, Height: 32769}
	if wrap.valid() {
		t.Error("a shape whose size wraps 32 bits is valid")
	}
	win := append(header(TypeThermal, 65542), AppendThermal(nil, Thermal{Width: 65535, Height: 32769, Samples: make([]byte, 65534)})...)
	if _, err := ReadFrame(bytes.NewReader(win), ToCore, wrap); !errors.Is(err, ErrShape) {
		t.Errorf("wrapping shape: %v", err)
	}
	if !(Shape{Width: 640, Height: 512}).valid() {
		t.Error("a Boson-class shape is not valid")
	}
}

// TestFrameRoundTrip: what AppendFrame writes ReadFrame reads, for every
// type in its direction.
func TestFrameRoundTrip(t *testing.T) {
	st := AppendStatus(nil, Status{Uptime: 9, Settings: 4, Temperature: -1250})
	th := AppendThermal(nil, Thermal{Width: 160, Height: 120, Samples: make([]byte, 160*120*2)})
	for _, c := range []struct {
		d Direction
		f Frame
	}{
		{ToCore, Frame{TypeVideo, au(64)}},
		{ToCore, Frame{TypeThermal, th}},
		{ToCore, Frame{TypeStatus, st}},
		{ToEnforcer, Frame{TypeStatus, st}},
		{FromEnforcer, Frame{TypeBundle, []byte{1}}},
		{FromEnforcer, Frame{TypeManifest, []byte{1}}},
		{FromEnforcer, Frame{TypeImage, make([]byte, MaxImage)}},
	} {
		var buf bytes.Buffer
		if err := WriteFrame(&buf, c.d, lepton, c.f); err != nil {
			t.Fatalf("type %d: write: %v", c.f.Type, err)
		}
		got, err := ReadFrame(&buf, c.d, lepton)
		if err != nil || got.Type != c.f.Type || !bytes.Equal(got.Payload, c.f.Payload) {
			t.Fatalf("type %d: read back: %v", c.f.Type, err)
		}
	}
	s, _ := ParseStatus(st)
	if s.Temperature != -1250 || s.Uptime != 9 || s.Settings != 4 {
		t.Fatalf("status round trip: %+v", s)
	}
	if _, err := AppendFrame(nil, ToCore, lepton, Frame{TypeBundle, []byte{1}}); !errors.Is(err, ErrType) {
		t.Errorf("writer sends a bundle on the stream: %v", err)
	}
}
