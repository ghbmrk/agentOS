package photo

// REQ: CH-23, ARC-5

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"image"
	"image/color"
	"image/jpeg"
	"image/png"
	"testing"

	"github.com/ghbmrk/agentos/broker/photo/decoder"
	"github.com/ghbmrk/agentos/broker/vm/gvisor"
)

// fakeRunner answers RunOnce with res and err, and keeps what it was asked.
type fakeRunner struct {
	res   gvisor.OneShotResult
	err   error
	calls []gvisor.OneShot
}

func (f *fakeRunner) RunOnce(_ context.Context, o gvisor.OneShot) (gvisor.OneShotResult, error) {
	f.calls = append(f.calls, o)
	return f.res, f.err
}

func pic(w, h int) image.Image {
	m := image.NewRGBA(image.Rect(0, 0, w, h))
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			m.Set(x, y, color.RGBA{uint8(x), uint8(y), 99, 255})
		}
	}
	return m
}

func jpegFile(t *testing.T, w, h int) []byte {
	var b bytes.Buffer
	if err := jpeg.Encode(&b, pic(w, h), nil); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

func pngFile(t *testing.T, w, h int) []byte {
	var b bytes.Buffer
	if err := png.Encode(&b, pic(w, h)); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

// frame is the real decoder's frame for raw.
func frame(t *testing.T, raw []byte) []byte {
	t.Helper()
	f, err := decoder.Decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	return f
}

// split is a frame's header and its two parts.
func split(t *testing.T, f []byte) (header, []byte, []byte) {
	t.Helper()
	line, rest, _ := bytes.Cut(f, []byte("\n"))
	var h header
	if err := json.Unmarshal(line, &h); err != nil {
		t.Fatal(err)
	}
	return h, rest[:h.Bytes], rest[h.Bytes:]
}

func join(h any, parts ...[]byte) []byte {
	b, _ := json.Marshal(h)
	return bytes.Join(append([][]byte{b}, bytes.Join(parts, nil)), []byte("\n"))
}

func decode(t *testing.T, raw []byte, f *fakeRunner) (Photo, error) {
	t.Helper()
	d := &Decoder{Runner: f, Root: "/img/photo", Cgroup: "/cg/broker"}
	return d.Decode(context.Background(), raw)
}

// TestDecodeAcceptsRealFrame: the real decoder's frames, JPEG and PNG,
// come back whole, and the run is the confined one (ARC-5).
func TestDecodeAcceptsRealFrame(t *testing.T) {
	for _, raw := range [][]byte{jpegFile(t, 600, 400), pngFile(t, 30, 20)} {
		f := &fakeRunner{res: gvisor.OneShotResult{Stdout: frame(t, raw)}}
		p, err := decode(t, raw, f)
		if err != nil {
			t.Fatal(err)
		}
		h, img, thumb := split(t, f.res.Stdout)
		if p.Format != h.Format || p.Width != h.Width || p.Height != h.Height || !bytes.Equal(p.Image, img) || !bytes.Equal(p.Thumb, thumb) ||
			p.ThumbWidth != h.ThumbWidth || p.ThumbHeight != h.ThumbHeight {
			t.Errorf("Decode = %s %dx%d, header %+v", p.Format, p.Width, p.Height, h)
		}
		o := f.calls[0]
		if o.Root != "/img/photo" || len(o.Argv) != 1 || o.Argv[0] != "/agentos-photo" || !bytes.Equal(o.Stdin, raw) ||
			o.MemBytes != MemBytes || o.Timeout != Timeout || o.MaxOutput != MaxOutput || o.Cgroup != "/cg/broker" {
			t.Errorf("run %+v", o)
		}
	}
}

// TestDecodeRejectsLyingHeader: a frame whose header disagrees with its
// bytes, or with the limits, is refused, whatever the sandbox says.
func TestDecodeRejectsLyingHeader(t *testing.T) {
	raw := jpegFile(t, 600, 400)
	h, img, thumb := split(t, frame(t, raw))
	pf := frame(t, pngFile(t, 30, 20))
	ph, pimg, pthumb := split(t, pf)
	lie := func(f func(*header)) []byte {
		c := h
		f(&c)
		return join(c, img, thumb)
	}
	// big is a PNG whose IHDR says 5000x10, with a header that agrees.
	big := append([]byte(nil), pimg...)
	binary.BigEndian.PutUint32(big[16:], 5000)
	bh := ph
	bh.Width, bh.Height, bh.Bytes = 5000, 20, len(big)
	cases := map[string][]byte{
		"width":       lie(func(c *header) { c.Width++ }),
		"height":      lie(func(c *header) { c.Height-- }),
		"thumb width": lie(func(c *header) { c.ThumbWidth = 100 }),
		"format":      lie(func(c *header) { c.Format = "png" }),
		"no format":   lie(func(c *header) { c.Format = "gif" }),
		"bytes short": lie(func(c *header) { c.Bytes--; c.ThumbBytes++ }),
		"bytes total": lie(func(c *header) { c.ThumbBytes-- }),
		"thumb over":  lie(func(c *header) { c.ThumbWidth, c.ThumbHeight = 400, 300 }),
		"zero":        lie(func(c *header) { c.ThumbBytes += c.Bytes; c.Bytes = 0 }),
		"over side":   join(bh, big, pthumb),
		"extra field": append([]byte(`{"x":1,`), join(h, img, thumb)[1:]...),
		"two values":  append(append(bytes.Clone(join(h)), ' '), join(h, img, thumb)...),
		"trailing":    append(join(h, img, thumb), 0),
		"no line":     img,
		"empty":       nil,
		"no EOI":      join(func() header { c := h; c.Bytes--; return c }(), img[:len(img)-1], thumb),
		"swapped":     join(func() header { c := h; c.Bytes, c.ThumbBytes = len(thumb), len(img); return c }(), thumb, img),
		"png as jpeg": join(func() header { c := ph; c.Format = "jpeg"; return c }(), pimg, pthumb),
	}
	for name, out := range cases {
		f := &fakeRunner{res: gvisor.OneShotResult{Stdout: out}}
		if _, err := decode(t, raw, f); err != RefuseDecode {
			t.Errorf("%s: Decode = %v, want %v", name, err, RefuseDecode)
		}
	}
	f := &fakeRunner{res: gvisor.OneShotResult{Stdout: join(h, img, thumb), Truncated: true}}
	if _, err := decode(t, raw, f); err != RefuseDecode {
		t.Errorf("truncated: Decode = %v", err)
	}
}

// TestDecodeRefusals: the size and magic checks run before the sandbox;
// the program's exit codes and the run's deadline map to refusals; a
// failure to run is no refusal.
func TestDecodeRefusals(t *testing.T) {
	f := &fakeRunner{}
	if _, err := decode(t, make([]byte, MaxInput+1), f); err != RefuseSize {
		t.Errorf("over MaxInput: %v", err)
	}
	if _, err := decode(t, []byte("GIF89a"), f); err != RefuseType {
		t.Errorf("gif: %v", err)
	}
	if len(f.calls) != 0 {
		t.Errorf("sandbox ran %d times for files refused before it", len(f.calls))
	}
	// A HEIC, or any ISOBMFF file, goes to the sandbox, which says which
	// brands it takes.
	for _, in := range []string{"\x00\x00\x00\x18ftypheic\x00\x00\x00\x00mif1heic", "\x00\x00\x00\x1cftypavif\x00\x00\x00\x00avifmif1miaf"} {
		f := &fakeRunner{res: gvisor.OneShotResult{ExitCode: 10}}
		if _, err := decode(t, []byte(in), f); err != RefuseType || len(f.calls) != 1 {
			t.Errorf("%q: %v after %d runs; want the sandbox's type", in[4:12], err, len(f.calls))
		}
	}
	raw := pngFile(t, 4, 4)
	for code, want := range map[int]Refusal{10: RefuseType, 11: RefuseSize, 12: RefusePixels, 13: RefuseDecode, 2: RefuseDecode, 137: RefuseDecode} {
		if _, err := decode(t, raw, &fakeRunner{res: gvisor.OneShotResult{ExitCode: code}}); err != want {
			t.Errorf("exit %d: %v, want %v", code, err, want)
		}
	}
	if _, err := decode(t, raw, &fakeRunner{err: context.DeadlineExceeded}); err != RefuseDecode {
		t.Errorf("deadline: %v", err)
	}
	if _, err := decode(t, raw, &fakeRunner{err: gvisor.ErrOneShotMemory}); err != RefuseDecode {
		t.Errorf("memory cap: %v", err)
	}
	if _, err := decode(t, raw, &fakeRunner{err: gvisor.ErrOneShotFailed}); !errors.Is(err, gvisor.ErrOneShotFailed) {
		t.Errorf("runsc failure: %v", err)
	}
	var r Refusal
	if _, err := decode(t, raw, &fakeRunner{err: gvisor.ErrOneShotFailed}); errors.As(err, &r) {
		t.Errorf("runsc failure answered refusal %q", r)
	}
}

// TestDecodeNeedsCgroup: with no cgroup to hold it to MemBytes, the
// sandbox does not run (ARC-5).
func TestDecodeNeedsCgroup(t *testing.T) {
	f := &fakeRunner{}
	d := &Decoder{Runner: f, Root: "/img/photo"}
	if _, err := d.Decode(context.Background(), pngFile(t, 4, 4)); err == nil || len(f.calls) != 0 {
		t.Errorf("Decode without a cgroup: %v, %d runs", err, len(f.calls))
	}
}

// TestLimitsMatchDecoder: this package's copies of the decoder's limits
// and refusal words are the decoder's.
func TestLimitsMatchDecoder(t *testing.T) {
	if MaxInput != decoder.MaxInput || MaxSide != decoder.MaxSide || ThumbSide != decoder.ThumbSide {
		t.Errorf("limits %d %d %d, decoder's %d %d %d", MaxInput, MaxSide, ThumbSide, decoder.MaxInput, decoder.MaxSide, decoder.ThumbSide)
	}
	for _, r := range []decoder.Refusal{decoder.RefuseType, decoder.RefuseSize, decoder.RefusePixels, decoder.RefuseDecode} {
		if got := exitRefusal[r.ExitCode()]; string(got) != string(r) {
			t.Errorf("exit %d maps to %q, decoder's %q", r.ExitCode(), got, r)
		}
	}
	for _, in := range []string{"\x00\x00\x00\x18ftypheic\x00\x00\x00\x00mif1heic", "\x00\x00\x00\x14ftypmif1\x00\x00\x00\x00hevc"} {
		if decoder.IsHEIC([]byte(in)) && !isoBMFF([]byte(in)) {
			t.Errorf("%q: the decoder takes it but the broker refuses it first", in)
		}
	}
	var h header
	var dh decoder.Header
	a, _ := json.Marshal(h)
	b, _ := json.Marshal(dh)
	if !bytes.Equal(a, b) {
		t.Errorf("header fields %s, decoder's %s", a, b)
	}
}
