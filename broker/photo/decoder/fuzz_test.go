package decoder

// REQ: CH-23

import (
	"bytes"
	"encoding/json"
	"errors"
	"image"
	"image/jpeg"
	"image/png"
	"testing"

	"github.com/gen2brain/h265/heic"
)

// fuzzPixels bounds what one fuzz input may make the decoder allocate:
// a few bytes can claim 50 MP, and the loop's leaf has a small memory cap.
const fuzzPixels = 1 << 20

// FuzzDecode feeds the decoder's input path arbitrary files, JPEG, PNG
// and HEIC seeded. It must not
// panic, must refuse with one of its four words, and every frame it
// writes must be a new image whose header matches its bytes and limits.
func FuzzDecode(f *testing.F) {
	var j, p bytes.Buffer
	img := image.NewRGBA(image.Rect(0, 0, 9, 5))
	_ = jpeg.Encode(&j, img, nil)
	_ = png.Encode(&p, img)
	f.Add(j.Bytes())
	f.Add(p.Bytes())
	f.Add(append([]byte{0xFF, 0xD8, 0xFF, 0xE1, 0, 16}, "Exif\x00\x00MM\x00\x2a\x00\x00\x00\x08"...))
	// HEIC seeds the vendored encoder writes: a still, a grid, a 10-bit
	// and a 4:4:4.
	n := image.NewNRGBA(image.Rect(0, 0, 48, 32))
	for i := range n.Pix {
		n.Pix[i] = uint8(i * 7)
	}
	for _, o := range []heic.EncodeOptions{{}, {Tile: 16}, {BitDepth: 10}, {Chroma: heic.Chroma444}} {
		var b bytes.Buffer
		if err := heic.Encode(&b, n, o); err != nil {
			f.Fatal(err)
		}
		f.Add(b.Bytes())
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		for _, c := range []func([]byte) (image.Config, error){jpegConfig, pngConfig, heicConfig} {
			if cfg, err := c(raw); err == nil && int64(cfg.Width)*int64(cfg.Height) > fuzzPixels {
				return
			}
		}
		Orientation(raw)
		// The property the 24 MP limit rests on: any file h265 decodes
		// above 8 bits, heifDeep sees as deep.
		if meta, ok := stillMeta(raw); IsHEIC(raw) && ok {
			if img, err := heic.Decode(bytes.NewReader(raw), heic.Options{AutoRotate: true}); err == nil {
				if _, wide := img.(*image.NRGBA64); wide && !heifDeep(meta) {
					t.Fatal("h265 decoded more than 8 bits; heifDeep said 8")
				}
			}
		}
		frame, err := Decode(raw)
		if err != nil {
			var r Refusal
			if !errors.As(err, &r) {
				t.Fatalf("not a refusal: %v", err)
			}
			return
		}
		checkFrame(t, frame)
	})
}

// checkFrame fails t unless frame is a new image whose header matches
// its bytes and limits.
func checkFrame(t *testing.T, frame []byte) {
	t.Helper()
	i := bytes.IndexByte(frame, '\n')
	var h Header
	if i < 0 || json.Unmarshal(frame[:i], &h) != nil {
		t.Fatal("frame has no header line")
	}
	body := frame[i+1:]
	if len(body) != h.Bytes+h.ThumbBytes {
		t.Fatalf("body %d bytes; header says %d+%d", len(body), h.Bytes, h.ThumbBytes)
	}
	for _, part := range []struct {
		b       []byte
		w, h, m int
	}{{body[:h.Bytes], h.Width, h.Height, MaxSide}, {body[h.Bytes:], h.ThumbWidth, h.ThumbHeight, ThumbSide}} {
		got, format, err := image.Decode(bytes.NewReader(part.b))
		if err != nil || format != h.Format {
			t.Fatalf("output is not a %s: %v", h.Format, err)
		}
		b := got.Bounds()
		if b.Dx() != part.w || b.Dy() != part.h || part.w > part.m || part.h > part.m || part.w < 1 || part.h < 1 {
			t.Fatalf("output %v; header %dx%d, limit %d", b, part.w, part.h, part.m)
		}
	}
}

func jpegConfig(b []byte) (image.Config, error) { return jpeg.DecodeConfig(bytes.NewReader(b)) }
func pngConfig(b []byte) (image.Config, error)  { return png.DecodeConfig(bytes.NewReader(b)) }
func heicConfig(b []byte) (image.Config, error) { return heic.DecodeConfig(bytes.NewReader(b)) }
