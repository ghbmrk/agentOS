package main

// REQ: CH-23

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"hash/crc32"
	"image"
	"image/color"
	"image/jpeg"
	"image/png"
	"strings"
	"testing"

	"github.com/ghbmrk/agentos/broker/photo/decoder"
)

// Synthetic canaries: none is real metadata.
const (
	canaryGPS   = "AGENTOS-CANARY-GPS-00.0000N"
	canaryCom   = "AGENTOS-CANARY-COMMENT"
	canaryThumb = "AGENTOS-CANARY-THUMB"
	canaryXMP   = "AGENTOS-CANARY-XMP"
	canaryICC   = "AGENTOS-CANARY-ICC"
)

func refusal(t *testing.T, in []byte) (string, int, []byte) {
	t.Helper()
	var out, errOut bytes.Buffer
	code := run(bytes.NewReader(in), &out, &errOut)
	return strings.TrimSpace(errOut.String()), code, out.Bytes()
}

func TestDecodeRefusesTypes(t *testing.T) {
	for name, in := range map[string]string{
		"gif":   "GIF89a\x01\x00\x01\x00\x00\x00\x00;",
		"webp":  "RIFF\x24\x00\x00\x00WEBPVP8 \x18\x00\x00\x00",
		"mp4":   "\x00\x00\x00\x18ftypmp42\x00\x00\x00\x00mp42isom",
		"vcard": "BEGIN:VCARD\r\nVERSION:3.0\r\nFN:Synthetic\r\nEND:VCARD\r\n",
		"pdf":   "%PDF-1.7\n%\xe2\xe3\xcf\xd3\n",
		"heic":  "\x00\x00\x00\x18ftypheic\x00\x00\x00\x00mif1heic",
		"empty": "",
	} {
		word, code, out := refusal(t, []byte(in))
		if word != "type" || code != 10 || len(out) != 0 {
			t.Errorf("%s: got %q exit %d with %d bytes out; want type, 10, none", name, word, code, len(out))
		}
	}
}

// pngHeader is a PNG signature and IHDR claiming w x h, and nothing else.
func pngHeader(w, h uint32) []byte {
	ihdr := make([]byte, 13)
	binary.BigEndian.PutUint32(ihdr, w)
	binary.BigEndian.PutUint32(ihdr[4:], h)
	ihdr[8], ihdr[9] = 8, 6 // 8-bit RGBA
	chunk := append([]byte("IHDR"), ihdr...)
	b := append([]byte("\x89PNG\r\n\x1a\n"), 0, 0, 0, 13)
	b = append(b, chunk...)
	return binary.BigEndian.AppendUint32(b, crc32.ChecksumIEEE(chunk))
}

func TestDecodeRefusesOver50MP(t *testing.T) {
	word, code, out := refusal(t, pngHeader(8000, 7000))
	if word != "pixels" || code != 12 || len(out) != 0 {
		t.Fatalf("got %q exit %d with %d bytes out; want pixels, 12, none", word, code, len(out))
	}
	// One past the limit in a JPEG frame header too.
	if _, err := decoder.Decode(jpegSOF(10001, 5000)); err != decoder.RefusePixels {
		t.Fatalf("10001x5000 JPEG: got %v, want pixels", err)
	}
}

// jpegSOF is a JPEG with only a JFIF marker and a baseline frame header
// claiming w x h.
func jpegSOF(w, h uint16) []byte {
	b := append([]byte{0xFF, 0xD8}, segment(0xE0, []byte("JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00"))...)
	b = append(b, 0xFF, 0xC0, 0, 11, 8)
	b = binary.BigEndian.AppendUint16(b, h)
	b = binary.BigEndian.AppendUint16(b, w)
	return append(b, 1, 1, 0x11, 0)
}

func TestDecodeRefusesOver20MB(t *testing.T) {
	in := make([]byte, decoder.MaxInput+1)
	copy(in, []byte{0xFF, 0xD8, 0xFF})
	word, code, out := refusal(t, in)
	if word != "size" || code != 11 || len(out) != 0 {
		t.Fatalf("got %q exit %d with %d bytes out; want size, 11, none", word, code, len(out))
	}
}

// photo is a w x h JPEG whose top-left quarter is red and the rest blue.
func photo(t *testing.T, w, h int) []byte {
	t.Helper()
	img := image.NewRGBA(image.Rect(0, 0, w, h))
	for y := range h {
		for x := range w {
			c := color.RGBA{0, 0, 255, 255}
			if x < w/2 && y < h/2 {
				c = color.RGBA{255, 0, 0, 255}
			}
			img.SetRGBA(x, y, c)
		}
	}
	var b bytes.Buffer
	if err := jpeg.Encode(&b, img, &jpeg.Options{Quality: 95}); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

func segment(marker byte, data []byte) []byte {
	s := []byte{0xFF, marker}
	s = binary.BigEndian.AppendUint16(s, uint16(len(data)+2))
	return append(s, data...)
}

// withSegments puts segs right after j's SOI.
func withSegments(j []byte, segs ...[]byte) []byte {
	out := append([]byte{}, j[:2]...)
	for _, s := range segs {
		out = append(out, s...)
	}
	return append(out, j[2:]...)
}

// exif is an APP1 Exif payload: IFD0 with the orientation, a description
// holding the GPS canary, a GPS IFD pointer, then an embedded thumbnail.
func exif(orientation uint16) []byte {
	le := binary.LittleEndian
	t := []byte("II*\x00")
	t = le.AppendUint32(t, 8)
	t = le.AppendUint16(t, 3)
	desc := uint32(8 + 2 + 3*12 + 4)
	entry := func(tag, typ uint16, count, val uint32) {
		t = le.AppendUint16(t, tag)
		t = le.AppendUint16(t, typ)
		t = le.AppendUint32(t, count)
		t = le.AppendUint32(t, val)
	}
	entry(0x010E, 2, uint32(len(canaryGPS)+1), desc)
	entry(0x0112, 3, 1, uint32(orientation))
	entry(0x8825, 4, 1, desc)
	t = le.AppendUint32(t, 0)
	t = append(append(t, canaryGPS...), 0)
	thumb := append([]byte{0xFF, 0xD8}, segment(0xFE, []byte(canaryThumb))...)
	t = append(t, append(thumb, 0xFF, 0xD9)...)
	return append([]byte("Exif\x00\x00"), t...)
}

func decodeFrame(t *testing.T, frame []byte) (decoder.Header, image.Image, []byte) {
	t.Helper()
	i := bytes.IndexByte(frame, '\n')
	if i < 0 {
		t.Fatal("no header line")
	}
	var h decoder.Header
	if err := json.Unmarshal(frame[:i], &h); err != nil {
		t.Fatal(err)
	}
	body := frame[i+1:]
	if len(body) != h.Bytes+h.ThumbBytes {
		t.Fatalf("frame body %d bytes; header says %d+%d", len(body), h.Bytes, h.ThumbBytes)
	}
	img, _, err := image.Decode(bytes.NewReader(body[:h.Bytes]))
	if err != nil {
		t.Fatal(err)
	}
	if b := img.Bounds(); b.Dx() != h.Width || b.Dy() != h.Height {
		t.Fatalf("image is %v; header says %dx%d", b, h.Width, h.Height)
	}
	return h, img, body
}

// markers lists a JPEG's segment markers up to its first scan.
func markers(t *testing.T, j []byte) []byte {
	t.Helper()
	var ms []byte
	for i := 2; i+4 <= len(j); {
		if j[i] != 0xFF {
			t.Fatalf("no marker at %d", i)
		}
		ms = append(ms, j[i+1])
		if j[i+1] == 0xDA {
			return ms
		}
		i += 2 + int(binary.BigEndian.Uint16(j[i+2:]))
	}
	t.Fatal("no scan")
	return nil
}

func TestDecodeStripsMetadata(t *testing.T) {
	in := withSegments(photo(t, 64, 48),
		segment(0xE1, exif(1)),
		segment(0xE1, []byte("http://ns.adobe.com/xap/1.0/\x00<x:xmpmeta>"+canaryXMP+"</x:xmpmeta>")),
		segment(0xE2, []byte("ICC_PROFILE\x00\x01\x01"+canaryICC)),
		segment(0xFE, []byte(canaryCom)))
	for _, c := range []string{canaryGPS, canaryThumb, canaryXMP, canaryICC, canaryCom} {
		if !bytes.Contains(in, []byte(c)) {
			t.Fatalf("test input lacks %s", c)
		}
	}
	frame, err := decoder.Decode(in)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []string{canaryGPS, canaryThumb, canaryXMP, canaryICC, canaryCom, "Exif", "xmpmeta", "ICC_PROFILE"} {
		if bytes.Contains(frame, []byte(c)) {
			t.Errorf("output still holds %q", c)
		}
	}
	h, _, body := decodeFrame(t, frame)
	for _, j := range [][]byte{body[:h.Bytes], body[h.Bytes:]} {
		for _, m := range markers(t, j) {
			if m != 0xDB && m != 0xC0 && m != 0xC4 && m != 0xDA {
				t.Errorf("output has segment 0xFF%02X; want only tables, frame and scan", m)
			}
		}
	}
}

func isRed(c color.Color) bool {
	r, g, b, _ := c.RGBA()
	return r > 0xC000 && g < 0x4000 && b < 0x4000
}

func TestDecodeAppliesOrientation(t *testing.T) {
	frame, err := decoder.Decode(withSegments(photo(t, 200, 100), segment(0xE1, exif(6))))
	if err != nil {
		t.Fatal(err)
	}
	h, img, _ := decodeFrame(t, frame)
	if h.Width != 100 || h.Height != 200 {
		t.Fatalf("got %dx%d; orientation 6 should give 100x200", h.Width, h.Height)
	}
	// Turned a quarter clockwise, the red top-left quarter is top-right.
	if !isRed(img.At(75, 50)) || isRed(img.At(25, 50)) || isRed(img.At(75, 150)) {
		t.Fatal("red quarter is not top-right after a clockwise quarter turn")
	}
}

func TestDecodeBoundsLongSide(t *testing.T) {
	frame, err := decoder.Decode(photo(t, 6000, 3000))
	if err != nil {
		t.Fatal(err)
	}
	h, img, _ := decodeFrame(t, frame)
	if h.Width != 4096 || h.Height != 2048 {
		t.Fatalf("got %dx%d; want 4096x2048", h.Width, h.Height)
	}
	if h.ThumbWidth != 320 || h.ThumbHeight != 160 {
		t.Fatalf("thumbnail %dx%d; want 320x160", h.ThumbWidth, h.ThumbHeight)
	}
	if !isRed(img.At(1000, 500)) || isRed(img.At(3000, 1500)) {
		t.Fatal("shrunk image lost its red quarter")
	}
	// A PNG keeps its format; a small one keeps its size.
	var b bytes.Buffer
	if err := png.Encode(&b, image.NewNRGBA(image.Rect(0, 0, 30, 20))); err != nil {
		t.Fatal(err)
	}
	frame, err = decoder.Decode(b.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if h, _, _ := decodeFrame(t, frame); h.Format != "png" || h.Width != 30 || h.Height != 20 {
		t.Fatalf("PNG: got %+v", h)
	}
}

func TestDecodeRefusesCorrupt(t *testing.T) {
	good := withSegments(photo(t, 64, 64), segment(0xFE, []byte(canaryCom)))
	var p bytes.Buffer
	if err := png.Encode(&p, image.NewRGBA(image.Rect(0, 0, 64, 64))); err != nil {
		t.Fatal(err)
	}
	for name, in := range map[string][]byte{
		"truncated jpeg":  good[:len(good)/2],
		"truncated png":   p.Bytes()[:p.Len()/2],
		"jpeg magic only": {0xFF, 0xD8, 0xFF},
		"zero size":       jpegSOF(0, 10),
	} {
		word, code, out := refusal(t, in)
		if code == 0 || len(out) != 0 || (word != "decode" && word != "pixels") {
			t.Errorf("%s: got %q exit %d with %d bytes out; want refused", name, word, code, len(out))
		}
	}
	// Flipped bytes: refused or re-encoded, never echoed.
	for i := 0; i < len(good); i += 7 {
		in := append([]byte{}, good...)
		in[i] ^= 0x5A
		frame, err := decoder.Decode(in)
		if err == nil && bytes.Contains(frame, []byte(canaryCom)) {
			t.Fatalf("flip at %d: output echoes input bytes", i)
		}
	}
}
