package main

// REQ: CH-23

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"fmt"
	"image"
	"image/color"
	"io"
	"os"
	"testing"

	"github.com/gen2brain/h265/heic"

	"github.com/ghbmrk/agentos/broker/photo/decoder"
)

// heicPhoto is a w x h HEIC whose top-left quarter is red and the rest
// blue, coded with opts.
func heicPhoto(t *testing.T, w, h int, opts heic.EncodeOptions) []byte {
	t.Helper()
	img := image.NewNRGBA(image.Rect(0, 0, w, h))
	for y := range h {
		for x := range w {
			c := color.NRGBA{0, 0, 255, 255}
			if x < w/2 && y < h/2 {
				c = color.NRGBA{255, 0, 0, 255}
			}
			img.SetNRGBA(x, y, c)
		}
	}
	if opts.Quality == 0 {
		opts.Quality = 90
	}
	var b bytes.Buffer
	if err := heic.Encode(&b, img, opts); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

// box is one ISOBMFF box: its type, and where its body starts and ends.
type box struct {
	typ        string
	start, end int
}

// children lists the boxes in b[from:to].
func children(t *testing.T, b []byte, from, to int) []box {
	t.Helper()
	var out []box
	for i := from; i+8 <= to; {
		n := int(binary.BigEndian.Uint32(b[i:]))
		if n < 8 || i+n > to {
			t.Fatalf("box at %d: size %d", i, n)
		}
		out = append(out, box{string(b[i+4 : i+8]), i + 8, i + n})
		i += n
	}
	return out
}

func find(t *testing.T, bs []box, typ string) box {
	t.Helper()
	for _, x := range bs {
		if x.typ == typ {
			return x
		}
	}
	t.Fatalf("no %s box", typ)
	return box{}
}

// metaBoxes returns the file's meta box and its children (meta is a full
// box: four bytes of version and flags come before them).
func metaBoxes(t *testing.T, b []byte) (box, []box) {
	t.Helper()
	meta := find(t, children(t, b, 0, len(b)), "meta")
	return meta, children(t, b, meta.start+4, meta.end)
}

// withISPE returns raw with every ispe property declaring w x h, though
// the coded picture is unchanged.
func withISPE(t *testing.T, raw []byte, w, h uint32) []byte {
	t.Helper()
	out := append([]byte{}, raw...)
	_, mb := metaBoxes(t, out)
	ipco := find(t, children(t, out, find(t, mb, "iprp").start, find(t, mb, "iprp").end), "ipco")
	n := 0
	for _, p := range children(t, out, ipco.start, ipco.end) {
		if p.typ == "ispe" {
			binary.BigEndian.PutUint32(out[p.start+4:], w)
			binary.BigEndian.PutUint32(out[p.start+8:], h)
			n++
		}
	}
	if n == 0 {
		t.Fatal("no ispe")
	}
	return out
}

// withIrot returns raw with an irot property turning the primary item by
// angle quarter turns anticlockwise. The property is appended to ipco and
// associated in ipma, the boxes holding them grow, and every iloc offset
// past the meta box (the mdat) moves by the bytes added.
func withIrot(t *testing.T, raw []byte, angle byte) []byte {
	t.Helper()
	meta, mb := metaBoxes(t, raw)
	primary := int(binary.BigEndian.Uint16(raw[find(t, mb, "pitm").start+4:]))
	iprp := find(t, mb, "iprp")
	pb := children(t, raw, iprp.start, iprp.end)
	ipco, ipma := find(t, pb, "ipco"), find(t, pb, "ipma")
	if raw[ipma.start] != 0 || raw[ipma.start+3]&1 != 0 {
		t.Fatal("helper reads only ipma version 0 with one-byte associations")
	}
	index := len(children(t, raw, ipco.start, ipco.end)) + 1
	irot := []byte{0, 0, 0, 9, 'i', 'r', 'o', 't', angle}

	// The new ipma body: the primary item's entry gains the association.
	body := append([]byte{}, raw[ipma.start:ipma.start+8]...)
	count := int(binary.BigEndian.Uint32(raw[ipma.start+4:]))
	found := false
	for i, e := 0, ipma.start+8; i < count; i++ {
		id, k := int(binary.BigEndian.Uint16(raw[e:])), int(raw[e+2])
		assoc := raw[e+3 : e+3+k]
		if id == primary {
			found = true
			body = append(body, raw[e], raw[e+1], byte(k+1))
			body = append(append(body, assoc...), 0x80|byte(index))
		} else {
			body = append(body, raw[e:e+3+k]...)
		}
		e += 3 + k
	}
	if !found {
		t.Fatal("primary item has no ipma entry")
	}
	grow := len(irot) + 1
	sized := func(typ string, b []byte) []byte {
		return append(binary.BigEndian.AppendUint32(nil, uint32(8+len(b))), append([]byte(typ), b...)...)
	}
	var iprpBody []byte
	for _, p := range pb {
		switch p.typ {
		case "ipco":
			iprpBody = append(iprpBody, sized("ipco", append(append([]byte{}, raw[p.start:p.end]...), irot...))...)
		case "ipma":
			iprpBody = append(iprpBody, sized("ipma", body)...)
		default:
			iprpBody = append(iprpBody, raw[p.start-8:p.end]...)
		}
	}
	metaBody := append([]byte{}, raw[meta.start:meta.start+4]...)
	for _, m := range mb {
		if m.typ == "iprp" {
			metaBody = append(metaBody, sized("iprp", iprpBody)...)
		} else {
			metaBody = append(metaBody, raw[m.start-8:m.end]...)
		}
	}
	out := append(append(append([]byte{}, raw[:meta.start-8]...), sized("meta", metaBody)...), raw[meta.end:]...)
	shiftIloc(t, out, meta.end, grow)
	return out
}

// shiftIloc adds by to every iloc extent offset at or past from, in the
// version 0 or 1 iloc the encoder writes (file offsets, no base).
func shiftIloc(t *testing.T, b []byte, from, by int) {
	t.Helper()
	_, mb := metaBoxes(t, b)
	il := find(t, mb, "iloc")
	v := b[il.start]
	off, ln, base := int(b[il.start+4]>>4), int(b[il.start+4]&15), int(b[il.start+5]>>4)
	idx := 0
	if v == 1 {
		idx = int(b[il.start+5] & 15)
	}
	if v > 1 || base != 0 || (off != 4 && off != 8) {
		t.Fatalf("helper does not read iloc v%d offset %d base %d", v, off, base)
	}
	p := il.start + 6
	items := int(binary.BigEndian.Uint16(b[p:]))
	p += 2
	for range items {
		p += 2 // item ID
		if v == 1 {
			if b[p+1]&15 != 0 {
				t.Fatal("helper reads only construction method 0")
			}
			p += 2
		}
		p += 2 // data reference index
		extents := int(binary.BigEndian.Uint16(b[p:]))
		p += 2
		for range extents {
			p += idx
			if off == 4 {
				if o := int(binary.BigEndian.Uint32(b[p:])); o >= from {
					binary.BigEndian.PutUint32(b[p:], uint32(o+by))
				}
			} else if o := int(binary.BigEndian.Uint64(b[p:])); o >= from {
				binary.BigEndian.PutUint64(b[p:], uint64(o+by))
			}
			p += off + ln
		}
	}
}

func TestDecodeHEICToJPEG(t *testing.T) {
	for name, in := range map[string][]byte{
		"8-bit":      heicPhoto(t, 200, 100, heic.EncodeOptions{}),
		"10-bit":     heicPhoto(t, 200, 100, heic.EncodeOptions{BitDepth: 10}),
		"4:4:4":      heicPhoto(t, 200, 100, heic.EncodeOptions{Chroma: heic.Chroma444}),
		"grid":       heicPhoto(t, 200, 100, heic.EncodeOptions{Tile: 64}),
		"lossless":   heicPhoto(t, 200, 100, heic.EncodeOptions{Lossless: true}),
		"big shrunk": heicPhoto(t, 5000, 2500, heic.EncodeOptions{Quality: 50}),
	} {
		word, code, frame := refusal(t, in)
		if code != 0 {
			t.Fatalf("%s: refused %q exit %d", name, word, code)
		}
		h, img, body := decodeFrame(t, frame)
		w, ht := 200, 100
		if name == "big shrunk" {
			w, ht = 4096, 2048
		}
		if h.Format != "jpeg" || h.Width != w || h.Height != ht || !bytes.HasPrefix(body, []byte{0xFF, 0xD8, 0xFF}) {
			t.Fatalf("%s: got %+v; want a %dx%d JPEG", name, h, w, ht)
		}
		if !isRed(img.At(w/4, ht/4)) || isRed(img.At(3*w/4, 3*ht/4)) {
			t.Fatalf("%s: the red quarter is not top-left", name)
		}
		if h.ThumbWidth != 320 && name == "big shrunk" {
			t.Fatalf("%s: thumbnail %dx%d", name, h.ThumbWidth, h.ThumbHeight)
		}
	}
}

func TestDecodeHEICAppliesRotation(t *testing.T) {
	in := heicPhoto(t, 200, 100, heic.EncodeOptions{})
	// irot 3 is three quarter turns anticlockwise: one clockwise, so the
	// red top-left quarter ends top-right, as EXIF orientation 6 does.
	frame, err := decoder.Decode(withIrot(t, in, 3))
	if err != nil {
		t.Fatal(err)
	}
	h, img, _ := decodeFrame(t, frame)
	if h.Width != 100 || h.Height != 200 {
		t.Fatalf("got %dx%d; irot 3 should give 100x200", h.Width, h.Height)
	}
	if !isRed(img.At(75, 50)) || isRed(img.At(25, 50)) || isRed(img.At(75, 150)) {
		t.Fatal("red quarter is not top-right after a clockwise quarter turn")
	}
	// A grid's transform is on the grid item, not its tiles.
	frame, err = decoder.Decode(withIrot(t, heicPhoto(t, 200, 100, heic.EncodeOptions{Tile: 64}), 1))
	if err != nil {
		t.Fatal(err)
	}
	h, img, _ = decodeFrame(t, frame)
	if h.Width != 100 || h.Height != 200 || !isRed(img.At(25, 150)) || isRed(img.At(75, 50)) {
		t.Fatalf("grid, irot 1: got %dx%d; the red quarter should be bottom-left", h.Width, h.Height)
	}
}

func TestDecodeHEICStripsMetadata(t *testing.T) {
	in := heicPhoto(t, 64, 48, heic.EncodeOptions{
		Exif: exif(6)[len("Exif\x00\x00"):],
		XMP:  []byte("<x:xmpmeta>" + canaryXMP + "</x:xmpmeta>"),
		ICC:  []byte("ICC_PROFILE\x00\x01\x01" + canaryICC),
	})
	for _, c := range []string{canaryGPS, canaryXMP, canaryICC} {
		if !bytes.Contains(in, []byte(c)) {
			t.Fatalf("test input lacks %s", c)
		}
	}
	frame, err := decoder.Decode(in)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []string{canaryGPS, canaryThumb, canaryXMP, canaryICC, "Exif", "xmpmeta", "ICC_PROFILE"} {
		if bytes.Contains(frame, []byte(c)) {
			t.Errorf("output still holds %q", c)
		}
	}
	h, _, body := decodeFrame(t, frame)
	// A HEIC's EXIF orientation is not applied: irot is the file's
	// transform (ISO/IEC 23008-12 says readers ignore the EXIF one).
	if h.Width != 64 || h.Height != 48 {
		t.Fatalf("got %dx%d; the EXIF orientation must not turn a HEIC", h.Width, h.Height)
	}
	for _, j := range [][]byte{body[:h.Bytes], body[h.Bytes:]} {
		for _, m := range markers(t, j) {
			if m != 0xDB && m != 0xC0 && m != 0xC4 && m != 0xDA {
				t.Errorf("output has segment 0xFF%02X; want only tables, frame and scan", m)
			}
		}
	}
}

func TestDecodeHEICOver50MPRefused(t *testing.T) {
	small := heicPhoto(t, 64, 64, heic.EncodeOptions{})
	word, code, out := refusal(t, withISPE(t, small, 10001, 5000))
	if word != "pixels" || code != 12 || len(out) != 0 {
		t.Fatalf("10001x5000: got %q exit %d with %d bytes out; want pixels, 12, none", word, code, len(out))
	}
	// Above 8 bits the limit is the same: nothing guesses the depth.
	for name, o := range map[string]heic.EncodeOptions{"10-bit": {BitDepth: 10}, "10-bit grid": {BitDepth: 10, Tile: 32}} {
		if _, err := decoder.Decode(withISPE(t, heicPhoto(t, 64, 64, o), 10001, 5000)); err != decoder.RefusePixels {
			t.Fatalf("%s 10001x5000: got %v, want pixels", name, err)
		}
	}
	// An ispe that lies small cannot let a bigger coded picture through.
	big := heicPhoto(t, 640, 640, heic.EncodeOptions{Quality: 30})
	if _, err := decoder.Decode(withISPE(t, big, 64, 64)); err != decoder.RefuseDecode {
		t.Fatalf("640x640 coded, 64x64 declared: got %v, want decode", err)
	}
}

// withHvcCDepth returns raw with every hvcC declaring bit depth 8+d.
func withHvcCDepth(t *testing.T, raw []byte, d byte) []byte {
	t.Helper()
	out := append([]byte{}, raw...)
	_, mb := metaBoxes(t, out)
	iprp := find(t, mb, "iprp")
	ipco := find(t, children(t, out, iprp.start, iprp.end), "ipco")
	for _, p := range children(t, out, ipco.start, ipco.end) {
		if p.typ == "hvcC" {
			out[p.start+17] = out[p.start+17]&^7 | d
			out[p.start+18] = out[p.start+18]&^7 | d
		}
	}
	return out
}

func TestDecodeHEICNeedsAPrimaryItem(t *testing.T) {
	in := heicPhoto(t, 64, 64, heic.EncodeOptions{})
	_, mb := metaBoxes(t, in)
	pitm := find(t, mb, "pitm")
	out := append([]byte{}, in...)
	copy(out[pitm.start-4:], "free")
	if word, code, frame := refusal(t, out); word != "decode" || code != 13 || len(frame) != 0 {
		t.Fatalf("no pitm: got %q exit %d with %d bytes out; want decode, 13, none", word, code, len(frame))
	}
	// A picture sequence (moov, no meta), which h265 would decode frame
	// by frame. testdata/sequence.heic is anim.heic from gen2brain/heic
	// v0.7.2's testdata (MIT).
	seq, err := os.ReadFile("testdata/sequence.heic")
	if err != nil {
		t.Fatal(err)
	}
	if word, code, frame := refusal(t, seq); word != "decode" || code != 13 || len(frame) != 0 {
		t.Fatalf("sequence: got %q exit %d with %d bytes out; want decode, 13, none", word, code, len(frame))
	}
	// The same sequence with a still's meta after it, whose pitm names no
	// item: h265 falls back to the track.
	bad := append([]byte{}, in...)
	meta, mb := metaBoxes(t, bad)
	binary.BigEndian.PutUint16(bad[find(t, mb, "pitm").start+4:], 999)
	withMeta := append(append([]byte{}, seq...), bad[meta.start-8:meta.end]...)
	if word, code, frame := refusal(t, withMeta); word != "decode" || code != 13 || len(frame) != 0 {
		t.Fatalf("sequence plus a meta naming no item: got %q exit %d with %d bytes out; want decode, 13, none", word, code, len(frame))
	}
}

func TestDecodeHEICTypes(t *testing.T) {
	for name, in := range map[string]string{
		"avif":      "\x00\x00\x00\x1cftypavif\x00\x00\x00\x00avifmif1miaf",
		"mif1 only": "\x00\x00\x00\x18ftypmif1\x00\x00\x00\x00mif1miaf",
		"short":     "\x00\x00\x00\x10ftyphe",
	} {
		if word, code, _ := refusal(t, []byte(in)); word != "type" || code != 10 {
			t.Errorf("%s: got %q exit %d; want type, 10", name, word, code)
		}
	}
	for name, in := range map[string][]byte{
		"brand only":   []byte("\x00\x00\x00\x18ftypheic\x00\x00\x00\x00mif1heic"),
		"compat brand": []byte("\x00\x00\x00\x18ftypmif1\x00\x00\x00\x00mif1heic"),
		"truncated":    heicPhoto(t, 64, 64, heic.EncodeOptions{})[:400],
	} {
		if word, code, out := refusal(t, in); word != "decode" || code != 13 || len(out) != 0 {
			t.Errorf("%s: got %q exit %d with %d bytes out; want decode, 13, none", name, word, code, len(out))
		}
	}
}

// TestDecodeHEICDeepTakesFullLimit: a HEIC above 8 bits, still, grid or
// 4:4:4, is held to MaxPixels like any other photo, and decodes whatever
// its hvcC says its depth is: its 50 MP run fits HEICMemBytes
// (ASSUMPTIONS CH-photo-heic-1), so no depth is guessed before decoding.
func TestDecodeHEICDeepTakesFullLimit(t *testing.T) {
	codings := map[string]heic.EncodeOptions{
		"still": {}, "grid": {Tile: 32}, "4:4:4": {Chroma: heic.Chroma444},
	}
	for cn, o := range codings {
		for _, depth := range []int{8, 10, 12} {
			o.BitDepth = depth
			name := fmt.Sprintf("%s %d-bit", cn, depth)
			small := heicPhoto(t, 64, 64, o)
			if _, err := decoder.Decode(small); err != nil {
				t.Errorf("%s at 64x64: %v", name, err)
			}
			if _, err := decoder.Decode(withHvcCDepth(t, small, 0)); err != nil {
				t.Errorf("%s with an hvcC saying 8 bits: %v", name, err)
			}
			if _, err := decoder.Decode(withISPE(t, small, 6000, 4001)); err == decoder.RefusePixels {
				t.Errorf("%s declared 6000x4001: refused as pixels under MaxPixels", name)
			}
			if _, err := decoder.Decode(withISPE(t, small, 10001, 5000)); err != decoder.RefusePixels {
				t.Errorf("%s declared 10001x5000: got %v, want pixels", name, err)
			}
		}
	}
}

// TestSoftLimitFollowsType: a HEIC run's Go soft limit sits under its
// larger cap; any other file keeps the JPEG and PNG one.
func TestSoftLimitFollowsType(t *testing.T) {
	for name, c := range map[string]struct {
		in   []byte
		want int64
	}{
		"heic": {heicPhoto(t, 64, 64, heic.EncodeOptions{}), heicSoftMemory},
		"avif": {[]byte("\x00\x00\x00\x1cftypavif\x00\x00\x00\x00avifmif1miaf"), softMemory},
		"png":  {pngHeader(64, 64), softMemory},
	} {
		in := bufio.NewReaderSize(bytes.NewReader(c.in), 1<<12)
		if got := softLimit(in); got != c.want {
			t.Errorf("%s: soft limit %d, want %d", name, got, c.want)
		}
		if rest, _ := io.ReadAll(in); !bytes.Equal(rest, c.in) {
			t.Errorf("%s: reading the limit consumed input", name)
		}
	}
}
