package main

// REQ: CH-23

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"image"
	"image/color"
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
	// Above 8 bits the limit is MaxDeepPixels.
	deep := heicPhoto(t, 64, 64, heic.EncodeOptions{BitDepth: 10})
	if _, err := decoder.Decode(withISPE(t, deep, 6000, 4001)); err != decoder.RefusePixels {
		t.Fatalf("10-bit 6000x4001: got %v, want pixels", err)
	}
	// A grid's own item has no hvcC: the limit follows its tiles' depth.
	deepGrid := heicPhoto(t, 64, 64, heic.EncodeOptions{BitDepth: 10, Tile: 32})
	if _, err := decoder.Decode(withISPE(t, deepGrid, 5000, 5000)); err != decoder.RefusePixels {
		t.Fatalf("10-bit grid 5000x5000: got %v, want pixels", err)
	}
	// Nor can an empty ipco ahead of the real one hide the tiles' depth.
	if _, err := decoder.Decode(withIprpFirst(t, withISPE(t, deepGrid, 5000, 5000), []byte("\x00\x00\x00\x08ipco"))); err != decoder.RefusePixels {
		t.Fatalf("10-bit grid behind an empty ipco: got %v, want pixels", err)
	}
	// An hvcC that says 8 bits over a 10-bit stream is refused.
	if _, err := decoder.Decode(withHvcCDepth(t, deep, 0)); err != decoder.RefuseDecode {
		t.Fatalf("10-bit stream declared 8-bit: got %v, want decode", err)
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

// withIprpFirst returns raw with box placed first in its iprp, the boxes
// holding it grown and the iloc offsets past meta moved to match.
func withIprpFirst(t *testing.T, raw, box []byte) []byte {
	t.Helper()
	meta, mb := metaBoxes(t, raw)
	sized := func(typ string, b []byte) []byte {
		return append(binary.BigEndian.AppendUint32(nil, uint32(8+len(b))), append([]byte(typ), b...)...)
	}
	metaBody := append([]byte{}, raw[meta.start:meta.start+4]...)
	for _, m := range mb {
		if m.typ == "iprp" {
			metaBody = append(metaBody, sized("iprp", append(append([]byte{}, box...), raw[m.start:m.end]...))...)
		} else {
			metaBody = append(metaBody, raw[m.start-8:m.end]...)
		}
	}
	out := append(append(append([]byte{}, raw[:meta.start-8]...), sized("meta", metaBody)...), raw[meta.end:]...)
	shiftIloc(t, out, meta.end, len(box))
	return out
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

// withHvcC rewrites every hvcC box in ipco with f, regrowing ipco, iprp
// and meta and moving the iloc offsets past meta.
func withHvcC(t *testing.T, raw []byte, f func(body []byte) []byte) []byte {
	t.Helper()
	sized := func(typ string, b []byte) []byte {
		return append(binary.BigEndian.AppendUint32(nil, uint32(8+len(b))), append([]byte(typ), b...)...)
	}
	meta, mb := metaBoxes(t, raw)
	metaBody := append([]byte{}, raw[meta.start:meta.start+4]...)
	for _, m := range mb {
		if m.typ != "iprp" {
			metaBody = append(metaBody, raw[m.start-8:m.end]...)
			continue
		}
		var iprp []byte
		for _, c := range children(t, raw, m.start, m.end) {
			if c.typ != "ipco" {
				iprp = append(iprp, raw[c.start-8:c.end]...)
				continue
			}
			var ipco []byte
			for _, p := range children(t, raw, c.start, c.end) {
				if p.typ == "hvcC" {
					ipco = append(ipco, f(raw[p.start:p.end])...)
				} else {
					ipco = append(ipco, raw[p.start-8:p.end]...)
				}
			}
			iprp = append(iprp, sized("ipco", ipco)...)
		}
		metaBody = append(metaBody, sized("iprp", iprp)...)
	}
	newMeta := sized("meta", metaBody)
	out := append(append(append([]byte{}, raw[:meta.start-8]...), newMeta...), raw[meta.end:]...)
	shiftIloc(t, out, meta.end, len(newMeta)-(meta.end-meta.start+8))
	return out
}

// withBeforeIprp returns raw with box placed in meta just before iprp,
// meta grown and the iloc offsets past it moved to match.
func withBeforeIprp(t *testing.T, raw, box []byte) []byte {
	t.Helper()
	meta, mb := metaBoxes(t, raw)
	metaBody := append([]byte{}, raw[meta.start:meta.start+4]...)
	for _, m := range mb {
		if m.typ == "iprp" {
			metaBody = append(metaBody, box...)
		}
		metaBody = append(metaBody, raw[m.start-8:m.end]...)
	}
	sized := append(binary.BigEndian.AppendUint32(nil, uint32(8+len(metaBody))), append([]byte("meta"), metaBody...)...)
	out := append(append(append([]byte{}, raw[:meta.start-8]...), sized...), raw[meta.end:]...)
	shiftIloc(t, out, meta.end, len(box))
	return out
}

// hvcCLarge writes an hvcC body with a 64-bit size.
func hvcCLarge(body []byte) []byte {
	b := append(binary.BigEndian.AppendUint32(nil, 1), "hvcC"...)
	return append(binary.BigEndian.AppendUint64(b, uint64(16+len(body))), body...)
}

// hvcCPadded writes an hvcC body followed by 70,000 bytes h265 ignores.
func hvcCPadded(body []byte) []byte {
	body = append(append([]byte{}, body...), make([]byte, 70000)...)
	return append(binary.BigEndian.AppendUint32(nil, uint32(8+len(body))), append([]byte("hvcC"), body...)...)
}

// TestDecodeHEICDepthSeenWhereverH265ReadsIt is the property the 24 MP
// limit rests on: for every layout here that h265 decodes, a file it
// decodes above 8 bits is held to MaxDeepPixels before any decode, and
// an 8-bit one is not. The layouts are those reviews of #3124 found a
// box walk could miss: grids, an empty leading ipco or iprp, an hvcC
// with a 64-bit size, and one padded past 64 KiB.
func TestDecodeHEICDepthSeenWhereverH265ReadsIt(t *testing.T) {
	layouts := map[string]func([]byte) []byte{
		"plain":       func(b []byte) []byte { return b },
		"empty ipco":  func(b []byte) []byte { return withIprpFirst(t, b, []byte("\x00\x00\x00\x08ipco")) },
		"empty iprp":  func(b []byte) []byte { return withBeforeIprp(t, b, []byte("\x00\x00\x00\x08iprp")) },
		"hvcC 64-bit": func(b []byte) []byte { return withHvcC(t, b, hvcCLarge) },
		"hvcC padded": func(b []byte) []byte { return withHvcC(t, b, hvcCPadded) },
	}
	codings := map[string]heic.EncodeOptions{
		"still": {}, "grid": {Tile: 32}, "4:4:4": {Chroma: heic.Chroma444},
	}
	for ln, layout := range layouts {
		for cn, o := range codings {
			for _, depth := range []int{8, 10, 12} {
				o.BitDepth = depth
				name := fmt.Sprintf("%s %s %d-bit", ln, cn, depth)
				small := layout(heicPhoto(t, 64, 64, o))
				img, err := heic.Decode(bytes.NewReader(small), heic.Options{AutoRotate: true})
				if err != nil {
					t.Fatalf("%s: h265 refuses the layout: %v", name, err)
				}
				_, wide := img.(*image.NRGBA64)
				if wide != (depth > 8) {
					t.Fatalf("%s: h265 gave %T", name, img)
				}
				if _, err := decoder.Decode(small); err != nil {
					t.Errorf("%s at 64x64: %v", name, err)
				}
				// Over MaxDeepPixels, under MaxPixels.
				big := layout(withISPE(t, heicPhoto(t, 64, 64, o), 6000, 4001))
				_, err = decoder.Decode(big)
				if wide && err != decoder.RefusePixels {
					t.Errorf("%s declared 6000x4001: got %v, want pixels before decoding", name, err)
				}
				if !wide && err == decoder.RefusePixels {
					t.Errorf("%s declared 6000x4001: refused as pixels, but 8 bits may have 50 MP", name)
				}
			}
		}
	}
}
