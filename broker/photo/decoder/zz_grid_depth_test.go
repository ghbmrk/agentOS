package decoder_test

// REQ: CH-23

import (
	"bytes"
	"encoding/binary"
	"errors"
	"image"
	"os"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"github.com/gen2brain/h265/heic"
	"github.com/ghbmrk/agentos/broker/photo/decoder"
)

// CI-soak-green (#6571): a grid whose tiles differ in chroma depth is
// refused, never stitched. hevc stores a tile's planes 16-bit when either
// depth is past 8, so a tile whose chroma depth differs from the grid's
// has the other kind of planes, and copying it read nil ones. The deep
// tiles' hvcC is the FuzzDecode crasher's (8-bit luma, 10-bit chroma); the
// rest are the encoder's 8-bit tiles.
func TestGridMixedChromaDepthRefused(t *testing.T) {
	defer runtime.GOMAXPROCS(runtime.GOMAXPROCS(max(runtime.GOMAXPROCS(0), 6)))
	plain := encodeGrid(t)
	deep := crasherHvcC(t)
	// The control: every tile deep is one depth throughout, and decodes.
	for _, threads := range []int{1, 6} {
		all := withTileHvcC(t, plain, deep, func(int) bool { return true })
		if _, err := heic.Decode(bytes.NewReader(all), heic.Options{Threads: threads}); err != nil {
			t.Fatalf("every tile deep, %d threads: %v", threads, err)
		}
	}
	for _, c := range []struct {
		name string
		deep func(k int) bool // which tiles, in dimg order, get the deep hvcC
	}{
		{"deep first", func(k int) bool { return k == 0 }},
		{"deep later", func(k int) bool { return k > 0 }},
	} {
		raw := withTileHvcC(t, plain, deep, c.deep)
		// One thread decodes every tile on the serial path; six (one per
		// tile) hand the later tiles to the workers' path, which they take
		// while the first tile decodes if they can run then (GOMAXPROCS is
		// raised for that, since -cpu 1 would leave the workers idle). Each
		// path has its own check, so both are run, the parallel one a few times.
		for _, threads := range []int{1, 6, 6, 6, 6} {
			if _, err := heic.Decode(bytes.NewReader(raw), heic.Options{Threads: threads}); !errors.Is(err, heic.ErrInvalid) {
				t.Fatalf("%s, %d threads: %v, want ErrInvalid", c.name, threads, err)
			}
		}
		var r decoder.Refusal
		if _, err := decoder.Decode(raw); !errors.As(err, &r) || r != decoder.RefuseDecode {
			t.Fatalf("%s: Decode returned %v, want refusal decode", c.name, err)
		}
	}
}

func encodeGrid(t *testing.T) []byte {
	t.Helper()
	n := image.NewNRGBA(image.Rect(0, 0, 48, 32))
	for i := range n.Pix {
		n.Pix[i] = uint8(i * 7)
	}
	var b bytes.Buffer
	if err := heic.Encode(&b, n, heic.EncodeOptions{Tile: 16}); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

// crasherHvcC is the first hvcC box of the committed FuzzDecode crasher.
func crasherHvcC(t *testing.T) []byte {
	t.Helper()
	text, err := os.ReadFile("testdata/fuzz/FuzzDecode/8a16659925ba2df0")
	if err != nil {
		t.Fatal(err)
	}
	_, lit, _ := strings.Cut(string(text), "\n")
	s, err := strconv.Unquote(strings.TrimSuffix(strings.TrimPrefix(strings.TrimSpace(lit), "[]byte("), ")"))
	if err != nil {
		t.Fatal(err)
	}
	f := parseHEIF(t, []byte(s))
	return f.props[f.colorProp-1]
}

type box struct {
	typ      string
	at, size int
}

func children(t *testing.T, b []byte, at, end int) []box {
	t.Helper()
	var out []box
	for at+8 <= end {
		n := int(binary.BigEndian.Uint32(b[at:]))
		if n < 8 || at+n > end {
			t.Fatalf("bad box at %d", at)
		}
		out = append(out, box{string(b[at+4 : at+8]), at, n})
		at += n
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

type heif struct {
	meta, iprp, ipco, ipma, iloc box
	props                        [][]byte
	colorProp                    int      // ipco index (1-based) of the tiles' hvcC
	tiles                        []uint16 // the primary grid's dimg, in order
}

// parseHEIF reads the boxes this test edits from a file the vendored
// encoder wrote: one meta, 8-bit ipma indices, a grid primary item.
func parseHEIF(t *testing.T, b []byte) heif {
	t.Helper()
	var f heif
	f.meta = find(t, children(t, b, 0, len(b)), "meta")
	inMeta := children(t, b, f.meta.at+12, f.meta.at+f.meta.size)
	f.iprp, f.iloc = find(t, inMeta, "iprp"), find(t, inMeta, "iloc")
	inIprp := children(t, b, f.iprp.at+8, f.iprp.at+f.iprp.size)
	f.ipco, f.ipma = find(t, inIprp, "ipco"), find(t, inIprp, "ipma")
	for _, p := range children(t, b, f.ipco.at+8, f.ipco.at+f.ipco.size) {
		f.props = append(f.props, b[p.at:p.at+p.size])
	}
	pitm := find(t, inMeta, "pitm")
	primary := binary.BigEndian.Uint16(b[pitm.at+12:])
	iref := find(t, inMeta, "iref")
	for _, r := range children(t, b, iref.at+12, iref.at+iref.size) {
		if r.typ == "dimg" && binary.BigEndian.Uint16(b[r.at+8:]) == primary {
			n := int(binary.BigEndian.Uint16(b[r.at+10:]))
			for i := range n {
				f.tiles = append(f.tiles, binary.BigEndian.Uint16(b[r.at+12+2*i:]))
			}
		}
	}
	if len(f.tiles) < 2 {
		t.Fatalf("primary item %d is not a grid of tiles", primary)
	}
	for _, a := range ipmaOf(t, b, f.ipma)[f.tiles[0]] {
		if idx := int(b[a] & 0x7f); string(f.props[idx-1][4:8]) == "hvcC" {
			f.colorProp = idx
		}
	}
	if f.colorProp == 0 {
		t.Fatal("first tile has no hvcC")
	}
	return f
}

// ipmaOf maps each item to the byte offsets of its 8-bit associations.
func ipmaOf(t *testing.T, b []byte, ipma box) map[uint16][]int {
	t.Helper()
	if b[ipma.at+8] != 0 || b[ipma.at+11]&1 != 0 {
		t.Fatal("ipma is not version 0 with 8-bit indices")
	}
	out := map[uint16][]int{}
	at := ipma.at + 16
	for range binary.BigEndian.Uint32(b[ipma.at+12:]) {
		id, n := binary.BigEndian.Uint16(b[at:]), int(b[at+2])
		for i := range n {
			out[id] = append(out[id], at+3+i)
		}
		at += 3 + n
	}
	return out
}

// withTileHvcC appends deep to ipco and points the tiles deepTile picks
// at it in place of the tiles' own hvcC, moving every iloc offset past
// the insertion (all of them: mdat follows meta).
func withTileHvcC(t *testing.T, b, deep []byte, deepTile func(k int) bool) []byte {
	t.Helper()
	f := parseHEIF(t, b)
	out := append(append(append([]byte{}, b[:f.ipco.at+f.ipco.size]...), deep...), b[f.ipco.at+f.ipco.size:]...)
	grow := func(x box) {
		binary.BigEndian.PutUint32(out[x.at:], uint32(x.size+len(deep)))
	}
	grow(f.meta)
	grow(f.iprp)
	grow(f.ipco)
	newProp := byte(len(f.props) + 1)
	assoc := ipmaOf(t, out, box{"ipma", f.ipma.at + len(deep), f.ipma.size})
	for k, id := range f.tiles {
		if !deepTile(k) {
			continue
		}
		for _, a := range assoc[id] {
			if int(out[a]&0x7f) == f.colorProp {
				out[a] = out[a]&0x80 | newProp
			}
		}
	}
	shiftIloc(t, out, f.iloc, len(deep))
	return out
}

func shiftIloc(t *testing.T, b []byte, iloc box, by int) {
	t.Helper()
	v := b[iloc.at+8]
	at := iloc.at + 12
	offSize, lenSize := int(b[at]>>4), int(b[at]&15)
	baseSize, idxSize := int(b[at+1]>>4), int(b[at+1]&15)
	at += 2
	var count int
	if v < 2 {
		count, at = int(binary.BigEndian.Uint16(b[at:])), at+2
	} else {
		count, at = int(binary.BigEndian.Uint32(b[at:])), at+4
	}
	shift := func(at, size int) {
		switch size {
		case 0:
		case 4:
			binary.BigEndian.PutUint32(b[at:], binary.BigEndian.Uint32(b[at:])+uint32(by))
		case 8:
			binary.BigEndian.PutUint64(b[at:], binary.BigEndian.Uint64(b[at:])+uint64(by))
		default:
			t.Fatalf("iloc field size %d", size)
		}
	}
	for range count {
		if v < 2 {
			at += 2
		} else {
			at += 4
		}
		method := 0
		if v == 1 || v == 2 {
			method, at = int(binary.BigEndian.Uint16(b[at:])&15), at+2
		}
		at += 2 // data_reference_index
		if method == 0 && baseSize > 0 {
			shift(at, baseSize)
		}
		at += baseSize
		extents := int(binary.BigEndian.Uint16(b[at:]))
		at += 2
		for range extents {
			if (v == 1 || v == 2) && idxSize > 0 {
				at += idxSize
			}
			if method == 0 && baseSize == 0 {
				shift(at, offSize)
			}
			at += offSize + lenSize
		}
	}
}
