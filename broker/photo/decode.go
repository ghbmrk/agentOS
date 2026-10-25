// Package photo turns an owner's photo into an image the broker can
// keep and send on (CH-23). No image decoder runs in the broker: the
// file goes to agentos-photo (broker/cmd/agentos-photo) in a one-shot
// gVisor sandbox with no network, a read-only root and a memory cap
// (ARC-5), and comes back re-encoded, with its metadata gone. The broker
// trusts none of what comes back: it checks the frame against the bytes,
// reading the dimensions itself from the PNG or JPEG header, before it
// keeps any of it.
package photo

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"time"

	"github.com/ghbmrk/agentos/broker/vm/gvisor"
)

// The decoder's limits (package photo/decoder, which this package must
// not import: it links Go's image decoders). TestLimitsMatchDecoder
// keeps the two in step.
const (
	MaxInput  = 20 << 20
	MaxSide   = 4096
	ThumbSide = 320
)

// The one-shot run's limits. MemBytes covers a 50-megapixel 16-bit PNG,
// the costliest file the decoder accepts (ASSUMPTIONS P-1); MaxOutput, a
// 4096-pixel square PNG that compresses badly, plus its thumbnail.
const (
	MemBytes  = 512 << 20
	Timeout   = 30 * time.Second
	MaxOutput = 80 << 20
	maxHeader = 1 << 10
)

// Refusal is why a photo was not taken: one of the words below, which
// the owner's channel turns into a reply.
type Refusal string

const (
	RefuseType   Refusal = "type"   // not a JPEG, PNG or HEIC
	RefuseSize   Refusal = "size"   // over MaxInput bytes
	RefusePixels Refusal = "pixels" // over 50 megapixels
	RefuseDecode Refusal = "decode" // corrupt, too costly, or a bad frame
)

func (r Refusal) Error() string { return "photo refused: " + string(r) }

// exitRefusal maps agentos-photo's exit codes to refusals; any other
// non-zero exit (a Go fatal error, the memory cap) is RefuseDecode.
var exitRefusal = map[int]Refusal{10: RefuseType, 11: RefuseSize, 12: RefusePixels, 13: RefuseDecode}

// Runner runs a one-shot sandbox; *gvisor.Runtime is one.
type Runner interface {
	RunOnce(context.Context, gvisor.OneShot) (gvisor.OneShotResult, error)
}

// Decoder re-encodes photos through agentos-photo.
type Decoder struct {
	Runner Runner
	Root   string // the read-only root holding /agentos-photo
	// Cgroup is the cgroup v2 group the sandbox's own group is made under,
	// which holds it to MemBytes; it is required (gvisor.OneShot.Cgroup).
	Cgroup string
}

// Photo is a re-encoded photo and its thumbnail, each a JPEG or a PNG
// as Format says.
type Photo struct {
	Format        string
	Width, Height int
	Image         []byte
	ThumbWidth    int
	ThumbHeight   int
	Thumb         []byte
}

type header struct {
	Format      string `json:"format"`
	Width       int    `json:"width"`
	Height      int    `json:"height"`
	Bytes       int    `json:"bytes"`
	ThumbWidth  int    `json:"thumb_width"`
	ThumbHeight int    `json:"thumb_height"`
	ThumbBytes  int    `json:"thumb_bytes"`
}

var (
	jpegMagic = []byte{0xFF, 0xD8, 0xFF}
	pngMagic  = []byte("\x89PNG\r\n\x1a\n")
)

// isoBMFF reports whether raw starts like an ISOBMFF file, as a HEIC
// does. Which brands are a HEIC is the decoder's to say (it refuses the
// rest as type), so the broker reads no more of the box than this.
func isoBMFF(raw []byte) bool { return len(raw) >= 12 && string(raw[4:8]) == "ftyp" }

// errNoCgroup refuses a run with no memory cap: gVisor enforces none of
// its own (gvisor.OneShot.MemBytes).
var errNoCgroup = errors.New("photo: no cgroup for the sandbox")

// Decode re-encodes raw. The error is a Refusal for a file that was not
// taken, and anything else for a failure to run the sandbox.
func (d *Decoder) Decode(ctx context.Context, raw []byte) (Photo, error) {
	if len(raw) > MaxInput {
		return Photo{}, RefuseSize
	}
	if !bytes.HasPrefix(raw, jpegMagic) && !bytes.HasPrefix(raw, pngMagic) && !isoBMFF(raw) {
		return Photo{}, RefuseType
	}
	if d.Cgroup == "" {
		return Photo{}, errNoCgroup
	}
	res, err := d.Runner.RunOnce(ctx, gvisor.OneShot{
		Name: "photo", Root: d.Root, Argv: []string{"/agentos-photo"},
		Stdin: raw, MaxOutput: MaxOutput, MemBytes: MemBytes, Timeout: Timeout, Cgroup: d.Cgroup,
	})
	if errors.Is(err, context.DeadlineExceeded) && ctx.Err() == nil {
		return Photo{}, RefuseDecode // the run's own deadline: too costly
	}
	if errors.Is(err, gvisor.ErrOneShotMemory) {
		return Photo{}, RefuseDecode // the memory cap: too costly
	}
	if err != nil {
		return Photo{}, err
	}
	if res.ExitCode != 0 {
		if r, ok := exitRefusal[res.ExitCode]; ok {
			return Photo{}, r
		}
		return Photo{}, RefuseDecode
	}
	if res.Truncated {
		return Photo{}, RefuseDecode
	}
	p, ok := parseFrame(res.Stdout)
	if !ok {
		return Photo{}, RefuseDecode
	}
	return p, nil
}

// parseFrame checks a frame (a JSON header line, the image, the
// thumbnail) against its bytes: the lengths add up, each part is the
// format the header names, and the dimensions it gives are the ones the
// part's own header holds, within MaxSide and ThumbSide.
func parseFrame(b []byte) (Photo, bool) {
	line, rest, ok := bytes.Cut(b[:min(len(b), maxHeader)], []byte("\n"))
	if !ok {
		return Photo{}, false
	}
	rest = b[len(line)+1:]
	var h header
	dec := json.NewDecoder(bytes.NewReader(line))
	dec.DisallowUnknownFields()
	if dec.Decode(&h) != nil || dec.More() {
		return Photo{}, false
	}
	if h.Bytes <= 0 || h.ThumbBytes <= 0 || h.Bytes+h.ThumbBytes != len(rest) {
		return Photo{}, false
	}
	if !within(h.Width, h.Height, MaxSide) || !within(h.ThumbWidth, h.ThumbHeight, ThumbSide) ||
		h.ThumbWidth > h.Width || h.ThumbHeight > h.Height {
		return Photo{}, false
	}
	img, thumb := rest[:h.Bytes], rest[h.Bytes:]
	dims := map[string]func([]byte) (int, int, bool){"jpeg": jpegDims, "png": pngDims}[h.Format]
	if dims == nil {
		return Photo{}, false
	}
	for _, part := range []struct {
		b    []byte
		w, h int
	}{{img, h.Width, h.Height}, {thumb, h.ThumbWidth, h.ThumbHeight}} {
		if w, ht, ok := dims(part.b); !ok || w != part.w || ht != part.h {
			return Photo{}, false
		}
	}
	return Photo{
		Format: h.Format, Width: h.Width, Height: h.Height, Image: img,
		ThumbWidth: h.ThumbWidth, ThumbHeight: h.ThumbHeight, Thumb: thumb,
	}, true
}

func within(w, h, side int) bool { return w >= 1 && h >= 1 && w <= side && h <= side }

// pngDims reads a PNG's width and height from its IHDR chunk, which
// must come first, and requires the file to end with an IEND chunk.
func pngDims(b []byte) (int, int, bool) {
	iend := []byte{0, 0, 0, 0, 'I', 'E', 'N', 'D', 0xAE, 0x42, 0x60, 0x82}
	if len(b) < 8+8+13+4+len(iend) || !bytes.HasPrefix(b, pngMagic) || !bytes.HasSuffix(b, iend) {
		return 0, 0, false
	}
	if binary.BigEndian.Uint32(b[8:]) != 13 || string(b[12:16]) != "IHDR" {
		return 0, 0, false
	}
	w, h := binary.BigEndian.Uint32(b[16:]), binary.BigEndian.Uint32(b[20:])
	if w > MaxSide || h > MaxSide {
		return 0, 0, false
	}
	return int(w), int(h), true
}

// jpegDims reads a JPEG's width and height from its frame header
// (SOFn), walking the marker segments before it, and requires the file
// to end with EOI.
func jpegDims(b []byte) (int, int, bool) {
	if !bytes.HasPrefix(b, jpegMagic) || !bytes.HasSuffix(b, []byte{0xFF, 0xD9}) {
		return 0, 0, false
	}
	for i := 2; i+4 <= len(b); {
		if b[i] != 0xFF {
			return 0, 0, false
		}
		m := b[i+1]
		if m == 0xFF { // fill byte
			i++
			continue
		}
		n := int(binary.BigEndian.Uint16(b[i+2:]))
		if n < 2 || i+2+n > len(b) || m == 0xDA || m == 0xD9 {
			return 0, 0, false // no frame header before the scan
		}
		if m >= 0xC0 && m <= 0xCF && m != 0xC4 && m != 0xC8 && m != 0xCC {
			if n < 8 {
				return 0, 0, false
			}
			h, w := int(binary.BigEndian.Uint16(b[i+5:])), int(binary.BigEndian.Uint16(b[i+7:]))
			return w, h, true
		}
		i += 2 + n
	}
	return 0, 0, false
}
