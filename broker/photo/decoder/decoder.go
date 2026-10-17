// Package decoder turns an owner's photo into a new image with nothing
// but its pixels (CH-23). It runs only inside agentos-photo, the confined
// one-shot process (ARC-5): the broker never imports it (photo's lint
// test), so a crafted file can at worst take over a process with no
// network, no broker state and a read-only root.
//
// It accepts JPEG and PNG by magic bytes, refuses more than MaxInput
// bytes or MaxPixels pixels before decoding any pixel, applies the EXIF
// orientation, shrinks the long side to at most MaxSide, and encodes a
// new image and a thumbnail from the decoded pixels only, so no EXIF,
// GPS, XMP, ICC profile, comment or embedded thumbnail can survive.
package decoder

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"image"
	"image/color"
	"image/jpeg"
	"image/png"
	"io"
)

// Limits from CH-23 (first release, not owner-settable), and the
// thumbnail's long side.
const (
	MaxInput  = 20 << 20
	MaxPixels = 50_000_000
	MaxSide   = 4096
	ThumbSide = 320
	// JPEGQuality is the new JPEG's quality.
	JPEGQuality = 90
)

// Refusal is why a file is refused; its text is the one word the
// process writes to stderr.
type Refusal string

const (
	RefuseType   Refusal = "type"
	RefuseSize   Refusal = "size"
	RefusePixels Refusal = "pixels"
	RefuseDecode Refusal = "decode"
)

func (r Refusal) Error() string { return string(r) }

// ExitCode is the process exit code for r: 10 type, 11 size, 12 pixels,
// 13 decode. They stay clear of 1 and 2, which the Go runtime uses for a
// panic or a fatal error such as running out of memory.
func (r Refusal) ExitCode() int {
	switch r {
	case RefuseType:
		return 10
	case RefuseSize:
		return 11
	case RefusePixels:
		return 12
	}
	return 13
}

// Header is the frame's first line: the image's format and size, then
// the thumbnail's. Image bytes, then thumbnail bytes, follow it.
type Header struct {
	Format      string `json:"format"` // "jpeg" or "png"
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

// Run reads one file from r and writes its frame to w. A refused file
// writes nothing and returns a Refusal.
func Run(r io.Reader, w io.Writer) error {
	raw, err := io.ReadAll(io.LimitReader(r, MaxInput+1))
	if err != nil {
		return RefuseDecode
	}
	frame, err := Decode(raw)
	if err != nil {
		return err
	}
	_, err = w.Write(frame)
	return err
}

// Decode returns raw's frame, or a Refusal.
func Decode(raw []byte) ([]byte, error) {
	if len(raw) > MaxInput {
		return nil, RefuseSize
	}
	var format string
	var config func(io.Reader) (image.Config, error)
	var decode func(io.Reader) (image.Image, error)
	switch {
	case bytes.HasPrefix(raw, jpegMagic):
		format, config, decode = "jpeg", jpeg.DecodeConfig, jpeg.Decode
	case bytes.HasPrefix(raw, pngMagic):
		format, config, decode = "png", png.DecodeConfig, png.Decode
	default:
		return nil, RefuseType
	}
	cfg, err := config(bytes.NewReader(raw))
	if err != nil {
		return nil, RefuseDecode
	}
	if cfg.Width <= 0 || cfg.Height <= 0 || int64(cfg.Width)*int64(cfg.Height) > MaxPixels {
		return nil, RefusePixels
	}
	orient := 1
	if format == "jpeg" {
		orient = Orientation(raw)
	}
	src, err := decode(bytes.NewReader(raw))
	if err != nil {
		return nil, RefuseDecode
	}
	b := src.Bounds()
	if b.Dx() != cfg.Width || b.Dy() != cfg.Height {
		return nil, RefuseDecode
	}
	img := Orient(Shrink(src, MaxSide), orient)
	thumb := Shrink(img, ThumbSide)
	var out, tout bytes.Buffer
	if err := encode(&out, img, format); err != nil {
		return nil, RefuseDecode
	}
	if err := encode(&tout, thumb, format); err != nil {
		return nil, RefuseDecode
	}
	h := Header{
		Format: format, Width: img.Rect.Dx(), Height: img.Rect.Dy(), Bytes: out.Len(),
		ThumbWidth: thumb.Rect.Dx(), ThumbHeight: thumb.Rect.Dy(), ThumbBytes: tout.Len(),
	}
	line, err := json.Marshal(h)
	if err != nil {
		return nil, err
	}
	frame := make([]byte, 0, len(line)+1+out.Len()+tout.Len())
	frame = append(append(append(append(frame, line...), '\n'), out.Bytes()...), tout.Bytes()...)
	return frame, nil
}

func encode(w io.Writer, img *image.RGBA, format string) error {
	if format == "jpeg" {
		return jpeg.Encode(w, img, &jpeg.Options{Quality: JPEGQuality})
	}
	return (&png.Encoder{CompressionLevel: png.DefaultCompression}).Encode(w, img)
}

// Shrink returns src scaled so its long side is at most max, by averaging
// each output pixel's source box (premultiplied RGBA). It never enlarges.
// It holds one source row and one output row of sums at a time, so its
// memory beyond the output is a few rows; golang.org/x/image/draw's
// kernel scalers keep a float64 buffer of output width by source height
// (about 750 MB for a 50 MP photo), more than the decoder's memory cap.
func Shrink(src image.Image, max int) *image.RGBA {
	b := src.Bounds()
	sw, sh := b.Dx(), b.Dy()
	dw, dh := sw, sh
	if sw >= sh && sw > max {
		dw, dh = max, int(int64(sh)*int64(max)/int64(sw))
	} else if sh > sw && sh > max {
		dw, dh = int(int64(sw)*int64(max)/int64(sh)), max
	}
	dw, dh = atLeast1(dw), atLeast1(dh)
	dst := image.NewRGBA(image.Rect(0, 0, dw, dh))
	row := make([]uint8, 4*sw)
	sums := make([]uint64, 4*dw)
	sy := 0
	for dy := 0; dy < dh; dy++ {
		y1 := boxEnd(dy, sh, dh)
		clear(sums)
		rows := 0
		for ; sy < y1; sy++ {
			readRow(src, b.Min.X, b.Min.Y+sy, row)
			for dx := 0; dx < dw; dx++ {
				x0, x1 := boxEnd(dx-1, sw, dw), boxEnd(dx, sw, dw)
				s := sums[4*dx : 4*dx+4]
				for x := x0; x < x1; x++ {
					p := row[4*x : 4*x+4]
					s[0] += uint64(p[0])
					s[1] += uint64(p[1])
					s[2] += uint64(p[2])
					s[3] += uint64(p[3])
				}
			}
			rows++
		}
		for dx := 0; dx < dw; dx++ {
			n := uint64(rows * (boxEnd(dx, sw, dw) - boxEnd(dx-1, sw, dw)))
			s, d := sums[4*dx:4*dx+4], dst.Pix[dy*dst.Stride+4*dx:dy*dst.Stride+4*dx+4]
			for c := range 4 {
				d[c] = uint8((s[c] + n/2) / n)
			}
		}
	}
	return dst
}

// boxEnd is where output cell i's source box ends (exclusive); cell -1
// ends at 0. Every box holds at least one source pixel since n <= src.
func boxEnd(i, src, n int) int {
	if i < 0 {
		return 0
	}
	return int(int64(i+1) * int64(src) / int64(n))
}

func atLeast1(n int) int { return max(n, 1) }

// readRow writes src's row y, from x0, into row as premultiplied RGBA.
func readRow(src image.Image, x0, y int, row []uint8) {
	n := len(row) / 4
	switch s := src.(type) {
	case *image.YCbCr:
		for x := range n {
			yi, ci := s.YOffset(x0+x, y), s.COffset(x0+x, y)
			r, g, b := color.YCbCrToRGB(s.Y[yi], s.Cb[ci], s.Cr[ci])
			row[4*x], row[4*x+1], row[4*x+2], row[4*x+3] = r, g, b, 0xFF
		}
	case *image.Gray:
		for x := range n {
			v := s.Pix[s.PixOffset(x0+x, y)]
			row[4*x], row[4*x+1], row[4*x+2], row[4*x+3] = v, v, v, 0xFF
		}
	case *image.RGBA:
		i := s.PixOffset(x0, y)
		copy(row, s.Pix[i:i+4*n])
	default:
		for x := range n {
			r, g, b, a := src.At(x0+x, y).RGBA()
			row[4*x], row[4*x+1], row[4*x+2], row[4*x+3] = uint8(r>>8), uint8(g>>8), uint8(b>>8), uint8(a>>8)
		}
	}
}

// Orient returns img turned upright for EXIF orientation o (1 to 8);
// any other value leaves it as it is.
func Orient(img *image.RGBA, o int) *image.RGBA {
	if o < 2 || o > 8 {
		return img
	}
	w, h := img.Rect.Dx(), img.Rect.Dy()
	dw, dh := w, h
	if o >= 5 {
		dw, dh = h, w
	}
	dst := image.NewRGBA(image.Rect(0, 0, dw, dh))
	for y := range h {
		for x := range w {
			var dx, dy int
			switch o {
			case 2:
				dx, dy = w-1-x, y
			case 3:
				dx, dy = w-1-x, h-1-y
			case 4:
				dx, dy = x, h-1-y
			case 5:
				dx, dy = y, x
			case 6:
				dx, dy = h-1-y, x
			case 7:
				dx, dy = h-1-y, w-1-x
			case 8:
				dx, dy = y, w-1-x
			}
			si, di := img.PixOffset(x, y), dst.PixOffset(dx, dy)
			copy(dst.Pix[di:di+4], img.Pix[si:si+4])
		}
	}
	return dst
}

// Orientation reads EXIF tag 0x0112 from a JPEG's APP1 Exif segment, and
// nothing else from it; it returns 1 when there is none or it is not
// readable. It reads only the segments before the first SOS, each at
// most 64 KiB by the format's own length field.
func Orientation(raw []byte) int {
	i := 2
	for i+4 <= len(raw) {
		if raw[i] != 0xFF {
			return 1
		}
		m := raw[i+1]
		if m == 0xDA || m == 0xD9 {
			return 1
		}
		if m == 0xFF || (m >= 0xD0 && m <= 0xD7) || m == 0x01 {
			i++
			if m != 0xFF {
				i++
			}
			continue
		}
		n := int(binary.BigEndian.Uint16(raw[i+2:]))
		if n < 2 || i+2+n > len(raw) {
			return 1
		}
		seg := raw[i+4 : i+2+n]
		if m == 0xE1 && bytes.HasPrefix(seg, []byte("Exif\x00\x00")) {
			if o, err := tiffOrientation(seg[6:]); err == nil {
				return o
			}
			return 1
		}
		i += 2 + n
	}
	return 1
}

var errNoOrientation = errors.New("no orientation")

func tiffOrientation(t []byte) (int, error) {
	if len(t) < 8 {
		return 0, errNoOrientation
	}
	var bo binary.ByteOrder
	switch string(t[:2]) {
	case "II":
		bo = binary.LittleEndian
	case "MM":
		bo = binary.BigEndian
	default:
		return 0, errNoOrientation
	}
	if bo.Uint16(t[2:]) != 42 {
		return 0, errNoOrientation
	}
	off := int64(bo.Uint32(t[4:]))
	if off < 8 || off+2 > int64(len(t)) {
		return 0, errNoOrientation
	}
	n := int64(bo.Uint16(t[off:]))
	for k := int64(0); k < n; k++ {
		e := off + 2 + 12*k
		if e+12 > int64(len(t)) {
			break
		}
		if bo.Uint16(t[e:]) != 0x0112 {
			continue
		}
		if bo.Uint16(t[e+2:]) != 3 || bo.Uint32(t[e+4:]) != 1 {
			return 0, errNoOrientation
		}
		o := int(bo.Uint16(t[e+8:]))
		if o < 1 || o > 8 {
			return 0, errNoOrientation
		}
		return o, nil
	}
	return 0, errNoOrientation
}
