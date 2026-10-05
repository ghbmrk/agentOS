package localui

import (
	"bytes"
	"errors"
	"image"
	"image/color"
	_ "image/jpeg" // phone photos
	_ "image/png"  // screenshots
	"io"
	"strings"

	"github.com/makiuchi-d/gozxing"
	multiqr "github.com/makiuchi-d/gozxing/multi/qrcode"
	"github.com/makiuchi-d/gozxing/qrcode"
)

// Scan errors; the page turns each into one owner-facing line.
var (
	ErrNotPhoto  = errors.New("localui: not a JPEG or PNG photo the box can read")
	ErrNoQR      = errors.New("localui: no QR code found")
	ErrWiFiQR    = errors.New("localui: only the Wi-Fi QR code was found")
	ErrManyQR    = errors.New("localui: more than one passphrase-like QR code found")
	ErrScanBusy  = errors.New("localui: another photo is being read")
	ErrPhotoSize = errors.New("localui: photo too large")
)

// Photo bounds. A phone camera photo is a few MB and about 12 MP; the
// bounds keep one upload from exhausting the box's memory, and only one
// photo is read at a time (Server.scan).
const (
	MaxPhotoBytes  = 20 << 20
	MaxPhotoPixels = 24_000_000
	// MaxProgressivePixels bounds a progressive JPEG, whose decoder keeps
	// every coefficient as an int32 until the end (an 8000x6000 4:4:4
	// progressive JPEG of 550 KB peaks at about 700 MB; #50 L3 F1).
	MaxProgressivePixels = 12_000_000
	// scanEdge is the longest side a photo is reduced to before the QR
	// search: a card-sized code is still several pixels per module.
	scanEdge = 2048
)

// ScanPassphrase reads the vault passphrase from a photo of the Owner Card
// (CRED-8: scanned on the local page). The page has no script and plain
// HTTP gets no live camera, so the phone uploads a photo instead. The card
// carries two QR codes, the Wi-Fi join code and the passphrase; the photo
// may hold either or both. A payload with a URI scheme (WIFI:, otpauth:,
// http:) is never the passphrase, which is words only.
func ScanPassphrase(photo []byte) (string, error) {
	cfg, _, err := image.DecodeConfig(bytes.NewReader(photo))
	if err != nil {
		return "", ErrNotPhoto
	}
	px := int64(cfg.Width) * int64(cfg.Height)
	if cfg.Width <= 0 || cfg.Height <= 0 || px > MaxPhotoPixels {
		return "", ErrPhotoSize
	}
	// 16-bit channels (8 bytes a pixel) are refused (#50 security B2),
	// and a progressive JPEG has a lower bound (L3 F1). Phone cameras
	// write baseline JPEGs.
	switch cfg.ColorModel {
	case color.RGBA64Model, color.NRGBA64Model, color.Gray16Model, color.Alpha16Model:
		return "", ErrNotPhoto
	}
	if px > MaxProgressivePixels && progressiveJPEG(photo) {
		return "", ErrPhotoSize
	}
	img, _, err := image.Decode(bytes.NewReader(photo))
	if err != nil {
		return "", ErrNotPhoto
	}
	// Three sizes until a passphrase turns up: the reduced photo, a
	// coarser one (which helps with blur and a code that fills the frame),
	// and a finer one (a small code in a large photo).
	var pass []string
	wifi := false
	seen := map[string]bool{}
	for _, edge := range []int{scanEdge, scanEdge / 2, scanEdge * 3 / 2} {
		for _, t := range decodeQR(gray(img, edge)) {
			if seen[t] {
				continue
			}
			seen[t] = true
			switch {
			case strings.HasPrefix(t, "WIFI:"):
				wifi = true
			case strings.Contains(t, ":") || strings.TrimSpace(t) == "":
				// Some other code; never a passphrase.
			default:
				pass = append(pass, t)
			}
		}
		if len(pass) > 0 {
			break
		}
	}
	switch {
	case len(pass) == 1:
		return pass[0], nil
	case len(pass) > 1:
		return "", ErrManyQR
	case wifi:
		return "", ErrWiFiQR
	}
	return "", ErrNoQR
}

// progressiveJPEG reports whether b is a JPEG whose first frame header is
// progressive (SOF2, SOF6, SOF10 or SOF14). Anything it cannot walk counts
// as progressive, so the lower bound applies.
func progressiveJPEG(b []byte) bool {
	if len(b) < 4 || b[0] != 0xff || b[1] != 0xd8 {
		return false
	}
	for i := 2; i+4 <= len(b); {
		if b[i] != 0xff {
			return true
		}
		m := b[i+1]
		switch {
		case m == 0xff: // fill byte
			i++
			continue
		case m == 0xd8 || m == 0x01 || (m >= 0xd0 && m <= 0xd7):
			i += 2
			continue
		case m == 0xc2 || m == 0xc6 || m == 0xca || m == 0xce:
			return true
		case m >= 0xc0 && m <= 0xcf && m != 0xc4 && m != 0xc8 && m != 0xcc:
			return false
		}
		i += 2 + (int(b[i+2])<<8 | int(b[i+3]))
	}
	return true
}

// decodeQR returns the text of every QR code found in g.
func decodeQR(g *image.Gray) []string {
	src := gozxing.NewLuminanceSourceFromImage(g)
	bmp, err := gozxing.NewBinaryBitmap(gozxing.NewHybridBinarizer(src))
	if err != nil {
		return nil
	}
	hints := map[gozxing.DecodeHintType]interface{}{gozxing.DecodeHintType_TRY_HARDER: true}
	var out []string
	if rs, err := multiqr.NewQRCodeMultiReader().DecodeMultiple(bmp, hints); err == nil {
		for _, r := range rs {
			out = append(out, r.GetText())
		}
	}
	if len(out) == 0 {
		if r, err := qrcode.NewQRCodeReader().Decode(bmp, hints); err == nil {
			out = append(out, r.GetText())
		}
	}
	return out
}

// gray reduces img to grayscale with its longest side at most edge pixels,
// averaging each block so fine print does not alias into noise.
func gray(img image.Image, edge int) *image.Gray {
	b := img.Bounds()
	w, h := b.Dx(), b.Dy()
	f := 1
	for (w+f-1)/f > edge || (h+f-1)/f > edge {
		f++
	}
	ow, oh := (w+f-1)/f, (h+f-1)/f
	// A JPEG decodes to YCbCr, whose Y plane is the luma already.
	luma := func(x, y int) uint8 {
		r, g, bl, _ := img.At(x, y).RGBA()
		// Rec. 601 luma on 16-bit channels.
		return uint8((19595*uint64(r) + 38470*uint64(g) + 7471*uint64(bl) + 1<<15) >> 24)
	}
	if yc, ok := img.(*image.YCbCr); ok {
		luma = func(x, y int) uint8 { return yc.Y[yc.YOffset(x, y)] }
	}
	out := image.NewGray(image.Rect(0, 0, ow, oh))
	for oy := 0; oy < oh; oy++ {
		for ox := 0; ox < ow; ox++ {
			var sum, n uint64
			for y := b.Min.Y + oy*f; y < b.Min.Y+(oy+1)*f && y < b.Max.Y; y++ {
				for x := b.Min.X + ox*f; x < b.Min.X+(ox+1)*f && x < b.Max.X; x++ {
					sum += uint64(luma(x, y))
					n++
				}
			}
			out.Pix[oy*out.Stride+ox] = uint8(sum / n)
		}
	}
	return out
}

// readPhoto reads at most MaxPhotoBytes from r into memory. A multipart
// upload is never spooled to a temporary file, so the photo of the
// passphrase never reaches the drive (CRED-8).
func readPhoto(r io.Reader) ([]byte, error) {
	b, err := io.ReadAll(io.LimitReader(r, MaxPhotoBytes+1))
	if err != nil {
		return nil, err
	}
	if len(b) > MaxPhotoBytes {
		return nil, ErrPhotoSize
	}
	return b, nil
}
