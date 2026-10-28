// Package camdecode is the camera decoder that runs only inside
// agentos-camdecode, in a camera's gVisor sandbox (CAM-clerk part b,
// #3514; SPEC NET-2 Cameras, DEV-7). It reads camwire frames, as the clerk
// passed them on unparsed, and writes raw frames of the shapes the node's
// bundle declares, never shapes the stream names. The clerk trusts none of
// it: it checks each output frame's header and length against those
// shapes (broker/clerk/camera decode.go). The clerk must not import this
// package: it links libavcodec (h264.go).
package camdecode

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/ghbmrk/agentos/broker/camwire"
)

// Output kinds: the first byte of an output frame's header.
const (
	// KindVideo is one decoded picture in I420 planes: Y, then U and V
	// at half width and height, each rounded up.
	KindVideo byte = 1
	// KindThermal is one thermal frame's width×height big-endian 16-bit
	// samples, row by row.
	KindThermal byte = 2
)

// HeaderLen is an output frame's header: kind (1 byte), three zero bytes,
// width and height (2 bytes each) and a counter (4 bytes), big-endian.
// The pixels follow, exactly Len(kind, shape) bytes of them.
const HeaderLen = 12

// MaxVideoSide bounds a declared video shape's sides, so one decoded
// picture is at most 24 MiB.
const MaxVideoSide = 4096

// Len is the pixel length of one output frame of kind k and shape s, or
// 0 for an unknown kind.
func Len(k byte, s camwire.Shape) int {
	w, h := int(s.Width), int(s.Height)
	switch k {
	case KindVideo:
		return w*h + 2*((w+1)/2)*((h+1)/2)
	case KindThermal:
		return 2 * w * h
	}
	return 0
}

// Config is the shapes the node's bundle declares. A zero Thermal declares
// no thermal core.
type Config struct{ Video, Thermal camwire.Shape }

// The decoder's refusals. Each ends the run with its exit code.
var (
	ErrUsage  = errors.New("usage")
	ErrStream = errors.New("stream")
	ErrVideo  = errors.New("video")
	ErrWrite  = errors.New("write")
)

// ExitCode is the process exit code for an error Run returned.
func ExitCode(err error) int {
	switch {
	case err == nil:
		return 0
	case errors.Is(err, ErrUsage):
		return 2
	case errors.Is(err, ErrStream):
		return 10
	case errors.Is(err, ErrVideo):
		return 11
	}
	return 12
}

// ParseArgs reads "-video WxH -thermal WxH", both required and in that
// order. Video sides are 1..MaxVideoSide; thermal is 0x0 or a shape the
// camera wire accepts.
func ParseArgs(args []string) (Config, error) {
	if len(args) != 4 || args[0] != "-video" || args[2] != "-thermal" {
		return Config{}, ErrUsage
	}
	v, ok1 := shape(args[1])
	t, ok2 := shape(args[3])
	if !ok1 || !ok2 || v.Width == 0 || v.Height == 0 || v.Width > MaxVideoSide || v.Height > MaxVideoSide {
		return Config{}, ErrUsage
	}
	if t != (camwire.Shape{}) && (t.Width == 0 || t.Height == 0 ||
		camwire.ThermalHeaderLen+2*int(t.Width)*int(t.Height) > camwire.MaxThermal) {
		return Config{}, ErrUsage
	}
	return Config{Video: v, Thermal: t}, nil
}

// Args is ParseArgs's inverse.
func Args(c Config) []string {
	return []string{"-video", dims(c.Video), "-thermal", dims(c.Thermal)}
}

func dims(s camwire.Shape) string { return fmt.Sprintf("%dx%d", s.Width, s.Height) }

func shape(s string) (camwire.Shape, bool) {
	a, b, ok := strings.Cut(s, "x")
	if !ok {
		return camwire.Shape{}, false
	}
	w, err1 := strconv.ParseUint(a, 10, 16)
	h, err2 := strconv.ParseUint(b, 10, 16)
	if err1 != nil || err2 != nil || a != strconv.FormatUint(w, 10) || b != strconv.FormatUint(h, 10) {
		return camwire.Shape{}, false
	}
	return camwire.Shape{Width: uint16(w), Height: uint16(h)}, true
}

// AppendHeader appends an output frame's header.
func AppendHeader(dst []byte, k byte, s camwire.Shape, counter uint32) []byte {
	dst = append(dst, k, 0, 0, 0)
	dst = binary.BigEndian.AppendUint16(dst, s.Width)
	dst = binary.BigEndian.AppendUint16(dst, s.Height)
	return binary.BigEndian.AppendUint32(dst, counter)
}

// Run decodes frames from in until it ends, writing one output frame per
// thermal input and one per decoded picture. A frame the camera wire
// refuses, or a status frame, is ErrStream. A decoder error, a picture of
// another shape, or more pictures than access units in, is ErrVideo; so
// is any video in a build without the H.264 decoder (HasH264). Video
// output frames are counted from 1 here: an access unit carries no
// counter. A clean end of input flushes the decoder and is nil.
func Run(in io.Reader, out io.Writer, c Config) error {
	w := bufio.NewWriterSize(out, 1<<16)
	hdr := make([]byte, 0, HeaderLen)
	var dec *h264
	defer func() {
		if dec != nil {
			dec.close()
		}
	}()
	var units, pictures uint32
	picture := func(i420 []byte) error {
		if pictures == units {
			return ErrVideo
		}
		pictures++
		return writeFrame(w, AppendHeader(hdr[:0], KindVideo, c.Video, pictures), i420)
	}
	for {
		f, err := camwire.ReadFrame(in, camwire.ToCore, c.Thermal)
		if err == io.EOF {
			if dec == nil {
				return nil
			}
			return dec.feed(nil, picture)
		}
		if err != nil {
			return ErrStream
		}
		switch f.Type {
		case camwire.TypeThermal:
			th, err := camwire.ParseThermal(f.Payload, c.Thermal)
			if err != nil {
				return ErrStream
			}
			if err := writeFrame(w, AppendHeader(hdr[:0], KindThermal, c.Thermal, th.Counter), th.Samples); err != nil {
				return err
			}
		case camwire.TypeVideo:
			if dec == nil {
				if dec, err = newH264(c.Video); err != nil {
					return err
				}
			}
			units++
			if err := dec.feed(f.Payload, picture); err != nil {
				return err
			}
		default:
			return ErrStream
		}
	}
}

// writeFrame writes one output frame and flushes it, so the clerk sees
// each frame as soon as it is decoded.
func writeFrame(w *bufio.Writer, hdr, pixels []byte) error {
	if _, err := w.Write(hdr); err != nil {
		return ErrWrite
	}
	if _, err := w.Write(pixels); err != nil {
		return ErrWrite
	}
	if err := w.Flush(); err != nil {
		return ErrWrite
	}
	return nil
}
