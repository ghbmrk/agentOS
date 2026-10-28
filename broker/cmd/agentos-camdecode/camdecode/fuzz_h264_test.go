//go:build libavcodec

package camdecode

// REQ: NET-2, KRN-2

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/ghbmrk/agentos/broker/camwire"
)

// FuzzH264Feed feeds the sandbox's decoder, libavcodec's H.264 decoder
// included, arbitrary input: seeded with good access units, units of
// another shape and of an oversized coded shape, a truncated unit, a unit
// with its parameter sets dropped or its slice bytes flipped, and video
// interleaved with thermal frames. It must not panic or crash; any
// refusal is one of its own errors; and everything it writes must be
// whole output frames of the declared shapes, thermal ones carrying the
// input's counters, video ones counted from 1 and no more of them than
// the access units in.
func FuzzH264Feed(f *testing.F) {
	good := pcmPicture(fuzzVideo, 0x10, 0x20, 0x30, 0)
	f.Add(videoFrame(good))
	f.Add(append(videoFrame(good), videoFrame(pcmPicture(fuzzVideo, 0x40, 0x50, 0x60, 1))...))
	f.Add(append(append(videoFrame(good), thermalFrame(4, 3, 7)...), videoFrame(good)...))
	f.Add(videoFrame(pcmPicture(camwire.Shape{Width: 6, Height: 8}, 1, 2, 3, 0)))
	f.Add(videoFrame(pcmPicture(camwire.Shape{Width: 128, Height: 128}, 1, 2, 3, 0)))
	f.Add(videoFrame(good[:len(good)/2]))
	slice := bytes.LastIndex(good, []byte{0, 0, 0, 1})
	f.Add(videoFrame(good[slice:]))
	flipped := bytes.Clone(good)
	for i := slice + 6; i < len(flipped); i += 7 {
		flipped[i] ^= 0x5a
	}
	f.Add(videoFrame(flipped))
	f.Fuzz(func(t *testing.T, in []byte) {
		var out bytes.Buffer
		err := Run(bytes.NewReader(in), &out, Config{Video: fuzzVideo, Thermal: fuzzThermal})
		if err != nil && err != ErrStream && err != ErrVideo {
			t.Fatalf("Run = %v", err)
		}
		var units int
		var counters []uint32
		for r := bytes.NewReader(in); ; {
			fr, err := camwire.ReadFrame(r, camwire.ToCore, fuzzThermal)
			if err != nil {
				break
			}
			switch fr.Type {
			case camwire.TypeVideo:
				units++
			case camwire.TypeThermal:
				counters = append(counters, binary.BigEndian.Uint32(fr.Payload[4:]))
			}
		}
		b := out.Bytes()
		var pictures uint32
		for len(b) > 0 {
			if len(b) < HeaderLen {
				t.Fatalf("%d bytes left, short of a header", len(b))
			}
			h := b[:HeaderLen]
			k, s := h[0], fuzzThermal
			if k == KindVideo {
				s = fuzzVideo
			}
			size := HeaderLen + Len(k, s)
			if size == HeaderLen || h[1]|h[2]|h[3] != 0 || binary.BigEndian.Uint16(h[4:]) != s.Width ||
				binary.BigEndian.Uint16(h[6:]) != s.Height || len(b) < size {
				t.Fatalf("header %x with %d bytes left", h, len(b))
			}
			c := binary.BigEndian.Uint32(h[8:])
			if k == KindVideo {
				if pictures++; c != pictures {
					t.Fatalf("picture %d counted %d", pictures, c)
				}
			} else {
				if len(counters) == 0 || c != counters[0] {
					t.Fatalf("thermal counter %d, input's next %v", c, counters)
				}
				counters = counters[1:]
			}
			b = b[size:]
		}
		if int(pictures) > units {
			t.Fatalf("%d pictures out for %d access units in", pictures, units)
		}
	})
}
