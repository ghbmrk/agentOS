package camdecode

// REQ: NET-2, KRN-2

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/ghbmrk/agentos/broker/camwire"
)

var (
	fuzzThermal = camwire.Shape{Width: 4, Height: 3}
	fuzzVideo   = camwire.Shape{Width: 8, Height: 6}
)

func thermalFrame(w, h uint16, counter uint32) []byte {
	p := camwire.AppendThermal(nil, camwire.Thermal{Width: w, Height: h, Counter: counter, Samples: make([]byte, 2*int(w)*int(h))})
	out := []byte{byte(camwire.TypeThermal)}
	out = binary.BigEndian.AppendUint32(out, uint32(len(p)))
	return append(out, p...)
}

// FuzzThermalFrame feeds the sandbox's decoder arbitrary input, seeded
// with good thermal frames, a frame of another shape, a truncated one, a
// status frame and a video frame. It must not panic; everything it writes
// must be whole output frames of the declared thermal shape, no more of
// them than the thermal frames in the input, and its counters must be the
// input's; any refusal is one of its own errors.
func FuzzThermalFrame(f *testing.F) {
	good := thermalFrame(4, 3, 1)
	f.Add(good)
	f.Add(append(thermalFrame(4, 3, 1), thermalFrame(4, 3, 2)...))
	f.Add(thermalFrame(3, 4, 1))
	f.Add(good[:len(good)-1])
	f.Add([]byte{byte(camwire.TypeStatus), 0, 0, 0, 1, 0})
	f.Add([]byte{byte(camwire.TypeVideo), 0, 0, 0, 5, 0, 0, 0, 1, 0x65})
	f.Add([]byte{byte(camwire.TypeThermal), 0xff, 0xff, 0xff, 0xff})
	f.Fuzz(func(t *testing.T, in []byte) {
		var out bytes.Buffer
		err := Run(bytes.NewReader(in), &out, Config{Video: fuzzVideo, Thermal: fuzzThermal})
		if err != nil && err != ErrStream && err != ErrVideo {
			t.Fatalf("Run = %v", err)
		}
		size := HeaderLen + Len(KindThermal, fuzzThermal)
		b := out.Bytes()
		if len(b)%size != 0 {
			t.Fatalf("output of %d bytes is not whole %d-byte frames", len(b), size)
		}
		var counters []uint32
		for r := bytes.NewReader(in); ; {
			fr, err := camwire.ReadFrame(r, camwire.ToCore, fuzzThermal)
			if err != nil || fr.Type != camwire.TypeThermal {
				break
			}
			counters = append(counters, binary.BigEndian.Uint32(fr.Payload[4:]))
		}
		if len(b)/size != len(counters) {
			t.Fatalf("%d frames out for %d good thermal frames in", len(b)/size, len(counters))
		}
		for i := 0; i < len(b); i += size {
			h := b[i : i+HeaderLen]
			if h[0] != KindThermal || h[1]|h[2]|h[3] != 0 || binary.BigEndian.Uint16(h[4:]) != fuzzThermal.Width ||
				binary.BigEndian.Uint16(h[6:]) != fuzzThermal.Height || binary.BigEndian.Uint32(h[8:]) != counters[i/size] {
				t.Fatalf("frame %d header %x", i/size, h)
			}
		}
	})
}
