package capture

import (
	"encoding/binary"
	"errors"
	"io"

	"github.com/ghbmrk/agentos/broker/camwire"
)

// VoSPI, the Lepton's video over SPI (FLIR Lepton engineering datasheet,
// "VoSPI"): 164-byte packets of a 2-byte ID, a 2-byte CRC and 160 bytes of
// payload, 80 raw14 pixels big-endian. A packet whose ID has 0xF in its
// second nibble is a discard packet. A Lepton 2 frame (80×60) is 60
// packets, one row each; a Lepton 3 frame (160×120) is four segments of 60
// packets, two per row, whose segment number (1 to 4) is in packet 20's
// ID, bits 14 to 12 (ASSUMPTIONS CAM-capture-3).
const (
	packetLen      = 164
	packetPayload  = 160
	packetsPerSeg  = 60
	segmentPacket  = 20
	discardMask    = 0x0F00
	packetNumMask  = 0x0FFF
	segmentShift   = 12
	segmentMask    = 0x7
	lepton3Segment = 4
)

// Lepton shapes.
var (
	Lepton2 = camwire.Shape{Width: 80, Height: 60}
	Lepton3 = camwire.Shape{Width: 160, Height: 120}
)

// ErrShape is a Lepton reader asked for a shape no Lepton has.
var ErrShape = errors.New("capture: not a Lepton frame shape")

// Lepton reads whole frames from a VoSPI byte source (spidev on the board;
// generated packets in tests). A packet that fails its CRC or arrives out
// of order drops the frame being gathered and resynchronises at the next
// packet 0, so a torn frame never reaches the core.
type Lepton struct {
	r       io.Reader
	shape   camwire.Shape
	counter uint32
	pkt     [packetLen]byte
}

// NewLepton reads frames of shape (Lepton2 or Lepton3) from r.
func NewLepton(r io.Reader, shape camwire.Shape) (*Lepton, error) {
	if shape != Lepton2 && shape != Lepton3 {
		return nil, ErrShape
	}
	return &Lepton{r: r, shape: shape}, nil
}

// segments is the number of segments per frame.
func (l *Lepton) segments() int {
	if l.shape == Lepton3 {
		return lepton3Segment
	}
	return 1
}

// Next is the next whole frame as a camwire thermal payload.
func (l *Lepton) Next() ([]byte, error) {
	samples := make([]byte, 2*int(l.shape.Width)*int(l.shape.Height))
	segLen := packetsPerSeg * packetPayload
	seg, want := 0, 0 // the segment being gathered (0-based) and the packet expected next
	for {
		if _, err := io.ReadFull(l.r, l.pkt[:]); err != nil {
			return nil, err
		}
		id := binary.BigEndian.Uint16(l.pkt[0:2])
		if id&discardMask == discardMask {
			continue
		}
		if !vospiCRCOK(l.pkt[:]) {
			seg, want = 0, 0
			continue
		}
		num := int(id & packetNumMask)
		if num != want {
			seg, want = 0, 0
			if num != 0 {
				continue
			}
		}
		if num == segmentPacket && l.segments() > 1 {
			// Segment 0 is invalid: the core is between frames.
			s := int(id>>segmentShift) & segmentMask
			if s != seg+1 {
				seg, want = 0, 0
				continue
			}
		}
		copy(samples[seg*segLen+num*packetPayload:], l.pkt[4:])
		want++
		if want < packetsPerSeg {
			continue
		}
		seg, want = seg+1, 0
		if seg < l.segments() {
			continue
		}
		l.counter++
		return camwire.AppendThermal(nil, camwire.Thermal{Width: l.shape.Width, Height: l.shape.Height, Counter: l.counter, Samples: samples}), nil
	}
}

// vospiCRCOK checks a packet's CRC: CRC-16-CCITT (polynomial 0x1021,
// initial value 0) over the whole packet with the ID's top four bits and
// the CRC field zeroed.
func vospiCRCOK(p []byte) bool {
	want := binary.BigEndian.Uint16(p[2:4])
	return vospiCRC(p) == want
}

func vospiCRC(p []byte) uint16 {
	q := append([]byte{}, p...)
	q[0] &= 0x0F
	q[2], q[3] = 0, 0
	return crcXMODEM(q)
}

// crcXMODEM is CRC-16/XMODEM: polynomial 0x1021, initial value 0, no
// reflection. Check value: "123456789" gives 0x31C3.
func crcXMODEM(p []byte) uint16 {
	var c uint16
	for _, b := range p {
		c ^= uint16(b) << 8
		for range 8 {
			if c&0x8000 != 0 {
				c = c<<1 ^ 0x1021
			} else {
				c <<= 1
			}
		}
	}
	return c
}
