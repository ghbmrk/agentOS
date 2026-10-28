// Package capture is the camera node's capture behind camnode.Source
// (CAM-node part b2, #3513; brief design point 5): H.264 access units from
// the board's hardware encoder, read from rpicam-vid's output pipe, and
// thermal frames from a FLIR Lepton class core over SPI (VoSPI). It opens
// no socket (TestCaptureOpensNoSocket); it starts one child, the encoder.
package capture

import (
	"bufio"
	"errors"
	"io"

	"github.com/ghbmrk/agentos/broker/camwire"
)

// ErrAccessUnit is an access unit over camwire.MaxVideo, or a stream that
// does not open with a start code.
var ErrAccessUnit = errors.New("capture: H.264 stream malformed or access unit over its cap")

// AccessUnits splits an H.264 Annex B byte stream into access units (ITU-T
// H.264 §7.4.1.2.3, as one encoder writes them): an access unit ends where
// a NAL unit that must open the next one starts, after a picture's slice.
// That is an access unit delimiter, SPS, PPS or SEI, or a slice whose
// first_mb_in_slice is 0. Each access unit is returned in Annex B form,
// start codes kept, so camwire.WriteFrame takes it as is.
type AccessUnits struct {
	r       *bufio.Reader
	au      []byte // the access unit being gathered
	slice   bool   // au holds a picture's slice
	pending []byte // a NAL unit read that opens the next access unit
	started bool
}

// NewAccessUnits reads r.
func NewAccessUnits(r io.Reader) *AccessUnits {
	return &AccessUnits{r: bufio.NewReaderSize(r, 64<<10)}
}

// Next is the next whole access unit. io.EOF ends a stream cleanly; the
// last access unit is returned before it.
func (a *AccessUnits) Next() ([]byte, error) {
	for {
		nal := a.pending
		a.pending = nil
		if nal == nil {
			var err error
			if nal, err = a.nal(); err == io.EOF && a.slice {
				out := a.au
				a.au, a.slice = nil, false
				return out, nil
			} else if err != nil {
				return nil, err
			}
		}
		if len(nal) < 4 {
			continue // an empty NAL unit: nothing to keep
		}
		t := nal[3] & 0x1F
		vcl := t == 1 || t == 5
		opens := t == 9 || t == 7 || t == 8 || t == 6 || (vcl && len(nal) > 4 && nal[4]&0x80 != 0)
		if a.slice && opens {
			out := a.au
			a.au, a.slice, a.pending = nil, false, nal
			return out, nil
		}
		if len(a.au)+len(nal) > camwire.MaxVideo {
			return nil, ErrAccessUnit
		}
		a.au = append(a.au, nal...)
		a.slice = a.slice || vcl
	}
}

// nal reads one NAL unit with a 3-byte start code before it. Zero bytes
// before the next start code are trailing_zero_8bits (or a 4-byte start
// code's first byte) and are dropped: a NAL unit's payload ends with its
// stop bit, so it never ends in a zero byte.
func (a *AccessUnits) nal() ([]byte, error) {
	if !a.started {
		// The stream opens with a start code: zero bytes, then 1.
		zeros := 0
		for {
			b, err := a.r.ReadByte()
			if err != nil {
				return nil, err
			}
			if b == 0 {
				zeros++
				continue
			}
			if b != 1 || zeros < 2 {
				return nil, ErrAccessUnit
			}
			break
		}
		a.started = true
	}
	out := []byte{0, 0, 1}
	zeros := 0
	for {
		b, err := a.r.ReadByte()
		if err == io.EOF {
			if out = trimZeros(out); len(out) == 3 {
				return nil, io.EOF
			}
			return out, nil
		}
		if err != nil {
			return nil, err
		}
		if b == 1 && zeros >= 2 {
			// A start code: drop its zeros from this unit.
			return trimZeros(out), nil
		}
		if b == 0 {
			zeros++
		} else {
			zeros = 0
		}
		if len(out) > camwire.MaxVideo {
			return nil, ErrAccessUnit
		}
		out = append(out, b)
	}
}

// trimZeros drops trailing zero bytes after a NAL unit's 3-byte start code.
func trimZeros(nal []byte) []byte {
	for len(nal) > 3 && nal[len(nal)-1] == 0 {
		nal = nal[:len(nal)-1]
	}
	return nal
}
