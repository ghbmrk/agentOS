package camnode

import (
	"errors"

	"github.com/ghbmrk/agentos/broker/camwire"
)

// Mode is one sensor mode the node's camera supports: a resolution and the
// highest frame rate at it.
type Mode struct {
	Width, Height uint16
	MaxFPS        uint8
}

// Ranges are the node's declared ranges: what its hardware can do, fixed
// in its image (part c). A bundle's settings must fall inside them before
// any of it reaches a source or the element's counter.
type Ranges struct {
	Modes          []Mode
	MinBitrateKbps uint32
	MaxBitrateKbps uint32
	IR             bool          // an IR illuminator is fitted
	Thermal        camwire.Shape // the thermal core's shape; zero for none
}

// ErrRange is settings outside the node's declared ranges.
var ErrRange = errors.New("camnode: settings outside the node's declared ranges")

// Check reports whether s is inside r.
func (r Ranges) Check(s camwire.Settings) error {
	mode := false
	for _, m := range r.Modes {
		if m.Width == s.Width && m.Height == s.Height && s.FPS <= m.MaxFPS {
			mode = true
			break
		}
	}
	switch {
	case !mode:
		return ErrRange
	case s.BitrateKbps < r.MinBitrateKbps, s.BitrateKbps > r.MaxBitrateKbps:
		return ErrRange
	case s.IR != camwire.IROff && !r.IR:
		return ErrRange
	case s.Thermal && r.Thermal == (camwire.Shape{}):
		return ErrRange
	}
	return nil
}
