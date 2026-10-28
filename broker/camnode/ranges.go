package camnode

import (
	"errors"

	"github.com/ghbmrk/agentos/broker/camwire"
)

// Resolution is one sensor mode.
type Resolution struct{ Width, Height uint16 }

// Ranges are the settings this node's hardware takes, declared by its
// image. A bundle outside them is refused before it reaches a source or the
// element's counter (TestSettingsWithinDeclaredRanges).
type Ranges struct {
	Resolutions      []Resolution
	MaxFPS           uint8
	MinKbps, MaxKbps uint32
	IR               bool // an IR illuminator is fitted
}

// ErrRange is a bundle whose settings this node cannot take.
var ErrRange = errors.New("camnode: settings outside the node's declared ranges")

// check reports whether s is within r. thermal is the declared thermal core
// (the zero Shape: none fitted).
func (r Ranges) check(s camwire.Settings, thermal camwire.Shape) error {
	ok := false
	for _, res := range r.Resolutions {
		ok = ok || (res.Width == s.Width && res.Height == s.Height)
	}
	switch {
	case !ok,
		s.FPS == 0, s.FPS > r.MaxFPS,
		s.BitrateKbps < r.MinKbps, s.BitrateKbps > r.MaxKbps,
		s.IR != camwire.IROff && !r.IR,
		s.Thermal && thermal == (camwire.Shape{}):
		return ErrRange
	}
	return nil
}
