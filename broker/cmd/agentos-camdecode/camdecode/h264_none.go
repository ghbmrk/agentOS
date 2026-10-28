//go:build !libavcodec

package camdecode

import "github.com/ghbmrk/agentos/broker/camwire"

// HasH264 reports whether this build decodes video. Without the
// libavcodec build tag (go test ./..., which has no libavcodec) it does
// not, and a video frame is ErrVideo; image/camdecode.sh builds with it.
const HasH264 = false

type h264 struct{}

func newH264(camwire.Shape) (*h264, error) { return nil, ErrVideo }

func (*h264) feed([]byte, func([]byte) error) error { return ErrVideo }

func (*h264) close() {}
