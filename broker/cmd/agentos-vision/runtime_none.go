package main

import (
	"errors"

	"github.com/ghbmrk/agentos/broker/vision"
)

// newRuntime is the runtime adapter. This build has none: every load is
// Unavailable, so the service answers but never detects. VIS-core part (e)
// replaces this file with its own runtime_<name>.go (ASSUMPTIONS VIS-A1).
func newRuntime() Runtime { return noRuntime{} }

type noRuntime struct{}

var errNoRuntime = errors.New("no runtime in this build")

func (noRuntime) Load() (Model, error)                   { return Model{}, errNoRuntime }
func (noRuntime) Detect(vision.Frame) ([]Seen, error)    { return nil, errNoRuntime }
func (noRuntime) Encode(vision.Frame) ([]float32, error) { return nil, errNoRuntime }
func (noRuntime) Sound([]byte) ([]vision.Sound, error)   { return nil, errNoRuntime }
