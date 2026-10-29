//go:build !vision_onnx

package main

import (
	"errors"

	"github.com/ghbmrk/agentos/broker/vision"
)

// newRuntime is the runtime adapter. This build has none: every load is
// Unavailable, so the service answers but never detects. Built with
// -tags vision_onnx, runtime_onnx.go is the adapter instead (VIS-A1,
// VIS-A27).
func newRuntime(string, int) Runtime { return noRuntime{} }

type noRuntime struct{}

var errNoRuntime = errors.New("no runtime in this build")

func (noRuntime) Load() (Model, error)                      { return Model{}, errNoRuntime }
func (noRuntime) Detect(vision.Frame, bool) ([]Seen, error) { return nil, errNoRuntime }
func (noRuntime) Encode(vision.Frame) ([]float32, error)    { return nil, errNoRuntime }
func (noRuntime) Sound([]byte) ([]vision.Sound, error)      { return nil, errNoRuntime }
