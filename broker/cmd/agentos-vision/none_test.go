//go:build !vision_onnx

package main

import "github.com/ghbmrk/agentos/broker/vision"

// noModelsCause is this build's answer with nothing to load: it links no
// runtime.
const noModelsCause = vision.Unavailable
