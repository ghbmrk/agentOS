package main

import "errors"

// newRuntime is the runtime adapter. This build has none: every load is
// Unavailable, so the service answers but never embeds. The runtime of
// INFER-SVC Q1 replaces this file with its own runtime_<name>.go
// (ASSUMPTIONS INFER-A1).
func newRuntime(path string) Runtime { return noRuntime{} }

type noRuntime struct{}

var errNoRuntime = errors.New("no runtime in this build")

func (noRuntime) Load(string) (int, error)            { return 0, errNoRuntime }
func (noRuntime) Embed([]string) ([][]float32, error) { return nil, errNoRuntime }
