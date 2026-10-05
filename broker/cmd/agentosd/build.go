package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"strings"
	"sync/atomic"

	"github.com/ghbmrk/agentos/broker/change"
	"github.com/ghbmrk/agentos/broker/loopbuild"
	"github.com/ghbmrk/agentos/broker/loops"
	"github.com/ghbmrk/agentos/broker/meter"
	"github.com/ghbmrk/agentos/broker/modelroute"
	"github.com/ghbmrk/agentos/broker/vm"
)

// builderShareMax is the most of the spare budget Loop 1's builder
// machines may use, so building never starves evaluation (potency
// C-3c-5: about 30-40%). It reserves nothing.
const builderShareMax = 0.35

// builderShare is the builder machines' share of the spare meter.
func builderShare() meter.Share {
	return meter.Share{Prefix: loopbuild.Prefix, Max: builderShareMax}
}

// errNoBuilder: the box has no builder machines (no -builder-image, or no
// agent machines).
var errNoBuilder = errors.New("loop 1 has no builder machines")

// lateBuild is Loop 1's model-backed builder (W3-builder) once the machine
// plane attaches one. Until then it is never ready, so Loop 1 offers no
// job for its signals and nothing is measured against the loop.
type lateBuild struct {
	b atomic.Pointer[loopbuild.Builder]
}

var (
	_ loops.Builder = (*lateBuild)(nil)
	_ loops.Readier = (*lateBuild)(nil)
	_ loops.Private = (*lateBuild)(nil)
)

func (l *lateBuild) Build(ctx context.Context, br loops.Brief) (change.Candidate, error) {
	b := l.b.Load()
	if b == nil {
		return change.Candidate{}, errNoBuilder
	}
	return b.Build(ctx, br)
}

func (l *lateBuild) Ready(loops.Brief) bool { return l.b.Load() != nil }

// Private: built in a private machine, so never public (C-3c-4).
func (l *lateBuild) Private(loops.Brief) bool { return true }

// builderDenied logs the vault process's refusals of builder machines'
// model calls by status only: the reason text may quote the request.
func builderDenied(logf func(string, ...any)) func(machine string, d modelroute.Denial) {
	return func(machine string, d modelroute.Denial) {
		if strings.HasPrefix(machine, loopbuild.Prefix) {
			logf("builder %s: model call refused (status %d)", machine, d.Status)
		}
	}
}

// buildConfig is Loop 1's builder machine and its model route.
type buildConfig struct {
	Dir   string // builder machines' socket directories
	Image string // the minimal builder image (C-3c-3), registered with -image
	// AgentImage is the agent's image, which the builder never runs
	// (security R2 on #126).
	AgentImage string
	Launch     string // its argv and env; empty: the image's own
	MemMB      int64
	Egress     string // the vault process's model socket; empty: no model access
}

// openBuilder attaches Loop 1's model-backed builder (W3-builder): builder
// machines (loopbuild.Prefix) get its socket and nothing else
// (lateServices.build), and their model calls go to the vault process as
// private (C-3c-6), metered on the spare meter's builder share (C-3c-5).
func (l *learning) openBuilder(m *vm.Manager, imgs images, services *lateServices, c buildConfig) error {
	if _, ok := imgs[c.Image]; !ok {
		return fmt.Errorf("image %q is not registered with -image", c.Image)
	}
	if c.AgentImage != "" && (c.Image == c.AgentImage || imgs[c.Image] == imgs[c.AgentImage]) {
		return fmt.Errorf("builder image %q is the agent's image; the builder runs a minimal image of its own", c.Image)
	}
	cfg := loopbuild.Config{Dir: c.Dir, Machines: m, Image: c.Image, MemMB: c.MemMB, Logf: log.Printf}
	if c.Launch != "" {
		argv, env, err := launchSpec(c.Launch)
		if err != nil {
			return err
		}
		cfg.Argv, cfg.Env = argv, env
	}
	if c.Egress != "" {
		cfg.Model = modelroute.Forward(modelroute.Config{Socket: c.Egress, Label: m.DataLabel, Denied: builderDenied(log.Printf), Logf: log.Printf})
		cfg.Meter = l.spare
	}
	b, err := loopbuild.New(cfg)
	if err != nil {
		return err
	}
	b.Cleanup()
	services.build.Store(&svc{b})
	l.build.b.Store(b)
	return nil
}
