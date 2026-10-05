package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/ghbmrk/agentos/broker/vm"
)

// liveMachines is the part of the machine manager that keeps the owner's
// agent machine up.
type liveMachines interface {
	Get(id string) (vm.Machine, error)
	Create(ctx context.Context, id string, s vm.Spec) (vm.Machine, error)
	Resume(ctx context.Context, id string) error
}

// keeper keeps the machine that receives the owner's task chat running
// (ARC-4, RES-1). On a first start it creates the machine, labelled public
// until owner data reaches it (REV-5: an owner message not marked public
// raises it). After a broker restart, or if the machine is found stopped or
// preempted, it resumes it on its layer; the guest plane then hands it the
// unanswered owner messages again (guest G5). A machine that already exists
// keeps its image: moving it to a new one is the update path's, not this.
// The machine is created without a seed: the managed tree reaches only
// private machines (vm.ErrSeedLabel, compile K7).
type keeper struct {
	m     liveMachines
	id    string
	spec  vm.Spec
	every time.Duration
	logf  func(format string, args ...any)
}

// ensure brings the machine to running, or says why it is not.
func (k *keeper) ensure(ctx context.Context) error {
	mc, err := k.m.Get(k.id)
	switch {
	case errors.Is(err, vm.ErrUnknown):
		_, err = k.m.Create(ctx, k.id, k.spec)
		return err
	case err != nil:
		return err
	case mc.State == vm.Running:
		return nil
	default:
		return k.m.Resume(ctx, k.id)
	}
}

// run calls ensure now and then every k.every until ctx ends. Admission may
// refuse while other work holds memory, so a failure is retried on the next
// tick; the log gets each distinct failure once, and the recovery.
func (k *keeper) run(ctx context.Context) {
	t := time.NewTicker(k.every)
	defer t.Stop()
	last := ""
	for {
		err := k.ensure(ctx)
		switch {
		case err != nil && err.Error() != last:
			last = err.Error()
			k.logf("agent machine %s not running: %v", k.id, err)
		case err == nil && last != "":
			last = ""
			k.logf("agent machine %s running", k.id)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// launchSpec reads how the agent machine starts (vm.Spec Argv and Env),
// as guest/openclaw/launch.json records it.
func launchSpec(path string) (argv, env []string, err error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}
	var l struct{ Argv, Env []string }
	if err := json.Unmarshal(b, &l); err != nil {
		return nil, nil, fmt.Errorf("%s: %w", path, err)
	}
	if len(l.Argv) == 0 {
		return nil, nil, fmt.Errorf("%s: no argv", path)
	}
	return l.Argv, l.Env, nil
}
