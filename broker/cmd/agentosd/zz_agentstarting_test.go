package main

import (
	"context"
	"fmt"
	"testing"

	"github.com/ghbmrk/agentos/broker/admission"
	"github.com/ghbmrk/agentos/broker/vm"
)

// REQ: CH-12, OWN-17

// noRoomMachines has no agent machine yet and refuses every start for
// memory.
type noRoomMachines struct{}

func (noRoomMachines) Get(id string) (vm.Machine, error) {
	return vm.Machine{}, fmt.Errorf("%w: machine %s", vm.ErrUnknown, id)
}

func (noRoomMachines) Create(context.Context, string, vm.Spec) (vm.Machine, error) {
	return vm.Machine{}, admission.ErrNoRoom
}

func (noRoomMachines) Resume(context.Context, string) error { return admission.ErrNoRoom }

// STATUS during boot says the agent is starting: before the guest plane
// has had its chance to open, and before the keeper's first try returns.
// It never says "not set up" (which asks for a restart) or names a memory
// wait the keeper has not seen (#6176).
func TestAgentStatusDuringBootSaysStarting(t *testing.T) {
	l := newLateStatus("", newCapState(""))
	if got := l.Status(); got != agentStarting {
		t.Fatalf("before the plane opens: %q, want %q", got, agentStarting)
	}

	k := newKeeper(noRoomMachines{}, "agent", testSpec)
	l.k.Store(k)
	l.settle()
	if got := l.Status(); got != agentStarting {
		t.Fatalf("before the keeper's first try: %q, want %q", got, agentStarting)
	}

	k.setStatus(k.ensure(context.Background()))
	if got := l.Status(); got != agentWaiting {
		t.Fatalf("after a try refused for memory: %q, want %q", got, agentWaiting)
	}
}

// Once start-up has had its chance and no keeper was stored, with no cause
// named, STATUS says the agent is not set up: the starting line holds only
// for the start-up window.
func TestAgentStatusAfterBootWithNoKeeperSaysNotSet(t *testing.T) {
	l := newLateStatus("", newCapState(""))
	l.settle()
	if got := l.Status(); got != agentNotSet {
		t.Fatalf("settled, no keeper: %q, want %q", got, agentNotSet)
	}
}

// A cause named before the daemon runs wins over the starting line.
func TestAgentStatusOffWinsOverStarting(t *testing.T) {
	l := newLateStatus(agentNoMachines, nil)
	if got := l.Status(); got != agentNoMachines {
		t.Fatalf("off during boot: %q, want %q", got, agentNoMachines)
	}
}
