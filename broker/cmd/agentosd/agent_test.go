package main

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/admission"
	"github.com/ghbmrk/agentos/broker/vm"
)

// REQ: RES-1, REV-5

// fakeMachines records what the keeper asked of the machine manager.
type fakeMachines struct {
	mu      sync.Mutex
	m       map[string]vm.Machine
	refuse  int // admissions to refuse before one succeeds
	created []vm.Spec
	resumed int
}

func (f *fakeMachines) Get(id string) (vm.Machine, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	mc, ok := f.m[id]
	if !ok {
		return vm.Machine{}, fmt.Errorf("%w: machine %s", vm.ErrUnknown, id)
	}
	return mc, nil
}

func (f *fakeMachines) admit() error {
	if f.refuse > 0 {
		f.refuse--
		return errors.New("admission: no memory")
	}
	return nil
}

func (f *fakeMachines) Create(_ context.Context, id string, s vm.Spec) (vm.Machine, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.admit(); err != nil {
		return vm.Machine{}, err
	}
	f.created = append(f.created, s)
	mc := vm.Machine{ID: id, Spec: s, Label: s.Label, State: vm.Running}
	f.m[id] = mc
	return mc, nil
}

func (f *fakeMachines) Resume(_ context.Context, id string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.admit(); err != nil {
		return err
	}
	mc := f.m[id]
	mc.State = vm.Running
	f.m[id] = mc
	f.resumed++
	return nil
}

var agentSpec = vm.Spec{Image: "openclaw", Class: admission.Foreground, MemMB: 1536, Argv: []string{"/bridge"}, Label: vm.Public}

// The owner's agent machine is created on first start as foreground work
// (RES-1: owner chat), labelled public until owner data reaches it (REV-5),
// and with no seed, which only private machines may take (compile K7).
func TestRES1AgentMachineCreatedOnFirstStart(t *testing.T) {
	f := &fakeMachines{m: map[string]vm.Machine{}}
	k := &keeper{m: f, id: "agent", spec: agentSpec}
	if err := k.ensure(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(f.created) != 1 || f.created[0].Class != admission.Foreground || f.created[0].Label != vm.Public {
		t.Fatalf("created %+v", f.created)
	}
	// Running: nothing more to do.
	if err := k.ensure(context.Background()); err != nil || len(f.created) != 1 || f.resumed != 0 {
		t.Fatalf("second ensure: %v, created %d, resumed %d", err, len(f.created), f.resumed)
	}
}

// After a broker restart machines come back stopped, and a preempted one
// stays down until something resumes it (P1-4 follow-up): the keeper resumes
// the agent machine on its layer and keeps its label, never re-creating it.
func TestRES1AgentMachineResumedAfterRestartOrPreemption(t *testing.T) {
	for _, st := range []vm.State{vm.Stopped, vm.Preempted} {
		f := &fakeMachines{m: map[string]vm.Machine{"agent": {ID: "agent", Spec: agentSpec, Label: vm.Private, State: st}}}
		k := &keeper{m: f, id: "agent", spec: agentSpec}
		if err := k.ensure(context.Background()); err != nil {
			t.Fatal(err)
		}
		if f.resumed != 1 || len(f.created) != 0 || f.m["agent"].Label != vm.Private {
			t.Fatalf("%s: resumed %d, created %d, label %v", st, f.resumed, len(f.created), f.m["agent"].Label)
		}
	}
}

// Admission may refuse while other work holds memory; the keeper tries
// again on its next tick and logs the failure once, then the recovery.
func TestRES1AgentMachineRetriedUntilAdmitted(t *testing.T) {
	f := &fakeMachines{m: map[string]vm.Machine{}, refuse: 3}
	var mu sync.Mutex
	var logs []string
	k := &keeper{m: f, id: "agent", spec: agentSpec, every: time.Millisecond, logf: func(format string, args ...any) {
		mu.Lock()
		logs = append(logs, fmt.Sprintf(format, args...))
		mu.Unlock()
	}}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { k.run(ctx); close(done) }()
	deadline := time.After(5 * time.Second)
	for {
		if mc, err := f.Get("agent"); err == nil && mc.State == vm.Running {
			break
		}
		select {
		case <-deadline:
			t.Fatal("agent machine never started")
		case <-time.After(time.Millisecond):
		}
	}
	cancel()
	<-done
	mu.Lock()
	defer mu.Unlock()
	if len(logs) != 2 {
		t.Fatalf("logs = %q, want one failure and one recovery", logs)
	}
}

// The launch file the guest rig ships is what agentosd reads.
func TestAgentLaunchSpecReadsTheGuestRig(t *testing.T) {
	argv, env, err := launchSpec("../../../guest/openclaw/launch.json")
	if err != nil {
		t.Fatal(err)
	}
	if argv[0] != "/usr/local/bin/agentos-guest-bridge" || len(env) == 0 {
		t.Fatalf("argv %q env %q", argv, env)
	}
}
