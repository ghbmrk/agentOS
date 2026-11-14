package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/ghbmrk/agentos/broker/admission"
	"github.com/ghbmrk/agentos/broker/budget"
	"github.com/ghbmrk/agentos/broker/vm"
)

// REQ: RES-2, KRN-7, KRN-2

// VM-wedged-status-owner (#5099): a machine whose kills never end
// (vm.Manager.Wedged) shows in STATUS and on the owner page by count,
// never by internal ID, saying it still counts and that only a restart
// frees it; none, no line and no page note.
func TestWedgedMachinesLine(t *testing.T) {
	var wedged []string
	s := &capState{}
	if got := s.wedgedLine(); got != "" {
		t.Fatalf("machines not open: %q", got)
	}
	if got := s.machineNotes(); got != nil {
		t.Fatalf("page notes, machines not open: %q", got)
	}
	s.machinesWedged(func() []string { return wedged })
	if got := s.wedgedLine(); got != "" {
		t.Fatalf("none wedged: %q", got)
	}
	if got := s.machineNotes(); got != nil {
		t.Fatalf("page notes, none wedged: %q", got)
	}
	wedged = []string{"agent.0"}
	const one = "Machines: one will not stop and still takes room from other machines; restart me."
	if got := s.wedgedLine(); got != one {
		t.Fatalf("one wedged: %q", got)
	}
	if got := s.machineNotes(); !slices.Equal(got, []string{one}) {
		t.Fatalf("page notes, one wedged: %q", got)
	}
	wedged = append(wedged, "helper.3")
	const two = "Machines: 2 will not stop and still take room from other machines; restart me."
	if got := s.wedgedLine(); got != two {
		t.Fatalf("two wedged: %q", got)
	}
	for _, l := range []string{one, two} {
		if err := ownerWorded(l); err != nil {
			t.Errorf("%q: %v", l, err)
		}
		if strings.Contains(l, "agent.0") || strings.Contains(l, "helper") {
			t.Errorf("%q names an internal ID", l)
		}
	}
	// The registry carries it, so STATUS and the digest show it.
	if d := newCapLines(s).Digest(); !slices.Contains(d, two) {
		t.Fatalf("digest %q lacks the wedged line", d)
	}
}

// The seam main opens the machines through wires the wedged line to the
// manager's live list; with nothing wedged it says nothing.
func TestOpenVMWiresWedgedLine(t *testing.T) {
	var m *vm.Manager
	adm, err := admission.New(admission.Config{CapacityMB: 8000}, lateManager{&m})
	must(t, err)
	caps := &capState{}
	m, err = openVM(context.Background(), vm.Config{
		StateDir: t.TempDir(), Images: map[string]string{"base": t.TempDir()},
		Runtime: &sleepRuntime{running: map[string]bool{}}, Admit: adm, NoCgroups: true, NoQuota: true,
		FreeBytes: func(string) (int64, error) { return 1 << 50, nil },
	}, caps, func(string) error { return nil })
	must(t, err)
	if caps.wedged.Load() == nil {
		t.Fatal("the wedged line is not wired to the open machines")
	}
	if got := caps.wedgedLine(); got != "" {
		t.Fatalf("nothing wedged: %q", got)
	}
}

// AGENTOSD-broker-group-status (#5186): a leftover broker group that will
// not go turns the agent off with a line that says a restart clears it,
// not that an update is needed, and names no mechanism. Other causes keep
// the update line.
func TestRES2BrokerGroupStuckSaysRestart(t *testing.T) {
	own := t.TempDir()
	must(t, os.MkdirAll(filepath.Join(own, "broker", "held"), 0o755))
	mem, err := budget.ForHost(7680, 4, budget.Floor())
	must(t, err)
	_, err = openPool(own, mem)
	var stuck *brokerGroupStuck
	if !errors.As(err, &stuck) {
		t.Fatalf("leftover that will not go: %v, want a brokerGroupStuck", err)
	}
	got := agentLimitsLine(err)
	if got != agentLimitsStuck {
		t.Fatalf("status line %q, want %q", got, agentLimitsStuck)
	}
	if !strings.Contains(got, "restart me") || strings.Contains(got, "update") {
		t.Errorf("line %q does not name a restart, or names an update", got)
	}
	for _, mech := range []string{"cgroup", "group", "broker", "kill"} {
		if strings.Contains(got, mech) {
			t.Errorf("line %q names a mechanism (%s)", got, mech)
		}
	}
	if s := (&lateStatus{off: got}).Status(); s != got {
		t.Errorf("STATUS %q", s)
	}
	for _, other := range []error{errNotDelegated, fmt.Errorf("root lacks cpu: %w", errors.New("x"))} {
		if l := agentLimitsLine(other); l != agentNoLimits {
			t.Errorf("%v: line %q, want the update line", other, l)
		}
	}
}

// REV-CHK-links-vm-lstat (#5617): a -machines path agentosd cannot walk
// (a name too long, a directory it may not search) is refused the same
// way on every start, so STATUS gives the setting line, not a restart.
func TestMachinesPathUnreachableIsASettingNotARestart(t *testing.T) {
	open := func(dir string) error {
		var m *vm.Manager
		adm, err := admission.New(admission.Config{CapacityMB: 8000}, lateManager{&m})
		must(t, err)
		_, err = openVM(context.Background(), vm.Config{
			StateDir: dir, Images: map[string]string{"base": t.TempDir()},
			Runtime: &sleepRuntime{running: map[string]bool{}}, Admit: adm, NoCgroups: true, NoQuota: true,
			FreeBytes: func(string) (int64, error) { return 1 << 50, nil },
		}, &capState{}, func(string) error { return nil })
		return err
	}
	err := open(filepath.Join(t.TempDir(), strings.Repeat("n", 300), "machines"))
	if !errors.Is(err, vm.ErrStateDirUnreachable) {
		t.Fatalf("over-long state path: %v, want ErrStateDirUnreachable", err)
	}
	if got := machinesOffLine(err); got != agentMachinesUnsafe {
		t.Fatalf("over-long state path: line %q, want %q", got, agentMachinesUnsafe)
	}
	if os.Geteuid() != 0 {
		shut := filepath.Join(t.TempDir(), "shut")
		must(t, os.MkdirAll(filepath.Join(shut, "inner"), 0o700))
		must(t, os.Chmod(shut, 0))
		t.Cleanup(func() { os.Chmod(shut, 0o700) })
		err := open(filepath.Join(shut, "inner", "machines"))
		if got := machinesOffLine(err); got != agentMachinesUnsafe {
			t.Errorf("unreadable parent (%v): line %q, want %q", err, got, agentMachinesUnsafe)
		}
	}
	if l := machinesOffLine(fmt.Errorf("vm: %w", vm.ErrStateDirUnreachable)); l != agentMachinesUnsafe {
		t.Errorf("wrapped unreachable: %q", l)
	}
	// STATUS-wording-f2 (#5648): one line serves an exposed path and an
	// unwalkable one, so it names neither cause alone ("unsafe place"
	// sends the installer looking for an exposure that is not there).
	const want = "Agent and worker tools: off, I cannot safely use their files; whoever set me up must move them."
	if agentMachinesUnsafe != want {
		t.Errorf("agentMachinesUnsafe %q, want %q", agentMachinesUnsafe, want)
	}
}

// REV-CHK-links-vm-ux (#4976): a -machines path vm.Open refuses is a
// setting to fix, which a restart does not; STATUS says so. Any other
// open failure keeps the restart line. The flag help names the rule.
func TestMachinesPathRefusalIsASettingNotARestart(t *testing.T) {
	var m *vm.Manager
	adm, err := admission.New(admission.Config{CapacityMB: 8000}, lateManager{&m})
	must(t, err)
	_, err = openVM(context.Background(), vm.Config{
		StateDir: "relative/machines", Images: map[string]string{"base": t.TempDir()},
		Runtime: &sleepRuntime{running: map[string]bool{}}, Admit: adm, NoCgroups: true, NoQuota: true,
		FreeBytes: func(string) (int64, error) { return 1 << 50, nil },
	}, &capState{}, func(string) error { return nil })
	if !errors.Is(err, vm.ErrStateDirExposed) {
		t.Fatalf("relative state path: %v, want ErrStateDirExposed", err)
	}
	got := machinesOffLine(err)
	if got != agentMachinesUnsafe {
		t.Fatalf("line %q, want %q", got, agentMachinesUnsafe)
	}
	if strings.Contains(got, fixRestart) {
		t.Errorf("line %q asks for a restart", got)
	}
	if err := ownerWorded(got); err != nil {
		t.Errorf("%q: %v", got, err)
	}
	if l := machinesOffLine(errors.New("runsc failed")); l != agentNoMachines {
		t.Errorf("other failure: %q, want %q", l, agentNoMachines)
	}
	// A fix clause that only says what does not work is refused (UX on
	// #5612): the line names a step that works.
	for _, l := range []string{"Agent and worker tools: off, x; a restart will not fix it.", "Model: off; restarting does not help.",
		// STATUS-wording-f1 (#5632): the house "cannot" and the other
		// clauses that name no step.
		"Model: off; a restart cannot fix it.", "Model: off; restarting does nothing.", "Model: off; a restart is no fix.", "Model: off; nothing helps.",
		// STATUS-wording-f2 (#5667 L3 and Potency F1): inflected verbs,
		// "nothing will <verb>" and every "do nothing" are refused too.
		"Model: off; nothing will fix it.", "Model: off; nothing will help.", "Model: off; restarting will do nothing.",
		"Model: off; you can do nothing.", "Model: off; do nothing.", "Model: off; a restart never works.",
		"Model: off; restarting is not working.", "Model: off; it is not fixable.", "Model: off; a restart is not helpful."} {
		if ownerWorded(l) == nil {
			t.Errorf("ownerWorded accepts %q", l)
		}
	}
	// STATUS-wording-f2 (#5648): a clause that does name a working step
	// is accepted, though it holds a word the refusals use.
	for _, l := range []string{"Model: off; nothing will be lost; restart me.",
		"Model: off; no fixed plan is set; connect one on the setup page.", "Model: off; nothing to do; a later box version adds this."} {
		if err := ownerWorded(l); err != nil {
			t.Errorf("ownerWorded refuses %q: %v", l, err)
		}
	}
	for _, want := range []string{"absolute", "clean", "symbolic link", "root", "group", "sticky"} {
		if !strings.Contains(machinesFlagHelp, want) {
			t.Errorf("-machines help %q lacks %q", machinesFlagHelp, want)
		}
	}
}
