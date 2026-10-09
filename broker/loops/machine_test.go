package loops

// REQ: LOOP-7, LOOP-9

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

// A synthetic canary planted in the broker-held targets: no report, text
// or evidence may carry it, nor the targets' host paths.
const plantedCanary = "CANARY-tamper-7f3a91c0-synthetic"

type noted struct{ machine, target string }

// tamperRig is a probe over three broker-held targets in a temporary
// directory; attempt stands in for the guest's scripted writes.
type tamperRig struct {
	dir    string
	probe  *TamperProbe
	notes  []noted
	paths  [][]string
	nonces []string
}

func newTamperRig(t *testing.T, attempt func(nonce string, paths []string) error) *tamperRig {
	t.Helper()
	x := &tamperRig{dir: t.TempDir()}
	snap := filepath.Join(x.dir, "snapshots", "m1-1")
	for _, d := range []string{snap, filepath.Join(x.dir, "suite")} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for p, s := range map[string]string{
		filepath.Join(snap, "meta.json"):                plantedCanary,
		filepath.Join(x.dir, "suite", "cases.json"):     "[]",
		filepath.Join(x.dir, "grader.json"):             `{"pass":0.5}`,
		filepath.Join(x.dir, "snapshots", "index.json"): "{}",
	} {
		if err := os.WriteFile(p, []byte(s), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	x.probe = &TamperProbe{
		Interval: time.Hour,
		Targets: []TamperTarget{
			{Name: "snapshots", Path: filepath.Join(x.dir, "snapshots")},
			{Name: "evaluator", Path: filepath.Join(x.dir, "suite")},
			{Name: "grader", Path: filepath.Join(x.dir, "grader.json"), Guest: []string{"/run/agentos/grader.json"}},
		},
		Attempt: func(_ context.Context, nonce string, paths []string) (string, error) {
			x.paths = append(x.paths, paths)
			x.nonces = append(x.nonces, nonce)
			return "probe-1", attempt(nonce, paths)
		},
		Journal: func(machine, target string) error {
			x.notes = append(x.notes, noted{machine, target})
			return nil
		},
	}
	return x
}

// LOOP-7 (tamper), clean run: the guest's writes changed no broker-held
// target, so nothing is reported, each refusal is journaled once per
// target, and every target counts as checked.
func TestATamperRoundThatChangesNothingReportsNothingAndJournalsEachRefusal(t *testing.T) {
	x := newTamperRig(t, func(string, []string) error { return nil })
	res, err := x.probe.Run(context.Background())
	if err != nil || len(res.Found) != 0 {
		t.Fatalf("%+v %v", res, err)
	}
	if got := strings.Join(res.Checked, ","); got != "snapshots,evaluator,grader" {
		t.Fatalf("checked %q", got)
	}
	want := []noted{{"probe-1", "snapshots"}, {"probe-1", "evaluator"}, {"probe-1", "grader"}}
	if len(x.notes) != len(want) {
		t.Fatalf("notes %v", x.notes)
	}
	for i := range want {
		if x.notes[i] != want[i] {
			t.Fatalf("notes %v", x.notes)
		}
	}
	// The guest is asked to write each target where it might reach it.
	if len(x.paths) != 1 {
		t.Fatal(x.paths)
	}
	for _, tg := range x.probe.Targets {
		n := 0
		for _, p := range x.paths[0] {
			if strings.HasSuffix(p, tg.Path) {
				n++
			}
		}
		if n < 2 {
			t.Fatalf("target %s tried by %d paths: %v", tg.Name, n, x.paths[0])
		}
	}
	if !slices.Contains(x.paths[0], "/run/agentos/grader.json") {
		t.Fatalf("a guest path was not tried: %v", x.paths[0])
	}
}

// LOOP-7 (tamper), a target that stays writable: the guest writes the
// round's marker the way the fixed script does, so a write that lands
// again with the script's own bytes still changes the target. Each round
// reports it and none journals a refusal (L3 #548 point 1).
func TestATargetThatStaysWritableIsReportedEveryRound(t *testing.T) {
	var x *tamperRig
	x = newTamperRig(t, func(nonce string, _ []string) error {
		return os.WriteFile(filepath.Join(x.dir, "grader.json"), []byte("agentos-tamper-probe "+nonce+"\n"), 0o600)
	})
	for round := 1; round <= 2; round++ {
		res, err := x.probe.Run(context.Background())
		if err != nil || len(res.Found) != 1 || res.Found[0].Subject != "grader" {
			t.Fatalf("round %d: %+v %v", round, res, err)
		}
	}
	for _, n := range x.notes {
		if n.target == "grader" {
			t.Fatalf("a refusal was journaled for a writable target: %v", x.notes)
		}
	}
	if len(x.nonces) != 2 || x.nonces[0] == x.nonces[1] || !tamperNonce.MatchString(x.nonces[0]) {
		t.Fatalf("round nonces %q", x.nonces)
	}
}

// LOOP-7 control (a writable snapshot in a test rig): a write that lands
// in a broker-held target is a High finding through Report, named by the
// target's owner word; the evidence, text and notes carry neither the
// planted canary nor the host path, and no refusal is journaled for it.
func TestAWritableSnapshotReportsATamperFindingThroughReport(t *testing.T) {
	var x *tamperRig
	x = newTamperRig(t, func(string, []string) error {
		return os.WriteFile(filepath.Join(x.dir, "snapshots", "m1-1", "meta.json"), []byte("tampered"), 0o600)
	})
	r := newReportRig(t, nil)
	r.probes = []Probe{x.probe}
	r.reopen(t)
	ctx := context.Background()
	runJob(t, r.g, ctx) // the passive pass
	name, res := runJob(t, r.g, ctx)
	if name != "probe:tamper" || res.Err != nil || res.Value != 1 {
		t.Fatalf("job %q: %+v", name, res)
	}
	id := findingID(CheckTamper, "snapshots", "writable")
	rec, open := r.open(id)
	if !open || !rec.Reported || rec.Finding.Severity != High {
		t.Fatalf("not reported: %+v", rec)
	}
	for _, n := range x.notes {
		if n.target == "snapshots" {
			t.Fatalf("a refusal was journaled for a target the guest changed: %v", x.notes)
		}
	}
	if len(r.texts) != 1 || !strings.Contains(r.texts[0], "snapshots") {
		t.Fatalf("texts %q", r.texts)
	}
	all := strings.Join(r.texts, "\n") + r.g.Status()
	for _, e := range r.g.Evidence() {
		all += e.Finding.Subject + e.Finding.Detail + e.Finding.ID
	}
	for _, bad := range []string{plantedCanary, x.dir} {
		if strings.Contains(all, bad) {
			t.Fatalf("report carries %q: %s", bad, all)
		}
	}
	// The next round that finds the target unchanged (no longer reachable)
	// closes the finding.
	x.probe.Attempt = func(context.Context, string, []string) (string, error) { return "probe-2", nil }
	r.now = r.now.Add(time.Hour)
	if name, res := runJob(t, r.g, ctx); name != "probe:tamper" || res.Err != nil {
		t.Fatalf("job %q: %+v", name, res)
	}
	if _, open := r.open(id); open {
		t.Fatal("a clean round left the tamper finding open")
	}
}

// LOOP-7: a missing target, a failed attempt or a refusal the journal does
// not take fails the round; it closes nothing.
func TestATamperRoundFailsClosed(t *testing.T) {
	x := newTamperRig(t, func(string, []string) error { return errors.New("guest did not start") })
	if _, err := x.probe.Run(context.Background()); err == nil {
		t.Fatal("a failed attempt passed the round")
	}
	x = newTamperRig(t, func(string, []string) error { return nil })
	x.probe.Journal = func(string, string) error { return errors.New("journal broken") }
	if _, err := x.probe.Run(context.Background()); err == nil {
		t.Fatal("an unjournaled refusal passed the round")
	}
	x = newTamperRig(t, func(string, []string) error { return nil })
	os.Remove(x.probe.Targets[2].Path)
	if _, err := x.probe.Run(context.Background()); err == nil {
		t.Fatal("a missing target passed the round")
	}
	x = newTamperRig(t, func(string, []string) error { return nil })
	x.probe.Targets[0].Name = "Snap shots/x"
	if _, err := x.probe.Run(context.Background()); err == nil {
		t.Fatal("a target name that is not an owner word passed")
	}
	x = newTamperRig(t, func(string, []string) error { return nil })
	x.probe.Targets[1].Guest = []string{"relative/x"}
	if _, err := x.probe.Run(context.Background()); err == nil {
		t.Fatal("a relative guest path passed")
	}
}

// exhaustRig is an exhaustion probe over a fake cgroup directory with all
// limits set; press, ping and preempt are instant.
type exhaustRig struct {
	cg      string
	probe   *ExhaustProbe
	pressed []string
	stopped bool
}

func newExhaustRig(t *testing.T) *exhaustRig {
	t.Helper()
	x := &exhaustRig{cg: t.TempDir()}
	for f, v := range map[string]string{"memory.max": "268435456\n", "pids.max": "4096\n", "cpu.weight": "1\n"} {
		if err := os.WriteFile(filepath.Join(x.cg, f), []byte(v), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	x.probe = &ExhaustProbe{
		Interval:       time.Hour,
		Hold:           30 * time.Millisecond,
		ResponseTarget: 200 * time.Millisecond,
		PreemptTarget:  time.Second,
		BrokerWeight:   1000,
		Press: func(_ context.Context, kinds []string) (PressedMachine, error) {
			x.pressed = kinds
			return PressedMachine{ID: "probe-1", Cgroup: x.cg, DiskBytes: 64 << 20}, nil
		},
		Ping:    func(context.Context) error { return nil },
		Preempt: func(string) error { x.stopped = true; return nil },
	}
	return x
}

// LOOP-7 (exhaustion), clean run: CPU, memory, disk and process pressure
// in a machine whose cgroup and disk are limited, the broker answering
// within its response target and the machine preempted within its
// target, reports nothing and checks every subject.
func TestAnExhaustionRoundWithinTargetsReportsNothing(t *testing.T) {
	x := newExhaustRig(t)
	res, err := x.probe.Run(context.Background())
	if err != nil || len(res.Found) != 0 {
		t.Fatalf("%+v %v", res, err)
	}
	if got := strings.Join(x.pressed, ","); got != "cpu,memory,disk,processes" {
		t.Fatalf("pressed %q", got)
	}
	if got := strings.Join(res.Checked, ","); got != "cpu,memory,disk,processes,response,preemption" {
		t.Fatalf("checked %q", got)
	}
	if !x.stopped {
		t.Fatal("the pressed machine was not preempted")
	}
}

// LOOP-7 control (a cgroup with no limit): memory.max and pids.max at
// "max", a machine that weighs as much as the broker and no disk budget
// each report a High finding through Report, named by the resource.
func TestACgroupWithNoLimitReportsExhaustionFindings(t *testing.T) {
	x := newExhaustRig(t)
	for f, v := range map[string]string{"memory.max": "max\n", "pids.max": "max\n", "cpu.weight": "1000\n"} {
		os.WriteFile(filepath.Join(x.cg, f), []byte(v), 0o600)
	}
	press := x.probe.Press
	x.probe.Press = func(ctx context.Context, k []string) (PressedMachine, error) {
		m, err := press(ctx, k)
		m.DiskBytes = 0
		return m, err
	}
	r := newReportRig(t, nil)
	r.probes = []Probe{x.probe}
	r.reopen(t)
	ctx := context.Background()
	runJob(t, r.g, ctx)
	name, res := runJob(t, r.g, ctx)
	if name != "probe:exhaustion" || res.Err != nil || res.Value != 4 {
		t.Fatalf("job %q: %+v", name, res)
	}
	for _, k := range []string{"cpu", "memory", "disk", "processes"} {
		if rec, open := r.open(findingID(CheckExhaust, k, "no limit")); !open || rec.Finding.Severity != High {
			t.Fatalf("%s: %+v", k, rec)
		}
	}
	if !x.stopped {
		t.Fatal("the pressed machine was not preempted")
	}
	// No cgroup at all is no limit on any cgroup resource.
	x = newExhaustRig(t)
	x.probe.Press = func(context.Context, []string) (PressedMachine, error) {
		return PressedMachine{ID: "probe-1", DiskBytes: 1 << 20}, nil
	}
	res2, err := x.probe.Run(ctx)
	if err != nil || len(res2.Found) != 3 {
		t.Fatalf("%+v %v", res2, err)
	}
}

// LOOP-7: a broker slower than its response target under pressure, or a
// preemption slower than its target, is a High finding.
func TestSlowResponseOrPreemptionUnderPressureIsAFinding(t *testing.T) {
	x := newExhaustRig(t)
	x.probe.ResponseTarget, x.probe.PreemptTarget = time.Millisecond, time.Millisecond
	x.probe.Ping = func(context.Context) error { time.Sleep(5 * time.Millisecond); return nil }
	x.probe.Preempt = func(string) error { time.Sleep(5 * time.Millisecond); return nil }
	res, err := x.probe.Run(context.Background())
	if err != nil || len(res.Found) != 2 {
		t.Fatalf("%+v %v", res, err)
	}
	if res.Found[0].Subject != "response" || res.Found[1].Subject != "preemption" || res.Found[0].Detail != "slow" {
		t.Fatalf("%+v", res.Found)
	}
}

// LOOP-7: a round whose pressure, ping or preemption fails is an error
// that closes nothing; the machine is still preempted.
func TestAnExhaustionRoundFailsClosed(t *testing.T) {
	x := newExhaustRig(t)
	x.probe.Ping = func(context.Context) error { return errors.New("broker gone") }
	if _, err := x.probe.Run(context.Background()); err == nil || !x.stopped {
		t.Fatalf("err %v, stopped %v", err, x.stopped)
	}
	x = newExhaustRig(t)
	x.probe.Preempt = func(string) error { return errors.New("kill failed") }
	if _, err := x.probe.Run(context.Background()); err == nil {
		t.Fatal("a failed preemption passed the round")
	}
	x = newExhaustRig(t)
	x.probe.Press = func(context.Context, []string) (PressedMachine, error) {
		return PressedMachine{}, errors.New("no room")
	}
	if _, err := x.probe.Run(context.Background()); err == nil {
		t.Fatal("a round with no pressure passed")
	}
}
