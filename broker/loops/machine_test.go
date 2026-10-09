package loops

// REQ: LOOP-7, LOOP-9

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/machprobe"
)

// A synthetic canary planted in the broker-held targets: no report, text
// or evidence may carry it, nor the targets' host paths.
const plantedCanary = "CANARY-tamper-7f3a91c0-synthetic"

type noted struct{ machine, target string }

// tamperRig is a probe over three broker-held targets in a temporary
// directory and a control directory; attempt stands in for the guest's
// scripted writes. Unless idle, each round's guest also writes the
// control the way the fixed script does, and each round runs in a new
// machine.
type tamperRig struct {
	dir     string
	control string
	probe   *TamperProbe
	attempt func(nonce string, paths []string) error
	idle    bool
	rounds  int
	notes   []noted
	paths   [][]string
	nonces  []string
}

func newTamperRig(t *testing.T, attempt func(nonce string, paths []string) error) *tamperRig {
	t.Helper()
	x := &tamperRig{dir: t.TempDir(), attempt: attempt}
	snap := filepath.Join(x.dir, "snapshots", "m1-1")
	x.control = filepath.Join(x.dir, "probe-mount")
	for _, d := range []string{snap, filepath.Join(x.dir, "suite"), x.control} {
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
		Control: TamperTarget{Path: x.control, Guest: []string{"/run/agentos/probe"}},
		Attempt: func(_ context.Context, nonce string, paths []string) (string, error) {
			x.paths = append(x.paths, paths)
			x.nonces = append(x.nonces, nonce)
			x.rounds++
			if !x.idle {
				machprobe.Tamper(nonce, []string{x.control})
			}
			return fmt.Sprintf("probe-%d", x.rounds), x.attempt(nonce, paths)
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

// LOOP-7 (tamper), a target that stays writable: the guest runs the
// fixed script on the grader's paths, so a sibling named by the round's
// nonce lands beside it each round. Each round reports it and none
// journals a refusal (L3 #548 point 1); the grader keeps its bytes and
// the broker removes the sibling after the verdict (P3-4b-4c-restore).
func TestATargetThatStaysWritableIsReportedEveryRound(t *testing.T) {
	var x *tamperRig
	x = newTamperRig(t, func(nonce string, _ []string) error {
		if machprobe.Tamper(nonce, []string{filepath.Join(x.dir, "grader.json")}) != 1 {
			return errors.New("rig: the sibling did not land")
		}
		return nil
	})
	for round := 1; round <= 2; round++ {
		res, err := x.probe.Run(context.Background())
		if err != nil || len(res.Found) != 1 || res.Found[0].Subject != "grader" {
			t.Fatalf("round %d: %+v %v", round, res, err)
		}
		if b, err := os.ReadFile(filepath.Join(x.dir, "grader.json")); err != nil || string(b) != `{"pass":0.5}` {
			t.Fatalf("round %d changed the grader: %q %v", round, b, err)
		}
		for _, d := range []string{x.dir, x.control} {
			if _, err := os.Lstat(filepath.Join(d, machprobe.Sibling(x.nonces[round-1]))); !errors.Is(err, fs.ErrNotExist) {
				t.Fatalf("round %d left a sibling in %s: %v", round, d, err)
			}
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
	if tamperSibling(x.nonces[0]) != machprobe.Sibling(x.nonces[0]) {
		t.Fatal("the broker removes a different name from the one the script creates")
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
	x.attempt = func(string, []string) error { return nil }
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
	x = newTamperRig(t, func(string, []string) error { return nil })
	x.probe.Control = TamperTarget{}
	if _, err := x.probe.Run(context.Background()); err == nil {
		t.Fatal("a round with no control passed")
	}
	x = newTamperRig(t, func(string, []string) error { return nil })
	os.Remove(x.control)
	if _, err := x.probe.Run(context.Background()); err == nil {
		t.Fatal("a missing control passed")
	}
}

// LOOP-7 positive control (P3-4b-4c-fresh, Security #548 4a 2): a guest
// that writes nothing, not even the broker-made control, fails the round.
// It journals nothing and an open tamper finding stays open, where on
// main such a round closed it.
func TestAGuestThatWritesNothingFailsTheRoundAndClosesNothing(t *testing.T) {
	var x *tamperRig
	x = newTamperRig(t, func(nonce string, _ []string) error {
		machprobe.Tamper(nonce, []string{filepath.Join(x.dir, "suite")})
		return nil
	})
	r := newReportRig(t, nil)
	r.probes = []Probe{x.probe}
	r.reopen(t)
	ctx := context.Background()
	runJob(t, r.g, ctx) // the passive pass
	if name, res := runJob(t, r.g, ctx); name != "probe:tamper" || res.Err != nil || res.Value != 1 {
		t.Fatalf("job %q: %+v", name, res)
	}
	id := findingID(CheckTamper, "evaluator", "writable")
	if _, open := r.open(id); !open {
		t.Fatal("rig: no open finding")
	}
	x.idle = true
	x.attempt = func(string, []string) error { return nil }
	notes := len(x.notes)
	r.now = r.now.Add(time.Hour)
	if name, res := runJob(t, r.g, ctx); name != "probe:tamper" || res.Err == nil {
		t.Fatalf("an idle guest passed the round: %q %+v", name, res)
	}
	if _, open := r.open(id); !open {
		t.Fatal("an idle guest closed an open tamper finding")
	}
	if len(x.notes) != notes {
		t.Fatalf("an idle round journaled refusals: %v", x.notes[notes:])
	}
}

// LOOP-7 positive control: a guest that runs the fixed script on every
// path it is given changes the control and every target. Each target is
// a finding and none is journaled; the control is tried like a target but
// is never checked, journaled or reported; no target's file contents
// change and no sibling is left (P3-4b-4c-restore).
func TestAGuestThatWritesEverythingIsReportedForEveryTargetButNotTheControl(t *testing.T) {
	x := newTamperRig(t, func(nonce string, paths []string) error {
		machprobe.Tamper(nonce, paths)
		return nil
	})
	x.idle = true // the script itself reaches the control
	res, err := x.probe.Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var found []string
	for _, f := range res.Found {
		found = append(found, f.Subject)
	}
	if strings.Join(found, ",") != "snapshots,evaluator,grader" || strings.Join(res.Checked, ",") != "snapshots,evaluator,grader" {
		t.Fatalf("found %v checked %v", found, res.Checked)
	}
	if len(x.notes) != 0 {
		t.Fatalf("journaled %v", x.notes)
	}
	for p, want := range map[string]string{
		filepath.Join(x.dir, "grader.json"):                    `{"pass":0.5}`,
		filepath.Join(x.dir, "suite", "cases.json"):            "[]",
		filepath.Join(x.dir, "snapshots", "m1-1", "meta.json"): plantedCanary,
	} {
		if b, err := os.ReadFile(p); err != nil || string(b) != want {
			t.Fatalf("%s holds %q %v", p, b, err)
		}
	}
	err = filepath.WalkDir(x.dir, func(p string, d fs.DirEntry, err error) error {
		if err == nil && strings.HasPrefix(d.Name(), ".agentos-tamper-") {
			t.Errorf("sibling left: %s", p)
		}
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
}

// LOOP-7 positive control: the control's paths go to the guest mixed in
// with the targets', tried the same ways (host path, process roots, guest
// path), in an order that changes between rounds, so the guest cannot
// write only the control.
func TestTheControlIsTriedLikeATargetInAnOrderTheGuestCannotPredict(t *testing.T) {
	x := newTamperRig(t, func(string, []string) error { return nil })
	at := map[int]bool{}
	for range 20 {
		if _, err := x.probe.Run(context.Background()); err != nil {
			t.Fatal(err)
		}
		ps := x.paths[len(x.paths)-1]
		n := 0
		for i, p := range ps {
			if strings.HasSuffix(p, x.control) || p == "/run/agentos/probe" {
				n++
				at[i] = true
			}
		}
		if n != 4 {
			t.Fatalf("control tried by %d paths: %v", n, ps)
		}
	}
	if len(at) < 5 {
		t.Fatalf("the control's paths sat at only %d positions over 20 rounds", len(at))
	}
}

// LOOP-7 fresh machine (P3-4b-4c-fresh): a round run in the same machine
// as the round before fails and journals nothing; so does a round that
// names no machine. The check is lastMachine, which the exhaustion probe
// reuses.
func TestATamperRoundInTheLastRoundsMachineFails(t *testing.T) {
	x := newTamperRig(t, func(string, []string) error { return nil })
	attempt := x.probe.Attempt
	x.probe.Attempt = func(ctx context.Context, nonce string, paths []string) (string, error) {
		attempt(ctx, nonce, paths)
		return "probe-same", nil
	}
	if _, err := x.probe.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	notes := len(x.notes)
	if _, err := x.probe.Run(context.Background()); err == nil {
		t.Fatal("a reused machine passed the round")
	}
	if len(x.notes) != notes {
		t.Fatalf("a reused machine's round journaled %v", x.notes[notes:])
	}
	x.probe.Attempt = func(ctx context.Context, nonce string, paths []string) (string, error) {
		attempt(ctx, nonce, paths)
		return "", nil
	}
	if _, err := x.probe.Run(context.Background()); err == nil {
		t.Fatal("a round with no machine passed")
	}
	var l lastMachine
	for i, c := range []struct {
		id string
		ok bool
	}{{"a", true}, {"b", true}, {"b", false}, {"a", true}, {"", false}} {
		if err := l.fresh(c.id); (err == nil) != c.ok {
			t.Fatalf("step %d fresh(%q) = %v", i, c.id, err)
		}
	}
}

// LOOP-7 read-only target: the fixed script on a target the guest cannot
// write gives no finding and journals the refusal.
func TestAReadOnlyTargetGivesNoFinding(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root writes through mode bits")
	}
	var x *tamperRig
	x = newTamperRig(t, func(nonce string, _ []string) error {
		machprobe.Tamper(nonce, []string{filepath.Join(x.dir, "suite")})
		return nil
	})
	suite := filepath.Join(x.dir, "suite")
	os.Chmod(suite, 0o500)
	t.Cleanup(func() { os.Chmod(suite, 0o700) })
	res, err := x.probe.Run(context.Background())
	if err != nil || len(res.Found) != 0 || !slices.Contains(x.notes, noted{"probe-1", "evaluator"}) {
		t.Fatalf("%+v %v %v", res, err, x.notes)
	}
}

// LOOP-7 broker writes (P3-4b-4c-attrib, L3 #548 point 2): a broker writer
// that changes a target during the round (a checkpoint into snapshots)
// is a false High without Quiesce, the control for this test, and none
// with it. Quiesce holds from before the first digest to after the last,
// resume is called on every path (a clean round, a failed attempt, a
// cancelled context), and a Quiesce error fails the round.
func TestQuiesceHoldsTheBrokersWritersForTheRound(t *testing.T) {
	var x *tamperRig
	held, resumed, digested := false, 0, false
	checkpoint := func() error {
		if held {
			return nil
		}
		return os.WriteFile(filepath.Join(x.dir, "snapshots", "index.json"), []byte(`{"m1":2}`), 0o600)
	}
	x = newTamperRig(t, func(string, []string) error { return checkpoint() })
	res, err := x.probe.Run(context.Background())
	if err != nil || len(res.Found) != 1 || res.Found[0].Subject != "snapshots" {
		t.Fatalf("control without Quiesce: %+v %v", res, err)
	}

	quiesce := func(context.Context) (func(), error) {
		if held {
			return nil, errors.New("rig: quiesced twice")
		}
		held = true
		return func() {
			if !digested {
				t.Error("resumed before the after-digest")
			}
			held = false
			resumed++
		}, nil
	}
	x = newTamperRig(t, func(string, []string) error { return checkpoint() })
	x.probe.Quiesce = quiesce
	journal := x.probe.Journal
	x.probe.Journal = func(m, tg string) error { digested = true; return journal(m, tg) }
	res, err = x.probe.Run(context.Background())
	if err != nil || len(res.Found) != 0 || resumed != 1 || held {
		t.Fatalf("with Quiesce: %+v %v resumed %d", res, err, resumed)
	}

	x.attempt = func(string, []string) error { return errors.New("guest did not start") }
	if _, err := x.probe.Run(context.Background()); err == nil || resumed != 2 || held {
		t.Fatalf("failed attempt: %v resumed %d", err, resumed)
	}
	ctx, cancel := context.WithCancel(context.Background())
	x.attempt = func(string, []string) error { cancel(); return nil }
	if _, err := x.probe.Run(ctx); err == nil || resumed != 3 || held {
		t.Fatalf("cancelled: %v resumed %d", err, resumed)
	}

	x.attempt = func(string, []string) error { return nil }
	x.probe.Quiesce = func(context.Context) (func(), error) { return nil, errors.New("checkpoint lock busy") }
	n := x.rounds
	if _, err := x.probe.Run(context.Background()); err == nil || x.rounds != n {
		t.Fatalf("a Quiesce error ran the round: %v", err)
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
