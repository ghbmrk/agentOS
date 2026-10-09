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

// LOOP-7 positive control, fail closed (#584 L3 3, delta L3 1): a control
// the broker cannot read after the round (here its parent became a file,
// ENOTDIR) fails the round instead of counting as changed; a removed
// control still counts as changed.
func TestAnUnreadableControlFailsTheRound(t *testing.T) {
	var x *tamperRig
	x = newTamperRig(t, func(string, []string) error {
		parent := filepath.Dir(x.control)
		if err := os.RemoveAll(parent); err != nil {
			return err
		}
		return os.WriteFile(parent, []byte("not a directory"), 0o600)
	})
	x.control = filepath.Join(x.dir, "mounts", "probe")
	if err := os.MkdirAll(x.control, 0o700); err != nil {
		t.Fatal(err)
	}
	x.probe.Control.Path = x.control
	x.idle = true
	if _, err := x.probe.Run(context.Background()); err == nil {
		t.Fatal("an unreadable control passed the round")
	}
	if len(x.notes) != 0 {
		t.Fatalf("journaled %v", x.notes)
	}

	x = newTamperRig(t, func(string, []string) error { return os.RemoveAll(x.control) })
	x.idle = true
	if _, err := x.probe.Run(context.Background()); err != nil {
		t.Fatalf("a removed control: %v", err)
	}
}

// LOOP-7 broker writes beside a file target (#584 L3 1): a broker write of
// another entry in a file target's directory during the round (a temp
// file, a journal) is not tamper, though Quiesce holds only the target's
// own writers; a tamper sibling there still is.
func TestAnUnrelatedWriteBesideAFileTargetIsNotTamper(t *testing.T) {
	var x *tamperRig
	x = newTamperRig(t, func(string, []string) error {
		return os.WriteFile(filepath.Join(x.dir, "grader.json.tmp"), []byte("{}"), 0o600)
	})
	res, err := x.probe.Run(context.Background())
	if err != nil || len(res.Found) != 0 {
		t.Fatalf("an unrelated write beside the grader: %+v %v", res, err)
	}
	x.attempt = func(nonce string, _ []string) error {
		machprobe.Tamper(nonce, []string{filepath.Join(x.dir, "grader.json")})
		return nil
	}
	res, err = x.probe.Run(context.Background())
	if err != nil || len(res.Found) != 1 || res.Found[0].Subject != "grader" {
		t.Fatalf("a tamper sibling beside the grader: %+v %v", res, err)
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

// REQ: LOOP-7, RES-1
//
// What the exhaustion round covers: limits set at or under the configured
// budget, the guest pressed, the broker answered, the machine was
// preempted in time. Pressure stays under the limits (S36), so it does
// not show that pressure cannot starve the broker, nor that the sandbox
// enforces a limit once it is reached.

// testBudget is the per-machine budget the exhaustion rig's broker wrote.
var testBudget = MachineBudget{MemoryBytes: 256 << 20, Pids: 4096, DiskBytes: 64 << 20}

// testScript is what the rig's guest presses: its counters must rise by
// half of it, 20 MiB and 16 MiB.
var testScript = PressScript{MemoryBytes: 40 << 20, DiskBytes: 32 << 20}

// The rig's cgroup may run on 100 CPUs, so its 30 ms hold asks for 1.5 s
// of CPU time, over the floor.
const testCPUs = "0-99"

// exhaustRig is an exhaustion probe over a fake cgroup directory whose
// limits sit at the configured budget. Each round runs in a new machine,
// and its guest's pressure raises every counter by press, but those named
// in flat; ping, preempt and the disk read are instant.
type exhaustRig struct {
	t        *testing.T
	cg       string
	probe    *ExhaustProbe
	pressed  []string
	stopped  []string
	machines int
	disk     int64
	flat     map[string]bool
	press    map[string]int64
}

func newExhaustRig(t *testing.T) *exhaustRig {
	t.Helper()
	x := &exhaustRig{t: t, cg: t.TempDir(), flat: map[string]bool{},
		press: map[string]int64{"cpu": 2000000, "memory": 40 << 20, "processes": 16, "disk": 32 << 20}}
	for f, v := range map[string]string{"memory.max": "268435456\n", "pids.max": "4096\n", "cpu.weight": "1\n", "cpuset.cpus.effective": testCPUs + "\n"} {
		x.write(f, v)
	}
	x.bump(map[string]int64{"cpu": 1000, "memory": 1 << 20, "processes": 2, "disk": 4096})
	x.probe = &ExhaustProbe{
		Interval:       time.Hour,
		Hold:           30 * time.Millisecond,
		ResponseTarget: 200 * time.Millisecond,
		PreemptTarget:  time.Second,
		BrokerWeight:   1000,
		Budget:         testBudget,
		Script:         testScript,
		Machine: func(context.Context) (PressedMachine, error) {
			x.machines++
			return PressedMachine{ID: fmt.Sprintf("probe-%d", x.machines), Cgroup: x.cg, DiskBytes: 64 << 20,
				DiskUsed: func() (int64, error) { return x.disk, nil }}, nil
		},
		Press: func(_ context.Context, id string, kinds []string) error {
			x.pressed = kinds
			up := map[string]int64{}
			for _, k := range kinds {
				if !x.flat[k] {
					up[k] = x.press[k]
				}
			}
			x.bump(up)
			return nil
		},
		Ping:    func(context.Context) error { return nil },
		Preempt: func(id string) error { x.stopped = append(x.stopped, id); return nil },
	}
	return x
}

func (x *exhaustRig) write(file, v string) {
	x.t.Helper()
	if err := os.WriteFile(filepath.Join(x.cg, file), []byte(v), 0o600); err != nil {
		x.t.Fatal(err)
	}
}

// bump raises the machine's counters by up, per pressure kind.
func (x *exhaustRig) bump(up map[string]int64) {
	read := func(file string) int64 {
		n, _ := cgroupCounter(x.cg, file, "")
		return n
	}
	cpu, _ := cgroupCounter(x.cg, "cpu.stat", "usage_usec")
	x.write("cpu.stat", fmt.Sprintf("usage_usec %d\nuser_usec 0\nsystem_usec 0\n", cpu+up["cpu"]))
	shmem, _ := cgroupCounter(x.cg, "memory.stat", "shmem")
	x.write("memory.stat", fmt.Sprintf("anon 4096\nfile %d\nshmem %d\n", shmem+up["memory"], shmem+up["memory"]))
	x.write("pids.current", fmt.Sprintf("%d\n", read("pids.current")+up["processes"]))
	x.disk += up["disk"]
}

// LOOP-7 (exhaustion), clean run: CPU, memory, disk and process pressure
// that raises the machine's counters, in a machine whose cgroup and disk
// are limited at or under the configured budget, the broker answering
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
	if !slices.Equal(x.stopped, []string{"probe-1"}) {
		t.Fatalf("preempted %v", x.stopped)
	}
}

// LOOP-7 control (a cgroup with no limit): memory.max and pids.max at
// "max", a machine that weighs as much as the broker and no disk budget
// each report a High "above budget" finding through Report, named by the
// resource.
func TestACgroupWithNoLimitReportsExhaustionFindings(t *testing.T) {
	x := newExhaustRig(t)
	for f, v := range map[string]string{"memory.max": "max\n", "pids.max": "max\n", "cpu.weight": "1000\n"} {
		x.write(f, v)
	}
	machine := x.probe.Machine
	x.probe.Machine = func(ctx context.Context) (PressedMachine, error) {
		m, err := machine(ctx)
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
		if rec, open := r.open(findingID(CheckExhaust, k, "above budget")); !open || rec.Finding.Severity != High {
			t.Fatalf("%s: %+v", k, rec)
		}
	}
	if len(x.stopped) != 1 {
		t.Fatal("the pressed machine was not preempted")
	}
	// No cgroup at all is no limit on any cgroup resource, and no
	// counters to show the guest pressed: the findings stand and the
	// round fails.
	x = newExhaustRig(t)
	x.probe.Machine = func(context.Context) (PressedMachine, error) {
		return PressedMachine{ID: "probe-1", DiskBytes: 1 << 20, DiskUsed: func() (int64, error) { return 1, nil }}, nil
	}
	res2, err := x.probe.Run(ctx)
	if err == nil || len(res2.Found) != 3 || len(res2.Checked) != 0 {
		t.Fatalf("%+v %v", res2, err)
	}
}

// LOOP-7, RES-1 (P3-4b-4c-limits; #548 Potency 2, L3 4): a limit holds
// only when it is set and at most the configured per-machine budget. A
// memory, process or disk limit above it is a finding, as is "max" or a
// missing file; at or under it passes. A probe without a budget, without
// a press script within it, or whose CPU minimum is under the floor fails
// the run closed.
func TestLimitsAreJudgedAgainstTheConfiguredBudget(t *testing.T) {
	ctx := context.Background()
	for _, c := range []struct {
		file, value, subject string
		disk                 int64
		found                bool
	}{
		{"memory.max", "17179869184\n", "memory", 64 << 20, true}, // 16 GiB against 256 MiB
		{"memory.max", "268435457\n", "memory", 64 << 20, true},
		{"memory.max", "268435456\n", "memory", 64 << 20, false},
		{"memory.max", "134217728\n", "memory", 64 << 20, false},
		{"memory.max", "max\n", "memory", 64 << 20, true},
		{"memory.max", "", "memory", 64 << 20, true}, // missing
		{"pids.max", "4097\n", "processes", 64 << 20, true},
		{"pids.max", "4096\n", "processes", 64 << 20, false},
		{"pids.max", "64\n", "processes", 64 << 20, false},
		{"pids.max", "max\n", "processes", 64 << 20, true},
		{"cpu.weight", "1\n", "disk", 64<<20 + 1, true},
		{"cpu.weight", "1\n", "disk", 1 << 20, false},
	} {
		x := newExhaustRig(t)
		if c.value == "" {
			os.Remove(filepath.Join(x.cg, c.file))
		} else {
			x.write(c.file, c.value)
		}
		machine := x.probe.Machine
		x.probe.Machine = func(ctx context.Context) (PressedMachine, error) {
			m, err := machine(ctx)
			m.DiskBytes = c.disk
			return m, err
		}
		res, err := x.probe.Run(ctx)
		if err != nil {
			t.Fatalf("%s=%q disk %d: %v", c.file, c.value, c.disk, err)
		}
		want := 0
		if c.found {
			want = 1
		}
		if len(res.Found) != want || c.found && !(res.Found[0].Subject == c.subject && res.Found[0].Detail == "above budget" && res.Found[0].Severity == High) {
			t.Fatalf("%s=%q disk %d: found %+v", c.file, c.value, c.disk, res.Found)
		}
	}
	for _, b := range []MachineBudget{{}, {Pids: 1, DiskBytes: 1}, {MemoryBytes: 1, DiskBytes: 1}, {MemoryBytes: 1, Pids: 1}} {
		x := newExhaustRig(t)
		x.probe.Budget = b
		if _, err := x.probe.Run(ctx); err == nil || x.machines != 0 {
			t.Fatalf("budget %+v: ran (%d machines), %v", b, x.machines, err)
		}
	}
	// So does a probe with no machine to press (Potency 1 on #599).
	x := newExhaustRig(t)
	x.probe.Machine = nil
	if _, err := x.probe.Run(ctx); err == nil || !strings.Contains(err.Error(), "not configured") {
		t.Fatalf("no Machine: %v", err)
	}
	// So does a script unset, too small to halve, or above the budget.
	for _, sc := range []PressScript{{}, {MemoryBytes: 1 << 20}, {DiskBytes: 1 << 20}, {MemoryBytes: 1, DiskBytes: 1 << 20},
		{MemoryBytes: 256<<20 + 1, DiskBytes: 1 << 20}, {MemoryBytes: 1 << 20, DiskBytes: 64<<20 + 1}} {
		x := newExhaustRig(t)
		x.probe.Script = sc
		if _, err := x.probe.Run(ctx); err == nil || x.machines != 0 {
			t.Fatalf("script %+v: ran (%d machines), %v", sc, x.machines, err)
		}
	}
	// A machine whose CPU minimum is under the floor (1 s of CPU time: too
	// few CPUs for the hold, or a hold so short it rounds to nothing)
	// fails before it presses. One whose CPU count cannot be read fails
	// as an unreadable counter does: its findings stand, nothing closes.
	// Either way the machine is preempted.
	for _, c := range []struct {
		cpus    string
		hold    time.Duration
		presses bool
	}{{"", 30 * time.Millisecond, true}, {"x", 30 * time.Millisecond, true}, {"3-1", 30 * time.Millisecond, true},
		{"0", time.Second + time.Second/2, false}, {"0-65", 30 * time.Millisecond, false}, {"0-1048575", time.Microsecond, false}} {
		x := newExhaustRig(t)
		if c.cpus == "" {
			os.Remove(filepath.Join(x.cg, "cpuset.cpus.effective"))
		} else {
			x.write("cpuset.cpus.effective", c.cpus)
		}
		x.probe.Hold = c.hold
		res, err := x.probe.Run(ctx)
		if err == nil || len(res.Checked) != 0 || (x.pressed != nil) != c.presses || len(x.stopped) != 1 {
			t.Fatalf("cpus %q, hold %v: pressed %v, stopped %v, %v", c.cpus, c.hold, x.pressed, x.stopped, err)
		}
	}
	// The CPU count is the nearest ancestor's where the machine's own
	// group does not enable cpuset; "0-1,4,8-9" is five CPUs.
	if n, err := cpusEffective(newExhaustRig(t).cg); err != nil || n != 100 {
		t.Fatalf("own group: %d %v", n, err)
	}
	parent := t.TempDir()
	child := filepath.Join(parent, "m")
	os.Mkdir(child, 0o700)
	os.WriteFile(filepath.Join(parent, "cgroup.controllers"), []byte("cpuset cpu\n"), 0o600)
	os.WriteFile(filepath.Join(parent, "cpuset.cpus.effective"), []byte("0-1,4,8-9\n"), 0o600)
	if n, err := cpusEffective(child); err != nil || n != 5 {
		t.Fatalf("ancestor: %d %v", n, err)
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

// LOOP-7: a round whose machine, pressure, ping or preemption fails is an
// error that closes nothing; a machine is still preempted.
func TestAnExhaustionRoundFailsClosed(t *testing.T) {
	x := newExhaustRig(t)
	x.probe.Ping = func(context.Context) error { return errors.New("broker gone") }
	if _, err := x.probe.Run(context.Background()); err == nil || len(x.stopped) != 1 {
		t.Fatalf("err %v, stopped %v", err, x.stopped)
	}
	x = newExhaustRig(t)
	x.probe.Preempt = func(string) error { return errors.New("kill failed") }
	if _, err := x.probe.Run(context.Background()); err == nil {
		t.Fatal("a failed preemption passed the round")
	}
	x = newExhaustRig(t)
	x.probe.Press = func(context.Context, string, []string) error { return errors.New("no room") }
	if _, err := x.probe.Run(context.Background()); err == nil || len(x.stopped) != 1 {
		t.Fatalf("a round with no pressure: %v, stopped %v", err, x.stopped)
	}
	x = newExhaustRig(t)
	x.probe.Machine = func(context.Context) (PressedMachine, error) {
		return PressedMachine{ID: "half-made"}, errors.New("no room")
	}
	if _, err := x.probe.Run(context.Background()); err == nil || !slices.Equal(x.stopped, []string{"half-made"}) {
		t.Fatalf("a round with no machine: %v, stopped %v", err, x.stopped)
	}
}

// LOOP-7 positive control (P3-4b-4c-fresh, exhaustion half; Security #548
// 4a 2, and B1 on #599): a guest that does not press, or presses a token
// amount, so a counter (cpu.stat usage_usec, memory.stat shmem, the disk
// quota's usage) rises by less than its minimum over the hold, fails the
// round; its machine is preempted and an open "slow" finding stays open,
// where on main such a round closed it.
func TestAGuestThatDoesNotPressFailsTheRoundAndClosesNothing(t *testing.T) {
	x := newExhaustRig(t)
	x.probe.ResponseTarget = time.Millisecond
	x.probe.Ping = func(context.Context) error { time.Sleep(5 * time.Millisecond); return nil }
	r := newReportRig(t, nil)
	r.probes = []Probe{x.probe}
	r.reopen(t)
	ctx := context.Background()
	runJob(t, r.g, ctx) // the passive pass
	if name, res := runJob(t, r.g, ctx); name != "probe:exhaustion" || res.Err != nil || res.Value != 1 {
		t.Fatalf("job %q: %+v", name, res)
	}
	id := findingID(CheckExhaust, "response", "slow")
	if _, open := r.open(id); !open {
		t.Fatal("rig: no open finding")
	}
	// The guest presses a token amount (every counter rises by 1), and
	// the broker answers at once.
	x.probe.ResponseTarget = 200 * time.Millisecond
	x.probe.Ping = func(context.Context) error { return nil }
	x.press = map[string]int64{"cpu": 1, "memory": 1, "processes": 1, "disk": 1}
	r.now = r.now.Add(time.Hour)
	if name, res := runJob(t, r.g, ctx); name != "probe:exhaustion" || res.Err == nil {
		t.Fatalf("a token press passed the round: %q %+v", name, res)
	}
	if _, open := r.open(id); !open {
		t.Fatal("a token press closed an open slow finding")
	}
	if len(x.stopped) != 2 {
		t.Fatalf("preempted %v", x.stopped)
	}
	// Each counter on its own: one that stays flat fails the round.
	// Processes have no counter under gVisor (S35).
	for _, k := range []string{"cpu", "memory", "disk"} {
		x := newExhaustRig(t)
		x.flat[k] = true
		res, err := x.probe.Run(ctx)
		if err == nil || !strings.Contains(err.Error(), k) || len(res.Checked) != 0 || len(x.stopped) != 1 {
			t.Fatalf("%s flat: %+v %v, stopped %v", k, res, err, x.stopped)
		}
	}
	// A press that raises every counter by only 1 (a page, a block, a
	// microsecond: the sandbox's own work, or a press that exits at once)
	// fails the round, as does one just under its minimum; at the
	// minimum it passes.
	for _, c := range []struct {
		press map[string]int64
		pass  bool
	}{
		{map[string]int64{"cpu": 1, "memory": 1, "processes": 1, "disk": 1}, false},
		{map[string]int64{"cpu": 2000000, "memory": 20<<20 - 1, "processes": 16, "disk": 32 << 20}, false},
		{map[string]int64{"cpu": 2000000, "memory": 40 << 20, "processes": 16, "disk": 16<<20 - 1}, false},
		{map[string]int64{"cpu": 1499999, "memory": 40 << 20, "processes": 16, "disk": 32 << 20}, false}, // 30 ms on 100 CPUs, halved
		{map[string]int64{"cpu": 1500000, "memory": 20 << 20, "processes": 0, "disk": 16 << 20}, true},
	} {
		x := newExhaustRig(t)
		x.press = c.press
		res, err := x.probe.Run(ctx)
		if (err == nil) != c.pass || !c.pass && len(res.Checked) != 0 {
			t.Fatalf("press %v: %+v %v", c.press, res, err)
		}
	}
	// A counter that cannot be read fails it too.
	x = newExhaustRig(t)
	machine := x.probe.Machine
	x.probe.Machine = func(ctx context.Context) (PressedMachine, error) {
		m, err := machine(ctx)
		m.DiskUsed = nil
		return m, err
	}
	if res, err := x.probe.Run(ctx); err == nil || len(res.Checked) != 0 {
		t.Fatalf("no disk usage: %+v %v", res, err)
	}
	os.Remove(filepath.Join(x.cg, "cpu.stat"))
	x.probe.Machine = machine
	if res, err := x.probe.Run(ctx); err == nil || len(res.Checked) != 0 {
		t.Fatalf("no cpu.stat: %+v %v", res, err)
	}
}

// LOOP-7 fresh machine (P3-4b-4c-fresh, exhaustion half): a round whose
// machine is the last round's fails through the tamper probe's check; the
// machine is still preempted and nothing closes. Distinct machines pass.
func TestAnExhaustionRoundInTheLastRoundsMachineFails(t *testing.T) {
	x := newExhaustRig(t)
	x.probe.ResponseTarget = time.Millisecond
	x.probe.Ping = func(context.Context) error { time.Sleep(5 * time.Millisecond); return nil }
	machine := x.probe.Machine
	x.probe.Machine = func(ctx context.Context) (PressedMachine, error) {
		m, err := machine(ctx)
		m.ID = "probe-same"
		return m, err
	}
	r := newReportRig(t, nil)
	r.probes = []Probe{x.probe}
	r.reopen(t)
	ctx := context.Background()
	runJob(t, r.g, ctx) // the passive pass
	if name, res := runJob(t, r.g, ctx); name != "probe:exhaustion" || res.Err != nil || res.Value != 1 {
		t.Fatalf("job %q: %+v", name, res)
	}
	id := findingID(CheckExhaust, "response", "slow")
	x.probe.ResponseTarget = 200 * time.Millisecond
	x.probe.Ping = func(context.Context) error { return nil }
	r.now = r.now.Add(time.Hour)
	name, res := runJob(t, r.g, ctx)
	if name != "probe:exhaustion" || res.Err == nil || !strings.Contains(res.Err.Error(), "same machine") {
		t.Fatalf("a round in the last round's machine passed: %q %+v", name, res)
	}
	if _, open := r.open(id); !open {
		t.Fatal("a reused machine closed an open slow finding")
	}
	if !slices.Equal(x.stopped, []string{"probe-same", "probe-same"}) {
		t.Fatalf("preempted %v", x.stopped)
	}
	// Distinct machines pass, round after round.
	x = newExhaustRig(t)
	for range 3 {
		if _, err := x.probe.Run(ctx); err != nil {
			t.Fatal(err)
		}
	}
}
