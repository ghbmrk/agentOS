package loop7

// REQ: LOOP-7, LOOP-9, ARC-2
//
// P3-4b-3a: the runner agentosd links. Children run only binaries the
// signed release lists, with a minimal environment, in their own process
// group, which a timeout kills whole.

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/journal"
	"github.com/ghbmrk/agentos/broker/loops"
)

// fakeBin writes a shell script standing in for a fuzz test binary into
// release, named name.
func fakeBin(t *testing.T, release, name, body string) string {
	t.Helper()
	p := filepath.Join(release, name)
	if err := os.WriteFile(p, []byte("#!/bin/sh\n"+body+"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	return p
}

func fakeTarget(t *testing.T, release, body string) Target {
	t.Helper()
	return Target{Pkg: "fake", Name: "FuzzFake", Binary: fakeBin(t, release, "fake.test", body), Dir: t.TempDir()}
}

// ARC-2: a binary that is not a direct child of the release directory is
// refused when the source is built, before anything runs.
func TestABinaryOutsideTheReleaseIsRefused(t *testing.T) {
	release := t.TempDir()
	ok := fakeTarget(t, release, "exit 0")
	if _, err := New(Config{Inner: newFake(), Report: newFake(), Targets: []Target{ok}, Release: release, CacheDir: t.TempDir()}); err != nil {
		t.Fatalf("a release binary refused: %v", err)
	}
	other := t.TempDir()
	outside := ok
	outside.Binary = fakeBin(t, other, "x.test", "exit 0")
	nested := ok
	nested.Binary = filepath.Join(release, "sub", "x.test")
	dotdot := ok
	dotdot.Binary = release + "/../x.test"
	notTest := ok
	notTest.Binary = fakeBin(t, release, "sh", "exit 0")
	for name, c := range map[string]Config{
		"outside":     {Targets: []Target{outside}, Release: release},
		"nested":      {Targets: []Target{nested}, Release: release},
		"dotdot":      {Targets: []Target{dotdot}, Release: release},
		"not a test":  {Targets: []Target{notTest}, Release: release},
		"no release":  {Targets: []Target{ok}},
		"relative":    {Targets: []Target{ok}, Release: "fuzz"},
		"state path":  {Targets: []Target{ok}, Release: ok.Dir},
		"release dir": {Targets: []Target{{Pkg: "fake", Name: "FuzzFake", Binary: release, Dir: ok.Dir}}, Release: filepath.Dir(release)},
	} {
		c.Inner, c.Report, c.CacheDir = newFake(), newFake(), t.TempDir()
		if _, err := New(c); err == nil {
			t.Errorf("%s: accepted %s", name, c.Targets[0].Binary)
		}
	}
}

// ARC-2: a release entry swapped for a link to anything else is refused
// at run time, before exec.
func TestALinkInTheReleaseIsNotExecuted(t *testing.T) {
	release, marker := t.TempDir(), filepath.Join(t.TempDir(), "ran")
	elsewhere := fakeBin(t, t.TempDir(), "x.test", "touch "+marker)
	tg := Target{Pkg: "fake", Name: "FuzzFake", Binary: filepath.Join(release, "fake.test"), Dir: t.TempDir()}
	if err := os.Symlink(elsewhere, tg.Binary); err != nil {
		t.Fatal(err)
	}
	s := newSource(t, newFake(), Config{Targets: []Target{tg}, Release: release})
	if _, err := s.Fuzz(context.Background(), tg); err == nil {
		t.Fatal("a linked binary ran without error")
	}
	if _, err := os.Stat(marker); err == nil {
		t.Fatal("the linked binary was executed")
	}
}

// LOOP-7: the manifest the image ships names each target and its binary;
// targets run in the state directory, where the release's seeds are
// copied once and crash inputs stay across updates. Entries naming a path
// are refused.
func TestLoadReadsTheReleaseManifest(t *testing.T) {
	release, state := t.TempDir(), t.TempDir()
	m := `{"targets":[{"pkg":"modem/at","name":"FuzzDecodeDeliver","binary":"modem_at.test"},
		{"pkg":"sockets","name":"FuzzRequest","binary":"sockets.test"}]}`
	if err := os.WriteFile(filepath.Join(release, "manifest.json"), []byte(m), 0o644); err != nil {
		t.Fatal(err)
	}
	seeds := filepath.Join(release, "corpus", "sockets", "FuzzRequest")
	if err := os.MkdirAll(seeds, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, n := range []string{"seed1", "crash"} {
		if err := os.WriteFile(filepath.Join(seeds, n), []byte("go test fuzz v1\n[]byte(\"release\")\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	// A crash input found before this update keeps its bytes.
	kept := filepath.Join(state, "targets", "sockets", "testdata", "fuzz", "FuzzRequest", "crash")
	if err := os.MkdirAll(filepath.Dir(kept), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(kept, []byte("found on this box"), 0o600); err != nil {
		t.Fatal(err)
	}
	ts, err := Load(release, state)
	if err != nil || len(ts) != 2 {
		t.Fatalf("%+v %v", ts, err)
	}
	if ts[0].Pkg != "modem/at" || ts[0].Binary != filepath.Join(release, "modem_at.test") || ts[0].Dir != filepath.Join(state, "targets", "modem", "at") {
		t.Fatalf("target %+v", ts[0])
	}
	if b, err := os.ReadFile(filepath.Join(ts[1].Dir, "testdata", "fuzz", "FuzzRequest", "seed1")); err != nil || !strings.Contains(string(b), "release") {
		t.Fatalf("seed not copied: %q %v", b, err)
	}
	if b, _ := os.ReadFile(kept); string(b) != "found on this box" {
		t.Fatalf("a kept crash input was overwritten: %q", b)
	}
	if _, err := New(Config{Inner: newFake(), Report: newFake(), Targets: ts, Release: release, CacheDir: t.TempDir()}); err != nil {
		t.Fatalf("loaded targets refused: %v", err)
	}
	for name, bad := range map[string]string{
		"binary path":   `{"targets":[{"pkg":"a","name":"FuzzA","binary":"/usr/bin/sh"}]}`,
		"binary up":     `{"targets":[{"pkg":"a","name":"FuzzA","binary":"../a.test"}]}`,
		"pkg up":        `{"targets":[{"pkg":"../a","name":"FuzzA","binary":"a.test"}]}`,
		"pkg absolute":  `{"targets":[{"pkg":"/a","name":"FuzzA","binary":"a.test"}]}`,
		"name":          `{"targets":[{"pkg":"a","name":"../FuzzA","binary":"a.test"}]}`,
		"unknown field": `{"targets":[{"pkg":"a","name":"FuzzA","binary":"a.test","dir":"/tmp"}]}`,
		"empty":         `{"targets":[]}`,
	} {
		if err := os.WriteFile(filepath.Join(release, "manifest.json"), []byte(bad), 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := Load(release, t.TempDir()); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// allowedEnv is every variable a child may see (LATER P3-4b-3 l1).
var allowedEnv = map[string]bool{"PATH": true, "HOME": true, "TMPDIR": true, "GOCACHE": true, "GOFLAGS": true}

// checkEnv reads the environment a child wrote and checks it is the
// minimal one: no canary from the parent, only allow-listed names, and a
// HOME that is the child's scratch, not the daemon's.
func checkEnv(t *testing.T, path, scratchUnder string) {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("the child wrote no environment: %v", err)
	}
	if strings.Contains(string(b), "synthetic-canary") {
		t.Fatalf("the child saw the daemon's canary:\n%s", b)
	}
	got := map[string]string{}
	for _, l := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		k, v, _ := strings.Cut(l, "=")
		if k == "PWD" || k == "SHLVL" || k == "_" {
			continue // set by the shell itself
		}
		if !allowedEnv[k] {
			t.Errorf("the child saw %s", k)
		}
		got[k] = v
	}
	if !strings.HasPrefix(got["HOME"], scratchUnder) || got["TMPDIR"] != got["HOME"] || got["GOFLAGS"] != "" || got["PATH"] == "" {
		t.Fatalf("environment %v", got)
	}
}

// ARC-2, LOOP-7: a fuzz child does not see the daemon's environment.
func TestAFuzzChildGetsAMinimalEnvironment(t *testing.T) {
	t.Setenv("AGENTOS_TEST_CANARY", "synthetic-canary-7f3a")
	release, out, cache := t.TempDir(), filepath.Join(t.TempDir(), "env"), t.TempDir()
	tg := fakeTarget(t, release, "env > "+out)
	s := newSource(t, newFake(), Config{Targets: []Target{tg}, Release: release, CacheDir: cache})
	if _, err := s.Fuzz(context.Background(), tg); err != nil {
		t.Fatal(err)
	}
	checkEnv(t, out, cache)
}

// gone reports pid exited (or is a zombie no one reaps in this container).
func gone(pid int) bool {
	b, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if err != nil {
		return true
	}
	f := strings.Fields(string(b[strings.LastIndexByte(string(b), ')')+1:]))
	return len(f) > 0 && f[0] == "Z"
}

// LOOP-1: a preempted or timed-out job kills its whole process group, so
// no grandchild holds the CPU after it returns.
func TestATimeoutKillsTheGrandchildToo(t *testing.T) {
	release, pidfile := t.TempDir(), filepath.Join(t.TempDir(), "pid")
	tg := fakeTarget(t, release, "sleep 10 &\necho $! > "+pidfile+"\nsleep 10")
	s := newSource(t, newFake(), Config{Targets: []Target{tg}, Release: release})
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	start := time.Now()
	if _, err := s.Fuzz(ctx, tg); err != nil {
		t.Fatal(err)
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("returned after %v", d)
	}
	b, err := os.ReadFile(pidfile)
	if err != nil {
		t.Fatal(err)
	}
	pid, _ := strconv.Atoi(strings.TrimSpace(string(b)))
	deadline := time.Now().Add(waitDelay)
	for !gone(pid) {
		if time.Now().After(deadline) {
			t.Fatalf("grandchild %d outlived the job", pid)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// LOOP-1: the recheck interval counts one slot per target and one for the
// probe, even while no probe is wired.
func TestRecheckCountsTheProbeSlot(t *testing.T) {
	release := t.TempDir()
	a := fakeTarget(t, release, "exit 0")
	b := a
	b.Name = "FuzzOther"
	s := newSource(t, newFake(), Config{Targets: []Target{a, b}, Release: release, Every: 30 * time.Minute})
	if got := s.Recheck(); got != 90*time.Minute {
		t.Fatalf("recheck %v", got)
	}
}

// LOOP-9 (Security 4a on #523): the probe's refusal codes come from the
// wiring, the broker's own probe set; a probe wired without them would
// pass an empty round, so it is refused.
func TestAProbeNeedsTheBrokersProbeSet(t *testing.T) {
	probe := func(context.Context) (string, []string, error) { return "m1", nil, nil }
	trail := func() []journal.Record { return nil }
	if _, err := New(Config{Inner: newFake(), Report: newFake(), Probe: probe, Trail: trail}); err == nil {
		t.Fatal("a probe without its probe set was accepted")
	}
	if _, err := New(Config{Inner: newFake(), Report: newFake(), Want: probeSet()}); err == nil {
		t.Fatal("a probe set without a probe was accepted")
	}
}

// digestGuard is a fake guard with the scheduler's optional interfaces.
type digestGuard struct {
	*fakeGuard
	measured bool
}

func (g digestGuard) Digest() []string { return []string{"Loop 2: partial"} }
func (g digestGuard) Measured() bool   { return g.measured }

// Wrapping the guard keeps what the scheduler reads from it: its digest
// lines (STATUS) and whether its return is measured (LOOP-3).
func TestTheSourceForwardsTheGuardsDigestAndMeasure(t *testing.T) {
	for _, m := range []bool{true, false} {
		g := digestGuard{newFake(), m}
		s, err := New(Config{Inner: g, Report: g})
		if err != nil {
			t.Fatal(err)
		}
		if d := strings.Join(s.Digest(), ""); d != "Loop 2: partial" || s.Measured() != m {
			t.Fatalf("digest %q measured %v", d, s.Measured())
		}
	}
	s, _ := New(Config{Inner: newFake(), Report: newFake()})
	if s.Digest() != nil || !s.Measured() {
		t.Fatal("a plain inner source gained a digest or lost its measure")
	}
}

// corpus writes inputs into t's stored corpus and returns each one's
// finding detail.
func corpus(t *testing.T, tg Target, inputs map[string]string) map[string]string {
	t.Helper()
	dir := filepath.Join(tg.Dir, "testdata", "fuzz", tg.Name)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	out := map[string]string{}
	for name, in := range inputs {
		data := []byte("go test fuzz v1\n[]byte(" + strconv.Quote(in) + ")\n")
		if err := os.WriteFile(filepath.Join(dir, name), data, 0o600); err != nil {
			t.Fatal(err)
		}
		out[name] = crashDetail(data)
	}
	return out
}

// A fake binary whose whole replay dies the way a runtime fatal error
// does (no "--- FAIL" line, exit 2), and whose run of the stored input
// "bad" alone fails while "good" passes.
const fatalReplay = `case "$1" in
-test.run=^FuzzFake\$) echo "fatal error: stack overflow"; exit 2;;
-test.run=^FuzzFake\$/^bad\$) echo "fatal error: stack overflow"; exit 2;;
-test.run=^FuzzFake\$/^good\$) echo "--- PASS: FuzzFake/good (0.00s)"; exit 0;;
esac
exit 0`

// LOOP-9 (Security 4a on #560, blocker 1): a crash the binary reports
// without a "--- FAIL" line (a stack overflow, out of memory, a
// concurrent map write, os.Exit) is still a finding: each stored input is
// replayed alone to name it. The target is not stuck on an error.
func TestACrashWithoutAFailLineIsReported(t *testing.T) {
	release := t.TempDir()
	g := newFake()
	tg := fakeTarget(t, release, fatalReplay)
	details := corpus(t, tg, map[string]string{"bad": "synthetic crash", "good": "ab"})
	s := newSource(t, g, Config{Targets: []Target{tg}, Release: release})
	n, err := s.Fuzz(context.Background(), tg)
	if err != nil || n != 1 || len(g.reported) != 1 || g.reported[0].Detail != details["bad"] {
		t.Fatalf("n=%d err=%v reported %+v", n, err, g.reported)
	}
	// Fixed by an update: the stored input passes alone and in the whole
	// replay, and the finding resolves.
	fakeBin(t, release, "fake.test", `case "$1" in -test.run=^FuzzFake\$) echo "--- PASS: FuzzFake/bad (0.00s)"; echo "--- PASS: FuzzFake/good (0.00s)";; esac; exit 0`)
	if n, err := s.Fuzz(context.Background(), tg); err != nil || n != 0 || len(g.open) != 0 {
		t.Fatalf("after the fix n=%d err=%v open %v", n, err, g.open)
	}
}

// A replay that dies before any stored input can be named (a seed added
// in code, a crash at start) is a finding for the target, resolved once a
// whole replay passes.
func TestACrashNoInputNamesIsATargetFinding(t *testing.T) {
	release := t.TempDir()
	g := newFake()
	tg := fakeTarget(t, release, `case "$1" in -test.run=^FuzzFake*) echo "fatal error: out of memory"; exit 2;; esac; exit 0`)
	s := newSource(t, g, Config{Targets: []Target{tg}, Release: release})
	if n, err := s.Fuzz(context.Background(), tg); err != nil || n != 1 || len(g.open) != 1 || g.reported[0].Detail != loops.FuzzNoInputDetail {
		t.Fatalf("n=%d err=%v reported %+v", n, err, g.reported)
	}
	fakeBin(t, release, "fake.test", "exit 0")
	if n, err := s.Fuzz(context.Background(), tg); err != nil || n != 0 || len(g.open) != 0 {
		t.Fatalf("after the fix n=%d err=%v open %v", n, err, g.open)
	}
}

// LOOP-9, LOOP-1 (Security 4a on #560, blocker 2): an input that hangs is
// a finding, and the job is bounded: the replay and each input alone have
// a deadline, so a hang does not hold the spare slot.
func TestAHangingInputIsReportedAndBounded(t *testing.T) {
	release := t.TempDir()
	g := newFake()
	tg := fakeTarget(t, release, `case "$1" in
-test.run=^FuzzFake\$|-test.run=^FuzzFake\$/^bad\$) sleep 10;;
-test.run=^FuzzFake\$/^good\$) exit 0;;
esac
exit 0`)
	details := corpus(t, tg, map[string]string{"bad": "synthetic hang", "good": "ab"})
	s := newSource(t, g, Config{Targets: []Target{tg}, Release: release, ReplayTime: 300 * time.Millisecond, InputTime: 300 * time.Millisecond})
	start := time.Now()
	n, err := s.Fuzz(context.Background(), tg)
	if err != nil || n != 1 || len(g.reported) != 1 || g.reported[0].Detail != details["bad"] {
		t.Fatalf("n=%d err=%v reported %+v", n, err, g.reported)
	}
	if d := time.Since(start); d > 5*time.Second {
		t.Fatalf("a hanging input held the job %v", d)
	}
}

// A fuzz step whose engine runs past its bound is a target finding. A
// later clean step does not resolve it: it never replayed what kept the
// engine running, so it is no evidence (delta L3 on #560). Only a good
// step of a different release binary closes it (P3-4b-3r-fuzz), and a
// step that prints no progress line is not a good step.
func TestAFuzzStepPastItsBoundIsReported(t *testing.T) {
	release := t.TempDir()
	g := newFake()
	tg := fakeTarget(t, release, `case "$1" in -test.run=^\$) sleep 10;; esac; exit 0`)
	s := newSource(t, g, Config{Targets: []Target{tg}, Release: release, FuzzTime: 100 * time.Millisecond, ReplayTime: 300 * time.Millisecond})
	if n, err := s.Fuzz(context.Background(), tg); err != nil || n != 1 || len(g.open) != 1 || g.reported[0].Detail != loops.FuzzOverrunDetail {
		t.Fatalf("n=%d err=%v reported %+v", n, err, g.reported)
	}
	fakeBin(t, release, "fake.test", "exit 0")
	if n, err := s.Fuzz(context.Background(), tg); err != nil || n != 0 || len(g.open) != 1 || len(g.resolved) != 0 {
		t.Fatalf("a clean step: n=%d err=%v open %v resolved %v", n, err, g.open, g.resolved)
	}
}

// A replay that prints both a FAIL and a PASS line for one input (a
// forged PASS from the decoder's own output) does not resolve its finding.
func TestAForgedPassLineResolvesNothing(t *testing.T) {
	release := t.TempDir()
	g := newFake()
	tg := fakeTarget(t, release, `case "$1" in -test.run=^FuzzFake\$) echo "--- PASS: FuzzFake/bad (0.00s)"; echo "--- FAIL: FuzzFake/bad (0.00s)"; exit 1;; esac; exit 0`)
	details := corpus(t, tg, map[string]string{"bad": "synthetic crash"})
	open := loops.Finding{Check: loops.CheckFuzz, Subject: tg.subject(), Severity: loops.High, Detail: details["bad"]}
	if _, err := g.Report(context.Background(), open); err != nil {
		t.Fatal(err)
	}
	s := newSource(t, g, Config{Targets: []Target{tg}, Release: release})
	if _, err := s.Fuzz(context.Background(), tg); err != nil || len(g.open) != 1 || len(g.resolved) != 0 {
		t.Fatalf("err=%v open %v resolved %v", err, g.open, g.resolved)
	}
}

// Each package's targets get a fuzz cache of their own: six packages name
// a target FuzzParse, and the engine keys its cache by target name.
func TestTheFuzzCacheIsPerPackage(t *testing.T) {
	release, args, cache := t.TempDir(), filepath.Join(t.TempDir(), "args"), t.TempDir()
	tg := fakeTarget(t, release, `case "$1" in -test.run=^\$) echo "$@" > `+args+`;; esac; exit 0`)
	tg.Pkg = "modem/at"
	s := newSource(t, newFake(), Config{Targets: []Target{tg}, Release: release, CacheDir: cache})
	if _, err := s.Fuzz(context.Background(), tg); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(args)
	if want := "-test.fuzzcachedir=" + filepath.Join(cache, "fuzz", "modem", "at"); !strings.Contains(string(b), want) {
		t.Fatalf("args %q lack %q", b, want)
	}
}

// The real engine's control for blocker 1: a planted decoder that
// overflows its stack, a runtime fatal error with no "--- FAIL" line, is
// found by fuzzing and reported with its stored input.
func TestAPlantedStackOverflowIsReported(t *testing.T) {
	g := newFake()
	tg := target(t, plantedWith(t, `var r func(int) int; r = func(n int) int { return r(n+1) + 1 }; _ = r(0)`))
	s := newSource(t, g, Config{Targets: []Target{tg}, FuzzTime: 20 * time.Second})
	n, err := s.Fuzz(context.Background(), tg)
	if err != nil || n != 1 || len(g.reported) != 1 {
		t.Fatalf("n=%d err=%v reported %+v", n, err, g.reported)
	}
	kept, _ := os.ReadDir(filepath.Join(tg.Dir, "testdata", "fuzz", "FuzzPlanted"))
	if len(kept) != 1 {
		t.Fatalf("corpus %v", kept)
	}
	data, _ := os.ReadFile(filepath.Join(tg.Dir, "testdata", "fuzz", "FuzzPlanted", kept[0].Name()))
	if g.reported[0].Detail != crashDetail(data) {
		t.Fatalf("finding %q does not name the kept input", g.reported[0].Detail)
	}
}

// L3 point 1 on #560: a child past its bound while the job's own context
// is live ends the job with a finding, not a preemption: the next job is
// the following target's, not a retry of the hung one.
func TestAHungTargetIsNotRetriedAsPreempted(t *testing.T) {
	release, marks := t.TempDir(), t.TempDir()
	hung := Target{Pkg: "hung", Name: "FuzzHung", Dir: t.TempDir(),
		Binary: fakeBin(t, release, "hung.test", "echo x >> "+filepath.Join(marks, "hung")+"; sleep 10")}
	next := Target{Pkg: "next", Name: "FuzzNext", Dir: t.TempDir(),
		Binary: fakeBin(t, release, "next.test", "touch "+filepath.Join(marks, "next"))}
	g := newFake()
	clock := time.Unix(1_800_000_000, 0)
	s := newSource(t, g, Config{Targets: []Target{hung, next}, Release: release, Every: time.Hour,
		ReplayTime: 200 * time.Millisecond, InputTime: 200 * time.Millisecond, Now: func() time.Time { return clock }})
	job, ok := s.Next(context.Background(), false)
	if !ok {
		t.Fatal("no job")
	}
	if r := job.Run(context.Background()); r.Value != 1 || len(g.open) != 1 {
		t.Fatalf("result %+v open %v", r, g.open)
	}
	if _, again := s.Next(context.Background(), false); again {
		t.Fatal("the hung target was offered again at once, as if preempted")
	}
	clock = clock.Add(time.Hour)
	job, ok = s.Next(context.Background(), false)
	if !ok {
		t.Fatal("no next job")
	}
	job.Run(context.Background())
	if _, err := os.Stat(filepath.Join(marks, "next")); err != nil {
		t.Fatal("the following target did not run")
	}
	if b, _ := os.ReadFile(filepath.Join(marks, "hung")); strings.Count(string(b), "x") != 1 {
		t.Fatalf("the hung target ran %d times", strings.Count(string(b), "x"))
	}
}

// Go's progress lines for one fuzz step, as Go 1.26 prints them to the
// fuzz step's output: a baseline of 2 inputs, then the exec count, one
// line every 3 s.
func progress(execs ...int) string {
	var at []execsAt
	for i, n := range execs {
		at = append(at, execsAt{3 * (i + 1), n})
	}
	return progressAt(at...)
}

// execsAt is one exec count line: elapsed seconds and the count.
type execsAt struct{ sec, execs int }

// progressAt is progress with each line's elapsed time given.
func progressAt(lines ...execsAt) string {
	out := `echo "fuzz: elapsed: 0s, gathering baseline coverage: 0/2 completed"
echo "fuzz: elapsed: 0s, gathering baseline coverage: 2/2 completed, now fuzzing with 1 workers"
`
	for _, l := range lines {
		out += "echo \"fuzz: elapsed: " + (time.Duration(l.sec) * time.Second).String() + ", execs: " + strconv.Itoa(l.execs) + " (0/sec), new interesting: 0 (total: 2)\"\n"
	}
	return out + "echo PASS"
}

// stepBin is a fake binary whose replays pass and whose fuzz step prints
// body and exits 0; tag makes two builds of it differ.
func stepBin(body, tag string) string {
	return "# build " + tag + "\ncase \"$1\" in -test.run=^\\$)\n" + body + "\n;; esac\nexit 0"
}

// 3h: a step that exits 0 while its exec count never moves past the
// baseline is a target finding: a fuzzed input hung the worker and the
// engine stopped at its deadline with no input stored. A rising count,
// or a step too short to print a progress line, is not.
//
// 3h-r1: so is a step whose count, wherever it stands against the
// baseline, has not moved for a whole progress period (3 s by the lines'
// own elapsed fields) by its last line: a worker that hung after the
// count moved. A count flat for less than a period is not.
func TestAStalledFuzzStepIsReported(t *testing.T) {
	for name, c := range map[string]struct {
		body   string
		report bool
	}{
		"stalled":                        {progress(2, 2), true},
		"stalled at once":                {progress(1), true},
		"rising":                         {progress(2, 900, 4000), false},
		"no progress line":               {"echo PASS", false},
		"baseline only":                  {progress(), false},
		"moved then stalled":             {progress(40, 40), true},
		"rose, then flat a period":       {progressAt(execsAt{3, 400}, execsAt{6, 900}, execsAt{9, 900}), true},
		"rose, then flat under a period": {progressAt(execsAt{3, 400}, execsAt{6, 900}, execsAt{8, 900}), false},
		"one line past the baseline":     {progressAt(execsAt{3, 900}), false},
		// The engine's last line comes as it stops, often a second
		// after its last tick: the count is flat since the tick before.
		"flat since an earlier line": {progressAt(execsAt{3, 400}, execsAt{6, 900}, execsAt{9, 900}, execsAt{10, 900}), true},
		"flat across minutes":        {progressAt(execsAt{57, 400}, execsAt{60, 900}, execsAt{63, 900}), true},
		"rose on the last line":      {progressAt(execsAt{3, 900}, execsAt{6, 900}, execsAt{9, 901}), false},
	} {
		t.Run(name, func(t *testing.T) {
			release := t.TempDir()
			g := newFake()
			tg := fakeTarget(t, release, stepBin(c.body, "1"))
			s := newSource(t, g, Config{Targets: []Target{tg}, Release: release})
			n, err := s.Fuzz(context.Background(), tg)
			if err != nil {
				t.Fatal(err)
			}
			if !c.report {
				if n != 0 || len(g.reported) != 0 {
					t.Fatalf("n=%d reported %+v", n, g.reported)
				}
				return
			}
			if n != 1 || len(g.reported) != 1 || g.reported[0].Detail != loops.FuzzStallDetail || g.reported[0].Subject != tg.subject() {
				t.Fatalf("n=%d reported %+v", n, g.reported)
			}
		})
	}
}

// 3h-r1: the step bounds the engine's minimizing below a progress
// period, so an honest worker's count never stands for one while it
// minimizes a new input (default 60 s).
func TestAFuzzStepBoundsMinimizing(t *testing.T) {
	release, args := t.TempDir(), filepath.Join(t.TempDir(), "args")
	g := newFake()
	tg := fakeTarget(t, release, stepBin(`echo "$@" > `+args+"\n"+progress(2, 900), "1"))
	s := newSource(t, g, Config{Targets: []Target{tg}, Release: release})
	if n, err := s.Fuzz(context.Background(), tg); err != nil || n != 0 {
		t.Fatalf("n=%d err=%v", n, err)
	}
	b, err := os.ReadFile(args)
	if err != nil || !strings.Contains(string(b), " -test.fuzzminimizetime=1s") || minimizeTime >= progressPeriod/2 {
		t.Fatalf("args %q %v", b, err)
	}
}

// P3-4b-3r-confine l9 (#588, #615): Go's coordinator can stop at its own
// -test.fuzztime yet exit 1 with "context deadline exceeded" (its done
// channel closes before the workers' context is cancelled, a race load
// widens). A step that ran its whole FuzzTime and failed only so is
// judged by its progress, as a clean stop is; the same text before
// FuzzTime has passed, or beside another failure, is still a step that
// did not run.
func TestAFuzzStepStoppedByItsOwnDeadlineIsJudgedByItsProgress(t *testing.T) {
	deadline := "echo '--- FAIL: FuzzFake (0.30s)'\necho '    context deadline exceeded'\necho FAIL\nexit 1"
	for name, c := range map[string]struct {
		body   string
		report int // findings; -1: the runner's error
	}{
		"stalled at its deadline":         {"sleep 0.3\n" + progress(1, 1) + "\n" + deadline, 1},
		"good step at its deadline":       {"sleep 0.3\n" + progress(2, 5000) + "\n" + deadline, 0},
		"deadline text before FuzzTime":   {progress(1, 1) + "\n" + deadline, -1},
		"another failure":                 {"sleep 0.3\n" + progress(1, 1) + "\necho '--- FAIL: FuzzFake (0.30s)'\necho '    fuzzing process hung or terminated unexpectedly: exit status 2'\nexit 1", -1},
		"deadline text and another error": {"sleep 0.3\n" + progress(1, 1) + "\necho '--- FAIL: FuzzFake (0.30s)'\necho '    context deadline exceeded'\necho '    exit status 2'\nexit 1", -1},
	} {
		t.Run(name, func(t *testing.T) {
			release := t.TempDir()
			g := newFake()
			tg := fakeTarget(t, release, stepBin(c.body, "1"))
			s := newSource(t, g, Config{Targets: []Target{tg}, Release: release, FuzzTime: 200 * time.Millisecond})
			n, err := s.Fuzz(context.Background(), tg)
			switch {
			case c.report < 0:
				if err == nil || !strings.Contains(err.Error(), "did not run") || len(g.reported) != 0 {
					t.Fatalf("n=%d err=%v reported %+v", n, err, g.reported)
				}
			case err != nil || n != c.report || len(g.reported) != c.report:
				t.Fatalf("n=%d err=%v reported %+v", n, err, g.reported)
			case c.report == 1 && g.reported[0].Detail != loops.FuzzStallDetail:
				t.Fatalf("reported %+v", g.reported)
			}
		})
	}
}

// 3h-r1: a step judged a stall is never a good step, so it closes no
// open hang finding, even from a new binary.
func TestALateStallClosesNothing(t *testing.T) {
	release := t.TempDir()
	g := newFake()
	tg := fakeTarget(t, release, stepBin(progress(2, 2), "1"))
	s := newSource(t, g, Config{Targets: []Target{tg}, Release: release})
	if n, err := s.Fuzz(context.Background(), tg); err != nil || n != 1 {
		t.Fatalf("n=%d err=%v", n, err)
	}
	fakeBin(t, release, "fake.test", stepBin(progress(400, 900, 900), "2"))
	if n, err := s.Fuzz(context.Background(), tg); err != nil || n != 1 || len(g.closed) != 0 || len(g.open) != 1 {
		t.Fatalf("n=%d err=%v open %v closed %v", n, err, g.open, g.closed)
	}
}

// fileDigest is the SHA-256 the runner records for a binary.
func fileDigest(t *testing.T, path string) string {
	t.Helper()
	d, err := binaryDigest(path)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

// 3h: a hang finding closes only on a good step (in time, exec count past
// the baseline) of a binary other than the one that produced it; the
// closure is not a replay. 3h-r2: the runner reports the producing
// binary's digest with the finding and passes only the step's own digest
// and counts to close it; loops holds the producer, across a restart.
func TestAHangClosesOnlyOnAGoodStepOfANewBinary(t *testing.T) {
	for _, hang := range []string{loops.FuzzStallDetail, loops.FuzzOverrunDetail} {
		t.Run(hang, func(t *testing.T) {
			release, good := t.TempDir(), filepath.Join(t.TempDir(), "good")
			bad := progress(2, 2)
			if hang == loops.FuzzOverrunDetail {
				bad = "sleep 10"
			}
			// One build: it hangs until the file good exists, then steps well.
			body := "if [ -e " + good + " ]; then\n" + progress(2, 5000) + "\nelse\n" + bad + "\nfi"
			g := newFake()
			tg := fakeTarget(t, release, stepBin(body, "1"))
			cfg := Config{Targets: []Target{tg}, Release: release, FuzzTime: 100 * time.Millisecond, ReplayTime: 300 * time.Millisecond}
			s := newSource(t, g, cfg)
			if n, err := s.Fuzz(context.Background(), tg); err != nil || n != 1 || len(g.open) != 1 || g.reported[0].Detail != hang {
				t.Fatalf("n=%d err=%v reported %+v", n, err, g.reported)
			}
			produced := fileDigest(t, tg.Binary)
			if g.reported[0].Producer != produced {
				t.Fatalf("reported producer %q, want %q", g.reported[0].Producer, produced)
			}

			// The same binary completes a good step: still open.
			if err := os.WriteFile(good, nil, 0o600); err != nil {
				t.Fatal(err)
			}
			if n, err := s.Fuzz(context.Background(), tg); err != nil || n != 0 || len(g.open) != 1 || len(g.closed) != 0 {
				t.Fatalf("same binary: n=%d err=%v open %v closed %v", n, err, g.open, g.closed)
			}

			// A restart, then a new build whose step is good: closed.
			fakeBin(t, release, "fake.test", stepBin(body, "2"))
			s = newSource(t, g, cfg)
			fresh := fileDigest(t, tg.Binary)
			if n, err := s.Fuzz(context.Background(), tg); err != nil || n != 0 || len(g.open) != 0 || len(g.closed) != 1 {
				t.Fatalf("new binary: n=%d err=%v open %v closed %v", n, err, g.open, g.closed)
			}
			c := g.closed[0]
			if c.Kind != loops.ClosureStep || c.Replayed || c.Binary != fresh || c.Produced != produced || c.Execs != 5000 || c.Baseline != 2 {
				t.Fatalf("closure %+v", c)
			}
			if len(g.resolved) != 0 {
				t.Fatalf("a hang was resolved as a replay: %v", g.resolved)
			}
		})
	}
}

// A hang the same target shows again on a newer build is reported with
// that build as the producer, so a lucky good step of it closes nothing.
func TestARepeatedHangRecordsTheNewerBuild(t *testing.T) {
	release, good := t.TempDir(), filepath.Join(t.TempDir(), "good")
	body := "if [ -e " + good + " ]; then\n" + progress(2, 5000) + "\nelse\n" + progress(2, 2) + "\nfi"
	g := newFake()
	tg := fakeTarget(t, release, stepBin(body, "1"))
	s := newSource(t, g, Config{Targets: []Target{tg}, Release: release})
	if n, err := s.Fuzz(context.Background(), tg); err != nil || n != 1 {
		t.Fatalf("n=%d err=%v", n, err)
	}
	fakeBin(t, release, "fake.test", stepBin(body, "2"))
	if n, err := s.Fuzz(context.Background(), tg); err != nil || n != 1 {
		t.Fatalf("n=%d err=%v", n, err)
	}
	newer := fileDigest(t, tg.Binary)
	if len(g.reported) != 2 || g.reported[1].Producer != newer {
		t.Fatalf("reported %+v", g.reported)
	}
	if err := os.WriteFile(good, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Fuzz(context.Background(), tg); err != nil || len(g.open) != 1 || len(g.closed) != 0 {
		t.Fatalf("a good step of the newer producer: err=%v open %v closed %v", err, g.open, g.closed)
	}
}

// 3h-r2: the fuzz child owns the target's directory, so a hang record
// there is the child's to forge. A good step whose child writes a
// hang.json naming another producer still closes nothing for its own
// binary, and a hang.json planted before any step is never read,
// rewritten or removed.
func TestAForgedHangRecordClosesNothing(t *testing.T) {
	release, good := t.TempDir(), filepath.Join(t.TempDir(), "good")
	// One build: it hangs until the file good exists, then steps well
	// and forges a record naming another producer.
	forge := `printf '%s' '{"` + loops.FuzzStallDetail + `":"` + strings.Repeat("b", 64) + `"}' > hang.json`
	body := "if [ -e " + good + " ]; then\n" + forge + "\n" + progress(2, 5000) + "\nelse\n" + progress(2, 2) + "\nfi"
	g := newFake()
	tg := fakeTarget(t, release, stepBin(body, "1"))
	planted := []byte(`{"` + loops.FuzzStallDetail + `":"` + strings.Repeat("c", 64) + `"}`)
	plant := filepath.Join(tg.Dir, "hang.json")
	if err := os.WriteFile(plant, planted, 0o600); err != nil {
		t.Fatal(err)
	}
	s := newSource(t, g, Config{Targets: []Target{tg}, Release: release})
	if n, err := s.Fuzz(context.Background(), tg); err != nil || n != 1 {
		t.Fatalf("n=%d err=%v", n, err)
	}
	if b, err := os.ReadFile(plant); err != nil || string(b) != string(planted) {
		t.Fatalf("the planted record was touched: %q %v", b, err)
	}
	if err := os.WriteFile(good, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if n, err := s.Fuzz(context.Background(), tg); err != nil || n != 0 || len(g.open) != 1 || len(g.closed) != 0 {
		t.Fatalf("a forged record closed it: n=%d err=%v open %v closed %v", n, err, g.open, g.closed)
	}
	if b, err := os.ReadFile(plant); err != nil || !strings.Contains(string(b), strings.Repeat("b", 64)) {
		t.Fatalf("the child's own record was touched: %q %v", b, err)
	}
}

// 3h, the real engine's control: a planted target that loops forever on
// inputs longer than three bytes stops at -test.fuzztime with PASS, exit
// 0 and no stored input; the runner reports it as a stall. FuzzTime
// leaves a loaded host (the -race suite) time to finish the baseline
// and print an exec count before it stops (P3-4b-3r-confine l9: at 2 s a
// step under load printed none, and was no stall and no good step).
func TestAPlantedHangIsReported(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a test binary")
	}
	src, err := filepath.Abs(filepath.Join("testdata", "hangtarget"))
	if err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(t.TempDir(), "hangtarget.test")
	cmd := exec.Command("go", "test", "-c", "-fuzz=FuzzHang", "-o", bin, ".")
	cmd.Dir = src
	cmd.Env = append(os.Environ(), "GOWORK=off", "GOFLAGS=-mod=mod")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	tg := Target{Pkg: "hangtarget", Name: "FuzzHang", Binary: bin, Dir: t.TempDir()}
	g := newFake()
	s := newSource(t, g, Config{Targets: []Target{tg}, FuzzTime: 6 * time.Second})
	start := time.Now()
	n, err := s.Fuzz(context.Background(), tg)
	if err != nil || n != 1 || len(g.reported) != 1 || g.reported[0].Detail != loops.FuzzStallDetail {
		t.Fatalf("n=%d err=%v reported %+v", n, err, g.reported)
	}
	t.Logf("reported after %v", time.Since(start))
}

// 3h-r1, the real engine's control: a planted target whose worker hangs a
// second after its first call, once its exec count has moved past the
// baseline, stops at -test.fuzztime with PASS, exit 0 and no stored
// input; the runner reports it as a stall.
func TestAPlantedLateHangIsReported(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a test binary")
	}
	src, err := filepath.Abs(filepath.Join("testdata", "latehang"))
	if err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(t.TempDir(), "latehang.test")
	cmd := exec.Command("go", "test", "-c", "-fuzz=FuzzLateHang", "-o", bin, ".")
	cmd.Dir = src
	cmd.Env = append(os.Environ(), "GOWORK=off", "GOFLAGS=-mod=mod")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	tg := Target{Pkg: "latehang", Name: "FuzzLateHang", Binary: bin, Dir: t.TempDir()}
	g := newFake()
	s := newSource(t, g, Config{Targets: []Target{tg}, FuzzTime: 8 * time.Second})
	start := time.Now()
	n, err := s.Fuzz(context.Background(), tg)
	if err != nil || n != 1 || len(g.reported) != 1 || g.reported[0].Detail != loops.FuzzStallDetail {
		t.Fatalf("n=%d err=%v reported %+v", n, err, g.reported)
	}
	t.Logf("reported after %v", time.Since(start))
}
