package loop7

// REQ: LOOP-7, LOOP-9, ARC-2
//
// P3-4b-3a: the runner agentosd links. Children run only binaries the
// signed release lists, with a minimal environment, in their own process
// group, which a timeout kills whole.

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/journal"
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
	tg := fakeTarget(t, release, "sleep 300 &\necho $! > "+pidfile+"\nsleep 300")
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
