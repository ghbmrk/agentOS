package main

// REQ: LOOP-7, LOOP-9
//
// P3-4b-3a: agentosd wires LOOP-7's fuzz source in front of Loop 2's
// passive guard, with the release's targets.

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/admission"
	"github.com/ghbmrk/agentos/broker/daemon"
	"github.com/ghbmrk/agentos/broker/loops"
)

// fuzzRelease writes a release directory with one fake target, fake.test,
// whose replay prints body's output.
func fakeFuzzRelease(t *testing.T, body string) string {
	t.Helper()
	release := t.TempDir()
	m := `{"targets":[{"pkg":"fake","name":"FuzzFake","binary":"fake.test"}]}`
	if err := os.WriteFile(filepath.Join(release, "manifest.json"), []byte(m), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(release, "fake.test"), []byte("#!/bin/sh\n"+body+"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	return release
}

// crashing is a fake fuzz binary whose replay fails one stored input.
const crashing = `case "$1" in -test.run=^FuzzFake$) echo "    --- FAIL: FuzzFake/0crash (0.00s)"; exit 1;; esac; exit 0`

func openFuzzLearning(t *testing.T, release string) *learning {
	t.Helper()
	dir := t.TempDir()
	cfg := daemon.Config{
		JournalPath: filepath.Join(dir, "journal.log"), SocketDir: filepath.Join(dir, "run"),
		OwnerNumber: ownerNum, ModemUID: os.Getuid(), Admission: admission.Config{CapacityMB: 4500, HeadroomMB: 600},
		OwnerState: filepath.Join(dir, "owner.json"),
	}
	lp, err := openLearning(learnPaths{Dir: dir, Spare: filepath.Join(dir, "spare.json"), Fuzz: release, Loop7: filepath.Join(dir, "loop7")}, false, &cfg)
	if err != nil {
		t.Fatal(err)
	}
	return lp
}

// LOOP-7, LOOP-9: in one round of Loop 2 work the guard's passive pass
// runs first, then the fuzz job, whose crash is reported through the
// guard as one fuzz finding.
func TestARoundRunsThePassThenReportsAFuzzCrash(t *testing.T) {
	lp := openFuzzLearning(t, fakeFuzzRelease(t, crashing))
	if lp.fuzz == nil {
		t.Fatal("no fuzz source wired")
	}
	// The scheduler runs Loop 2's jobs one at a time, as offered (it
	// needs an attached daemon to tick, so the jobs are run here): the
	// passive pass, the guard's corpus replay, then a fuzz round.
	ctx := context.Background()
	var ran []string
	for i := 0; i < 4; i++ {
		j, ok := lp.fuzz.Next(ctx, false)
		if !ok {
			break
		}
		if r := j.Run(ctx); r.Err != nil {
			t.Fatalf("%s: %v", j.Name, r.Err)
		}
		ran = append(ran, j.Name)
	}
	if strings.Join(ran, ",") != "passive,probe:corpus,fuzz" {
		t.Fatalf("jobs %v", ran)
	}
	if d := lp.guard.Status(); !strings.Contains(d, "Loop 2: partial") {
		t.Fatalf("the passive pass did not run: %q", d)
	}
	fs := lp.guard.OpenReported(loops.CheckFuzz)
	if len(fs) != 1 || fs[0].Subject != "fake.FuzzFake" || fs[0].Severity != loops.High {
		t.Fatalf("fuzz findings %+v", fs)
	}
}

// LOOP-1: a preempted fuzz job leaves no finding, and is offered again.
func TestAPreemptedFuzzRoundLeavesNoFinding(t *testing.T) {
	lp := openFuzzLearning(t, fakeFuzzRelease(t, "sleep 30; "+crashing))
	if _, err := lp.guard.Pass(context.Background()); err != nil {
		t.Fatal(err)
	}
	if j, ok := lp.fuzz.Next(context.Background(), false); !ok || j.Name != "probe:corpus" || j.Run(context.Background()).Err != nil {
		t.Fatalf("job %+v %v", j, ok)
	}
	job, ok := lp.fuzz.Next(context.Background(), false)
	if !ok || job.Name != "fuzz" {
		t.Fatalf("job %+v %v", job, ok)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	start := time.Now()
	if r := job.Run(ctx); r.Err != nil {
		t.Fatal(r.Err)
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("yielded in %v", d)
	}
	if fs := lp.guard.OpenReported(loops.CheckFuzz); len(fs) != 0 {
		t.Fatalf("a preempted round reported %+v", fs)
	}
	if j, ok := lp.fuzz.Next(context.Background(), false); !ok || j.Name != "fuzz" {
		t.Fatal("the preempted job is not offered again")
	}
}

// REQ: LOOP-1
//
// The cadence P3-4b-3c's owner text promises: with the targets the image
// ships (image/fuzz-targets.json, read as agentosd reads it) and the Every
// agentosd sets, each target is rechecked at least twice a day, counting
// the probe's slot even while no probe is wired. When the manifest grows,
// lower fuzzEvery or group targets per job, not the wording.
func TestEachFuzzTargetIsRecheckedTwiceADay(t *testing.T) {
	m, err := os.ReadFile(filepath.Join("..", "..", "..", "image", "fuzz-targets.json"))
	if err != nil {
		t.Fatal(err)
	}
	release := t.TempDir()
	if err := os.WriteFile(filepath.Join(release, "manifest.json"), m, 0o644); err != nil {
		t.Fatal(err)
	}
	lp := openFuzzLearning(t, release)
	n := strings.Count(string(m), `"name"`)
	if n == 0 || lp.fuzz.Recheck() != time.Duration(n+1)*fuzzEvery {
		t.Fatalf("%d targets: recheck %v, Every %v", n, lp.fuzz.Recheck(), fuzzEvery)
	}
	if lp.fuzz.Recheck() > 12*time.Hour {
		t.Fatalf("%d targets every %v: each is rechecked every %v, over 12 h", n, fuzzEvery, lp.fuzz.Recheck())
	}
}

// Without a release (a dev box, a test), the source wraps the guard with
// no targets, and the guard still runs.
func TestNoReleaseRunsNoFuzz(t *testing.T) {
	lp := openFuzzLearning(t, filepath.Join(t.TempDir(), "absent"))
	if lp.fuzz == nil || lp.fuzz.Recheck() != fuzzEvery {
		t.Fatal("the guard is not wrapped, or targets came from nowhere")
	}
	if j, ok := lp.fuzz.Next(context.Background(), false); !ok || j.Name != "passive" {
		t.Fatalf("the guard's pass is not offered: %+v %v", j, ok)
	}
}
