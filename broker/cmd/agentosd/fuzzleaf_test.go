package main

// REQ: LOOP-1, LOOP-7
//
// P3-4b-3r-confine: agentosd confines every fuzz child (agentosd
// ASSUMPTIONS L7-6): its own cgroup leaf beside the broker's group, an
// unprivileged user, no network. A box that cannot confine them runs no
// fuzz rounds.

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/admission"
	"github.com/ghbmrk/agentos/broker/budget"
	"github.com/ghbmrk/agentos/broker/cgroup"
	"github.com/ghbmrk/agentos/broker/daemon"
	"github.com/ghbmrk/agentos/broker/loops"
)

func openConfinedLearning(t *testing.T, dir string, p learnPaths) *learning {
	t.Helper()
	cfg := daemon.Config{
		JournalPath: filepath.Join(dir, "journal.log"), SocketDir: filepath.Join(dir, "run"),
		OwnerNumber: ownerNum, ModemUID: os.Getuid(), Admission: admission.Config{CapacityMB: 4500, HeadroomMB: 600},
		OwnerState: filepath.Join(dir, "owner.json"),
	}
	p.Dir, p.Spare = dir, filepath.Join(dir, "spare.json")
	lp, err := openLearning(p, false, &cfg)
	if err != nil {
		t.Fatal(err)
	}
	return lp
}

// LOOP-1: with a fuzz user named (as main always names one) but no
// cgroup root to put the leaf in, or no such user, agentosd runs no fuzz
// targets rather than unconfined ones; the guard still runs.
func TestFuzzRunsNothingItCannotConfine(t *testing.T) {
	release := fakeFuzzRelease(t, crashing)
	for name, p := range map[string]learnPaths{
		"no cgroup root": {FuzzUser: "nobody"},
		"no such user":   {FuzzUser: "agentos-no-such-user", Cgroup: t.TempDir()},
	} {
		dir := t.TempDir()
		p.Fuzz, p.Loop7 = release, filepath.Join(dir, "loop7")
		lp := openConfinedLearning(t, dir, p)
		if lp.fuzz == nil || lp.fuzz.Recheck() != fuzzEvery {
			t.Errorf("%s: fuzz targets wired unconfined (recheck %v)", name, lp.fuzz.Recheck())
		}
	}
}

// LOOP-1: the leaf's CPU weight is the lowest in use, below the broker's.
func TestTheFuzzLeafWeighsLeast(t *testing.T) {
	for _, w := range []int{budget.BrokerWeight, budget.InferenceWeight, budget.BrowserWeight, budget.PoolWeight} {
		if fuzzLimits.CPUWeight > w || fuzzLimits.IOWeight > w {
			t.Fatalf("fuzz weights %d/%d above a component's %d", fuzzLimits.CPUWeight, fuzzLimits.IOWeight, w)
		}
	}
	if fuzzLimits.CPUWeight >= budget.BrokerWeight {
		t.Fatal("fuzz weight not below the broker's")
	}
}

// LOOP-1, LOOP-7 (root, cgroup v2; CI machines job): agentosd puts the
// fuzz leaf beside broker/ under its root, with memory.max, pids.max and
// the lowest weight, and no group OOM kill, so the engine survives a
// worker's OOM kill and stores the input; it gives the state to the fuzz
// user; and a round's crash, from a child in that leaf, still reaches the
// guard as a finding.
func TestTheFuzzLeafSitsBesideTheBrokerAndConfinesARound(t *testing.T) {
	parent := os.Getenv("AGENTOS_CGROUP_PARENT")
	if os.Geteuid() != 0 || parent == "" {
		t.Skip("needs root and AGENTOS_CGROUP_PARENT (CI machines job)")
	}
	root := filepath.Join(parent, "agentosd-fuzz")
	if err := os.Mkdir(root, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		leaf := &cgroup.Group{Path: filepath.Join(root, "fuzz")}
		leaf.Kill(ctx)
		leaf.Remove()
		os.Remove(root)
	})
	if _, err := cgroup.Open(root); err != nil {
		t.Fatal(err)
	}
	// nobody must reach the release and the state, as agentos-fuzz
	// reaches /var/lib/agentos-fuzz under /var/lib; the state is on a
	// file system with project quotas, which its jail needs (RES-4).
	state := filepath.Join(reachableQuotaDir(t), "loop7")
	base, err := os.MkdirTemp("", "agentosd-fuzz-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(base) })
	release := filepath.Join(base, "release")
	if err := os.Chmod(base, 0o755); err != nil || os.Mkdir(release, 0o755) != nil {
		t.Fatal(err)
	}
	m := `{"targets":[{"pkg":"fake","name":"FuzzFake","binary":"fake.test"}]}`
	bin := "#!/bin/sh\ngrep -q '^0::" + strings.TrimPrefix(root, "/sys/fs/cgroup") + "/fuzz$' /proc/self/cgroup || exit 3\n" + crashing + "\n"
	if os.WriteFile(filepath.Join(release, "manifest.json"), []byte(m), 0o644) != nil || os.WriteFile(filepath.Join(release, "fake.test"), []byte(bin), 0o755) != nil {
		t.Fatal("release")
	}
	dir := t.TempDir()
	lp := openConfinedLearning(t, dir, learnPaths{Fuzz: release, Loop7: state, FuzzUser: "nobody", Cgroup: root, DiskQuota: "on"})

	leaf := filepath.Join(root, "fuzz")
	for f, want := range map[string]string{
		"memory.max": strconv.FormatInt(1<<30, 10), "memory.high": strconv.FormatInt(1<<30, 10), "pids.max": "256",
		"cpu.weight": strconv.Itoa(fuzzLimits.CPUWeight), "memory.oom.group": "0",
	} {
		b, err := os.ReadFile(filepath.Join(leaf, f))
		if got := strings.TrimSpace(string(b)); err != nil || got != want {
			t.Errorf("leaf %s = %q (%v), want %q", f, got, err, want)
		}
	}
	var st syscall.Stat_t
	if err := syscall.Stat(filepath.Join(state, "targets", "fake"), &st); err != nil || st.Uid != 65534 {
		t.Errorf("the state is not the fuzz user's: uid %d, %v", st.Uid, err)
	}

	ctx := context.Background()
	if _, err := lp.guard.Pass(ctx); err != nil {
		t.Fatal(err)
	}
	// The guard's corpus replay (P3-4b-4c-corpus) is offered before the
	// fuzz round, as in TestARoundRunsThePassThenReportsAFuzzCrash.
	j, ok := lp.fuzz.Next(ctx, false)
	if ok && j.Name == "probe:corpus" {
		if r := j.Run(ctx); r.Err != nil {
			t.Fatal(r.Err)
		}
		j, ok = lp.fuzz.Next(ctx, false)
	}
	if !ok || j.Name != "fuzz" {
		t.Fatalf("job %+v %v", j, ok)
	}
	if r := j.Run(ctx); r.Err != nil {
		t.Fatal(r.Err)
	}
	fs := lp.guard.OpenReported(loops.CheckFuzz)
	if len(fs) != 1 || !strings.HasPrefix(fs[0].Detail, "crash input sha256:") {
		t.Fatalf("a confined round's crash was not reported by its input: %+v", fs)
	}
}
