package loop7

// REQ: LOOP-1, LOOP-7
//
// P3-4b-3r-confine-r1: the fuzz leaf's memory cap is measured, not
// guessed. CI's machines job runs each target the image's manifest lists
// for one fuzz round, as agentosd wires it, in a fresh leaf, and reads
// the leaf's peak; agentosd L7-6 sets the cap from the table.

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/cgroup"
)

// peakLimits are the leaf's limits while measuring: agentosd's fuzzLimits
// before the measurement (1 GiB, 256 tasks; L7-6), so no target is cut
// short by the cap the measurement decides.
var peakLimits = cgroup.Limits{MaxBytes: 1 << 30, HighBytes: 1 << 30, Pids: 256, CPUWeight: 100, IOWeight: 100}

// LOOP-1 (root, cgroup v2; CI machines job with AGENTOS_FUZZ_PEAKS set):
// each target image/fuzz-targets.json lists, built as image/build.sh
// builds it, runs one round (corpus replay, then FuzzTime 30 s with one
// worker) in a fresh leaf, jailed as nobody, and the leaf's memory.peak
// after it goes in a table, logged and written to AGENTOS_FUZZ_PEAKS.
func TestFuzzLeafPeakPerTarget(t *testing.T) {
	table := os.Getenv("AGENTOS_FUZZ_PEAKS")
	if table == "" {
		t.Skip("set AGENTOS_FUZZ_PEAKS to the table's path (CI machines job)")
	}
	needRoot(t)
	parent := os.Getenv("AGENTOS_CGROUP_PARENT")
	if parent == "" {
		t.Skip("set AGENTOS_CGROUP_PARENT to a writable cgroup v2 group (root only)")
	}
	p, err := cgroup.Open(parent)
	if err != nil {
		t.Fatal(err)
	}
	base := jailDir(t)
	release := fuzzRelease(t, filepath.Join(base, "release"))
	state := filepath.Join(base, "state")
	ts, err := Load(release, state)
	if err != nil {
		t.Fatal(err)
	}
	var b strings.Builder
	fmt.Fprintf(&b, "| Target | Peak MiB | OOM kills | Failures | Error |\n|---|---|---|---|---|\n")
	var most int64
	for i, tg := range ts {
		leaf, err := p.Component(fmt.Sprintf("loop7-peak-%d", i), peakLimits)
		if err != nil {
			t.Fatal(err)
		}
		peak, oom, n, ferr := peakOf(t, leaf, ts, tg, release, state)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		leaf.Kill(ctx)
		cancel()
		if err := leaf.Remove(); err != nil {
			t.Errorf("removing %s: %v", leaf.Path, err)
		}
		e := "-"
		if ferr != nil {
			e = strings.ReplaceAll(ferr.Error(), "|", "/")
			t.Errorf("%s: %v", tg.subject(), ferr)
		}
		fmt.Fprintf(&b, "| %s | %.1f | %d | %d | %s |\n", tg.subject(), float64(peak)/(1<<20), oom, n, e)
		most = max(most, peak)
	}
	fmt.Fprintf(&b, "\nLargest peak: %.1f MiB (%d targets; leaf memory.max %d MiB).\n", float64(most)/(1<<20), len(ts), peakLimits.MaxBytes>>20)
	t.Log("\n" + b.String())
	if err := os.WriteFile(table, []byte(b.String()), 0o644); err != nil {
		t.Fatal(err)
	}
}

// fuzzRelease builds the image's fuzz release in dir as image/build.sh
// does: the manifest, one instrumented test binary per package, and each
// target's seed corpus.
func fuzzRelease(t *testing.T, dir string) string {
	t.Helper()
	repo, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	m, err := os.ReadFile(filepath.Join(repo, "image", "fuzz-targets.json"))
	if err != nil {
		t.Fatal(err)
	}
	var man manifest
	if err := json.Unmarshal(m, &man); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "manifest.json"), m, 0o644); err != nil {
		t.Fatal(err)
	}
	built := map[string]bool{}
	for _, e := range man.Targets {
		if !built[e.Binary] {
			built[e.Binary] = true
			cmd := exec.Command("go", "test", "-c", "-trimpath", "-ldflags=-s -w -buildid=", "-fuzz=.", "-o", filepath.Join(dir, e.Binary), "./"+e.Pkg)
			cmd.Dir = filepath.Join(repo, "broker")
			cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
			if out, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("building %s: %v\n%s", e.Pkg, err, out)
			}
		}
		seeds := filepath.Join(repo, "broker", filepath.FromSlash(e.Pkg), "testdata", "fuzz", e.Name)
		es, err := os.ReadDir(seeds)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		} else if err != nil {
			t.Fatal(err)
		}
		to := filepath.Join(dir, "corpus", filepath.FromSlash(e.Pkg), e.Name)
		if err := os.MkdirAll(to, 0o755); err != nil {
			t.Fatal(err)
		}
		for _, f := range es {
			b, err := os.ReadFile(filepath.Join(seeds, f.Name()))
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(to, f.Name()), b, 0o644); err != nil {
				t.Fatal(err)
			}
		}
	}
	return dir
}

// peakOf runs tg's round in leaf and returns the leaf's peak memory, its
// OOM kills, and the round's failures and error. Without memory.peak
// (kernels before 5.19) it polls memory.current every 100 ms instead.
func peakOf(t *testing.T, leaf *cgroup.Group, ts []Target, tg Target, release, state string) (peak, oom int64, n int, err error) {
	t.Helper()
	j := &Jail{Leaf: leaf.Path, UID: nobody, GID: nobody, State: state}
	if err := j.Own(); err != nil {
		t.Fatal(err)
	}
	s := newSource(t, newFake(), Config{Targets: ts, Release: release, CacheDir: filepath.Join(state, "cache"), Jail: j, FuzzTime: 30 * time.Second})
	var polled atomic.Int64
	stop := make(chan struct{})
	done := make(chan struct{})
	_, perr := os.Stat(filepath.Join(leaf.Path, "memory.peak"))
	go func() {
		defer close(done)
		if perr == nil {
			return
		}
		tick := time.NewTicker(100 * time.Millisecond)
		defer tick.Stop()
		for {
			if v, err := cgroupInt(leaf.Path, "memory.current"); err == nil && v > polled.Load() {
				polled.Store(v)
			}
			select {
			case <-stop:
				return
			case <-tick.C:
			}
		}
	}()
	n, err = s.Fuzz(context.Background(), tg)
	close(stop)
	<-done
	if perr == nil {
		if peak, perr = cgroupInt(leaf.Path, "memory.peak"); perr != nil {
			t.Fatal(perr)
		}
	} else {
		peak = polled.Load()
	}
	return peak, oomKills(t, leaf.Path), n, err
}

// cgroupInt reads a cgroup file holding one integer.
func cgroupInt(dir, file string) (int64, error) {
	b, err := os.ReadFile(filepath.Join(dir, file))
	if err != nil {
		return 0, err
	}
	return strconv.ParseInt(strings.TrimSpace(string(b)), 10, 64)
}

// oomKills is memory.events' oom_kill count.
func oomKills(t *testing.T, dir string) int64 {
	t.Helper()
	f, err := os.Open(filepath.Join(dir, "memory.events"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if v, ok := strings.CutPrefix(sc.Text(), "oom_kill "); ok {
			n, _ := strconv.ParseInt(v, 10, 64)
			return n
		}
	}
	return 0
}
