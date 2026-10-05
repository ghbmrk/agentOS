// Package floor measures resource admission on a host sized like the HW-4
// floor box (N95, 8 GB): RES-1 preemption time against the provisional target,
// and RES-2 admission against the declared budget, with every component
// loaded. It needs root, cgroup v2 and runsc, so it runs only in CI's
// machines job; elsewhere it skips.
package floor

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/admission"
	"github.com/ghbmrk/agentos/broker/budget"
	"github.com/ghbmrk/agentos/broker/cgroup"
	"github.com/ghbmrk/agentos/broker/vm"
	"github.com/ghbmrk/agentos/broker/vm/gvisor"
)

// REQ: RES-1, RES-2

// PreemptTarget is the provisional RES-1 target at the floor: from a
// foreground request to the experiment's memory being released. No
// DECISIONS.md row freezes it yet; it is proposed for freezing once the
// N95 run (A2) confirms it (budget R6).
const PreemptTarget = time.Second

// floorMiB is what an 8 GB N95 reports as MemTotal (firmware and the iGPU
// take the rest).
const floorMiB = 7680

// Guest sizes: an OpenClaw machine is about 1.6 GB (S4). Its budget leaves
// gVisor and memory.high room above the heap.
const (
	guestHeapMiB = 1400
	guestMemMB   = 1700
)

type timing struct {
	mu    sync.Mutex
	m     **vm.Manager
	took  []time.Duration
	extra func()
}

func (p *timing) Preempt(id string) error {
	t0 := time.Now()
	err := (*p.m).Preempt(id)
	p.mu.Lock()
	p.took = append(p.took, time.Since(t0))
	p.mu.Unlock()
	return err
}

func (p *timing) last() time.Duration {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.took[len(p.took)-1]
}

type floorRig struct {
	t      *testing.T
	root   *cgroup.Group
	groups budget.Groups
	mem    budget.Memory
	adm    *admission.Controller
	m      *vm.Manager
	pre    *timing
	rt     *gvisor.Runtime
	hogBin string
}

func build(t *testing.T, out string) {
	t.Helper()
	b := exec.Command("go", "build", "-o", out, "./testdata/hog")
	b.Env = append(os.Environ(), "CGO_ENABLED=0")
	if o, err := b.CombinedOutput(); err != nil {
		t.Fatalf("building hog: %v\n%s", err, o)
	}
}

func newFloor(t *testing.T) *floorRig {
	t.Helper()
	bin, parent := os.Getenv("AGENTOS_RUNSC"), os.Getenv("AGENTOS_CGROUP_PARENT")
	if bin == "" || parent == "" || os.Geteuid() != 0 {
		t.Skip("set AGENTOS_RUNSC and AGENTOS_CGROUP_PARENT and run as root (CI machines job)")
	}
	p, err := cgroup.Open(parent)
	must(t, err)
	// The whole box: everything below shares 7680 MiB, as on the N95.
	box, err := p.Component("floor", cgroup.Limits{MaxBytes: floorMiB << 20, HighBytes: floorMiB << 20})
	must(t, err)
	root, err := cgroup.Open(box.Path)
	must(t, err)
	mem, err := budget.ForHost(floorMiB, budget.Floor())
	must(t, err)
	gs, err := mem.Apply(root)
	must(t, err)

	img := t.TempDir()
	for _, d := range []string{"work", "tmp", "proc", "dev", "sys"} {
		must(t, os.Mkdir(filepath.Join(img, d), 0o755))
	}
	build(t, filepath.Join(img, "hog"))
	r := &floorRig{t: t, root: root, groups: gs, mem: mem, hogBin: filepath.Join(img, "hog")}
	state := t.TempDir()
	r.rt = &gvisor.Runtime{Bin: bin, StateDir: filepath.Join(state, "runsc")}
	r.pre = &timing{m: &r.m}
	r.adm, err = admission.New(mem.Admission(), r.pre)
	must(t, err)
	if read, ok := cgroup.PressureSource(filepath.Join(gs.Machines.Path, "memory.pressure")); ok {
		r.adm.Pressure, r.adm.MaxPressure = read, 10
	}
	r.m, err = vm.Open(context.Background(), vm.Config{
		StateDir: filepath.Join(state, "broker"),
		Images:   map[string]string{"base": img},
		Runtime:  r.rt,
		Admit:    r.adm,
		Cgroups:  gs.Machines,
	})
	must(t, err)
	t.Cleanup(func() {
		for _, id := range r.m.Machines() {
			r.m.Destroy(context.Background(), id)
		}
		syscall.Unmount(filepath.Join(r.rt.StateDir, "null-netns"), syscall.MNT_DETACH)
	})
	return r
}

// hostHog runs a hog of mib in group g, outside any sandbox: local
// inference and the browser at their budgets.
func (r *floorRig) hostHog(g *cgroup.Group, mib int64) {
	r.t.Helper()
	fd, err := syscall.Open(g.Path, syscall.O_DIRECTORY|syscall.O_RDONLY, 0)
	must(r.t, err)
	defer syscall.Close(fd)
	c := exec.Command(r.hogBin, strconv.FormatInt(mib, 10))
	c.SysProcAttr = &syscall.SysProcAttr{UseCgroupFD: true, CgroupFD: fd}
	must(r.t, c.Start())
	r.t.Cleanup(func() { c.Process.Kill(); c.Wait() })
	r.waitFilled(g.Path, mib)
}

func memCurrentMiB(dir string) int64 {
	b, err := os.ReadFile(filepath.Join(dir, "memory.current"))
	if err != nil {
		return 0
	}
	n, _ := strconv.ParseInt(strings.TrimSpace(string(b)), 10, 64)
	return n >> 20
}

// waitFilled waits until group dir holds at least 90% of mib.
func (r *floorRig) waitFilled(dir string, mib int64) {
	r.t.Helper()
	deadline := time.Now().Add(60 * time.Second)
	for memCurrentMiB(dir) < mib*9/10 {
		if time.Now().After(deadline) {
			r.t.Fatalf("%s holds %d MiB, want %d", dir, memCurrentMiB(dir), mib)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func (r *floorRig) experiment(id string) {
	r.t.Helper()
	_, err := r.m.Create(context.Background(), id, vm.Spec{
		Image: "base", Class: admission.Experiment, MemMB: guestMemMB,
		Argv: []string{"/hog", strconv.Itoa(guestHeapMiB)},
	})
	must(r.t, err)
	r.waitFilled(filepath.Join(r.groups.Machines.Path, id), guestHeapMiB)
}

func (r *floorRig) foreground(id string) time.Duration {
	r.t.Helper()
	t0 := time.Now()
	_, err := r.m.Create(context.Background(), id, vm.Spec{
		Image: "base", Class: admission.Foreground, MemMB: 1000,
		Argv: []string{"/hog", "200"},
	})
	must(r.t, err)
	return time.Since(t0)
}

func pressure(dir string) string {
	b, _ := os.ReadFile(filepath.Join(dir, "memory.pressure"))
	return strings.Join(strings.Fields(strings.SplitN(string(b), "\n", 2)[0]), " ")
}

func pct(ds []time.Duration, q float64) time.Duration {
	s := append([]time.Duration(nil), ds...)
	sort.Slice(s, func(i, j int) bool { return s[i] < s[j] })
	return s[int(q*float64(len(s)-1)+0.5)]
}

// TestFloorAdmissionAndPreemption loads the floor box as RES-2 declares it
// (inference and browser hogs at their budgets, two OpenClaw-sized
// experiments in the pool), then: a third experiment is refused before it
// cuts into the headroom; a foreground machine preempts an experiment
// within the provisional target, both idle and while the experiment is in the
// middle of a full checkpoint; and nothing is OOM-killed.
func TestFloorAdmissionAndPreemption(t *testing.T) {
	r := newFloor(t)
	ctx := context.Background()
	r.hostHog(r.groups.Inference, r.mem.InferenceMB*9/10)
	r.hostHog(r.groups.Browser, r.mem.BrowserMB*9/10)
	t.Logf("budget (MiB): host %d, inference %d, browser %d, headroom %d, pool %d",
		r.mem.HostMB, r.mem.InferenceMB, r.mem.BrowserMB, r.mem.HeadroomMB, r.mem.PoolMB)

	const reps = 5
	var idle, underCkpt []time.Duration
	for i := 0; i < reps; i++ {
		r.experiment("e1")
		r.experiment("e2")
		t.Logf("rep %d: pool %d MiB in use; pool PSI: %s", i, memCurrentMiB(r.groups.Machines.Path), pressure(r.groups.Machines.Path))

		// RES-2: a third OpenClaw-sized machine would cut into the headroom.
		if _, err := r.m.Create(ctx, "e3", vm.Spec{Image: "base", Class: admission.Experiment, MemMB: guestMemMB, Argv: []string{"/hog", "1"}}); !errors.Is(err, admission.ErrNoRoom) && !errors.Is(err, admission.ErrPressure) {
			t.Fatalf("third experiment: %v, want refusal", err)
		}

		// RES-1, idle experiment.
		total := r.foreground("call")
		idle = append(idle, r.pre.last())
		t.Logf("rep %d: preempt idle experiment %v (create with preemption %v)", i, r.pre.last().Round(time.Millisecond), total.Round(time.Millisecond))

		// RES-1, experiment in the middle of a full checkpoint (seconds for
		// a 1.4 GiB heap, S3).
		before := len(r.m.Snapshots("e1"))
		ck := make(chan error, 1)
		go func() { _, err := r.m.Checkpoint(ctx, "e1"); ck <- err }()
		time.Sleep(300 * time.Millisecond)
		total = r.foreground("call2")
		underCkpt = append(underCkpt, r.pre.last())
		ckErr := <-ck
		t.Logf("rep %d: preempt experiment mid-checkpoint %v (create %v; checkpoint returned %v)", i, r.pre.last().Round(time.Millisecond), total.Round(time.Millisecond), ckErr)
		// The foreground may have preempted e2 instead, or the checkpoint
		// may have finished first, so success is allowed; what is not is a
		// failed checkpoint leaving a snapshot behind, or a successful one
		// leaving none (Security R2 on #124).
		if published := len(r.m.Snapshots("e1")) - before; (ckErr == nil) != (published == 1) {
			t.Fatalf("rep %d: checkpoint returned %v and published %d snapshots", i, ckErr, published)
		}
		if errors.Is(ckErr, vm.ErrPreempted) {
			t.Logf("rep %d: the cut-short checkpoint was discarded", i)
		}

		for _, id := range r.m.Machines() {
			must(t, r.m.Destroy(ctx, id))
		}
	}
	oom, err := r.root.OOMKills()
	must(t, err)

	fmt.Printf("FLOOR-RESULT preempt_idle p50=%v max=%v; preempt_mid_checkpoint p50=%v max=%v; target=%v; oom_kills=%d\n",
		pct(idle, 0.5).Round(time.Millisecond), pct(idle, 1).Round(time.Millisecond),
		pct(underCkpt, 0.5).Round(time.Millisecond), pct(underCkpt, 1).Round(time.Millisecond), PreemptTarget, oom)
	if oom != 0 {
		t.Errorf("%d OOM kills on the floor box (RES-2: none)", oom)
	}
	for _, d := range append(idle, underCkpt...) {
		if d > PreemptTarget {
			t.Errorf("preemption took %v, over the %v target (RES-1)", d, PreemptTarget)
		}
	}
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
