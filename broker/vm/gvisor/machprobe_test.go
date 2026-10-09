package gvisor

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/admission"
	"github.com/ghbmrk/agentos/broker/budget"
	"github.com/ghbmrk/agentos/broker/loops"
	"github.com/ghbmrk/agentos/broker/quota"
	"github.com/ghbmrk/agentos/broker/quota/quotatest"
	"github.com/ghbmrk/agentos/broker/vm"
)

// REQ: LOOP-7, LOOP-9, RES-1
//
// P3-4b-4b in a real agent machine: loops.TamperProbe and
// loops.ExhaustProbe driving broker/machprobe's scripts under gVisor with
// guest authority, the verdict taken broker-side.

// tamperIn is an Attempt that runs the tamper script in machine id.
func (r *rig) tamperIn(id string) func(context.Context, string, []string) (string, error) {
	return func(ctx context.Context, nonce string, paths []string) (string, error) {
		out, err := r.rt.cmd(ctx, append([]string{"exec", cid(id), "/guest", "tamper", nonce}, paths...)...).Output()
		if err != nil {
			return "", fmt.Errorf("tamper script: %v", err)
		}
		r.t.Logf("guest accepted %s writes (its own view)", strings.TrimSpace(string(out)))
		return id, nil
	}
}

// upper is machine id's writable layer as the broker sees it.
func (r *rig) upper(id string, rel ...string) string {
	return filepath.Join(append([]string{r.cfg.StateDir, "machines", id, "disk", "upper"}, rel...)...)
}

// LOOP-7 (tamper), clean: a guest writing a real snapshot directory, an
// evaluator suite and a grader file held broker-side, the grader also at
// its read-only services mount, changes none of them; each refusal is
// journaled. The round's positive control (P3-4b-4c-fresh) is the probe
// machine's own writable root, standing in for the broker-made directory
// the wiring mounts: the script's sibling lands there, so the round
// counts. Control (a writable snapshot in a test rig): a snapshot target
// in the machine's own writable layer is reported on every round, each in
// a fresh machine; the target keeps its bytes and the sibling is removed
// (P3-4b-4c-restore). A round in the last round's machine fails.
func TestIntegrationTamperProbeInAGuest(t *testing.T) {
	svc := &services{t: t, root: t.TempDir(), srv: map[string]*http.Server{}}
	r := newRigWith(t, 4096, svc)
	ctx := context.Background()
	r.create("m1", admission.Accepted)
	r.ask("m1", "write", "/work/r", "kept")
	if _, err := r.m.Checkpoint(ctx, "m1"); err != nil {
		t.Fatal(err)
	}
	snaps := filepath.Join(r.cfg.StateDir, "snapshots")
	if ents, err := os.ReadDir(snaps); err != nil || len(ents) == 0 {
		t.Fatalf("no snapshot to tamper with: %v", err)
	}
	r.create("probe", admission.Experiment)
	r.ask("probe", "token")
	suite := filepath.Join(t.TempDir(), "suite")
	os.MkdirAll(suite, 0o755)
	os.WriteFile(filepath.Join(suite, "cases.json"), []byte("[]"), 0o644)
	grader := filepath.Join(svc.root, "probe", "grader.json")
	if err := os.WriteFile(grader, []byte(`{"pass":0.5}`), 0o644); err != nil {
		t.Fatal(err)
	}
	var notes []string
	p := &loops.TamperProbe{
		Interval: time.Hour,
		Targets: []loops.TamperTarget{
			{Name: "snapshots", Path: snaps},
			{Name: "evaluator", Path: suite},
			{Name: "grader", Path: grader, Guest: []string{vm.ServicesMount + "/grader.json"}},
		},
		Control: loops.TamperTarget{Path: r.upper("probe"), Guest: []string{"/"}},
		Attempt: r.tamperIn("probe"),
		Journal: func(machine, target string) error { notes = append(notes, machine+"/"+target); return nil },
	}
	res, err := p.Run(ctx)
	if err != nil || len(res.Found) != 0 {
		t.Fatalf("clean round: %+v %v", res, err)
	}
	if strings.Join(notes, ",") != "probe/snapshots,probe/evaluator,probe/grader" {
		t.Fatalf("journaled %v", notes)
	}
	if b, err := os.ReadFile(grader); err != nil || string(b) != `{"pass":0.5}` {
		t.Fatalf("grader holds %q %v", b, err)
	}

	// Control: the snapshot target is each round's guest's own /work/snap.
	for round, id := range []string{"probe2", "probe3"} {
		r.create(id, admission.Experiment)
		r.ask(id, "write", "/work/snap", "original")
		snap := r.upper(id, "work", "snap")
		if b, err := os.ReadFile(snap); err != nil || string(b) != "original" {
			t.Fatalf("rig: the guest's layer is not at %s: %q %v", snap, b, err)
		}
		p.Targets = []loops.TamperTarget{{Name: "snapshots", Path: snap, Guest: []string{"/work/snap"}}}
		p.Control = loops.TamperTarget{Path: r.upper(id), Guest: []string{"/"}}
		p.Attempt = r.tamperIn(id)
		// Guard hands each found to Report (loops' probe tests). A target
		// that stays writable is reported on every round, not just the
		// first (each round's nonce lands a new sibling).
		res, err = p.Run(ctx)
		if err != nil || len(res.Found) != 1 || !same(res.Found[0], loops.CheckTamper, "snapshots", "writable") {
			t.Fatalf("control round %d: %+v %v", round+1, res, err)
		}
		if b, err := os.ReadFile(snap); err != nil || string(b) != "original" {
			t.Fatalf("control round %d changed the target: %q %v", round+1, b, err)
		}
		for _, d := range []string{r.upper(id), r.upper(id, "work")} {
			ents, _ := os.ReadDir(d)
			for _, e := range ents {
				if strings.HasPrefix(e.Name(), ".agentos-tamper-") {
					t.Fatalf("control round %d left %s in %s", round+1, e.Name(), d)
				}
			}
		}
	}
	if _, err := p.Run(ctx); err == nil || !strings.Contains(err.Error(), "same machine") {
		t.Fatalf("a round in the last round's machine: %v", err)
	}
}

// exhaustProbe starts machine id, presses it with every kind for hold,
// pings the broker's own service socket for that machine, and preempts
// it. Its budget is what the rig's broker writes for the machine.
func (r *rig) exhaustProbe(svc *services, q *quota.FS, id string, hold time.Duration, adjust func(cg string)) *loops.ExhaustProbe {
	sock := filepath.Join(svc.root, id, "broker.sock")
	client := &http.Client{Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", sock)
	}}}
	return &loops.ExhaustProbe{
		Interval:       time.Hour,
		Hold:           hold,
		ResponseTarget: time.Second, // stand-in: SPEC freezes no figure yet (S35, RES-1)
		PreemptTarget:  2 * time.Second,
		BrokerWeight:   budget.BrokerWeight,
		Budget:         loops.MachineBudget{MemoryBytes: 256 << 20, Pids: vm.MachinePids, DiskBytes: 64 << 20},
		// What the test guest's press holds (MemMB 48, DiskMB 32 in
		// testdata's press command; S35).
		Script: loops.PressScript{MemoryBytes: 48 << 20, DiskBytes: 32 << 20},
		Machine: func(ctx context.Context) (loops.PressedMachine, error) {
			r.create(id, admission.Experiment)
			r.ask(id, "token")
			mc, err := r.m.Get(id)
			if err != nil {
				return loops.PressedMachine{}, err
			}
			cg := filepath.Join(r.cfg.Cgroups.Path, id)
			if adjust != nil {
				adjust(cg)
			}
			// The disk budget and usage as the file system holds them,
			// not as configured.
			u, err := q.Usage(mc.Project)
			if err != nil {
				return loops.PressedMachine{ID: id}, err
			}
			used := func() (int64, error) {
				u, err := q.Usage(mc.Project)
				return u.Bytes, err
			}
			return loops.PressedMachine{ID: id, Cgroup: cg, DiskBytes: u.LimitBytes, DiskUsed: used}, nil
		},
		Press: r.pressFor(hold),
		Ping: func(ctx context.Context) error {
			req, _ := http.NewRequestWithContext(ctx, "GET", "http://broker/", nil)
			resp, err := client.Do(req)
			if err != nil {
				return err
			}
			resp.Body.Close()
			return nil
		},
		Preempt: r.m.Preempt,
	}
}

// pressFor has machine id's guest press each kind for hold and more, but
// the kinds in brief for 1 ms: those presses run and exit at once.
func (r *rig) pressFor(hold time.Duration, brief ...string) func(context.Context, string, []string) error {
	return func(ctx context.Context, id string, kinds []string) error {
		for _, k := range kinds {
			if slices.Contains(brief, k) {
				if out, err := r.rt.cmd(ctx, "exec", cid(id), "/guest", "press", k, "1").CombinedOutput(); err != nil {
					return fmt.Errorf("press %s: %v: %s", k, err, out)
				}
				continue
			}
			c := r.rt.cmd(context.Background(), "exec", cid(id), "/guest", "press", k, fmt.Sprint((hold + 5*time.Second).Milliseconds()))
			if err := c.Start(); err != nil {
				return err
			}
			go c.Wait() // ends when the machine is preempted
		}
		time.Sleep(500 * time.Millisecond) // let the pressure start
		return nil
	}
}

// logRise logs how far p's machine's counters rose from just before the
// press to just before the preemption, the window the probe reads, so
// CI shows the margin over the probe's minimums. File is the cache the
// memory gate leaves out (S35).
func (r *rig) logRise(t *testing.T, q *quota.FS, p *loops.ExhaustProbe, name string) {
	read := func(id string) (cpu, shmem, file, disk int64) {
		cg := filepath.Join(r.cfg.Cgroups.Path, id)
		for _, f := range []string{"cpu.stat", "memory.stat"} {
			b, _ := os.ReadFile(filepath.Join(cg, f))
			for line := range strings.Lines(string(b)) {
				k, v, _ := strings.Cut(strings.TrimSpace(line), " ")
				n, _ := strconv.ParseInt(v, 10, 64)
				switch k {
				case "usage_usec":
					cpu = n
				case "shmem":
					shmem = n
				case "file":
					file = n
				}
			}
		}
		if mc, err := r.m.Get(id); err == nil {
			u, _ := q.Usage(mc.Project)
			disk = u.Bytes
		}
		return
	}
	var c0, s0, f0, d0 int64
	press, preempt := p.Press, p.Preempt
	p.Press = func(ctx context.Context, id string, kinds []string) error {
		c0, s0, f0, d0 = read(id)
		return press(ctx, id, kinds)
	}
	p.Preempt = func(id string) error {
		if c0 != 0 {
			c1, s1, f1, d1 := read(id)
			t.Logf("%s: over the hold (%v; host CPUs %d) cpu rose %d us (minimum hold x CPUs / 2), shmem %d (minimum %d; file %d), disk %d (minimum %d)",
				name, p.Hold, runtime.NumCPU(), c1-c0, s1-s0, p.Script.MemoryBytes/2, f1-f0, d1-d0, p.Script.DiskBytes/2)
			c0 = 0
		}
		return preempt(id)
	}
}

// LOOP-7 (exhaustion): CPU, memory, disk and process pressure in an
// experiment machine with its cgroup limits and disk quota at the
// broker's budget leaves the broker answering within target and the
// machine preempted within the frozen target: nothing reported. The
// round passing shows the machine's cpu.stat usage_usec, memory.stat shmem
// and quota usage rose by their minimums over the hold (S35); the rises
// are logged. Controls: a guest that does not press, one whose presses all
// exit at once, and ones where only the CPU press or only the memory
// press exits at once each fail the round, the last two on that counter
// alone (P3-4b-4c-fresh; B1 on #599); a cgroup with memory.max and
// pids.max at "max" reports both above budget, pids.max's as the
// sandbox's threads, which is what it bounds under gVisor (RES-2;
// P3-4b-4c-pids).
func TestIntegrationExhaustionProbeInAGuest(t *testing.T) {
	if os.Getenv("AGENTOS_RUNSC") == "" || os.Geteuid() != 0 {
		t.Skip("set AGENTOS_RUNSC to a runsc binary and run as root (CI integration job)")
	}
	if os.Getenv("AGENTOS_CGROUP_PARENT") == "" {
		t.Skip("needs AGENTOS_CGROUP_PARENT")
	}
	state := quotatest.Dir(t, 512)
	q, err := quota.Open(state)
	if err != nil {
		t.Fatal(err)
	}
	svc := &services{t: t, root: t.TempDir(), srv: map[string]*http.Server{}}
	r := newRigOn(t, 4096, svc, state, func(c *vm.Config) {
		c.NoQuota, c.Quota, c.MachineDiskBytes = false, q, 64<<20
		c.DiskReserveBytes = 16 << 20
	})
	ctx := context.Background()
	clean := r.exhaustProbe(svc, q, "load", 3*time.Second, nil)
	r.logRise(t, q, clean, "clean round")
	res, err := clean.Run(ctx)
	if err != nil || len(res.Found) != 0 {
		t.Fatalf("clean round: %+v %v", res, err)
	}
	if mc, _ := r.m.Get("load"); mc.State != vm.Preempted {
		t.Fatalf("pressed machine %s, want preempted", mc.State)
	}
	r.m.Destroy(ctx, "load")

	idle := r.exhaustProbe(svc, q, "idle", time.Second, nil)
	idle.Press = func(context.Context, string, []string) error { return nil }
	if res, err := idle.Run(ctx); err == nil || !strings.Contains(err.Error(), "did not press") || len(res.Checked) != 0 {
		t.Fatalf("a guest that did not press: %+v %v", res, err)
	}
	if mc, _ := r.m.Get("idle"); mc.State != vm.Preempted {
		t.Fatalf("idle machine %s, want preempted", mc.State)
	}
	r.m.Destroy(ctx, "idle")

	for _, c := range []struct {
		id    string
		brief []string
		fail  []string // the counters that must fall short, and only they
	}{
		{"brief", []string{"cpu", "memory", "disk", "processes"}, []string{"cpu", "memory", "disk"}},
		{"cpuburst", []string{"cpu"}, []string{"cpu"}},
		// The process press's idle children hold memory of their own, so
		// it exits at once here too; processes are not gated (S35).
		{"memdrop", []string{"memory", "processes"}, []string{"memory"}},
	} {
		p := r.exhaustProbe(svc, q, c.id, time.Second, nil)
		p.Press = r.pressFor(time.Second, c.brief...)
		r.logRise(t, q, p, c.id)
		res, err := p.Run(ctx)
		if err == nil || !strings.Contains(err.Error(), "did not press") || len(res.Checked) != 0 {
			t.Fatalf("%s: %+v %v", c.id, res, err)
		}
		for _, k := range []string{"cpu", "memory", "disk"} {
			if short := strings.Contains(err.Error(), k+" rose"); short != slices.Contains(c.fail, k) {
				t.Fatalf("%s: %s short %v, want %v: %v", c.id, k, short, !short, err)
			}
		}
		t.Logf("%s: %v", c.id, err)
		r.m.Destroy(ctx, c.id)
	}

	unlimit := func(cg string) {
		for _, f := range []string{"memory.max", "pids.max"} {
			if err := os.WriteFile(filepath.Join(cg, f), []byte("max"), 0o644); err != nil {
				t.Fatal(err)
			}
		}
	}
	control := r.exhaustProbe(svc, q, "load2", time.Second, unlimit)
	r.logRise(t, q, control, "control round")
	res, err = control.Run(ctx)
	if err != nil || len(res.Found) != 2 {
		t.Fatalf("control round: %+v %v", res, err)
	}
	for i, k := range []string{"memory", "sandbox threads"} {
		if !same(res.Found[i], loops.CheckExhaust, k, "above budget") {
			t.Fatalf("control round found %+v, want %s above budget", res.Found[i], k)
		}
	}
}

func same(f loops.Finding, c loops.Check, subject, detail string) bool {
	return f.Check == c && f.Subject == subject && f.Detail == detail && f.Severity == loops.High && f.Rule == nil
}
