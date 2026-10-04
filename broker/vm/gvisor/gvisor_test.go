package gvisor

import (
	"context"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/admission"
	"github.com/ghbmrk/agentos/broker/cgroup"
	"github.com/ghbmrk/agentos/broker/vm"
)

// REQ: REV-1, REV-4, ARC-4, RES-1, RES-2

// TestOnlyRunscIsExecuted: the one process this package may start is the
// configured runsc binary (ARC-2 review aid: the guest launcher is not a
// back door to other programs).
func TestOnlyRunscIsExecuted(t *testing.T) {
	fs := token.NewFileSet()
	f, err := parser.ParseFile(fs, "gvisor.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	ast.Inspect(f, func(x ast.Node) bool {
		call, ok := x.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		if id, ok := sel.X.(*ast.Ident); ok && id.Name == "exec" {
			n++
			if sel.Sel.Name != "CommandContext" || len(call.Args) < 2 {
				t.Errorf("%s: exec.%s", fs.Position(call.Pos()), sel.Sel.Name)
				return true
			}
			if s, ok := call.Args[1].(*ast.SelectorExpr); !ok || s.Sel.Name != "Bin" {
				t.Errorf("%s: executes something other than r.Bin", fs.Position(call.Pos()))
			}
		}
		return true
	})
	if n != 1 {
		t.Fatalf("%d exec call sites, want exactly 1", n)
	}
}

// rig is a real broker-side setup: runsc, overlay mounts, admission, and a
// cgroup parent when AGENTOS_CGROUP_PARENT names one.
type rig struct {
	t   *testing.T
	rt  *Runtime
	m   *vm.Manager
	adm *admission.Controller
	cfg vm.Config
}

type late struct{ m **vm.Manager }

func (l late) Preempt(id string) error { return (*l.m).Preempt(id) }

func newRig(t *testing.T, capacityMB int64) *rig {
	t.Helper()
	bin := os.Getenv("AGENTOS_RUNSC")
	if bin == "" || os.Geteuid() != 0 {
		t.Skip("set AGENTOS_RUNSC to a runsc binary and run as root (CI integration job)")
	}
	img := t.TempDir()
	for _, d := range []string{"work", "tmp", "proc", "dev", "sys"} {
		if err := os.Mkdir(filepath.Join(img, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	build := exec.Command("go", "build", "-o", filepath.Join(img, "guest"), "./testdata/guest")
	build.Env = append(os.Environ(), "CGO_ENABLED=0")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("building guest: %v\n%s", err, out)
	}
	state := t.TempDir()
	r := &rig{t: t, rt: &Runtime{Bin: bin, StateDir: filepath.Join(state, "runsc")}}
	adm, err := admission.New(admission.Config{CapacityMB: capacityMB}, late{&r.m})
	if err != nil {
		t.Fatal(err)
	}
	r.adm = adm
	r.cfg = vm.Config{
		StateDir: filepath.Join(state, "broker"),
		Images:   map[string]string{"base": img},
		Runtime:  r.rt,
		Admit:    r.adm,
	}
	if p := os.Getenv("AGENTOS_CGROUP_PARENT"); p != "" {
		g, err := cgroup.Open(p)
		if err != nil {
			t.Fatal(err)
		}
		r.cfg.Cgroups = g
	} else {
		r.cfg.NoCgroups = true
		t.Log("no AGENTOS_CGROUP_PARENT: running without cgroups")
	}
	m, err := vm.Open(context.Background(), r.cfg)
	if err != nil {
		t.Fatal(err)
	}
	r.m = m
	t.Cleanup(func() {
		for _, id := range r.m.Machines() {
			r.m.Destroy(context.Background(), id)
		}
		// runsc --network=none bind-mounts an empty netns file here.
		syscall.Unmount(filepath.Join(r.rt.StateDir, "null-netns"), syscall.MNT_DETACH)
	})
	return r
}

func (r *rig) create(id string, c admission.Class) {
	r.t.Helper()
	if _, err := r.m.Create(context.Background(), id, vm.Spec{Image: "base", Class: c, MemMB: 256, Argv: []string{"/guest", "serve"}}); err != nil {
		r.t.Fatalf("create %s: %v", id, err)
	}
}

// ask sends one request to the guest server in machine id, retrying while it
// starts.
func (r *rig) ask(id string, args ...string) string {
	r.t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for {
		c := r.rt.cmd(context.Background(), append([]string{"exec", cid(id), "/guest"}, args...)...)
		out, err := c.Output()
		s := strings.TrimSpace(string(out))
		if err == nil && !strings.HasPrefix(s, "ERR dial") {
			return s
		}
		if time.Now().After(deadline) {
			r.t.Fatalf("guest %s: %v %s", id, err, s)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func timed(t *testing.T, what string, f func() error) {
	t.Helper()
	t0 := time.Now()
	if err := f(); err != nil {
		t.Fatalf("%s: %v", what, err)
	}
	t.Logf("%-28s %v", what, time.Since(t0).Round(time.Millisecond))
}

func TestIntegrationLifecycleUnderGVisor(t *testing.T) {
	r := newRig(t, 4096)
	ctx := context.Background()
	timed(t, "create", func() error { r.create("m1", admission.Accepted); return nil })
	tok := r.ask("m1", "token")
	if r.ask("m1", "write", "/work/a", "one") != "ok" {
		t.Fatal("guest cannot write its root")
	}

	var step, full vm.Snapshot
	timed(t, "step (fs snapshot)", func() (err error) { step, err = r.m.Step(ctx, "m1"); return })
	r.ask("m1", "write", "/work/a", "two")
	timed(t, "checkpoint (full)", func() (err error) { full, err = r.m.Checkpoint(ctx, "m1"); return })
	r.ask("m1", "write", "/work/a", "three")
	if got := r.ask("m1", "token"); got != tok {
		t.Fatal("checkpoint disturbed the running guest")
	}

	// REV-1 custody: the guest's root contains none of the broker's paths.
	for _, p := range []string{r.cfg.StateDir, filepath.Join(r.cfg.StateDir, "snapshots", full.ID), r.rt.StateDir} {
		if got := r.ask("m1", "stat", p); got != "absent" {
			t.Errorf("guest can see %s", p)
		}
	}

	timed(t, "rollback full", func() error { return r.m.Rollback(ctx, "m1", full.ID) })
	if r.ask("m1", "token") != tok || r.ask("m1", "read", "/work/a") != "two" {
		t.Fatal("full rollback did not restore memory and files")
	}
	timed(t, "rollback fs (cold start)", func() error { return r.m.Rollback(ctx, "m1", step.ID) })
	if r.ask("m1", "token") == tok || r.ask("m1", "read", "/work/a") != "one" {
		t.Fatal("fs rollback: want old files and a fresh guest")
	}

	// fork(2): both forks carry the source's memory and files.
	tok = r.ask("m1", "token")
	timed(t, "fork(2)", func() error { _, err := r.m.Fork(ctx, "m1", []string{"f1", "f2"}); return err })
	for _, f := range []string{"f1", "f2"} {
		if r.ask(f, "token") != tok || r.ask(f, "read", "/work/a") != "one" {
			t.Fatalf("%s did not inherit the source's state", f)
		}
	}
	r.ask("f1", "write", "/work/b", "from f1")
	if r.ask("f2", "read", "/work/b") != "ERR open /work/b: no such file or directory" {
		t.Fatal("forks share a file system")
	}

	// merge f1 back; diff shows the change.
	var merged vm.Snapshot
	timed(t, "merge", func() (err error) { merged, err = r.m.Merge(ctx, "m1", "f1"); return })
	if r.ask("m1", "read", "/work/b") != "from f1" {
		t.Fatal("merge did not bring f1's file into m1")
	}
	ch, err := r.m.Diff("", step.ID, merged.ID)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, c := range ch {
		found = found || (c.Path == "work/b" && c.Op() == "added")
	}
	if !found {
		t.Fatalf("diff missing work/b: %v", ch)
	}

	// ARC-4: rebuild from the image.
	timed(t, "rebuild", func() error { return r.m.Rebuild(ctx, "m1") })
	if !strings.HasPrefix(r.ask("m1", "read", "/work/b"), "ERR") {
		t.Fatal("rebuild kept guest files")
	}

	timed(t, "destroy x3", func() error {
		return errors.Join(r.m.Destroy(ctx, "f1"), r.m.Destroy(ctx, "f2"), r.m.Destroy(ctx, "m1"))
	})
	out, _ := r.rt.cmd(ctx, "list").Output()
	if strings.Contains(string(out), "_") {
		t.Fatalf("runsc still lists sandboxes:\n%s", out)
	}
}

func TestIntegrationForegroundPreemptsExperiment(t *testing.T) {
	r := newRig(t, 400)
	ctx := context.Background()
	r.create("exp", admission.Experiment)
	r.ask("exp", "write", "/work/r", "partial")
	t0 := time.Now()
	r.create("call", admission.Foreground)
	t.Logf("foreground create incl. preemption: %v", time.Since(t0).Round(time.Millisecond))
	mc, _ := r.m.Get("exp")
	if mc.State != vm.Preempted {
		t.Fatalf("experiment %s", mc.State)
	}
	if r.cfg.Cgroups != nil {
		if _, err := os.Stat(filepath.Join(r.cfg.Cgroups.Path, "exp")); !os.IsNotExist(err) {
			t.Fatal("preempted machine's cgroup still exists, so memory may be held")
		}
	}
	if err := r.m.Destroy(ctx, "call"); err != nil {
		t.Fatal(err)
	}
	if err := r.m.Resume(ctx, "exp"); err != nil {
		t.Fatal(err)
	}
	if r.ask("exp", "read", "/work/r") != "partial" {
		t.Fatal("experiment lost its files across preemption")
	}
}

func TestIntegrationBudgetIsEnforced(t *testing.T) {
	r := newRig(t, 4096)
	if r.cfg.Cgroups == nil {
		t.Skip("needs AGENTOS_CGROUP_PARENT")
	}
	r.create("m", admission.Accepted)
	g := &cgroup.Group{Path: filepath.Join(r.cfg.Cgroups.Path, "m")}
	if p, err := g.Populated(); err != nil || !p {
		t.Fatalf("sandbox not in the machine's cgroup: %v %v", p, err)
	}
	b, _ := os.ReadFile(filepath.Join(g.Path, "memory.current"))
	t.Logf("memory.current with guest running: %s", strings.TrimSpace(string(b)))
	if _, err := g.Pressure(); err != nil {
		t.Fatal(err)
	}
}
