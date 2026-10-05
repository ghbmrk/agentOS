package gvisor

import (
	"context"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/admission"
	"github.com/ghbmrk/agentos/broker/cgroup"
	"github.com/ghbmrk/agentos/broker/vm"
)

// REQ: REV-1, REV-4, ARC-4, RES-1, RES-2, ARC-6, CAP-1, CAP-8, A15

// TestOnlyRunscIsExecuted: in the whole machine plane, the one process that
// may be started is the configured runsc binary, from one call site (ARC-2
// review aid: the guest launcher is not a back door to other programs).
func TestOnlyRunscIsExecuted(t *testing.T) {
	launchers := map[string]bool{
		"exec.Command": true, "exec.CommandContext": true, "os.StartProcess": true,
		"syscall.ForkExec": true, "syscall.Exec": true, "syscall.StartProcess": true,
	}
	files, _ := filepath.Glob("../*.go")
	more, _ := filepath.Glob("../*/*.go")
	files = append(files, more...)
	n := 0
	for _, path := range files {
		if strings.HasSuffix(path, "_test.go") || strings.Contains(path, "testdata") {
			continue
		}
		fs := token.NewFileSet()
		f, err := parser.ParseFile(fs, path, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		ast.Inspect(f, func(x ast.Node) bool {
			call, ok := x.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			id, ok := sel.X.(*ast.Ident)
			if !ok || !launchers[id.Name+"."+sel.Sel.Name] {
				return true
			}
			n++
			if filepath.Base(path) != "gvisor.go" || sel.Sel.Name != "CommandContext" || len(call.Args) < 2 {
				t.Errorf("%s: %s.%s", fs.Position(call.Pos()), id.Name, sel.Sel.Name)
				return true
			}
			if s, ok := call.Args[1].(*ast.SelectorExpr); !ok || s.Sel.Name != "Bin" {
				t.Errorf("%s: executes something other than r.Bin", fs.Position(call.Pos()))
			}
			return true
		})
	}
	if n != 1 {
		t.Fatalf("%d process-launch call sites in vm/..., want exactly 1", n)
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

func newRig(t *testing.T, capacityMB int64) *rig { return newRigWith(t, capacityMB, nil) }

func newRigWith(t *testing.T, capacityMB int64, svc vm.Services) *rig {
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
		Services: svc,
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

	// A fork that deletes /work (an image directory: real whiteouts) while
	// the parent writes into it conflicts instead of losing the write.
	if _, err := r.m.Fork(ctx, "m1", []string{"f3"}); err != nil {
		t.Fatal(err)
	}
	if r.ask("f3", "remove", "/work") != "ok" || r.ask("m1", "write", "/work/c", "parent") != "ok" {
		t.Fatal("guest commands failed")
	}
	if _, err := r.m.Merge(ctx, "m1", "f3"); !errors.Is(err, vm.ErrConflict) {
		t.Fatalf("merge over a removed directory: %v", err)
	}
	if r.ask("m1", "read", "/work/c") != "parent" {
		t.Fatal("refused merge lost the parent's file")
	}
	if err := r.m.Destroy(ctx, "f3"); err != nil {
		t.Fatal(err)
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

// services is a test vm.Services: one directory and one HTTP socket per
// machine, answering with the machine the socket belongs to.
type services struct {
	t    *testing.T
	root string
	mu   sync.Mutex
	srv  map[string]*http.Server
}

func (s *services) Open(id string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	dir := filepath.Join(s.root, id)
	if s.srv[id] != nil {
		return dir, nil
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	l, err := net.Listen("unix", filepath.Join(dir, "broker.sock"))
	if err != nil {
		return "", err
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprintf(w, "machine %s", id)
	})}
	go srv.Serve(l)
	s.srv[id] = srv
	return dir, nil
}

func (s *services) Close(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if srv := s.srv[id]; srv != nil {
		srv.Close()
		os.RemoveAll(filepath.Join(s.root, id))
		delete(s.srv, id)
	}
}

const svcSock = vm.ServicesMount + "/broker.sock"

// TestIntegrationGuestReachesOnlyItsOwnServiceSocket: each machine, forks
// included, reaches exactly its own broker socket, read-only, and nothing
// else on the host (ARC-6, V15). Checkpoints and forks still work with the
// mount in place.
func TestIntegrationGuestReachesOnlyItsOwnServiceSocket(t *testing.T) {
	svc := &services{t: t, root: t.TempDir(), srv: map[string]*http.Server{}}
	r := newRigWith(t, 4096, svc)
	ctx := context.Background()
	r.create("m1", admission.Accepted)
	r.create("m2", admission.Accepted)
	for _, id := range []string{"m1", "m2"} {
		if got := r.ask(id, "svc", svcSock, "/"); got != "200 OK machine "+id {
			t.Fatalf("%s reached %q", id, got)
		}
	}
	if got := r.ask("m1", "stat", filepath.Join(svc.root, "m2", "broker.sock")); got != "absent" {
		t.Fatal("m1 can see m2's socket path")
	}
	if got := r.ask("m1", "write", vm.ServicesMount+"/x", "y"); !strings.HasPrefix(got, "ERR") {
		t.Fatal("services directory is writable from the guest")
	}
	if _, err := r.m.Checkpoint(ctx, "m1"); err != nil {
		t.Fatalf("checkpoint with the services mount: %v", err)
	}
	if _, err := r.m.Fork(ctx, "m1", []string{"f1"}); err != nil {
		t.Fatalf("fork with the services mount: %v", err)
	}
	if got := r.ask("f1", "svc", svcSock, "/"); got != "200 OK machine f1" {
		t.Fatalf("fork reached %q, want its own socket", got)
	}
	if got := r.ask("m1", "svc", svcSock, "/"); got != "200 OK machine m1" {
		t.Fatalf("m1 after fork reached %q", got)
	}
	if err := r.m.Destroy(ctx, "f1"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(svc.root, "f1")); !os.IsNotExist(err) {
		t.Fatal("destroy did not close the fork's services")
	}
}

// TestIntegrationForkDoesNotInheritServiceIdentity: a connection the guest
// held open when it was checkpointed never speaks for the source machine
// from inside a fork, so identity stays bound to the listener (ARC-6).
// Checkpoint and fork-restore succeed with the connection open; the guest
// must reconnect after either (observed: the held connection reads EOF).
func TestIntegrationForkDoesNotInheritServiceIdentity(t *testing.T) {
	svc := &services{t: t, root: t.TempDir(), srv: map[string]*http.Server{}}
	r := newRigWith(t, 4096, svc)
	ctx := context.Background()
	r.create("m1", admission.Accepted)
	if got := r.ask("m1", "hold", svcSock); got != "ok" {
		t.Fatal(got)
	}
	if got := r.ask("m1", "heldget", "/"); got != "machine m1" {
		t.Fatalf("held connection before checkpoint: %q", got)
	}
	if _, err := r.m.Fork(ctx, "m1", []string{"f1"}); err != nil {
		t.Fatalf("fork with an open service connection: %v", err)
	}
	if got := r.ask("f1", "heldget", "/"); got == "machine m1" {
		t.Fatal("fork speaks as its source over an inherited connection")
	} else {
		t.Logf("fork's inherited connection: %s", got)
	}
	t.Logf("source's connection after checkpoint: %s", r.ask("m1", "heldget", "/"))
	if got := r.ask("f1", "svc", svcSock, "/"); got != "200 OK machine f1" {
		t.Fatalf("fork reconnects to %q", got)
	}
}

// TestIntegrationHostSocketInImageIsUnreachable: --host-uds=open applies to
// the whole sandbox, so a host socket file anywhere in a machine's root
// would be reachable. Only the services mount may lead to one: a socket
// planted in the image is not a way out.
func TestIntegrationHostSocketInImageIsUnreachable(t *testing.T) {
	svc := &services{t: t, root: t.TempDir(), srv: map[string]*http.Server{}}
	r := newRigWith(t, 4096, svc)
	l, err := net.Listen("unix", filepath.Join(r.cfg.Images["base"], "planted.sock"))
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	go http.Serve(l, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { io.WriteString(w, "host") }))
	r.create("m1", admission.Accepted)
	if got := r.ask("m1", "stat", "/planted.sock"); got == "absent" {
		t.Fatal("the planted socket is not in the guest's root: the test proves nothing")
	}
	out, _ := r.rt.cmd(context.Background(), "exec", cid("m1"), "/guest", "svc", "/planted.sock", "/").Output()
	if got := strings.TrimSpace(string(out)); !strings.HasPrefix(got, "ERR") {
		t.Fatalf("guest reached a host socket in its image: %q", got)
	}
}

// TestIntegrationWorkerExec: a worker runs a command under runsc exec with
// stdin, its exit code comes back as a result, and output is capped
// (CAP-8).
func TestIntegrationWorkerExec(t *testing.T) {
	r := newRig(t, 4096)
	ctx := context.Background()
	r.create("agent", admission.Experiment)
	a, err := r.m.Get("agent")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.m.CreateWorker(ctx, "wk-1", a.Lineage, vm.Spec{Image: "base", Class: admission.Experiment, MemMB: 256, Argv: []string{"/guest", "serve"}}); err != nil {
		t.Fatal(err)
	}
	res, err := r.m.Exec(ctx, "wk-1", vm.Command{Argv: []string{"/guest", "stdin", "3"}, Stdin: []byte("hello worker"), MaxOutput: 5}, 20*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if res.ExitCode != 3 || string(res.Stdout) != "hello" || !res.Truncated {
		t.Fatalf("exec = code %d, stdout %q, truncated %v; want 3, %q, true", res.ExitCode, res.Stdout, res.Truncated, "hello")
	}
}

func TestCappedKeepsTheFirstBytes(t *testing.T) {
	c := &capped{max: 4}
	c.Write([]byte("ab"))
	c.Write([]byte("cdef"))
	c.Write([]byte("g"))
	if c.b.String() != "abcd" || !c.over {
		t.Fatalf("capped = %q, over %v", c.b.String(), c.over)
	}
	u := &capped{}
	u.Write([]byte("all of it"))
	if u.b.String() != "all of it" || u.over {
		t.Fatal("uncapped writer dropped output")
	}
}

// worker starts an agent machine and a worker in its lineage.
func (r *rig) worker(id string) vm.Machine {
	r.t.Helper()
	r.create("agent", admission.Experiment)
	a, err := r.m.Get("agent")
	if err != nil {
		r.t.Fatal(err)
	}
	if _, err := r.m.CreateWorker(context.Background(), id, a.Lineage, vm.Spec{Image: "base", Class: admission.Experiment, MemMB: 256, Argv: []string{"/guest", "serve"}}); err != nil {
		r.t.Fatal(err)
	}
	return a
}

// lingering reports whether a linger command still runs in machine id: its
// file still grows.
func (r *rig) lingering(id string) bool {
	r.t.Helper()
	n := len(r.ask(id, "read", "/work/linger"))
	time.Sleep(300 * time.Millisecond)
	return len(r.ask(id, "read", "/work/linger")) != n
}

// A command that ignores signals and holds stdout past its timeout ends:
// Exec returns in bounded time and the process inside the sandbox is gone
// (L3 MUST-1 on #146).
func TestIntegrationWorkerExecOutlivesTimeout(t *testing.T) {
	r := newRig(t, 4096)
	r.worker("wk-1")
	start := time.Now()
	res, err := r.m.Exec(context.Background(), "wk-1", vm.Command{Argv: []string{"/guest", "linger"}}, time.Second)
	d := time.Since(start)
	t.Logf("timed-out exec returned after %v", d.Round(time.Millisecond))
	if d > time.Second+ExecWaitDelay+3*time.Second {
		t.Fatalf("exec returned after %v", d)
	}
	if err != nil || !res.TimedOut {
		t.Fatalf("exec = %+v, %v; want a timed-out result", res, err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for r.lingering("wk-1") {
		if time.Now().After(deadline) {
			t.Fatal("the timed-out command still runs in the worker")
		}
	}
}

// Erasure during such a command does not wait for it, and the command does
// not survive it (CAP-3, F1; L3 MUST-1 on #146).
func TestIntegrationForgetSinceDuringWorkerExec(t *testing.T) {
	r := newRig(t, 4096)
	a := r.worker("wk-1")
	since := time.Now()
	done := make(chan error, 1)
	go func() {
		_, err := r.m.Exec(context.Background(), "wk-1", vm.Command{Argv: []string{"/guest", "linger"}}, 10*time.Minute)
		done <- err
	}()
	deadline := time.Now().Add(20 * time.Second)
	for !strings.HasPrefix(r.ask("wk-1", "read", "/work/linger"), ".") {
		if time.Now().After(deadline) {
			t.Fatal("the command never started")
		}
		time.Sleep(50 * time.Millisecond)
	}
	start := time.Now()
	if err := r.m.ForgetSince(context.Background(), a.Lineage, since); err != nil {
		t.Fatal(err)
	}
	d := time.Since(start)
	t.Logf("ForgetSince during a command took %v", d.Round(time.Millisecond))
	if d > ExecWaitDelay+10*time.Second {
		t.Fatalf("ForgetSince took %v", d)
	}
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("the erased command reported success")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the command's Exec never returned")
	}
	if w, err := r.m.Get("wk-1"); err == nil && w.State == vm.Running {
		if got := r.ask("wk-1", "read", "/work/linger"); !strings.HasPrefix(got, "ERR") && r.lingering("wk-1") {
			t.Fatal("the command survived erasure")
		}
	}
}

// CAP-1 and A15 under gVisor: on the floor's pool (4500 MB) beside a
// 1600 MB agent, a worker forks into 8 workers that each run a command
// with their memory intact, and the winner is kept; admission stays
// within its budget throughout (RES-2).
func TestIntegrationEightWorkersWithinRES2(t *testing.T) {
	r := newRig(t, 4500)
	ctx := context.Background()
	if _, err := r.m.Create(ctx, "agent", vm.Spec{Image: "base", Class: admission.Foreground, MemMB: 1600, Argv: []string{"/guest", "serve"}}); err != nil {
		t.Fatal(err)
	}
	a, err := r.m.Get("agent")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.m.CreateWorker(ctx, "wk-src", a.Lineage, vm.Spec{Image: "base", Class: admission.Foreground, MemMB: 256, Argv: []string{"/guest", "serve"}}); err != nil {
		t.Fatal(err)
	}
	token := r.ask("wk-src", "token")
	var ids []string
	for i := range 8 {
		ids = append(ids, fmt.Sprintf("wk-try%d", i))
	}
	timed(t, "fork(8)", func() error { _, err := r.m.Fork(ctx, "wk-src", ids); return err })
	if free := r.adm.Snapshot().FreeMB; free < 0 {
		t.Fatalf("admission over budget: %d MB free", free)
	}
	for i, id := range ids {
		if got := r.ask(id, "token"); got != token {
			t.Fatalf("%s lost the source's memory: %q", id, got)
		}
		res, err := r.m.Exec(ctx, id, vm.Command{Argv: []string{"/guest", "stdin", fmt.Sprint(i)}, Stdin: []byte(id)}, 20*time.Second)
		if err != nil || res.ExitCode != i || string(res.Stdout) != id {
			t.Fatalf("%s exec = %+v, %v", id, res, err)
		}
	}
	for _, id := range ids {
		if id != "wk-try5" {
			if err := r.m.Destroy(ctx, id); err != nil {
				t.Fatal(err)
			}
		}
	}
	if n := len(r.adm.Snapshot().Running); n != 3 {
		t.Fatalf("%d machines admitted after keeping the winner, want 3", n)
	}
}
