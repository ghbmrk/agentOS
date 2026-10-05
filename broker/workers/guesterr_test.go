package workers

// REQ: CAP-8, RES-4

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/admission"
	"github.com/ghbmrk/agentos/broker/vm"
	"github.com/ghbmrk/agentos/broker/vm/overlay"
)

// canary stands for a host path and an internal machine ID that no worker
// tool's error may carry to the guest (SR2-3f, security R1 on #174).
const canary = "/canary-state/machines/wk-1a2b3c4d-x/disk/upper"

// noLeak fails the test if text carries a host path or an internal ID.
func noLeak(t *testing.T, what, text string) {
	t.Helper()
	for _, bad := range []string{"canary", "/machines/", "wk-", "/state/"} {
		if strings.Contains(text, bad) {
			t.Fatalf("%s names %q: %s", what, bad, text)
		}
	}
}

// captureLog returns what the broker's log gets while the test runs.
func captureLog(t *testing.T) *bytes.Buffer {
	var b bytes.Buffer
	log.SetOutput(&b)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })
	return &b
}

var refRE = regexp.MustCompile(`^worker_exec failed \(ref ([0-9a-f]{8})\); the broker's log has the detail$`)

// Each allowlisted sentinel keeps its own fixed text, whatever vm wrapped
// around it, and drops the wrapped detail.
func TestSentinelsKeepOnlyTheirFixedText(t *testing.T) {
	wrap := func(e error) error { return fmt.Errorf("%w: %s at %s", e, "wk-1a2b3c4d-x", canary) }
	for _, tc := range []struct {
		err  error
		want string
	}{
		{&vm.WorkerFull{ID: "wk-1a2b3c4d-x", Bytes: 9 << 20, Cap: 8 << 20}, "more files than its 8 MB cap"},
		{wrap(vm.ErrQuota), "disk budget"},
		{fmt.Errorf("%w (%w)", vm.ErrQuota, overlay.ErrTooDeep), "flatten them"},
		{wrap(vm.ErrDiskFull), "not enough disk"},
		{wrap(vm.ErrBusy), "busy"},
		{wrap(vm.ErrState), "not in a state"},
		{wrap(vm.ErrHeld), "STOP"},
		{wrap(vm.ErrLabel), "private data"},
		{wrap(vm.ErrUnknown), "no such worker"},
		{wrap(vm.ErrLineage), "not in this worker's lineage"},
		{wrap(vm.ErrExists), "already exists"},
		{wrap(vm.ErrPreempted), "preempted"},
		{wrap(vm.ErrContained), "owner deleted"},
		{wrap(vm.ErrNoExec), "cannot run commands"},
		{wrap(overlay.ErrDeleteFailed), "deletion could not finish"},
		{wrap(overlay.ErrUnsafe), "unsafe"},
		{wrap(admission.ErrNoRoom), "no room"},
	} {
		got := guestErr("agent", toolExec, tc.err).Error()
		if !strings.Contains(got, tc.want) {
			t.Errorf("%v -> %q, want it to say %q", tc.err, got, tc.want)
		}
		noLeak(t, "sentinel text", got)
	}
}

// Anything else reaches the guest as a ref only; the detail goes to the
// broker's log under the same ref, and refs differ per occurrence.
func TestOtherErrorsBecomeARef(t *testing.T) {
	logged := captureLog(t)
	err := &os.PathError{Op: "open", Path: canary, Err: syscall.EIO}
	a := guestErr("agent", toolExec, err).Error()
	b := guestErr("agent", toolExec, context.DeadlineExceeded).Error()
	ma, mb := refRE.FindStringSubmatch(a), refRE.FindStringSubmatch(b)
	if ma == nil || mb == nil || ma[1] == mb[1] {
		t.Fatalf("refs %q, %q", a, b)
	}
	if !strings.Contains(logged.String(), ma[1]) || !strings.Contains(logged.String(), canary) {
		t.Fatalf("log lacks the ref or the detail: %s", logged)
	}
}

// Text the workers package wrote passes as it is.
func TestOwnTextPassesAsItIs(t *testing.T) {
	e := say("worker %s: %d", named("w1"), num(3))
	if got := guestErr("agent", toolExec, e).Error(); got != "worker w1: 3" {
		t.Fatalf("got %q", got)
	}
}

// failing passes reads through to the real manager and fails every other
// call with a host path, wrapped as vm wraps its errors.
type failing struct {
	inner
	err error
}

// inner names the embedded manager: a field called Machines would hide
// the method of that name.
type inner = Machines

func (f failing) ForkSiblings(string) (string, []string, error) { return "", nil, f.err }
func (f failing) CreateWorker(context.Context, string, string, vm.Spec) (vm.Machine, error) {
	return vm.Machine{}, f.err
}
func (f failing) Exec(context.Context, string, vm.Command, time.Duration) (vm.ExecResult, error) {
	return vm.ExecResult{}, f.err
}
func (f failing) Checkpoint(context.Context, string) (vm.Snapshot, error) {
	return vm.Snapshot{}, f.err
}
func (f failing) Fork(context.Context, string, []string) (vm.Snapshot, error) {
	return vm.Snapshot{}, f.err
}
func (f failing) Diff(string, string, string) ([]overlay.Change, error) { return nil, f.err }
func (f failing) Rollback(context.Context, string, string) error        { return f.err }
func (f failing) Destroy(context.Context, string) error                 { return f.err }
func (f failing) RaiseLabel(string, vm.Label) error                     { return f.err }
func (f failing) DeleteFiles(context.Context, string, vm.Deletion) (vm.DeleteReport, error) {
	return vm.DeleteReport{}, f.err
}

// Every worker tool, driven through Call against a manager that fails
// with host paths, answers the guest no host path and no internal ID.
func TestNoWorkerToolErrorNamesAHostPath(t *testing.T) {
	captureLog(t)
	r := newRig(t, 8000)
	r.agent("agent", vm.Public)
	r.must("agent", toolCreate, m{"name": "w1"}, nil)
	var snap struct{ Snapshot string }
	r.must("agent", toolCkpt, m{"name": "w1"}, &snap)
	r.must("agent", toolFork, m{"name": "w1", "into": []string{"w2"}}, nil)
	path := &os.PathError{Op: "open", Path: canary, Err: syscall.EIO}
	args := map[string]m{
		toolCreate:   {"name": "w9"},
		toolExec:     {"name": "w1", "argv": []string{"echo", "x"}},
		toolRead:     {"name": "w1", "path": "/f"},
		toolWrite:    {"name": "w1", "path": "/f", "content": "x"},
		toolCkpt:     {"name": "w1"},
		toolFork:     {"name": "w1", "into": []string{"w3"}},
		toolDiff:     {"a": snap.Snapshot, "b": snap.Snapshot},
		toolRollback: {"name": "w1", "snapshot": snap.Snapshot},
		toolDestroy:  {"name": "w1"},
		toolList:     {},
		toolFit:      {},
		toolKeep:     {"name": "w2"},
		toolDelete:   {"name": "w1", "paths": []string{"/f"}},
	}
	for _, tool := range r.tools.List() {
		name := tool["name"].(string)
		if _, ok := args[name]; !ok {
			t.Fatalf("no arguments for %s", name)
		}
	}
	real := r.tools.M
	for name, a := range args {
		for _, e := range []error{
			path,
			fmt.Errorf("%w: %s: %w", vm.ErrState, "wk-1a2b3c4d-w1", path),
			fmt.Errorf("vm: %s: %w", "wk-1a2b3c4d-w1", path),
		} {
			r.tools.M = failing{real, e}
			mc, _ := r.m.Get("agent")
			b, _ := json.Marshal(a)
			text, _, err := r.tools.Call(context.Background(), "agent", mc.Lineage, name, b)
			noLeak(t, name+" answer", text)
			if err == nil && name != toolList && name != toolFit {
				t.Fatalf("%s did not reach the failing manager: %s", name, text)
			}
			if err != nil {
				noLeak(t, name+" error", err.Error())
			}
		}
	}
}

// panicking fails CreateWorker with a panic whose message names a host
// path, as a runtime bug could.
type panicking struct{ inner }

func (panicking) CreateWorker(context.Context, string, string, vm.Spec) (vm.Machine, error) {
	panic("runtime: open " + canary + ": input/output error")
}

// A panic in a tool is answered as a ref, the detail logged (security F2
// on SR2-3f), and the broker goes on.
func TestAToolPanicIsARef(t *testing.T) {
	logged := captureLog(t)
	r := newRig(t, 8000)
	r.agent("agent", vm.Public)
	r.tools.M = panicking{r.m}
	err := r.call("agent", toolCreate, m{"name": "w1"}, nil)
	if err == nil || !regexp.MustCompile(`^worker_create failed \(ref [0-9a-f]{8}\)`).MatchString(err.Error()) {
		t.Fatalf("panic answered %v", err)
	}
	if !strings.Contains(logged.String(), canary) {
		t.Fatalf("log lacks the panic: %s", logged)
	}
	r.tools.M = r.m
	r.must("agent", toolCreate, m{"name": "w1"}, nil)
}

// The guard (security F1 on SR2-3f): in the workers package, errors are
// made only by say, whose format is a literal and whose arguments are
// typed as safe; said literals outside guesterr.go hold one literal; and
// no conversion to a safe type takes an error, its text, or a host value.
func TestWorkerErrorsAreBuiltOnlyFromSafeText(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, f, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		ast.Inspect(file, func(n ast.Node) bool {
			switch n := n.(type) {
			case *ast.CallExpr:
				switch fn := n.Fun.(type) {
				case *ast.SelectorExpr:
					if pkg, ok := fn.X.(*ast.Ident); ok {
						switch pkg.Name + "." + fn.Sel.Name {
						case "errors.New", "fmt.Errorf", "errors.Join":
							t.Errorf("%s: %s.%s builds an error outside say", fset.Position(n.Pos()), pkg.Name, fn.Sel.Name)
						}
					}
				case *ast.Ident:
					switch fn.Name {
					case "say":
						if lit, ok := n.Args[0].(*ast.BasicLit); !ok || lit.Kind != token.STRING {
							t.Errorf("%s: say's format is not a literal", fset.Position(n.Pos()))
						}
					case "named", "guest":
						if bad := unsafeIn(n.Args[0]); bad != "" {
							t.Errorf("%s: %s(...) takes %s", fset.Position(n.Pos()), fn.Name, bad)
						}
					}
				}
			case *ast.CompositeLit:
				if id, ok := n.Type.(*ast.Ident); ok && id.Name == "said" && f != "guesterr.go" {
					if len(n.Elts) > 1 {
						t.Errorf("%s: said literal of %d parts", fset.Position(n.Pos()), len(n.Elts))
					} else if len(n.Elts) == 1 {
						if lit, ok := n.Elts[0].(*ast.BasicLit); !ok || lit.Kind != token.STRING {
							t.Errorf("%s: said literal is not one string literal", fset.Position(n.Pos()))
						}
					}
				}
			}
			return true
		})
	}
}

// unsafeIn names what in e may carry host text: an error or its text, or
// a value from a package that deals in host paths.
func unsafeIn(e ast.Expr) string {
	bad := ""
	ast.Inspect(e, func(n ast.Node) bool {
		switch n := n.(type) {
		case *ast.Ident:
			// Stderr is the guest command's own output, not an error.
			l := strings.ToLower(n.Name)
			if strings.HasPrefix(l, "err") || strings.HasSuffix(l, "err") && n.Name != "Stderr" {
				bad = "an error " + n.Name
			}
		case *ast.SelectorExpr:
			if n.Sel.Name == "Error" {
				bad = "an error's text"
			}
			if pkg, ok := n.X.(*ast.Ident); ok {
				switch pkg.Name {
				case "os", "filepath", "syscall", "vm", "overlay", "quota":
					bad = "a " + pkg.Name + " value"
				}
			}
		}
		return bad == ""
	})
	return bad
}

// The guard catches what it is for.
func TestTheGuardCatchesAnErrorPassedAsText(t *testing.T) {
	for src, want := range map[string]string{
		"guest(err.Error())":            "an error",
		"guest(filepath.Join(a, b))":    "a filepath value",
		"named(w.ID + vm.WorkerPrefix)": "a vm value",
		"guest(a.Path)":                 "",
		"guest(string(r.Stderr))":       "",
		"named(serr.Name)":              "an error",
	} {
		e, err := parser.ParseExpr(src)
		if err != nil {
			t.Fatal(err)
		}
		got := unsafeIn(e.(*ast.CallExpr).Args[0])
		if want == "" && got != "" || want != "" && !strings.HasPrefix(got, want) {
			t.Errorf("%s: %q, want %q", src, got, want)
		}
	}
}
