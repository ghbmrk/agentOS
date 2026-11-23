package vm

// REQ: RES-2

import (
	"fmt"
	"go/ast"
	"go/token"
	"go/types"
	"sort"
	"strings"
	"testing"

	"github.com/ghbmrk/agentos/broker/internal/lintload"
)

// plainLocks is the lock check's one allowlist: each function of package
// vm that may take a machine's lock (mc.mu.Lock, mc.mu.TryLock or
// mc.lockEndingExec) other than through lockLive, lockEndingExecLive or
// tryLockLive, how many times, and why a handle Destroy retired is safe
// there. Everything else takes the lock through those three, which refuse
// a retired handle, so a new path cannot forget (security S1 on #1575,
// the second round of stale-handle findings). An entry no longer needed
// fails the check too.
var plainLocks = map[string]struct {
	n   int
	why string
}{
	// The primitives themselves.
	"machine.lockLive":           {1, "the primitive: unlessGone follows"},
	"machine.lockEndingExec":     {1, "the primitive behind lockEndingExecLive: unlessGone follows there"},
	"machine.tryLockLive":        {1, "the primitive: unlessGone follows"},
	"machine.lockEndingExecLive": {1, "the primitive: unlessGone follows"},

	// Starts: claimLocked refuses a retired machine under the lock, and
	// admit refused it before (Destroy sets gone under admitMu).
	"Manager.create":     {1, "a handle this call reserved; claimLocked refuses it if Destroy retired it meanwhile"},
	"Manager.rollbackTo": {1, "after admit; claimLocked refuses a retired machine"},
	"Manager.resumeOf":   {2, "a state read (a retired machine reads Stopped), then after admit; admit and claimLocked refuse a retired machine"},
	"Manager.rebuildOf":  {2, "a state read (a retired machine reads Stopped), then after admit; admit and claimLocked refuse a retired machine"},
	"Manager.Fork":       {2, "a read of src.Last (takeOf then refuses a retired src), and each reserved fork's claim: claimLocked refuses it and the cleanup skips it (!mc.gone)"},

	// admit only reads the request; it checks gone under admitMu.
	"Manager.admit": {1, "reads the request; refuses a retired machine under admitMu before admission"},

	// Read only: nothing is written through the handle.
	"Manager.labelOf":              {1, "a label read; a stale one only ever raises a label (Diff)"},
	"Manager.contained":            {1, "a lineage read, fixed at reserve"},
	"Manager.ResetPlan":            {1, "a layer path read; measures, changes nothing"},
	"Manager.Prune":                {2, "reads ForkBase and Last to keep more; unpublishes only snapshots it listed by their own records"},
	"Manager.ResumeFromCheckpoint": {1, "a state read after a failed restore; a retired machine reads Stopped and resumeOf refuses it"},

	// Preempt never waits on the lock. Under TryLock a retired machine is
	// refused with ErrUnknown, so admission never counts it preempted; the
	// kill without the lock goes through killLive, which refuses a retired
	// handle the same way. The deferred completion runs only after a live
	// kill, and on a machine retired since, preemptLocked only marks it
	// revoked.
	"Manager.preempt": {2, "Preempt and PreemptInstance: a life other than the one asked for is refused before any lock; TryLock refuses a retired machine with ErrUnknown, not success, so admission keeps a same-ID successor's entry; the deferred completion follows a live kill, and on a since-retired (Stopped) machine only marks it revoked"},
}

// TestMachineLockOnlyThroughLockLive type-checks package vm's non-test
// files and fails on any function that takes a machine's lock other than
// through lockLive, lockEndingExecLive or tryLockLive beyond what
// plainLocks allows it.
func TestMachineLockOnlyThroughLockLive(t *testing.T) {
	fset, pkg, files, info := typeCheckVM(t)
	mt, ok := pkg.Scope().Lookup("machine").(*types.TypeName)
	if !ok {
		t.Fatal("no type machine in package vm")
	}
	st := mt.Type().Underlying().(*types.Struct)
	var muField types.Object
	for i := range st.NumFields() {
		if f := st.Field(i); f.Name() == "mu" {
			muField = f
		}
	}
	if muField == nil {
		t.Fatal("machine has no field mu")
	}
	ms := types.NewMethodSet(types.NewPointer(mt.Type()))
	sel := ms.Lookup(pkg, "lockEndingExec")
	if sel == nil {
		t.Fatal("machine has no method lockEndingExec")
	}
	lockEndingExec := sel.Obj()

	found := map[string][]string{}
	// Any other use of mc.mu or lockEndingExec, such as an alias
	// (mu := &mc.mu; mu.Lock()), a method value (lk := mc.mu.Lock; lk()) or
	// a method expression, would take the lock out of the check's sight
	// (Security delta 2 P-L4 on #1575, #1710): each is refused outright.
	var evade []string
	for _, f := range files {
		for _, d := range f.Decls {
			// A package-level func literal (a var's value) is read too,
			// under no function's name, so no allowlist entry covers it.
			var body ast.Node = d
			name := "package-level declaration"
			if fd, ok := d.(*ast.FuncDecl); ok {
				if fd.Body == nil {
					continue
				}
				body, name = fd.Body, funcName(fd)
			}
			var stack []ast.Node
			ast.Inspect(body, func(n ast.Node) bool {
				if n == nil {
					stack = stack[:len(stack)-1]
					return true
				}
				parent := func(up int) ast.Node {
					if len(stack) < up {
						return nil
					}
					return stack[len(stack)-up]
				}
				stack = append(stack, n)
				s, ok := n.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				sl := info.Selections[s]
				if sl == nil {
					return true
				}
				at := fset.Position(s.Pos()).String()
				switch sl.Obj() {
				case muField:
					// Only mc.mu.Lock(), mc.mu.TryLock() and mc.mu.Unlock().
					m, ok := parent(2).(*ast.SelectorExpr)
					call, cok := parent(3).(*ast.CallExpr)
					if !ok || m.X != s || !cok || call.Fun != m {
						evade = append(evade, fmt.Sprintf("%s selects a machine's mu other than to call Lock, TryLock or Unlock on it: %s", name, at))
						return true
					}
					switch m.Sel.Name {
					case "Lock", "TryLock":
						found[name] = append(found[name], fset.Position(call.Pos()).String())
					case "Unlock":
					default:
						evade = append(evade, fmt.Sprintf("%s calls %s on a machine's mu: %s", name, m.Sel.Name, at))
					}
				case lockEndingExec:
					call, ok := parent(2).(*ast.CallExpr)
					if !ok || call.Fun != s {
						evade = append(evade, fmt.Sprintf("%s uses lockEndingExec other than by calling it: %s", name, at))
						return true
					}
					found[name] = append(found[name], fset.Position(call.Pos()).String())
				}
				return true
			})
		}
	}

	bad := evade
	for name, at := range found {
		if len(at) > plainLocks[name].n {
			bad = append(bad, fmt.Sprintf("%s takes a machine's lock %d time(s) other than through lockLive (allowed %d): %s", name, len(at), plainLocks[name].n, strings.Join(at, ", ")))
		}
	}
	for name, a := range plainLocks {
		if a.why == "" {
			bad = append(bad, fmt.Sprintf("%s: an allowlist entry needs its reason", name))
		}
		if len(found[name]) < a.n {
			bad = append(bad, fmt.Sprintf("%s: allowlisted for %d plain lock(s), takes %d: lower the entry", name, a.n, len(found[name])))
		}
	}
	if len(found) == 0 {
		t.Fatal("the check found no lock at all: it is not looking")
	}
	sort.Strings(bad)
	if len(bad) > 0 {
		t.Fatalf("a machine's lock taken other than through lockLive, lockEndingExecLive or tryLockLive (V38; a retired handle may name a new machine): use one of those, or add the function to plainLocks with why a retired handle is safe there:\n%s", strings.Join(bad, "\n"))
	}
}

// byIDAfterHandle is the by-ID check's allowlist: each function of
// package vm that holds a machine handle (any expression of type *machine)
// and still names an exported Manager method, how many times, and why the
// call cannot reach a same-ID successor. An exported method looks its
// machine up by ID again, so a path that checked a handle and then calls
// one may act on a successor Destroy let take the ID (L3 B2 on #1575:
// DeleteFiles resumed by ID). Such a path calls the handle's own helper
// instead (resumeOf, rebuildOf, takeOf, rollbackTo; V38 rule 2). An entry
// no longer needed fails the check too.
var byIDAfterHandle = map[string]struct {
	n   int
	why string
}{
	// Snapshot-store reads: they resolve a snapshot, not a machine, and
	// the caller then tests the snapshot against its handle.
	"Manager.ResumeFromCheckpoint": {1, "Snapshot(snapID) reads a snapshot record; ownSnap(mc, s) then refuses one not of mc's life"},
	"Manager.Rollback":             {1, "Snapshot(snapID) reads a snapshot record; inLineage then refuses one not of mc's life"},
	"Manager.Merge":                {1, "Snapshot(baseID) reads the fork point's record; it must name dst and be of its life (ownSnap)"},
	"Manager.forgetMachine":        {1, "Snapshots(mc.ID) lists records by ID; ownSnap keeps only mc's own life"},
	"Manager.ForgetSince":          {1, "Unread() lists unreadable snapshot IDs; no machine is resolved"},
	"Manager.Prune":                {1, "Unread() lists unreadable snapshot IDs; no machine is resolved"},
}

// TestHandlePathsActOnlyThroughTheHandle type-checks package vm's non-test
// files and fails on any function that holds a machine handle and names an
// exported Manager method (called, as a method value or as a method
// expression) beyond what byIDAfterHandle allows it (#1710 item 1).
func TestHandlePathsActOnlyThroughTheHandle(t *testing.T) {
	fset, pkg, files, info := typeCheckVM(t)
	mt, ok := pkg.Scope().Lookup("machine").(*types.TypeName)
	if !ok {
		t.Fatal("no type machine in package vm")
	}
	mgr, ok := pkg.Scope().Lookup("Manager").(*types.TypeName)
	if !ok {
		t.Fatal("no type Manager in package vm")
	}
	handle := types.NewPointer(mt.Type())
	isManager := func(fn *types.Func) bool {
		r := fn.Signature().Recv()
		if r == nil {
			return false
		}
		rt := r.Type()
		if p, ok := rt.(*types.Pointer); ok {
			rt = p.Elem()
		}
		n, ok := rt.(*types.Named)
		return ok && n.Obj() == mgr
	}

	found := map[string][]string{}
	handles := 0
	for _, f := range files {
		for _, d := range f.Decls {
			fd, ok := d.(*ast.FuncDecl)
			if !ok || fd.Body == nil {
				continue
			}
			holds := false
			ast.Inspect(fd, func(n ast.Node) bool {
				if e, ok := n.(ast.Expr); ok && !holds {
					if tv, ok := info.Types[e]; ok && tv.Type != nil && types.Identical(tv.Type, handle) {
						holds = true
					}
					if id, ok := e.(*ast.Ident); ok {
						if o := info.Defs[id]; o != nil && types.Identical(o.Type(), handle) {
							holds = true
						}
					}
				}
				return !holds
			})
			if !holds {
				continue
			}
			handles++
			name := funcName(fd)
			ast.Inspect(fd.Body, func(n ast.Node) bool {
				s, ok := n.(*ast.SelectorExpr)
				if !ok || !s.Sel.IsExported() {
					return true
				}
				sl := info.Selections[s]
				if sl == nil || (sl.Kind() != types.MethodVal && sl.Kind() != types.MethodExpr) {
					return true
				}
				if fn, ok := sl.Obj().(*types.Func); ok && isManager(fn) {
					found[name] = append(found[name], fmt.Sprintf("%s at %s", s.Sel.Name, fset.Position(s.Pos())))
				}
				return true
			})
		}
	}
	if handles == 0 {
		t.Fatal("the check found no function holding a handle: it is not looking")
	}

	var bad []string
	for name, at := range found {
		if len(at) > byIDAfterHandle[name].n {
			bad = append(bad, fmt.Sprintf("%s holds a machine handle and names an exported Manager method %d time(s) (allowed %d): %s", name, len(at), byIDAfterHandle[name].n, strings.Join(at, ", ")))
		}
	}
	for name, a := range byIDAfterHandle {
		if a.why == "" {
			bad = append(bad, fmt.Sprintf("%s: an allowlist entry needs its reason", name))
		}
		if len(found[name]) < a.n {
			bad = append(bad, fmt.Sprintf("%s: allowlisted for %d by-ID call(s), makes %d: lower the entry", name, a.n, len(found[name])))
		}
	}
	sort.Strings(bad)
	if len(bad) > 0 {
		t.Fatalf("a path holding a machine handle acts by ID (V38 rule 2; the ID may name a same-ID successor): call the handle's own helper, or add the function to byIDAfterHandle with why the call cannot reach a successor:\n%s", strings.Join(bad, "\n"))
	}
}

// funcName names fd as Type.Method, or Func.
func funcName(fd *ast.FuncDecl) string {
	if fd.Recv == nil || len(fd.Recv.List) == 0 {
		return fd.Name.Name
	}
	rt := fd.Recv.List[0].Type
	if s, ok := rt.(*ast.StarExpr); ok {
		rt = s.X
	}
	if id, ok := rt.(*ast.Ident); ok {
		return id.Name + "." + fd.Name.Name
	}
	return "?." + fd.Name.Name
}

// typeCheckVM type-checks package vm's non-test files through the shared
// lint loader, and fails on a file of the package it leaves unread.
func typeCheckVM(t *testing.T) (*token.FileSet, *types.Package, []*ast.File, *types.Info) {
	t.Helper()
	l, err := lintload.Load(".", lintload.Build{}, ".")
	if err != nil {
		t.Fatal(err)
	}
	if unread, err := lintload.Unread(l); err != nil || len(unread) != 0 {
		t.Fatalf("files the lock check does not read: %q (%v)", unread, err)
	}
	if len(l.Packages) != 1 {
		t.Fatalf("loaded %d packages, want vm alone", len(l.Packages))
	}
	p := l.Packages[0]
	return l.Fset, p.Types, p.Files, p.Info
}
