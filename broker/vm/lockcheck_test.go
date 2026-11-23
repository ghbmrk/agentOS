package vm

// REQ: RES-2

import (
	"fmt"
	"go/ast"
	"go/parser"
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
	if bad := lockFindings(t, fset, pkg, files, info); len(bad) > 0 {
		t.Fatalf("a machine's lock taken other than through lockLive, lockEndingExecLive or tryLockLive (V38; a retired handle may name a new machine): use one of those, or add the function to plainLocks with why a retired handle is safe there:\n%s", strings.Join(bad, "\n"))
	}
}

// lockFindings is the lock check over files, type-checked as package vm:
// one line per function that breaks it.
func lockFindings(t testing.TB, fset *token.FileSet, pkg *types.Package, files []*ast.File, info *types.Info) []string {
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
	// unsafe or reflect reaches mu without naming it, as
	// (*sync.Mutex)(unsafe.Pointer(mc)) does while mu is the first field
	// (Security on #6609): package vm imports neither.
	for _, f := range files {
		for _, im := range f.Imports {
			if p := strings.Trim(im.Path.Value, `"`); p == "unsafe" || p == "reflect" {
				evade = append(evade, fmt.Sprintf("%s imports %s, which can take a machine's lock out of the check's sight", fset.Position(im.Pos()), p))
			}
		}
	}
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
	return bad
}

// byIDAfterHandle is the by-ID check's allowlist: each function of
// package vm that holds a machine handle (any expression of type *machine)
// and still names an exported Manager method, or once it holds the handle
// indexes the table or names a by-ID resolver (get, take, labelOf,
// preempt and any other derived in the test), how many times, and why the
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
	"Manager.Merge":                {2, "Snapshot(baseID) reads the fork point's record; it must name dst and be of its life (ownSnap); get(dst) is the first lookup of the second machine, of another ID, after src's checks"},
	"Manager.forgetMachine":        {1, "Snapshots(mc.ID) lists records by ID; ownSnap keeps only mc's own life"},
	"Manager.ForgetSince":          {2, "Unread() lists unreadable snapshot IDs, and lineageSnaps(lineage, since) takes a lineage, not a machine ID, reading the table only for a legacy snapshot's lineage; neither resolves a machine to act on"},
	"Manager.Prune":                {1, "Unread() lists unreadable snapshot IDs; no machine is resolved"},

	// The table's own upkeep: each writes or compares the entry for the
	// handle it holds, never acts on what the ID names.
	"Manager.reserve":   {1, "m.machines[id] = mc stores the new handle, under m.mu, after refusing an ID already in the table"},
	"Manager.unreserve": {1, "m.machines[mc.ID] == mc compares the entry with the handle and deletes only that handle's"},
	"Manager.load":      {1, "m.machines[mc.ID] = mc fills the table at open, before any other path runs"},
	"Manager.Fork":      {1, "reserve(f, ...) makes each new fork under its own new ID and refuses one already in the table (ErrExists)"},
}

// TestHandlePathsActOnlyThroughTheHandle type-checks package vm's non-test
// files and fails on any function that holds a machine handle and names an
// exported Manager method (called, as a method value or as a method
// expression), or, once it holds the handle, indexes Manager.machines or
// names an unexported by-ID resolver, beyond what byIDAfterHandle allows it
// (#1710 item 1; Security blocker on #6609).
func TestHandlePathsActOnlyThroughTheHandle(t *testing.T) {
	fset, pkg, files, info := typeCheckVM(t)
	if bad := byIDFindings(t, fset, pkg, files, info); len(bad) > 0 {
		t.Fatalf("a path holding a machine handle acts by ID (V38 rule 2; the ID may name a same-ID successor): call the handle's own helper, or add the function to byIDAfterHandle with why the call cannot reach a successor:\n%s", strings.Join(bad, "\n"))
	}
}

// byIDFindings is the by-ID check over files, type-checked as package vm:
// one line per function that breaks it.
func byIDFindings(t testing.TB, fset *token.FileSet, pkg *types.Package, files []*ast.File, info *types.Info) []string {
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

	// The by-ID resolvers: Manager methods that take an ID (a string) and
	// no handle, and reach a machine through the table, directly
	// (m.machines[id]) or through another resolver: get, take, labelOf,
	// preempt and the rest. Derived, so a new one is covered (Security
	// blocker on #6609).
	mgrSt := mgr.Type().Underlying().(*types.Struct)
	var machinesField types.Object
	for i := range mgrSt.NumFields() {
		if f := mgrSt.Field(i); f.Name() == "machines" {
			machinesField = f
		}
	}
	if machinesField == nil {
		t.Fatal("Manager has no field machines")
	}
	indexesTable := func(n ast.Node) bool {
		ix, ok := n.(*ast.IndexExpr)
		if !ok {
			return false
		}
		s, ok := ix.X.(*ast.SelectorExpr)
		return ok && info.Selections[s] != nil && info.Selections[s].Obj() == machinesField
	}
	methods := map[*types.Func]*ast.FuncDecl{}
	for _, f := range files {
		for _, d := range f.Decls {
			fd, ok := d.(*ast.FuncDecl)
			if !ok || fd.Body == nil || fd.Recv == nil {
				continue
			}
			if fn, ok := info.Defs[fd.Name].(*types.Func); ok && isManager(fn) {
				methods[fn] = fd
			}
		}
	}
	takesIDOnly := func(fn *types.Func) bool {
		ps := fn.Signature().Params()
		id := false
		for i := range ps.Len() {
			switch {
			case types.Identical(ps.At(i).Type(), handle):
				return false
			case types.Identical(ps.At(i).Type(), types.Typ[types.String]):
				id = true
			}
		}
		return id
	}
	resolvers := map[*types.Func]bool{}
	for grew := true; grew; {
		grew = false
		for fn, fd := range methods {
			if resolvers[fn] || !takesIDOnly(fn) {
				continue
			}
			ast.Inspect(fd.Body, func(n ast.Node) bool {
				if resolvers[fn] {
					return false
				}
				if indexesTable(n) {
					resolvers[fn], grew = true, true
				}
				if s, ok := n.(*ast.SelectorExpr); ok {
					if sl := info.Selections[s]; sl != nil {
						if g, ok := sl.Obj().(*types.Func); ok && resolvers[g] {
							resolvers[fn], grew = true, true
						}
					}
				}
				return true
			})
		}
	}
	for _, want := range []string{"get", "take", "labelOf", "preempt"} {
		if fn, ok := mgr.Type().(*types.Named); ok {
			found := false
			for i := range fn.NumMethods() {
				if m := fn.Method(i); m.Name() == want && resolvers[m] {
					found = true
				}
			}
			if !found {
				t.Errorf("%s is not derived as a by-ID resolver: the derivation is not looking", want)
			}
		}
	}

	found := map[string][]string{}
	handles := 0
	for _, f := range files {
		for _, d := range f.Decls {
			fd, ok := d.(*ast.FuncDecl)
			if !ok || fd.Body == nil {
				continue
			}
			// gotAt is where the function first holds a handle: a handle
			// parameter at the body's start, a defined handle at the end
			// of the statement that defines it (a range's at its range
			// expression), any other handle-typed expression at its end.
			gotAt := token.NoPos
			at := func(p token.Pos) {
				if !gotAt.IsValid() || p < gotAt {
					gotAt = p
				}
			}
			var stack []ast.Node
			ast.Inspect(fd, func(n ast.Node) bool {
				if n == nil {
					stack = stack[:len(stack)-1]
					return true
				}
				stack = append(stack, n)
				e, ok := n.(ast.Expr)
				if !ok {
					return true
				}
				if id, ok := e.(*ast.Ident); ok {
					if o := info.Defs[id]; o != nil && types.Identical(o.Type(), handle) {
						p := id.End()
					up:
						for i := len(stack) - 2; i >= 0; i-- {
							switch st := stack[i].(type) {
							case *ast.Field:
								if fd.Body != nil && st.Pos() < fd.Body.Pos() {
									p = fd.Body.Pos()
								}
								break up
							case *ast.RangeStmt:
								p = st.X.End()
								break up
							case *ast.AssignStmt, *ast.DeclStmt:
								p = st.End()
								break up
							case ast.Stmt:
								break up
							}
						}
						at(p)
						return true
					}
				}
				if tv, ok := info.Types[e]; ok && !tv.IsType() && tv.Type != nil && types.Identical(tv.Type, handle) {
					at(e.End())
				}
				return true
			})
			if !gotAt.IsValid() {
				continue
			}
			handles++
			name := funcName(fd)
			ast.Inspect(fd.Body, func(n ast.Node) bool {
				if indexesTable(n) && n.Pos() >= gotAt {
					found[name] = append(found[name], fmt.Sprintf("the table by ID at %s", fset.Position(n.Pos())))
					return true
				}
				s, ok := n.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				sl := info.Selections[s]
				if sl == nil || (sl.Kind() != types.MethodVal && sl.Kind() != types.MethodExpr) {
					return true
				}
				fn, ok := sl.Obj().(*types.Func)
				if !ok || !isManager(fn) {
					return true
				}
				// An exported method anywhere in the function; an
				// unexported resolver once the function holds a handle.
				if s.Sel.IsExported() || (resolvers[fn] && s.Pos() >= gotAt) {
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
			bad = append(bad, fmt.Sprintf("%s holds a machine handle and re-resolves by ID %d time(s) (allowed %d): %s", name, len(at), byIDAfterHandle[name].n, strings.Join(at, ", ")))
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
	return bad
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

// TestLockChecksCatchPlantedEvasions plants each known way around the two
// checks, one at a time, in a file type-checked with package vm's own, and
// requires the check to name the planted function (#1710; Security on
// #6609).
func TestLockChecksCatchPlantedEvasions(t *testing.T) {
	l, p := loadVM(t)
	planted := []struct {
		name, src string
		check     func(testing.TB, *token.FileSet, *types.Package, []*ast.File, *types.Info) []string
	}{
		// The lock check.
		{"plantAlias", "func plantAlias(mc *machine) { mu := &mc.mu; mu.Lock(); mu.Unlock() }", lockFindings},
		{"plantMethodValue", "func plantMethodValue(mc *machine) { lk := mc.mu.Lock; lk(); mc.mu.Unlock() }", lockFindings},
		{"plantMethodExpr", "func plantMethodExpr(mc *machine) { (*sync.Mutex).Lock(&mc.mu); mc.mu.Unlock() }", lockFindings},
		{"plantLocker", "func plantLocker(mc *machine) { var l sync.Locker = &mc.mu; l.Lock(); l.Unlock() }", lockFindings},
		{"plantEndingExecValue", "func plantEndingExecValue(mc *machine) { f := mc.lockEndingExec; _ = f }", lockFindings},
		{"plantPlainLock", "func plantPlainLock(mc *machine) { mc.mu.Lock(); mc.mu.Unlock() }", lockFindings},
		{"package-level", "var plantVar = func(mc *machine) { mc.mu.Lock(); mc.mu.Unlock() }", lockFindings},
		{"imports unsafe", "func plantUnsafe(mc *machine) { (*sync.Mutex)(unsafe.Pointer(mc)).Lock() }", lockFindings},
		// The by-ID check: a handle, then the ID again.
		{"plantGet", "func plantGet(m *Manager, mc *machine) { _, _ = m.get(mc.ID) }", byIDFindings},
		{"plantTake", "func plantTake(m *Manager, mc *machine) { _, _ = m.take(context.Background(), mc.ID, FS) }", byIDFindings},
		{"plantLabelOf", "func plantLabelOf(m *Manager, mc *machine) { _ = m.labelOf(mc.ID) }", byIDFindings},
		{"plantPreempt", "func plantPreempt(m *Manager, mc *machine) { _ = m.preempt(mc.ID, nil) }", byIDFindings},
		{"plantTable", "func plantTable(m *Manager, mc *machine) { _ = m.machines[mc.ID] }", byIDFindings},
		{"plantResolverValue", "func plantResolverValue(m *Manager, mc *machine) { g := m.get; _, _ = g(mc.ID) }", byIDFindings},
		{"plantExported", "func plantExported(m *Manager, mc *machine) { _ = m.Resume(context.Background(), mc.ID) }", byIDFindings},
		{"plantAfterLookup", "func plantAfterLookup(m *Manager, id string) { if mc, err := m.get(id); err == nil { _, _ = m.get(mc.ID) } }", byIDFindings},
		{"plantInRange", "func plantInRange(m *Manager, hs []*machine) { for _, mc := range hs { _ = m.labelOf(mc.ID) } }", byIDFindings},
	}
	src := "package vm\n\nimport (\n\t\"context\"\n\t\"sync\"\n\t\"unsafe\"\n)\n\nvar _ = context.Background\nvar _ sync.Locker\nvar _ unsafe.Pointer\n\n"
	for _, c := range planted {
		t.Run(c.name, func(t *testing.T) {
			f, err := parser.ParseFile(l.Fset, "planted.go", src+c.src+"\n", 0)
			if err != nil {
				t.Fatal(err)
			}
			files := append(append([]*ast.File(nil), p.Files...), f)
			pkg, info, err := l.Check(p.Types.Path(), files)
			if err != nil {
				t.Fatal(err)
			}
			bad := c.check(t, l.Fset, pkg, files, info)
			for _, b := range bad {
				if strings.Contains(b, c.name) {
					return
				}
			}
			t.Errorf("the planted %s passed the check:\n%s\n(findings: %q)", c.name, c.src, bad)
		})
	}
	// A clean plant passes both, so the cases above fail for their shape.
	f, err := parser.ParseFile(l.Fset, "planted.go", src+"func plantClean(m *Manager, mc *machine) { _ = m.resumeOf(context.Background(), mc) }\n", 0)
	if err != nil {
		t.Fatal(err)
	}
	files := append(append([]*ast.File(nil), p.Files...), f)
	pkg, info, err := l.Check(p.Types.Path(), files)
	if err != nil {
		t.Fatal(err)
	}
	for _, check := range []func(testing.TB, *token.FileSet, *types.Package, []*ast.File, *types.Info) []string{lockFindings, byIDFindings} {
		for _, b := range check(t, l.Fset, pkg, files, info) {
			if !strings.Contains(b, "imports unsafe") {
				t.Errorf("a clean plant failed: %s", b)
			}
		}
	}
}

// typeCheckVM type-checks package vm's non-test files through the shared
// lint loader, and fails on a file of the package it leaves unread.
func typeCheckVM(t *testing.T) (*token.FileSet, *types.Package, []*ast.File, *types.Info) {
	t.Helper()
	l, p := loadVM(t)
	return l.Fset, p.Types, p.Files, p.Info
}

// loadVM loads package vm's non-test files through the shared lint
// loader, and fails on a file of the package it leaves unread.
func loadVM(t *testing.T) (*lintload.Loaded, *lintload.Package) {
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
	return l, l.Packages[0]
}
