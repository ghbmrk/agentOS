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
// (or anywhere in a func literal) selects the table (an index, a range,
// an alias) or calls a by-ID resolver (get, take, labelOf, preempt and
// any other function the test derives, of any receiver or none), or that
// uses a resolver as a value anywhere, how many times, and why the use
// cannot reach a same-ID successor. An exported method looks its
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
	"Manager.unreserve": {2, "m.machines[mc.ID] == mc compares the entry with the handle, and delete(m.machines, mc.ID) runs only when it is that handle's"},
	"Manager.load":      {2, "m.machines[mc.ID] = mc fills the table at open, before any other path runs; stampLegacy then reads the table at open too, to stamp legacy snapshots, and acts on no machine"},
	"Manager.Fork":      {1, "reserve(f, ...) makes each new fork under its own new ID and refuses one already in the table (ErrExists)"},

	// Read-only listings under m.mu: they return IDs, act on no machine.
	"Manager.ForkSiblings": {1, "range m.machines under m.mu lists the IDs of mc's sibling workers (same lineage and fork base); it returns them and acts on none"},
}

// TestHandlePathsActOnlyThroughTheHandle type-checks package vm's non-test
// files and fails on any function that holds a machine handle and names an
// exported Manager method (called, as a method value or as a method
// expression), or, once it holds the handle or in a func literal, selects
// Manager.machines or calls a by-ID resolver, or that uses a resolver as a
// value, beyond what byIDAfterHandle allows it (#1710 item 1; Security
// blockers on #6609).
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

	// Every function body of the package: each declared function or
	// method, of any type, and each package-level func literal (a var's
	// value), which no declaration names.
	type unit struct {
		name string
		obj  types.Object
		sig  *types.Signature
		node ast.Node // the FuncDecl or FuncLit, parameters included
		body *ast.BlockStmt
	}
	var units []unit
	for _, f := range files {
		for _, d := range f.Decls {
			switch d := d.(type) {
			case *ast.FuncDecl:
				if fn, ok := info.Defs[d.Name].(*types.Func); ok && d.Body != nil {
					units = append(units, unit{funcName(d), fn, fn.Signature(), d, d.Body})
				}
			case *ast.GenDecl:
				for _, sp := range d.Specs {
					vs, ok := sp.(*ast.ValueSpec)
					if !ok {
						continue
					}
					for i, v := range vs.Values {
						lit, ok := ast.Unparen(v).(*ast.FuncLit)
						if !ok || i >= len(vs.Names) {
							continue
						}
						if sig, ok := info.Types[lit].Type.(*types.Signature); ok {
							units = append(units, unit{vs.Names[i].Name, info.Defs[vs.Names[i]], sig, lit, lit.Body})
						}
					}
				}
			}
		}
	}

	// The by-ID resolvers: every function of the package, whatever its
	// receiver (a Manager method, another type's, or none), that takes no
	// handle and reaches a machine through the table (any selection of
	// Manager.machines: an index, a range, an alias) or through another
	// resolver: get, take, labelOf, preempt and the rest. Derived, so a new
	// one, or a wrapper of one, is covered (Security blockers on #6609). A
	// use is matched by the object its name resolves to (info.Uses), so a
	// plain call, a method call, a method value and a method expression
	// all count.
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
	selectsTable := func(n ast.Node) bool {
		s, ok := n.(*ast.SelectorExpr)
		return ok && info.Selections[s] != nil && info.Selections[s].Obj() == machinesField
	}
	takesHandle := func(sig *types.Signature) bool {
		if r := sig.Recv(); r != nil && types.Identical(r.Type(), handle) {
			return true
		}
		for i := range sig.Params().Len() {
			if types.Identical(sig.Params().At(i).Type(), handle) {
				return true
			}
		}
		return false
	}
	// An interface method the package names (its own interface's or
	// another package's) is a resolver when a resolver method of the same
	// name implements it, so a call through the interface counts too.
	var ifaceMethods []*types.Func
	seen := map[*types.Func]bool{}
	for _, o := range info.Uses {
		fn, ok := o.(*types.Func)
		if !ok || seen[fn] || fn.Signature().Recv() == nil || !types.IsInterface(fn.Signature().Recv().Type()) {
			continue
		}
		seen[fn] = true
		ifaceMethods = append(ifaceMethods, fn)
	}
	resolvers := map[types.Object]bool{}
	for grew := true; grew; {
		grew = false
		for _, im := range ifaceMethods {
			if resolvers[im] {
				continue
			}
			iface := im.Signature().Recv().Type().Underlying().(*types.Interface)
			for g := range resolvers {
				fn, ok := g.(*types.Func)
				if !ok || fn.Name() != im.Name() || fn.Signature().Recv() == nil {
					continue
				}
				if rt := fn.Signature().Recv().Type(); types.Implements(rt, iface) || types.Implements(types.NewPointer(rt), iface) {
					resolvers[im], grew = true, true
					break
				}
			}
		}
		for _, u := range units {
			if resolvers[u.obj] || takesHandle(u.sig) {
				continue
			}
			ast.Inspect(u.body, func(n ast.Node) bool {
				if resolvers[u.obj] {
					return false
				}
				if id, ok := n.(*ast.Ident); selectsTable(n) || ok && resolvers[info.Uses[id]] {
					resolvers[u.obj], grew = true, true
				}
				return true
			})
		}
	}
	for _, want := range []string{"get", "take", "labelOf", "preempt"} {
		if !resolvers[mgrMethod(mgr, want)] {
			t.Errorf("%s is not derived as a by-ID resolver: the derivation is not looking", want)
		}
	}

	found := map[string][]string{}
	handles := 0
	for _, u := range units {
		// gotAt is where the function first holds a handle: a handle
		// parameter or receiver at the body's start, a defined handle at
		// the end of the statement that defines it (a range's at its range
		// expression), any other handle-typed expression at its end.
		gotAt := token.NoPos
		at := func(p token.Pos) {
			if !gotAt.IsValid() || p < gotAt {
				gotAt = p
			}
		}
		var stack []ast.Node
		ast.Inspect(u.node, func(n ast.Node) bool {
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
							if st.Pos() < u.body.Pos() {
								p = u.body.Pos()
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
		// In a handle-holding function: an exported Manager method
		// anywhere (it looks its machine up by ID again); and, once the
		// function holds the handle, or anywhere in a func literal (which
		// may run after it, as again := func() { m.get(id) } does), a
		// resolver call or any selection of the table.
		stack = stack[:0]
		ast.Inspect(u.body, func(n ast.Node) bool {
			if n == nil {
				stack = stack[:len(stack)-1]
				return true
			}
			stack = append(stack, n)
			inLit := false
			for _, a := range stack[:len(stack)-1] {
				if _, ok := a.(*ast.FuncLit); ok {
					inLit = true
				}
			}
			late := inLit || n.Pos() >= gotAt
			if selectsTable(n) {
				if late {
					found[u.name] = append(found[u.name], fmt.Sprintf("the table at %s", fset.Position(n.Pos())))
				}
				return true
			}
			id, ok := n.(*ast.Ident)
			if !ok {
				return true
			}
			fn, _ := info.Uses[id].(*types.Func)
			switch {
			case fn != nil && isManager(fn) && fn.Exported():
				found[u.name] = append(found[u.name], fmt.Sprintf("%s at %s", id.Name, fset.Position(id.Pos())))
			case resolvers[info.Uses[id]] && calledDirectly(stack) && late:
				found[u.name] = append(found[u.name], fmt.Sprintf("%s at %s", id.Name, fset.Position(id.Pos())))
			}
			return true
		})
	}
	// Anywhere in the package, a resolver used other than as a direct
	// call's callee (a method value, a method expression, a func value
	// stored or passed on) is refused: where it is called is out of sight,
	// so g := m.get; mc, _ := g(id); g(mc.ID) would pass (Security release
	// item 2 on #6609).
	for _, f := range files {
		for _, d := range f.Decls {
			name := "package-level declaration"
			if fd, ok := d.(*ast.FuncDecl); ok {
				name = funcName(fd)
			}
			var stack []ast.Node
			ast.Inspect(d, func(n ast.Node) bool {
				if n == nil {
					stack = stack[:len(stack)-1]
					return true
				}
				stack = append(stack, n)
				if id, ok := n.(*ast.Ident); ok && resolvers[info.Uses[id]] && !calledDirectly(stack) {
					found[name] = append(found[name], fmt.Sprintf("%s as a value at %s", id.Name, fset.Position(id.Pos())))
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
			bad = append(bad, fmt.Sprintf("%s re-resolves a machine by ID while it may hold a handle, or passes a resolver on as a value, %d time(s) (allowed %d): %s", name, len(at), byIDAfterHandle[name].n, strings.Join(at, ", ")))
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

// calledDirectly reports whether the name at the top of stack (an
// identifier, alone or as a selector's Sel) is the callee of the call
// around it.
func calledDirectly(stack []ast.Node) bool {
	id := stack[len(stack)-1]
	var e ast.Node = id
	i := len(stack) - 2
	if i >= 0 {
		if s, ok := stack[i].(*ast.SelectorExpr); ok && s.Sel == id {
			e, i = s, i-1
		}
	}
	if i < 0 {
		return false
	}
	call, ok := stack[i].(*ast.CallExpr)
	return ok && call.Fun == e
}

// mgrMethod is Manager's method name, or nil.
func mgrMethod(mgr *types.TypeName, name string) types.Object {
	n := mgr.Type().(*types.Named)
	for i := range n.NumMethods() {
		if m := n.Method(i); m.Name() == name {
			return m
		}
	}
	return nil
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
		// A resolver that is not a Manager method (Security 7109348060 1a).
		{"plantWrapperCall", "func plantLookup(m *Manager, id string) (*machine, error) { return m.get(id) }\nfunc plantWrapperCall(m *Manager, mc *machine) { _, _ = plantLookup(m, mc.ID) }", byIDFindings},
		{"plantWrapperChain", "func plantLookup(m *Manager, id string) (*machine, error) { return m.get(id) }\nfunc plantLookup2(m *Manager, id string) bool { _, err := plantLookup(m, id); return err == nil }\nfunc plantWrapperChain(m *Manager, mc *machine) { _ = plantLookup2(m, mc.ID) }", byIDFindings},
		{"plantOtherType", "type plantReg struct{ m *Manager }\nfunc (r plantReg) find(id string) *machine { return r.m.machines[id] }\nfunc plantOtherType(r plantReg, mc *machine) { _ = r.find(mc.ID) }", byIDFindings},
		{"plantVarResolver", "var plantFind = func(m *Manager, id string) *machine { return m.machines[id] }\nfunc plantVarResolver(m *Manager, mc *machine) { _ = plantFind(m, mc.ID) }", byIDFindings},
		{"plantViaInterface", "type plantFinder interface{ find(string) *machine }\ntype plantReg struct{ m *Manager }\nfunc (r plantReg) find(id string) *machine { return r.m.machines[id] }\nfunc plantViaInterface(m *Manager, mc *machine) { var f plantFinder = plantReg{m}; _ = f.find(mc.ID) }", byIDFindings},
		{"plantViaAnonInterface", "type plantReg struct{ m *Manager }\nfunc (r plantReg) Find(id string) *machine { return r.m.machines[id] }\nfunc plantViaAnonInterface(m *Manager, mc *machine) { var f interface{ Find(string) *machine } = plantReg{m}; _ = f.Find(mc.ID) }", byIDFindings},
		{"plantNoIDResolver", "func (m *Manager) plantFirst() *machine { for _, x := range m.machines { return x }; return nil }\nfunc plantNoIDResolver(m *Manager, mc *machine) { _ = m.plantFirst() }", byIDFindings},
		// The table other than by an index (Security 7109348060 1b).
		{"plantTableRange", "func plantTableRange(m *Manager, mc *machine) { for id, x := range m.machines { if id == mc.ID { x.State = Stopped } } }", byIDFindings},
		{"plantTableAlias", "func plantTableAlias(m *Manager, mc *machine) { mm := m.machines; _ = mm[mc.ID] }", byIDFindings},
		{"plantTableDelete", "func plantTableDelete(m *Manager, mc *machine) { delete(m.machines, mc.ID) }", byIDFindings},
		// Bound before the handle, called after it (Security 7109348060 2).
		{"plantValueBefore", "func plantValueBefore(m *Manager, id string) { g := m.get; mc, _ := g(id); _, _ = g(mc.ID) }", byIDFindings},
		{"plantLitBefore", "func plantLitBefore(m *Manager, id string) { again := func() { _, _ = m.get(id) }; mc, _ := m.get(id); _ = mc; again() }", byIDFindings},
		{"plantTableLitBefore", "func plantTableLitBefore(m *Manager, id string) { look := func() *machine { return m.machines[id] }; mc, _ := m.get(id); _ = mc; _ = look() }", byIDFindings},
		{"plantWrapperValue", "func plantLookup(m *Manager, id string) (*machine, error) { return m.get(id) }\nfunc plantWrapperValue(m *Manager, mc *machine) { f := plantLookup; _, _ = f(m, mc.ID) }", byIDFindings},
		// A resolver stored where no handle is in sight, called later.
		{"plantStored", "func plantStored(m *Manager) func(string) (*machine, error) { return m.get }", byIDFindings},
		{"package-level declaration", "var plantFindExpr = (*Manager).get", byIDFindings},
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
	// A clean plant passes both, so the cases above fail for their shape:
	// a handle's own helper, and a wrapper resolver called before any
	// handle is held.
	f, err := parser.ParseFile(l.Fset, "planted.go", src+"func plantClean(m *Manager, mc *machine) { _ = m.resumeOf(context.Background(), mc) }\nfunc plantCleanLookup(m *Manager, id string) (*machine, error) { return m.get(id) }\nfunc plantCleanWrapped(m *Manager, id string) error { mc, err := plantCleanLookup(m, id); if err != nil { return err }; return m.resumeOf(context.Background(), mc) }\n", 0)
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
