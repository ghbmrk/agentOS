package vm

// REQ: RES-2

import (
	"bytes"
	"encoding/json"
	"fmt"
	"go/ast"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
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
	fset := token.NewFileSet()
	pkg, files, info := typeCheckVM(t, fset)
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
	for _, f := range files {
		for _, d := range f.Decls {
			fd, ok := d.(*ast.FuncDecl)
			if !ok || fd.Body == nil {
				continue
			}
			name := funcName(fd)
			ast.Inspect(fd.Body, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				s, ok := call.Fun.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				switch s.Sel.Name {
				case "Lock", "TryLock":
					inner, ok := s.X.(*ast.SelectorExpr)
					if !ok {
						return true
					}
					if sl := info.Selections[inner]; sl != nil && sl.Obj() == muField {
						found[name] = append(found[name], fset.Position(call.Pos()).String())
					}
				case "lockEndingExec":
					if sl := info.Selections[s]; sl != nil && sl.Obj() == lockEndingExec {
						found[name] = append(found[name], fset.Position(call.Pos()).String())
					}
				}
				return true
			})
		}
	}

	var bad []string
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

// typeCheckVM type-checks package vm's non-test files against the export
// data go list builds for its imports.
func typeCheckVM(t *testing.T, fset *token.FileSet) (*types.Package, []*ast.File, *types.Info) {
	t.Helper()
	cmd := exec.Command("go", "list", "-export", "-deps", "-json=ImportPath,Dir,Export,GoFiles,DepOnly,Error", ".")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("go list: %v\n%s", err, stderr.String())
	}
	type listed struct {
		ImportPath, Dir, Export string
		GoFiles                 []string
		DepOnly                 bool
		Error                   *struct{ Err string }
	}
	export := map[string]string{}
	var self *listed
	dec := json.NewDecoder(bytes.NewReader(out))
	for {
		var p listed
		if err := dec.Decode(&p); err == io.EOF {
			break
		} else if err != nil {
			t.Fatal(err)
		}
		if p.Error != nil {
			t.Fatalf("go list %s: %s", p.ImportPath, p.Error.Err)
		}
		export[p.ImportPath] = p.Export
		if !p.DepOnly {
			p := p
			self = &p
		}
	}
	if self == nil {
		t.Fatal("go list did not list package vm")
	}
	imp := importer.ForCompiler(fset, "gc", func(path string) (io.ReadCloser, error) {
		e, ok := export[path]
		if !ok || e == "" {
			return nil, fmt.Errorf("no export data for %s", path)
		}
		return os.Open(e)
	})
	var files []*ast.File
	for _, name := range self.GoFiles {
		f, err := parser.ParseFile(fset, filepath.Join(self.Dir, name), nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatal(err)
		}
		files = append(files, f)
	}
	info := &types.Info{Selections: map[*ast.SelectorExpr]*types.Selection{}}
	pkg, err := (&types.Config{Importer: imp}).Check(self.ImportPath, fset, files, info)
	if err != nil {
		t.Fatalf("type-check %s: %v", self.ImportPath, err)
	}
	return pkg, files, info
}
