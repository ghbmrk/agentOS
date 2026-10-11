package cleanroom

// SR3-8-f2: the durability tests observe the fsyncs themselves. Every sync
// in the package runs through one seam (fileSync, dirSync) that calls the
// fault hook and then the real sync; a recorder in place of the real sync
// sees the calls that ran, so removing one fails a test even while its hook
// call stays.
//
// REQ: OSS-2 (SR3-8-f2)

import (
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
)

// syncRec records the real syncs, in order, as "file <rel>" or
// "dir <rel>", with the stage directory's random name made ".stage".
type syncRec struct {
	mu     sync.Mutex
	root   string
	seen   []string
	at     func(dir string)  // called before each directory sync
	atFile func(path string) // called before each file sync
}

func (r *syncRec) add(kind, path string) {
	rel, err := filepath.Rel(r.root, path)
	if err != nil {
		rel = path
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.seen = append(r.seen, kind+" "+stageName.ReplaceAllString(filepath.ToSlash(rel), ".stage"))
}

func (r *syncRec) list() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.seen...)
}

// recordSyncs puts a recorder in place of the real syncs until the test
// ends. The recorder calls the originals.
func recordSyncs(t *testing.T, root string) *syncRec {
	t.Helper()
	r := &syncRec{root: root}
	file, dir := syncFile, syncDirFn
	syncFile = func(f *os.File) error {
		if r.atFile != nil {
			r.atFile(f.Name())
		}
		r.add("file", f.Name())
		return file(f)
	}
	syncDirFn = func(d string) error {
		if r.at != nil {
			r.at(d)
		}
		r.add("dir", d)
		return dir(d)
	}
	t.Cleanup(func() { syncFile, syncDirFn = file, dir })
	return r
}

// Committing an artifact syncs each file it writes, each directory fill
// created (deepest first, before the manifest), the stage directory after
// the manifest's rename, and the store directory after the commit rename.
func TestCommitMakesRealSyncs(t *testing.T) {
	s, _, err := openStore(filepath.Join(t.TempDir(), "store"))
	if err != nil {
		t.Fatal(err)
	}
	rec := recordSyncs(t, s.dir)
	committed := false
	rec.at = func(d string) {
		if d == s.dir {
			_, err := os.Stat(filepath.Join(s.dir, "a-x"))
			committed = err == nil
		}
	}
	if _, err := s.put(Manifest{ID: "a-x", Job: "x", Output: "skill"}, nestedFiles); err != nil {
		t.Fatal(err)
	}
	seen := rec.list()
	at := func(op string) int {
		i := slices.Index(seen, op)
		if i < 0 {
			t.Fatalf("no %q among the syncs that ran:\n%s", op, strings.Join(seen, "\n"))
		}
		return i
	}
	for p := range nestedFiles {
		at("file .stage/files/" + p)
	}
	manifest := at("file .stage/manifest.json.tmp")
	// Each directory fill created is synced before the manifest is written,
	// and before its parent (deepest first).
	created := []string{".stage", ".stage/files", ".stage/files/skill", ".stage/files/skill/lib", ".stage/files/skill/lib/tz", ".stage/files/skill/tests"}
	for _, d := range created {
		i := at("dir " + d)
		if i > manifest {
			t.Errorf("dir %s synced after the manifest was written", d)
		}
		if parent := filepath.Dir(d); slices.Contains(created, parent) && i > at("dir "+parent) {
			t.Errorf("dir %s synced after its parent", d)
		}
	}
	if i := slices.Index(seen[manifest:], "dir .stage"); i < 0 {
		t.Error("stage directory not synced after the manifest's rename")
	}
	if last := seen[len(seen)-1]; last != "dir ." || !committed {
		t.Errorf("store directory not synced after the commit rename: last %q, committed %v", last, committed)
	}
}

// since returns the syncs recorded after the first n.
func (r *syncRec) since(n int) []string { return r.list()[n:] }

// Quarantine syncs the quarantine directory, then the store directory,
// after the rename that moves the artifact out.
func TestQuarantineMakesRealSyncs(t *testing.T) {
	s, _, err := openStore(filepath.Join(t.TempDir(), "store"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.put(Manifest{ID: "a-x", Job: "x", Output: "skill"}, nestedFiles); err != nil {
		t.Fatal(err)
	}
	rec := recordSyncs(t, s.dir)
	moved := true
	rec.at = func(string) {
		if _, err := os.Stat(filepath.Join(s.dir, "a-x")); err == nil {
			moved = false
		}
	}
	if err := s.quarantine("a-x"); err != nil {
		t.Fatal(err)
	}
	if got, want := rec.list(), []string{"dir .quarantine", "dir ."}; !slices.Equal(got, want) || !moved {
		t.Errorf("quarantine syncs %q (after the rename: %v), want %q after it", got, moved, want)
	}
}

// Settle syncs the store directory, also when the commit's own sync failed
// (errCommittedUnsynced): settle is where the commit becomes durable (C14).
func TestSettleMakesRealSync(t *testing.T) {
	for name, failCommit := range map[string]bool{"synced": false, "unsynced": true} {
		t.Run(name, func(t *testing.T) {
			s, _, err := openStore(filepath.Join(t.TempDir(), "store"))
			if err != nil {
				t.Fatal(err)
			}
			rec := recordSyncs(t, s.dir)
			if failCommit {
				s.fault = func(op, path string) error {
					if op == "syncdir" && path == s.dir {
						return errors.New("synthetic sync failure")
					}
					return nil
				}
			}
			_, err = s.put(Manifest{ID: "a-x", Job: "x", Output: "skill"}, nestedFiles)
			if failCommit != errors.Is(err, errCommittedUnsynced) || (!failCommit && err != nil) {
				t.Fatalf("put: %v", err)
			}
			s.fault = nil
			n := len(rec.list())
			if err := s.settle("a-x"); err != nil {
				t.Fatal(err)
			}
			if got := rec.since(n); !slices.Equal(got, []string{"dir ."}) {
				t.Errorf("settle syncs %q, want [dir .]", got)
			}
		})
	}
}

// The real syncs are made only inside the seam: no function calls File.Sync
// or package durable (whose renames would skip the hook), and syncFile and
// syncDirFn are called only from fileSync and dirSync. A durable write anywhere else
// would skip the hook, and so the recorder above. The "sync" and "syncdir"
// hooks are called only there too, so no hook stands in for a sync that
// is not made.
func TestSyncsOnlyThroughSeam(t *testing.T) {
	allowed := map[string]string{"Sync": "", "durable": "", "syncFile": "fileSync", "syncDirFn": "dirSync"}
	fset := token.NewFileSet()
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, d := range f.Decls {
			fn, ok := d.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				if op, ok := syncHit(n); ok && fn.Name.Name != map[string]string{"sync": "fileSync", "syncdir": "dirSync"}[op] {
					t.Errorf("%s: hit(%q) in %s, outside the sync seam: a hook with no sync behind it", fset.Position(n.Pos()), op, fn.Name.Name)
				}
				id, ok := n.(*ast.Ident)
				if !ok {
					return true
				}
				if in, ok := allowed[id.Name]; ok && fn.Name.Name != in {
					t.Errorf("%s: %s used in %s, outside the sync seam", fset.Position(id.Pos()), id.Name, fn.Name.Name)
				}
				return true
			})
		}
	}
}

// syncHit reports whether n is a hit call whose op is "sync" or "syncdir".
func syncHit(n ast.Node) (string, bool) {
	call, ok := n.(*ast.CallExpr)
	if !ok || len(call.Args) == 0 {
		return "", false
	}
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != "hit" {
		return "", false
	}
	lit, ok := call.Args[0].(*ast.BasicLit)
	if !ok || lit.Kind != token.STRING {
		return "", false
	}
	op := strings.Trim(lit.Value, "`\"")
	return op, op == "sync" || op == "syncdir"
}
