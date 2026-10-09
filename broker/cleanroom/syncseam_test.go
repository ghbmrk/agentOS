package cleanroom

// SR3-8-f2: the durability tests observe the fsyncs themselves. Every sync
// in the package runs through one seam (fileSync, dirSync) that calls the
// fault hook and then the real sync; a recorder in place of the real sync
// sees the calls that ran, so removing one fails a test even while its hook
// call stays.
//
// REQ: OSS-2 (SR3-8-f2)

import (
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
	mu   sync.Mutex
	root string
	seen []string
	at   func(dir string) // called before each directory sync
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

// The real syncs are made only inside the seam: syncDir (the directory
// sync) is the only caller of File.Sync, and syncFile and syncDirFn are
// called only from fileSync and dirSync. A durable write anywhere else
// would skip the hook, and so the recorder above.
func TestSyncsOnlyThroughSeam(t *testing.T) {
	allowed := map[string]string{"Sync": "syncDir", "syncDir": "", "syncFile": "fileSync", "syncDirFn": "dirSync"}
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
