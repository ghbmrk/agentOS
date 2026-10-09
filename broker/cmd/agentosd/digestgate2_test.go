package main

import (
	"fmt"
	"go/ast"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// bootOrder checks main's source order: `go dg.run` comes after the one
// `lp.attach`, so the forget owner's replay reaches the digest before its
// first send (CAP-3, OP-2). Moving the start above the attach compiles and
// passes every behavior test, so the order is pinned here.
func bootOrder(src string) []string {
	f, err := parser.ParseFile(token.NewFileSet(), "main.go", src, 0)
	if err != nil {
		return []string{err.Error()}
	}
	var mainFn *ast.FuncDecl
	for _, d := range f.Decls {
		if fn, ok := d.(*ast.FuncDecl); ok && fn.Recv == nil && fn.Name.Name == "main" {
			mainFn = fn
		}
	}
	if mainFn == nil {
		return []string{"no func main"}
	}
	var attaches, runs []token.Pos
	ast.Inspect(mainFn.Body, func(n ast.Node) bool {
		switch n := n.(type) {
		case *ast.CallExpr:
			if s, ok := n.Fun.(*ast.SelectorExpr); ok && s.Sel.Name == "attach" && isIdent(s.X, "lp") {
				attaches = append(attaches, n.Pos())
			}
		case *ast.GoStmt:
			if s, ok := n.Call.Fun.(*ast.SelectorExpr); ok && s.Sel.Name == "run" && isIdent(s.X, "dg") {
				runs = append(runs, n.Pos())
			}
		}
		return true
	})
	if len(attaches) != 1 || len(runs) != 1 {
		return []string{fmt.Sprintf("main has %d lp.attach and %d go dg.run, want 1 and 1", len(attaches), len(runs))}
	}
	if runs[0] < attaches[0] {
		return []string{"go dg.run starts before lp.attach"}
	}
	return nil
}

// REQ: CAP-3, OP-2
func TestDigestRunStartsAfterTheOwnerAttach(t *testing.T) {
	src, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatal(err)
	}
	if bad := bootOrder(string(src)); len(bad) != 0 {
		t.Fatalf("boot order: %q", bad)
	}
	const pre = "package main\nfunc main() {\n"
	for name, body := range map[string]string{
		"run above attach":  "go dg.run(ctx)\nlp.attach(ctx, d)\n",
		"run above fs":      "go dg.run(ctx)\nfs.attach(ctx, d)\nlp.attach(ctx, d)\n",
		"run dropped":       "lp.attach(ctx, d)\n",
		"attach dropped":    "go dg.run(ctx)\n",
		"run started twice": "lp.attach(ctx, d)\ngo dg.run(ctx)\ngo dg.run(ctx)\n",
	} {
		if len(bootOrder(pre+body+"}\n")) == 0 {
			t.Errorf("%s: not caught", name)
		}
	}
	if bad := bootOrder(pre + "fs.attach(ctx, d)\nlp.attach(ctx, d)\ngo dg.run(ctx)\n}\n"); len(bad) != 0 {
		t.Errorf("the right order is refused: %q", bad)
	}
}

// leakPkgs are the packages whose calls print or encode their arguments.
var leakPkgs = map[string]bool{"fmt": true, "encoding/json": true, "log": true, "log/slog": true}

// holdsBatch reports whether a value of type t can carry a digestqueue
// Batch or Snapshot, by name or through any field, element or pointer.
func holdsBatch(t types.Type, seen map[types.Type]bool) bool {
	if t == nil || seen[t] {
		return false
	}
	seen[t] = true
	switch t := t.(type) {
	case *types.Named:
		if o := t.Obj(); o.Pkg() != nil && strings.HasSuffix(o.Pkg().Path(), "/digestqueue") && (o.Name() == "Batch" || o.Name() == "Snapshot") {
			return true
		}
		return holdsBatch(t.Underlying(), seen)
	case *types.Pointer:
		return holdsBatch(t.Elem(), seen)
	case *types.Slice:
		return holdsBatch(t.Elem(), seen)
	case *types.Array:
		return holdsBatch(t.Elem(), seen)
	case *types.Map:
		return holdsBatch(t.Key(), seen) || holdsBatch(t.Elem(), seen)
	case *types.Struct:
		for i := 0; i < t.NumFields(); i++ {
			if holdsBatch(t.Field(i).Type(), seen) {
				return true
			}
		}
	}
	return false
}

// gateImporter reads the standard library and digestqueue from source and
// gives every other import an empty package; the check needs only the
// types of values that come from digestqueue.
type gateImporter struct{ src types.ImporterFrom }

func (g gateImporter) Import(path string) (*types.Package, error) {
	if !strings.Contains(strings.SplitN(path, "/", 2)[0], ".") || strings.HasSuffix(path, "/digestqueue") {
		return g.src.ImportFrom(path, ".", 0)
	}
	name := path[strings.LastIndex(path, "/")+1:]
	p := types.NewPackage(path, name)
	p.MarkComplete()
	return p, nil
}

// batchLeaks type-checks the agentosd sources (name to source, no tests)
// and reports each call to fmt, encoding/json, log, log/slog or a Logf
// field that takes a value able to carry a Batch or Snapshot: printing one
// would put the snapshots' lines out without the Sender's filters (OP-2).
// A spread argument (args...) is not looked into.
func batchLeaks(srcs map[string]string) []string {
	fset := token.NewFileSet()
	var files []*ast.File
	var names []string
	for n := range srcs {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		f, err := parser.ParseFile(fset, n, srcs[n], 0)
		if err != nil {
			return []string{err.Error()}
		}
		files = append(files, f)
	}
	info := &types.Info{Types: map[ast.Expr]types.TypeAndValue{}, Uses: map[*ast.Ident]types.Object{}}
	conf := types.Config{
		Importer: gateImporter{importer.ForCompiler(fset, "source", nil).(types.ImporterFrom)},
		Error:    func(error) {},
	}
	conf.Check("main", fset, files, info)
	var bad []string
	for _, f := range files {
		ast.Inspect(f, func(n ast.Node) bool {
			c, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			s, ok := c.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			sink := s.Sel.Name == "Logf"
			if o := info.Uses[s.Sel]; o != nil && o.Pkg() != nil && leakPkgs[o.Pkg().Path()] {
				sink = true
			}
			if !sink {
				return true
			}
			for _, a := range c.Args {
				if tv, ok := info.Types[a]; ok && holdsBatch(tv.Type, map[types.Type]bool{}) {
					bad = append(bad, fmt.Sprintf("%s: %s takes a value that holds a batch", fset.Position(a.Pos()), s.Sel.Name))
				}
			}
			return true
		})
	}
	return bad
}

func agentosdSources(t *testing.T) map[string]string {
	t.Helper()
	paths, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	srcs := map[string]string{}
	for _, p := range paths {
		if strings.HasSuffix(p, "_test.go") {
			continue
		}
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		srcs[p] = string(b)
	}
	return srcs
}

// REQ: OP-2
func TestNoBatchValueReachesFmtJSONOrLog(t *testing.T) {
	srcs := agentosdSources(t)
	if bad := batchLeaks(srcs); len(bad) != 0 {
		t.Fatalf("batch to a printer: %q", bad)
	}
	const pre = "package main\nimport (\n\"encoding/json\"\n\"fmt\"\n\"log\"\n\"github.com/ghbmrk/agentos/broker/digestqueue\"\n)\n"
	cases := map[string]string{
		"fmt batch":      "func leak(b digestqueue.Batch) { _ = fmt.Sprintf(\"%v\", b) }\n",
		"fmt snapshot":   "func leak(b digestqueue.Batch) { fmt.Println(b.Snapshots[0]) }\n",
		"json batches":   "func leak(bs []digestqueue.Batch) { json.Marshal(bs) }\n",
		"log pointer":    "func leak(b *digestqueue.Batch) { log.Printf(\"%+v\", b) }\n",
		"logf from list": "func (d *digestBox) leak() { bs, _ := d.q.List(); d.cfg.Logf(\"%v\", bs[0]) }\n",
		"in a struct":    "type w struct{ b digestqueue.Batch }\nfunc leak(x w) { fmt.Sprint(x) }\n",
		"in a map":       "func leak(m map[int]digestqueue.Snapshot) { fmt.Sprint(m) }\n",
	}
	for name, body := range cases {
		mut := map[string]string{"zz_leak.go": pre + body}
		for k, v := range srcs {
			mut[k] = v
		}
		if bad := batchLeaks(mut); len(bad) == 0 {
			t.Errorf("%s: not caught", name)
		}
	}
}
