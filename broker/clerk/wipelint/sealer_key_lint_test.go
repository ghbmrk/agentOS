package wipelint_test

// REQ: CLK-1, STO-2

// The sealer key-wipe lint (LINT-sealer-key-wipe, #6344). A sealing key
// handed to a sealer constructor is wiped by its caller once the
// constructor returns: the constructor expands the key into its own state
// and keeps no reference, so the caller's slice is the copy left in
// memory. A deleted wipe is a statement no package test can observe, so
// the shape is held here, by the build, instead of by review.
//
// The rule, over every non-test file in broker that imports a listed
// constructor's package (or is in it), testdata included, type-checked: a
// call of a function listed in sealerKeys is the only right-hand side of
// an assignment (`s, err := clerk.NewAESSealer(k)`, or =) that sits in a
// statement list, each []byte argument is a local variable, and the
// statements right after it are `clear(v)` or `defer clear(v)` with the
// builtin clear, one for each such argument, so the wipe runs before
// anything can return. Any other use fails: an argument that is an
// expression (a reslice, a call, a field), a wipe after an error check, a
// clear of another variable, the call in a return, a var declaration, an
// if header or another call's arguments, or the constructor taken as a
// value. A function listed in keyExempt has its calls unheld, the reason
// given (its key is no secret). A function whose results hold a clerk.Sealer and whose
// parameters include a byte slice must be listed in sealerKeys or in
// sealerNotKey (with the reason its slice is no key), so a new
// constructor fails until a reviewed PR lists it; a listed name that is
// gone fails too (stale). A file of those packages that the load did not
// read (a build tag, an ignored file) fails, so no call hides from it.
//
// Bound: what the code does with the key before the call (a copy kept,
// an early return that skips the wipe) is held by review, as are callers
// in a package that does not import the constructor's package (none can
// name it) and _test.go files, whose keys are fixed test bytes.

import (
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/ghbmrk/agentos/broker/internal/lintload"
)

// sealerKeys names, by types.Func.FullName, each constructor that takes a
// sealing key as a byte slice and keeps no reference to it, with what it
// does with the key. Each []byte argument of a call is a key its caller
// wipes right after the call.
var sealerKeys = map[string]string{
	"github.com/ghbmrk/agentos/broker/clerk.NewAESSealer": "aes.NewCipher expands the key into its own schedule; the slice is not kept",
}

// sealerNotKey names, by types.Func.FullName, each function whose results
// hold a clerk.Sealer and whose parameters include a byte slice that is no
// key, with the reason. Nothing but review holds an entry.
var sealerNotKey = map[string]string{}

// keyExempt names, by types.Func.FullName, each function whose calls of a
// listed constructor are not held, with the reason its key is no secret.
// Nothing but review holds an entry.
var keyExempt = map[string]string{
	// The CI boot probe derives its key from a synthetic clerk root it
	// fills with fixed bytes; it stands in for the kernel's unlock.
	"github.com/ghbmrk/agentos/broker/clerk/devslot/proc/testdata/bootprobe.setUp": "synthetic root key, fixed bytes; CI probe only",
}

// sealerPkg is the import path of the clerk.Sealer interface.
const sealerPkg = "github.com/ghbmrk/agentos/broker/clerk"

// brokerDir is the broker module root, the tree the rule walks.
const brokerDir = "../.."

// keyLoad loads each package directory of broker whose non-test files
// import sealerPkg, sealerPkg's own included, testdata included, and
// returns the non-test files it walked there.
var keyLoad = sync.OnceValues(func() (*keyLoaded, error) {
	root, err := filepath.Abs(brokerDir)
	if err != nil {
		return nil, err
	}
	files, err := importers(root, sealerPkg)
	if err != nil {
		return nil, err
	}
	dirs := map[string]bool{}
	for _, f := range files {
		dirs[filepath.Dir(f)] = true
	}
	var patterns []string
	for d := range dirs {
		rel, err := filepath.Rel(root, d)
		if err != nil {
			return nil, err
		}
		patterns = append(patterns, "./"+filepath.ToSlash(rel))
	}
	sort.Strings(patterns)
	l, err := lintload.Load(root, lintload.Build{}, patterns...)
	if err != nil {
		return nil, err
	}
	return &keyLoaded{l, root, files}, nil
})

type keyLoaded struct {
	*lintload.Loaded
	root  string
	files []string // every non-test .go file walked that imports sealerPkg, or is in it
}

// importers walks root and returns, sorted, each non-test .go file that
// imports pkg or sits in pkg's own directory. A directory holding its own
// go.mod is another module and is skipped.
func importers(root, pkg string) ([]string, error) {
	own := filepath.Join(root, strings.TrimPrefix(pkg, "github.com/ghbmrk/agentos/broker/"))
	fset := token.NewFileSet()
	var out []string
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if path != root {
				if _, err := os.Stat(filepath.Join(path, "go.mod")); err == nil {
					return filepath.SkipDir
				}
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		if filepath.Dir(path) == own {
			out = append(out, path)
			return nil
		}
		f, err := parser.ParseFile(fset, path, nil, parser.ImportsOnly)
		if err != nil {
			return err
		}
		for _, im := range f.Imports {
			if p, err := strconv.Unquote(im.Path.Value); err == nil && p == pkg {
				out = append(out, path)
				break
			}
		}
		return nil
	})
	sort.Strings(out)
	return out, err
}

// TestEverySealingKeyIsWipedRightAfterItsSealer runs the rule over the tree.
func TestEverySealingKeyIsWipedRightAfterItsSealer(t *testing.T) {
	l, err := keyLoad()
	if err != nil {
		t.Fatal(err)
	}
	var sealer *types.Interface
	for _, p := range l.Packages {
		if p.Path == sealerPkg {
			if tn, ok := p.Types.Scope().Lookup("Sealer").(*types.TypeName); ok {
				sealer, _ = tn.Type().Underlying().(*types.Interface)
			}
		}
	}
	if sealer == nil {
		t.Fatalf("the load holds no %s.Sealer interface", sealerPkg)
	}
	var problems []string
	read := map[string]bool{}
	seen := map[string]bool{}
	calls := 0
	for _, p := range l.Packages {
		for _, f := range p.Files {
			name := l.Fset.File(f.Pos()).Name()
			read[name] = true
			if strings.HasSuffix(name, "_test.go") {
				continue
			}
			rel, err := filepath.Rel(l.root, name)
			if err != nil {
				rel = name
			}
			n, ps := keyProblems(l.Fset, f, p.Info, sealerKeys, keyExempt, seen)
			calls += n
			ps = append(ps, constructorProblems(l.Fset, f, p.Info, sealer, sealerKeys, sealerNotKey, seen)...)
			for _, s := range ps {
				problems = append(problems, filepath.ToSlash(rel)+":"+s)
			}
		}
	}
	for _, name := range l.files {
		if !read[name] {
			rel, _ := filepath.Rel(l.root, name)
			problems = append(problems, filepath.ToSlash(rel)+": imports "+sealerPkg+" but no build here reads it; the rule cannot see its calls")
		}
	}
	// A loader that read nothing would pass every tree: the clerk's mail
	// sign-ins, the four clerk mains and the device-slot boot probe hold
	// seven calls.
	if calls < 7 {
		t.Fatalf("the lint saw %d sealer constructor calls; want the clerk mains among them", calls)
	}
	for name, list := range map[string]map[string]string{"sealerKeys": sealerKeys, "sealerNotKey": sealerNotKey, "keyExempt": keyExempt} {
		for w := range list {
			if !seen[w] {
				problems = append(problems, name+": "+w+" is no function in the tree the rule reads any more; remove the stale entry")
			}
		}
	}
	sort.Strings(problems)
	for _, s := range problems {
		t.Error(s)
	}
}

// keyProblems returns how many uses of a listed constructor the file
// holds and, for each one the rule refuses, its line and why. A function
// listed in exempt is marked in seen, and its own uses are not held.
func keyProblems(fset *token.FileSet, f *ast.File, info *types.Info, keys, exempt map[string]string, seen map[string]bool) (int, []string) {
	ok := map[*ast.Ident]bool{}
	called := map[*ast.Ident]bool{}
	line := func(n ast.Node) string { return strconv.Itoa(fset.PositionFor(n.Pos(), false).Line) }
	listed := func(obj types.Object) bool {
		fn, isFunc := obj.(*types.Func)
		if !isFunc {
			return false
		}
		_, in := keys[fn.FullName()]
		return in
	}
	ast.Inspect(f, func(n ast.Node) bool {
		if fd, isFn := n.(*ast.FuncDecl); isFn {
			if fn, isFunc := info.Defs[fd.Name].(*types.Func); isFunc {
				if _, ex := exempt[fn.FullName()]; ex {
					seen[fn.FullName()] = true
					ast.Inspect(fd, func(n ast.Node) bool {
						if id, isID := n.(*ast.Ident); isID && listed(info.Uses[id]) {
							ok[id] = true
						}
						return true
					})
				}
			}
		}
		if c, isCall := n.(*ast.CallExpr); isCall {
			if id := callee(c); id != nil && listed(info.Uses[id]) {
				called[id] = true
			}
		}
		var list []ast.Stmt
		switch b := n.(type) {
		case *ast.BlockStmt:
			list = b.List
		case *ast.CaseClause:
			list = b.Body
		case *ast.CommClause:
			list = b.Body
		}
		for i, s := range list {
			if id := keyedCall(s, info, listed, list[i+1:]); id != nil {
				ok[id] = true
			}
		}
		return true
	})
	uses := 0
	var problems []string
	ast.Inspect(f, func(n ast.Node) bool {
		id, isID := n.(*ast.Ident)
		if !isID || !listed(info.Uses[id]) {
			return true
		}
		uses++
		switch {
		case ok[id]:
		case !called[id]:
			problems = append(problems, line(id)+": "+id.Name+" taken as a value; call it and clear its key right after")
		default:
			problems = append(problems, line(id)+": "+id.Name+"'s key is not wiped right after the call; write `s, err := "+id.Name+"(k)` then `clear(k)` (or `defer clear(k)`) as the next statement, with k a local variable")
		}
		return true
	})
	return uses, problems
}

// keyedCall returns the listed callee of s when s is `a, b := f(k)` (or
// =) with f listed, every []byte argument a local variable, and the
// statements in rest starting with one builtin clear (or defer clear) of
// each such argument.
func keyedCall(s ast.Stmt, info *types.Info, listed func(types.Object) bool, rest []ast.Stmt) *ast.Ident {
	a, isAssign := s.(*ast.AssignStmt)
	if !isAssign || len(a.Rhs) != 1 {
		return nil
	}
	c, isCall := ast.Unparen(a.Rhs[0]).(*ast.CallExpr)
	if !isCall || c.Ellipsis.IsValid() {
		return nil
	}
	id := callee(c)
	if id == nil || !listed(info.Uses[id]) {
		return nil
	}
	sig, isSig := info.Uses[id].Type().(*types.Signature)
	if !isSig || sig.Variadic() || sig.Params().Len() != len(c.Args) {
		return nil
	}
	want := map[types.Object]bool{}
	for i, arg := range c.Args {
		if !isByteSlice(sig.Params().At(i).Type()) {
			continue
		}
		v, isID := ast.Unparen(arg).(*ast.Ident)
		if !isID {
			return nil
		}
		obj, isVar := info.Uses[v].(*types.Var)
		if !isVar || obj.IsField() || obj.Parent() == nil || obj.Parent() == obj.Pkg().Scope() {
			return nil
		}
		want[obj] = true
	}
	if len(want) == 0 || len(rest) < len(want) {
		return nil
	}
	for _, r := range rest[:len(want)] {
		obj := clearOf(r, info)
		if obj == nil || !want[obj] {
			return nil
		}
		delete(want, obj)
	}
	if len(want) != 0 {
		return nil
	}
	return id
}

// clearOf returns the variable s wipes when s is `clear(v)` or `defer
// clear(v)` with the builtin clear, else nil.
func clearOf(s ast.Stmt, info *types.Info) types.Object {
	var c *ast.CallExpr
	switch s := s.(type) {
	case *ast.ExprStmt:
		c, _ = ast.Unparen(s.X).(*ast.CallExpr)
	case *ast.DeferStmt:
		c = s.Call
	}
	if c == nil || len(c.Args) != 1 {
		return nil
	}
	fn, isID := ast.Unparen(c.Fun).(*ast.Ident)
	if !isID || fn.Name != "clear" {
		return nil
	}
	if _, builtin := info.Uses[fn].(*types.Builtin); !builtin {
		return nil
	}
	v, isID := ast.Unparen(c.Args[0]).(*ast.Ident)
	if !isID {
		return nil
	}
	return info.Uses[v]
}

// constructorProblems marks each listed function the file declares in
// seen and returns a problem for each declared function whose results
// hold a sealer and whose parameters include a byte slice, unlisted.
func constructorProblems(fset *token.FileSet, f *ast.File, info *types.Info, sealer *types.Interface, keys, notKey map[string]string, seen map[string]bool) []string {
	var problems []string
	for _, decl := range f.Decls {
		fd, isFn := decl.(*ast.FuncDecl)
		if !isFn {
			continue
		}
		fn, isFunc := info.Defs[fd.Name].(*types.Func)
		if !isFunc {
			continue
		}
		name := fn.FullName()
		_, k := keys[name]
		_, nk := notKey[name]
		if k || nk {
			seen[name] = true
			continue
		}
		sig := fn.Type().(*types.Signature)
		if !takesBytes(sig) || !givesSealer(sig, sealer) {
			continue
		}
		problems = append(problems, strconv.Itoa(fset.PositionFor(fd.Pos(), false).Line)+": "+name+" makes a sealer from a byte slice; list it in sealerKeys (its key is wiped by each caller) or sealerNotKey (with why the slice is no key)")
	}
	return problems
}

// takesBytes reports whether a parameter of sig is a byte slice.
func takesBytes(sig *types.Signature) bool {
	for i := range sig.Params().Len() {
		if isByteSlice(sig.Params().At(i).Type()) {
			return true
		}
	}
	return false
}

// givesSealer reports whether a result of sig is, or implements, the
// sealer interface.
func givesSealer(sig *types.Signature, sealer *types.Interface) bool {
	for i := range sig.Results().Len() {
		t := sig.Results().At(i).Type()
		if types.Implements(t, sealer) || types.Implements(types.NewPointer(t), sealer) {
			return true
		}
	}
	return false
}

// isByteSlice reports whether t's underlying type is []byte.
func isByteSlice(t types.Type) bool {
	return types.Identical(t.Underlying(), types.NewSlice(types.Typ[types.Byte]))
}

// TestTheKeyLintRefusesEachShape checks the rule on synthetic sources:
// each case is one function body, and want is the number of problems it
// has. newSealer stands for a listed constructor of two keys.
func TestTheKeyLintRefusesEachShape(t *testing.T) {
	l, err := keyLoad()
	if err != nil {
		t.Fatal(err)
	}
	const head = `package p

import (
	"errors"

	"github.com/ghbmrk/agentos/broker/clerk"
)

func newSealer(a []byte, label string, b []byte) (clerk.Sealer, error) { return nil, nil }

var _ = errors.New
var sink clerk.Sealer
var pkgKey []byte

`
	cases := []struct {
		name, body string
		want       int
	}{
		{"clear right after the call", `func f() error {
	k := make([]byte, 32)
	s, err := clerk.NewAESSealer(k)
	// a comment between is no statement
	clear(k)
	if err != nil {
		return err
	}
	sink = s
	return nil
}`, 0},
		{"defer clear right after the call", `func f(k []byte) (err error) {
	sink, err = clerk.NewAESSealer(k)
	defer clear(k)
	return err
}`, 0},
		{"two keys, cleared in either order", `func f(a, b []byte) error {
	s, err := newSealer(a, "x", b)
	clear(b)
	defer clear(a)
	sink = s
	return err
}`, 0},
		{"in a closure and a switch case", `func f(k []byte, n int) {
	go func() {
		s, _ := clerk.NewAESSealer(k)
		clear(k)
		sink = s
	}()
	switch n {
	case 1:
		s, _ := clerk.NewAESSealer(k)
		defer clear(k)
		sink = s
	}
}`, 0},
		{"no clear", `func f(k []byte) error {
	s, err := clerk.NewAESSealer(k)
	sink = s
	return err
}`, 1},
		{"clear after the error check", `func f(k []byte) error {
	s, err := clerk.NewAESSealer(k)
	if err != nil {
		return err
	}
	clear(k)
	sink = s
	return nil
}`, 1},
		{"clear of another variable", `func f(k, other []byte) error {
	s, err := clerk.NewAESSealer(k)
	clear(other)
	sink = s
	return err
}`, 1},
		{"one of two keys cleared", `func f(a, b []byte) error {
	s, err := newSealer(a, "x", b)
	clear(a)
	sink = s
	return err
}`, 1},
		{"one key cleared twice", `func f(a, b []byte) error {
	s, err := newSealer(a, "x", b)
	clear(a)
	clear(a)
	clear(b)
	sink = s
	return err
}`, 1},
		{"a clear that is not the builtin", `func clear(b []byte) {}

func f(k []byte) error {
	s, err := clerk.NewAESSealer(k)
	clear(k)
	sink = s
	return err
}`, 1},
		{"a key that is a reslice", `func f(k []byte) error {
	s, err := clerk.NewAESSealer(k[:32])
	clear(k)
	sink = s
	return err
}`, 1},
		{"a key that is a call", `func key() []byte { return make([]byte, 32) }

func f() error {
	s, err := clerk.NewAESSealer(key())
	sink = s
	return err
}`, 1},
		{"a key that is a field", `type box struct{ k []byte }

func f(b box) error {
	s, err := clerk.NewAESSealer(b.k)
	clear(b.k)
	sink = s
	return err
}`, 1},
		{"a key that is a package variable", `func f() error {
	s, err := clerk.NewAESSealer(pkgKey)
	clear(pkgKey)
	sink = s
	return err
}`, 1},
		{"the call returned on, by an unlisted constructor", `func f(k []byte) (clerk.Sealer, error) {
	return clerk.NewAESSealer(k)
}`, 2},
		{"the call in a var declaration", `func f(k []byte) error {
	var s, err = clerk.NewAESSealer(k)
	clear(k)
	sink = s
	return err
}`, 1},
		{"the call in an if header", `func f(k []byte) error {
	if s, err := clerk.NewAESSealer(k); err != nil {
		return err
	} else {
		sink = s
	}
	clear(k)
	return nil
}`, 1},
		{"the call passed straight on", `func use(s clerk.Sealer, err error) {}

func f(k []byte) {
	use(clerk.NewAESSealer(k))
	clear(k)
}`, 1},
		{"the constructor taken as a value", `func f(k []byte) error {
	mk := clerk.NewAESSealer
	s, err := mk(k)
	clear(k)
	sink = s
	return err
}`, 1},
		{"an unlisted constructor from a byte slice", `type own struct{}

func (own) Seal(plain, aad []byte) ([]byte, error) { return nil, nil }
func (own) Open(blob, aad []byte) ([]byte, error) { return nil, nil }

func newOwn(key []byte) (*own, error) { return &own{}, nil }`, 1},
		{"an exempt function's calls are not held", `func probe(k []byte) error {
	s, err := clerk.NewAESSealer(k)
	sink = s
	return err
}`, 0},
		{"a sealer from no byte slice is no constructor", `func wrap(s clerk.Sealer, name string) clerk.Sealer { return s }`, 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f, err := parser.ParseFile(l.Fset, "case.go", head+c.body, parser.SkipObjectResolution)
			if err != nil {
				t.Fatal(err)
			}
			pkg, info, err := l.Check("example.test/p", []*ast.File{f})
			if err != nil {
				t.Fatal(err)
			}
			sealer := pkg.Imports()[0]
			for _, im := range pkg.Imports() {
				if im.Path() == sealerPkg {
					sealer = im
				}
			}
			iface := sealer.Scope().Lookup("Sealer").Type().Underlying().(*types.Interface)
			keys := map[string]string{sealerPkg + ".NewAESSealer": "case", "example.test/p.newSealer": "case"}
			exempt := map[string]string{"example.test/p.probe": "case"}
			_, got := keyProblems(l.Fset, f, info, keys, exempt, map[string]bool{})
			got = append(got, constructorProblems(l.Fset, f, info, iface, keys, map[string]string{}, map[string]bool{})...)
			if len(got) != c.want {
				t.Fatalf("got %d problems %q; want %d", len(got), got, c.want)
			}
		})
	}
}
