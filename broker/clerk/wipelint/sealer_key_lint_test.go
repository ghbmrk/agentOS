package wipelint_test

// REQ: CLK-1, STO-2

// The sealer key-wipe lint (LINT-sealer-key-wipe, #6344; by type, #6349).
// A sealing key handed to a sealer constructor is wiped by its caller once
// the constructor returns: the constructor expands the key into its own
// state and keeps no reference, so the caller's copy is the one left in
// memory. A deleted wipe is a statement no package test can observe, so
// the shape is held here, by the build, instead of by review.
//
// The rule runs over every non-test file of broker, testdata included,
// type-checked, whatever the file imports. A sealer constructor is any
// function, method or func type whose results hold a clerk.Sealer, the
// type or its pointer implementing it, found by type alone. Its possible
// keys are the receiver and parameters whose type can hold key bytes
// (keyForm): a byte slice or byte array, named or not, a string, a type
// parameter whose type set holds one, or a type the lint cannot wipe
// (any, a type set without terms, a pointer, slice, map or struct holding
// key bytes). A named constructor with a possible key is listed in
// sealers, naming which of them are keys, or the build fails; a func
// type or literal with one fails outright (no name to list). A listed key
// is a byte slice: a string key cannot be wiped, an array key passes by
// value and leaves the callee an unwiped copy, and a key of any other form
// cannot be wiped by a statement, so each fails the listing, with the
// reason. A call of a listed constructor with keys is the only right-hand
// side of an assignment (`s, err := f(k)`, or =) in a statement list,
// each key argument a local variable, and the statements right after it
// are the builtin `clear(k)` or `defer clear(k)`, one per key. `clear(k)`
// wipes before anything can return; `defer clear(k)` wipes when the
// function returns, on every path, so the key lives until then. Any other use fails: an argument that is an
// expression, a wipe after an error check, a clear of another variable,
// the call in a return, a var declaration, an if header or another call's
// arguments, or the constructor taken as a value. A function listed in
// keyExempt has its calls unheld, the reason given. A listed name that is
// gone fails (stale). A non-test file the load did not read (a build tag,
// cgo; lintload.Unread) fails unless unreadOK lists it with the reason it
// holds no sealer.
//
// Bound: what the code does with the key before the call (a copy kept,
// an early return that skips the wipe), what a constructor does with it
// inside, and _test.go files, whose keys are fixed test bytes, are held
// by review.

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/ghbmrk/agentos/broker/internal/lintload"
)

// sealerKey is one listed sealer constructor: the names of its parameters
// that are sealing keys, wiped by each caller right after the call, and
// what it does with them (or, with no keys, why its possible keys are
// none).
type sealerKey struct {
	keys []string
	why  string
}

// sealers names, by types.Func.FullName, each sealer constructor with a
// possible key. Nothing but review holds an entry.
var sealers = map[string]sealerKey{
	sealerPkg + ".NewAESSealer": {[]string{"key"}, "aes.NewCipher expands the key into its own schedule; the slice is not kept"},
}

// keyExempt names, by types.Func.FullName, each function whose calls of a
// listed constructor are not held, with the reason its key is no secret.
// Nothing but review holds an entry.
var keyExempt = map[string]string{
	// The CI boot probe derives its key from a synthetic clerk root it
	// fills with fixed bytes; it stands in for the kernel's unlock.
	"github.com/ghbmrk/agentos/broker/clerk/devslot/proc/testdata/bootprobe.setUp": "synthetic root key, fixed bytes; CI probe only",
}

// unreadOK names, by path from broker, each file lintload.Unread reports
// (a file this platform compiles only under another tag set or cgo, or a
// non-Go source), with why it holds no sealer and no key. Nothing but
// review holds an entry.
var unreadOK = map[string]string{
	"clerk/devslot/testdata/asmdriver/trap_amd64.s": "assembly test driver; declares no Go type and takes no key",
	"clerk/devslot/testdata/tagdriver/dial.go":      "agentos_box-tagged test driver that dials out; no sealer, no key",
	"cmd/agentos-camdecode/camdecode/h264.go":       "libavcodec cgo decoder; frames in, pictures out, no sealer",
	"cmd/agentos-egress/upstream_e2e.go":            "agentos_e2e-tagged upstream stub; no sealer, no key",
	"cmd/agentos-infer/runtime_llamacpp.go":         "llama.cpp cgo runtime; model weights and text, no sealer",
	"cmd/agentos-vision/runtime_onnx.go":            "onnxruntime cgo runtime; images and sound in, labels out, no sealer",
}

// sealerPkg is the import path of the clerk.Sealer interface.
const sealerPkg = "github.com/ghbmrk/agentos/broker/clerk"

// brokerModule is the broker module's path.
const brokerModule = "github.com/ghbmrk/agentos/broker"

// brokerDir is the broker module root, the tree the rule walks.
const brokerDir = "../.."

// keyLoad loads each package directory of broker holding a non-test .go
// file, testdata included.
var keyLoad = sync.OnceValues(func() (*keyLoaded, error) {
	root, err := filepath.Abs(brokerDir)
	if err != nil {
		return nil, err
	}
	files, err := sources(root)
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
	var sealer *types.Interface
	for _, p := range l.Packages {
		if p.Path == sealerPkg {
			if tn, ok := p.Types.Scope().Lookup("Sealer").(*types.TypeName); ok {
				sealer, _ = tn.Type().Underlying().(*types.Interface)
			}
		}
	}
	if sealer == nil {
		return nil, fmt.Errorf("the load holds no %s.Sealer interface", sealerPkg)
	}
	return &keyLoaded{l, root, sealer}, nil
})

type keyLoaded struct {
	*lintload.Loaded
	root   string
	sealer *types.Interface
}

// sources walks root and returns, sorted, each non-test .go file. A
// directory holding its own go.mod, and vendor, are other modules and are
// skipped.
func sources(root string) ([]string, error) {
	var out []string
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if path == filepath.Join(root, "vendor") {
				return filepath.SkipDir // other modules' code; calls into it are held where they are made
			}
			if path != root {
				if _, err := os.Stat(filepath.Join(path, "go.mod")); err == nil {
					return filepath.SkipDir
				}
			}
			return nil
		}
		if strings.HasSuffix(path, ".go") && !strings.HasSuffix(path, "_test.go") {
			out = append(out, path)
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
			n, ps := keyProblems(l.Fset, f, p.Info, sealers, keyExempt, seen)
			calls += n
			ps = append(ps, constructorProblems(l.Fset, f, p.Info, l.sealer, sealers, brokerModule+"/", seen)...)
			for _, s := range ps {
				problems = append(problems, filepath.ToSlash(rel)+":"+s)
			}
		}
	}
	unread, err := lintload.Unread(l.Loaded)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range unread {
		rel, _ := filepath.Rel(l.root, name)
		rel = filepath.ToSlash(rel)
		if _, ok := unreadOK[rel]; ok {
			seen[rel] = true
			continue
		}
		problems = append(problems, rel+": a build of this platform compiles it under another tag set or cgo, and the load did not read it, so the rule cannot see its sealers; list it in unreadOK with why it holds none")
	}
	// A loader that read nothing would pass every tree: the clerk's mail
	// sign-ins, the four clerk mains and the device-slot boot probe hold
	// seven calls.
	if calls < 7 {
		t.Fatalf("the lint saw %d sealer constructor calls; want the clerk mains among them", calls)
	}
	for name, list := range map[string][]string{"sealers": slices.Collect(mapKeys(sealers)), "keyExempt": slices.Collect(mapKeys(keyExempt)), "unreadOK": slices.Collect(mapKeys(unreadOK))} {
		for _, w := range list {
			if !seen[w] {
				problems = append(problems, name+": "+w+" is no longer in the tree the rule reads as listed; remove the stale entry")
			}
		}
	}
	sort.Strings(problems)
	for _, s := range problems {
		t.Error(s)
	}
}

func mapKeys[V any](m map[string]V) func(func(string) bool) {
	return func(yield func(string) bool) {
		for k := range m {
			if !yield(k) {
				return
			}
		}
	}
}

// keyProblems returns how many uses of a listed constructor with keys the
// file holds and, for each one the rule refuses, its line and why. A
// function listed in exempt is marked in seen, and its own uses are not
// held.
func keyProblems(fset *token.FileSet, f *ast.File, info *types.Info, keys map[string]sealerKey, exempt map[string]string, seen map[string]bool) (int, []string) {
	ok := map[*ast.Ident]bool{}
	called := map[*ast.Ident]bool{}
	line := func(n ast.Node) string { return strconv.Itoa(fset.PositionFor(n.Pos(), false).Line) }
	listed := func(obj types.Object) *sealerKey {
		fn, isFunc := obj.(*types.Func)
		if !isFunc {
			return nil
		}
		if e, in := keys[fn.Origin().FullName()]; in && len(e.keys) > 0 {
			return &e
		}
		return nil
	}
	ast.Inspect(f, func(n ast.Node) bool {
		if fd, isFn := n.(*ast.FuncDecl); isFn {
			if fn, isFunc := info.Defs[fd.Name].(*types.Func); isFunc {
				if _, ex := exempt[fn.FullName()]; ex {
					seen[fn.FullName()] = true
					ast.Inspect(fd, func(n ast.Node) bool {
						if id, isID := n.(*ast.Ident); isID && listed(info.Uses[id]) != nil {
							ok[id] = true
						}
						return true
					})
				}
			}
		}
		if c, isCall := n.(*ast.CallExpr); isCall {
			if id := callee(c); id != nil && listed(info.Uses[id]) != nil {
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
		if !isID || listed(info.Uses[id]) == nil {
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
// =) with f listed, every key argument a local byte slice variable, and
// the statements in rest starting with one builtin clear (or defer clear)
// of each.
func keyedCall(s ast.Stmt, info *types.Info, listed func(types.Object) *sealerKey, rest []ast.Stmt) *ast.Ident {
	a, isAssign := s.(*ast.AssignStmt)
	if !isAssign || len(a.Rhs) != 1 {
		return nil
	}
	c, isCall := ast.Unparen(a.Rhs[0]).(*ast.CallExpr)
	if !isCall || c.Ellipsis.IsValid() {
		return nil
	}
	id := callee(c)
	if id == nil {
		return nil
	}
	entry := listed(info.Uses[id])
	if entry == nil {
		return nil
	}
	// The call's own signature, instantiated: a type parameter key is
	// wiped as the type the caller passes.
	sig, isSig := info.TypeOf(c.Fun).(*types.Signature)
	if !isSig || sig.Variadic() || sig.Params().Len() != len(c.Args) {
		return nil
	}
	want := map[types.Object]bool{}
	for i, arg := range c.Args {
		p := sig.Params().At(i)
		if !slices.Contains(entry.keys, p.Name()) {
			continue
		}
		if keyForm(p.Type()) != formSlice {
			return nil
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

// constructorProblems marks each listed function the file declares or
// uses in seen and returns a problem for each sealer constructor the file
// declares with a possible key that is unlisted, listed with a key that
// cannot be wiped, or nameless, and for each use of an unlisted one with
// a possible key declared outside the tree (import paths under tree),
// such as a vendored module's, whose declaration the rule never reads.
func constructorProblems(fset *token.FileSet, f *ast.File, info *types.Info, sealer *types.Interface, keys map[string]sealerKey, tree string, seen map[string]bool) []string {
	var problems []string
	line := func(n ast.Node) string { return strconv.Itoa(fset.PositionFor(n.Pos(), false).Line) }
	named := func(id *ast.Ident) {
		fn, isFunc := info.Defs[id].(*types.Func)
		if !isFunc {
			return
		}
		name := fn.FullName()
		sig := fn.Type().(*types.Signature)
		entry, listed := keys[name]
		if listed {
			seen[name] = true
		}
		held := possibleKeys(sig)
		if !givesSealer(sig, sealer) {
			if listed {
				problems = append(problems, line(id)+": "+name+" is listed in sealers but makes no sealer; remove the entry")
			}
			return
		}
		if len(held) == 0 && !listed {
			return
		}
		if !listed {
			problems = append(problems, line(id)+": "+name+" makes a sealer from a possible key ("+strings.Join(held.names(), ", ")+"); list it in sealers with which of them are keys (each caller wipes them) and why")
			return
		}
		for _, k := range entry.keys {
			fm, in := held[k]
			switch {
			case !in:
				problems = append(problems, line(id)+": "+name+" lists key "+k+", which is no parameter of it that can hold key bytes")
			case k == recvName(sig):
				problems = append(problems, line(id)+": "+name+" takes its key "+k+" as the receiver, which no call site can wipe; take it as a parameter")
			case fm == formString:
				problems = append(problems, line(id)+": "+name+" takes its key "+k+" as a string, which cannot be wiped; take it as a []byte")
			case fm == formArray:
				problems = append(problems, line(id)+": "+name+" takes its key "+k+" as a byte array, which passes by value and leaves the callee an unwiped copy; take it as a []byte")
			case fm != formSlice:
				problems = append(problems, line(id)+": "+name+" takes its key "+k+" as a type the lint cannot wipe; take it as a []byte")
			}
		}
	}
	owned := map[*ast.FuncType]bool{}
	ast.Inspect(f, func(n ast.Node) bool {
		switch n := n.(type) {
		case *ast.Ident:
			fn, isFunc := info.Uses[n].(*types.Func)
			if !isFunc || fn.Pkg() == nil || strings.HasPrefix(fn.Pkg().Path()+"/", tree) {
				return true
			}
			name := fn.Origin().FullName()
			if _, listed := keys[name]; listed {
				seen[name] = true
				return true
			}
			if sig := fn.Type().(*types.Signature); givesSealer(sig, sealer) && len(possibleKeys(sig)) > 0 {
				problems = append(problems, line(n)+": "+name+", declared outside the tree the rule reads, makes a sealer from a possible key ("+strings.Join(possibleKeys(sig).names(), ", ")+"); list it in sealers with which of them are keys and why")
			}
		case *ast.FuncDecl:
			owned[n.Type] = true
			named(n.Name)
		case *ast.InterfaceType:
			for _, m := range n.Methods.List {
				if ft, isFunc := m.Type.(*ast.FuncType); isFunc && len(m.Names) > 0 {
					owned[ft] = true
					for _, id := range m.Names {
						named(id)
					}
				}
			}
		case *ast.FuncLit:
			owned[n.Type] = true
			if sig, isSig := info.TypeOf(n).(*types.Signature); isSig && givesSealer(sig, sealer) && len(possibleKeys(sig)) > 0 {
				problems = append(problems, line(n)+": a func literal makes a sealer from a possible key; declare it as a function and list it in sealers")
			}
		case *ast.FuncType:
			if owned[n] {
				return true
			}
			if sig, isSig := info.TypeOf(n).(*types.Signature); isSig && givesSealer(sig, sealer) && len(possibleKeys(sig)) > 0 {
				problems = append(problems, line(n)+": a func type makes a sealer from a possible key, and no call through it can be listed; call a listed function instead")
			}
		}
		return true
	})
	return problems
}

// held maps each possible key of a signature, by name, to its form.
type held map[string]form

func (h held) names() []string {
	out := slices.Collect(mapKeys(h))
	sort.Strings(out)
	return out
}

// possibleKeys returns the receiver and parameters of sig whose type can
// hold key bytes, by name (an unnamed one as _N, its position).
func possibleKeys(sig *types.Signature) held {
	h := held{}
	add := func(v *types.Var, i int) {
		if fm := keyForm(v.Type()); fm != formNone {
			name := v.Name()
			if name == "" || name == "_" {
				name = "_" + strconv.Itoa(i)
			}
			h[name] = fm
		}
	}
	if r := sig.Recv(); r != nil {
		add(r, -1)
	}
	for i := range sig.Params().Len() {
		add(sig.Params().At(i), i)
	}
	return h
}

// recvName returns the name of sig's receiver, or "".
func recvName(sig *types.Signature) string {
	if r := sig.Recv(); r != nil && r.Name() != "" && r.Name() != "_" {
		return r.Name()
	}
	return ""
}

// givesSealer reports whether a result of sig is, or implements, the
// sealer interface, as itself or through its pointer.
func givesSealer(sig *types.Signature, sealer *types.Interface) bool {
	for i := range sig.Results().Len() {
		t := sig.Results().At(i).Type()
		if types.Implements(t, sealer) || types.Implements(types.NewPointer(t), sealer) {
			return true
		}
	}
	return false
}

// form is how a key held in a type is wiped.
type form int

const (
	formNone    form = iota // holds no key bytes
	formSlice               // a byte slice, named or not: clear(v)
	formArray               // a byte array, named or not: passes by value, so the callee holds a copy
	formString              // a string: cannot be wiped
	formUnknown             // holds key bytes no statement wipes, or a type the lint cannot read
)

// keyForm returns the form of key a value of type t can hold.
func keyForm(t types.Type) form { return formOf(t, map[types.Type]bool{}) }

func formOf(t types.Type, seen map[types.Type]bool) form {
	if seen[t] {
		return formNone // a cycle holds no bytes the rest of the type does not
	}
	seen[t] = true
	if tp, isTP := t.(*types.TypeParam); isTP {
		iface, _ := tp.Constraint().Underlying().(*types.Interface)
		if iface == nil {
			return formUnknown
		}
		fm, terms := termsForm(iface, seen)
		if !terms {
			return formUnknown // any instantiation, a key among them
		}
		return fm
	}
	holds := func(e types.Type) form {
		if formOf(e, seen) != formNone {
			return formUnknown
		}
		return formNone
	}
	switch u := t.Underlying().(type) {
	case *types.Basic:
		switch {
		case u.Kind() == types.Invalid:
			return formUnknown
		case u.Info()&types.IsString != 0:
			return formString
		}
	case *types.Slice:
		if isByte(u.Elem()) {
			return formSlice
		}
		return holds(u.Elem())
	case *types.Array:
		if isByte(u.Elem()) {
			return formArray
		}
		return holds(u.Elem())
	case *types.Pointer:
		return holds(u.Elem())
	case *types.Map:
		if holds(u.Key()) != formNone {
			return formUnknown
		}
		return holds(u.Elem())
	case *types.Struct:
		for i := range u.NumFields() {
			if holds(u.Field(i).Type()) != formNone {
				return formUnknown
			}
		}
	case *types.Interface:
		if u.NumMethods() == 0 {
			return formUnknown // any value, a key among them
		}
	}
	return formNone
}

// termsForm returns the one form every type term of iface's type set
// holds (a string among them: formString; mixed: formUnknown), and
// whether iface has terms at all.
func termsForm(iface *types.Interface, seen map[types.Type]bool) (form, bool) {
	var forms []form
	terms := false
	var walk func(t types.Type)
	walk = func(t types.Type) {
		switch e := t.(type) {
		case *types.Union:
			for i := range e.Len() {
				walk(e.Term(i).Type())
			}
			return
		}
		if in, isIface := t.Underlying().(*types.Interface); isIface {
			for i := range in.NumEmbeddeds() {
				walk(in.EmbeddedType(i))
			}
			return
		}
		terms = true
		forms = append(forms, formOf(t, seen))
	}
	for i := range iface.NumEmbeddeds() {
		walk(iface.EmbeddedType(i))
	}
	if !terms {
		return formNone, false
	}
	switch {
	case slices.Contains(forms, formString):
		return formString, true
	case !slices.ContainsFunc(forms, func(f form) bool { return f != forms[0] }):
		return forms[0], true
	}
	return formUnknown, true
}

// isByte reports whether t's underlying type is byte.
func isByte(t types.Type) bool {
	b, isBasic := t.Underlying().(*types.Basic)
	return isBasic && b.Kind() == types.Uint8
}

// TestTheKeyLintRefusesEachShape checks the rule on synthetic sources:
// each case is one package (the head below, then the body, unless the
// body is a whole file), and want is the number of problems it has.
// newSealer stands for a listed constructor of two keys and a label,
// newGen for a generic one, newNonce for one listed with no keys.
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
func newGen[K ~[]byte](k K) (clerk.Sealer, error)                      { return nil, nil }
func newNonce(n []byte) (clerk.Sealer, error)                          { return nil, nil }

var _ = errors.New
var sink clerk.Sealer
var pkgKey []byte

`
	listing := map[string]sealerKey{
		sealerPkg + ".NewAESSealer":      {[]string{"key"}, "case"},
		"example.test/p.newSealer":       {[]string{"a", "b"}, "case"},
		"example.test/p.newArr":          {[]string{"k"}, "case"},
		"example.test/p.newGen":          {[]string{"k"}, "case"},
		"example.test/p.newNonce":        {nil, "case: n is a nonce"},
		"example.test/p.newStr":          {[]string{"k"}, "case"},
		"example.test/p.newGenStr":       {[]string{"k"}, "case"},
		"example.test/p.newAny":          {[]string{"k"}, "case"},
		"example.test/p.newPtr":          {[]string{"k"}, "case"},
		"example.test/p.newMissing":      {[]string{"key"}, "case"},
		"example.test/p.notSealer":       {[]string{"k"}, "case"},
		"(example.test/p.rawKey).Sealer": {[]string{"r"}, "case"},
		"example.test/q.NewQ":            {[]string{"k"}, "case"},
	}
	cases := []struct {
		name, body string
		want       int
	}{
		// The accepted forms from #6347.
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
		{"two keys, cleared in either order, the label no key", `func f(a, b []byte) error {
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
		{"an exempt function's calls are not held", `func probe(k []byte) error {
	s, err := clerk.NewAESSealer(k)
	sink = s
	return err
}`, 0},
		{"a sealer from no possible key is no constructor", `func wrap(s clerk.Sealer, n int) clerk.Sealer { return s }`, 0},
		{"a constructor listed with no keys has its calls unheld", `func f(n []byte) error {
	s, err := newNonce(n[:12])
	sink = s
	return err
}`, 0},
		// The refused shapes from #6347.
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
		// Key forms (#6349).
		{"an array key, listed, passes by value", `func newArr(k [32]byte) (clerk.Sealer, error) { return nil, nil }`, 1},
		{"a key cleared through a reslice", `func f(k []byte) error {
	s, err := clerk.NewAESSealer(k)
	clear(k[:])
	sink = s
	return err
}`, 1},
		{"a generic key, cleared as the slice the caller passes", `type key []byte

func f(k key) error {
	s, err := newGen(k)
	clear(k)
	sink = s
	return err
}`, 0},
		{"a generic key not cleared", `func f(k []byte) error {
	s, err := newGen(k)
	sink = s
	return err
}`, 1},
		{"a named byte-slice key, unlisted", `type key []byte

func newNamed(k key) (clerk.Sealer, error) { return nil, nil }`, 1},
		{"an array key, unlisted", `func newA(k [16]byte) (clerk.Sealer, error) { return nil, nil }`, 1},
		{"a string key, unlisted", `func newS(k string) (clerk.Sealer, error) { return nil, nil }`, 1},
		{"a string key, listed, cannot be wiped", `func newStr(k string) (clerk.Sealer, error) { return nil, nil }`, 1},
		{"a generic key that may be a string, listed", `func newGenStr[K ~[]byte | ~string](k K) (clerk.Sealer, error) { return nil, nil }`, 1},
		{"a generic key that may be a string, unlisted", `func newGenS[K ~[]byte | ~string](k K) (clerk.Sealer, error) { return nil, nil }`, 1},
		{"a key of a type the lint cannot resolve, unlisted", `func newA2(k any) (clerk.Sealer, error) { return nil, nil }

func newT[K any](k K) (clerk.Sealer, error) { return nil, nil }`, 2},
		{"a key of a type the lint cannot resolve, listed", `func newAny(k any) (clerk.Sealer, error) { return nil, nil }`, 1},
		{"a key behind a pointer, listed", `func newPtr(k *[32]byte) (clerk.Sealer, error) { return nil, nil }`, 1},
		{"a key in a struct, unlisted", `type config struct {
	name string
	key  []byte
}

func newC(c config) (clerk.Sealer, error) { return nil, nil }`, 1},
		{"a listed key that is no parameter", `func newMissing(k []byte) (clerk.Sealer, error) { return nil, nil }`, 1},
		{"a listed function that makes no sealer", `func notSealer(k []byte) error { return nil }`, 1},
		{"a key receiver, listed", `type rawKey []byte

func (r rawKey) Sealer() (clerk.Sealer, error) { return nil, nil }`, 1},
		{"a key receiver, unlisted", `type rawKey2 []byte

func (r rawKey2) Sealer() (clerk.Sealer, error) { return nil, nil }`, 1},
		{"an interface method from a key, unlisted", `type maker interface {
	New(k []byte) (clerk.Sealer, error)
}`, 1},
		{"a func literal from a key", `func f() {
	mk := func(k []byte) (clerk.Sealer, error) { return nil, nil }
	_ = mk
}`, 1},
		{"a func type from a key", `type maker func(k []byte) (clerk.Sealer, error)`, 1},
		{"a value result whose pointer is the sealer, unlisted", `type vs struct{}

func (*vs) Seal(plain, aad []byte) ([]byte, error) { return nil, nil }
func (*vs) Open(blob, aad []byte) ([]byte, error) { return nil, nil }

func newVS(k []byte) vs { return vs{} }`, 1},
		// A package that does not import clerk: its sealer is found by
		// type, and its callers are held.
		{"a wrapper in a package that does not import clerk", `package q

type qs struct{}

func (qs) Seal(plain, aad []byte) ([]byte, error) { return nil, nil }
func (qs) Open(blob, aad []byte) ([]byte, error) { return nil, nil }

func NewQ(k []byte) (*qs, error) { return &qs{}, nil }

func newQ2(k string) (qs, error) { return qs{}, nil }

func good(k []byte) error {
	s, err := NewQ(k)
	clear(k)
	_ = s
	return err
}

func bad(k []byte) error {
	s, err := NewQ(k)
	_ = s
	return err
}`, 2},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			src, path := head+c.body, "example.test/p"
			if strings.HasPrefix(c.body, "package q") {
				src, path = c.body, "example.test/q"
			}
			f, err := parser.ParseFile(l.Fset, "case.go", src, parser.SkipObjectResolution)
			if err != nil {
				t.Fatal(err)
			}
			_, info, err := l.Check(path, []*ast.File{f})
			if err != nil {
				t.Fatal(err)
			}
			exempt := map[string]string{"example.test/p.probe": "case"}
			_, got := keyProblems(l.Fset, f, info, listing, exempt, map[string]bool{})
			got = append(got, constructorProblems(l.Fset, f, info, l.sealer, listing, "example.test/", map[string]bool{})...)
			if len(got) != c.want {
				t.Fatalf("got %d problems %q; want %d", len(got), got, c.want)
			}
		})
	}
}

// TestTheKeyLintHoldsConstructorsFromOutsideTheTree checks that a use of
// a sealer constructor declared outside the tree, whose declaration the
// rule never reads, fails unlisted: in a synthetic package, clerk stands
// outside the tree.
func TestTheKeyLintHoldsConstructorsFromOutsideTheTree(t *testing.T) {
	l, err := keyLoad()
	if err != nil {
		t.Fatal(err)
	}
	const src = `package p

import "github.com/ghbmrk/agentos/broker/clerk"

var _ = clerk.NewAESSealer
`
	f, err := parser.ParseFile(l.Fset, "outside.go", src, parser.SkipObjectResolution)
	if err != nil {
		t.Fatal(err)
	}
	_, info, err := l.Check("example.test/p", []*ast.File{f})
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		listing map[string]sealerKey
		want    int
	}{
		{map[string]sealerKey{}, 1},
		{map[string]sealerKey{sealerPkg + ".NewAESSealer": {[]string{"key"}, "case"}}, 0},
	} {
		seen := map[string]bool{}
		got := constructorProblems(l.Fset, f, info, l.sealer, c.listing, "example.test/", seen)
		if len(got) != c.want {
			t.Errorf("listing %v: got %d problems %q; want %d", c.listing, len(got), got, c.want)
		}
		if c.want == 0 && !seen[sealerPkg+".NewAESSealer"] {
			t.Errorf("a listed constructor from outside the tree was not marked seen")
		}
	}
}
