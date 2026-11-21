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
// function, method or func type whose results hold a clerk.Sealer (a type
// that, or whose pointer, implements it, anywhere inside a result: a
// field, pointer, slice, map, channel or func result), found by type
// alone. Its possible keys are the receiver and parameters whose type can
// hold or produce key bytes (keyForm): a byte slice or byte array, named
// or not, a string, a type parameter whose type set holds one, or a type
// the lint cannot wipe (an interface, func, channel, uintptr or
// unsafe.Pointer, a type set without terms, a pointer, slice, map or
// struct holding key bytes). A named constructor with a possible key is
// listed in sealers, classifying each as a key or not, or the build fails
// (and fails again when its possible keys change); a
// func type or literal with one fails outright (no name to list). A listed
// key is a byte slice: a string key cannot be wiped, an array key passes
// by value and leaves the callee an unwiped copy, and a key of any other
// form cannot be wiped by a statement, so each fails the listing, with the
// reason. A call of a listed constructor with keys is the only right-hand
// side of an assignment (`s, err := f(k)`, or =) in a statement list, each
// key argument a local variable, and the statements right after it are the
// builtin `clear(k)`, one per key, so the key is wiped straight after its
// last use, before anything can return (#6383). `defer clear(k)` fails: it
// wipes only when the function returns, so the key stays live through the
// rest of the function, a serve loop's whole life included. Any other use
// fails: an argument that is an expression, a wipe after an error check, a
// clear of another variable, the call in a return, a var declaration, an
// if header or another call's arguments, or the constructor taken as a
// value. A function listed in keyExempt has its calls unheld, the reason
// given. A listed name that is gone fails (stale). A non-test file the
// load did not read (a build tag, cgo; lintload.Unread) fails unless
// unreadOK lists it with the reason it holds no sealer.
//
// A sealer may also come into being with no call: a conversion to a
// sealer type, or a composite literal of one, from a possible key fails
// outside the body of a listed constructor with keys. A function declared
// to return an interface (any) that returns a value holding a sealer
// counts as making one.
//
// The body of a listed constructor with keys, declared in the tree, is
// held too (#6383): it keeps, copies, builds and derives no key, so the
// caller's wipe is the only one owed. Each key parameter appears only as
// the operand of len or cap, or as an argument of a function listed in
// keyUses (one that keeps no reference to the slice and returns no key
// bytes), and never inside a func literal; and no other expression in the
// body has a type that holds bytes (bytesIn: a byte slice, byte array or
// string that is not a constant, or a pointer, struct, array, slice or map
// holding one), the parameters the entry classifies as not keys aside. A
// copy kept, a reslice, a conversion, a key drawn or derived inside, or a
// sealer literal holding bytes, directly or behind a pointer or field,
// each fail.
//
// Bound, held by review: what the code does with the key before the call
// (a copy kept, `string(k)`, an early return that skips the wipe); what a
// keyUses function does inside; key bytes a listed body carries inside an
// interface, func or channel value; a key stored into a sealer after it
// is made (a field assignment, an append, a channel send); a sealer
// reached through reflect or unsafe; and _test.go files, whose keys are
// fixed test bytes.

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

// sealerKey is one listed sealer constructor: each of its possible keys
// (possibleKeys) by name, classified as a key or not, and why. The rule
// fails when the signature's possible keys differ from the classified
// set, so a parameter added later is held until a review classifies it.
// classified returns the names the entry classifies, sorted.
func (e sealerKey) classified() []string {
	out := append(slices.Clone(e.keys), e.not...)
	sort.Strings(out)
	return out
}

type sealerKey struct {
	keys []string // its keys, each wiped by every caller right after the call
	not  []string // its other possible keys, none a key, for the reason in why
	why  string
}

// sealers names, by types.Func.FullName, each sealer constructor with a
// possible key. Nothing but review holds an entry.
var sealers = map[string]sealerKey{
	sealerPkg + ".NewAESSealer": {[]string{"key"}, nil, "aes.NewCipher expands the key into its own schedule; the slice is not kept"},

	// Constructors of things that hold a sealer, whose possible keys
	// (paths, configs, built sealers, sealed stores, write funcs) are none.
	"github.com/ghbmrk/agentos/broker/clerk.NewAPI":                          {nil, []string{"d", "roots", "secrets"}, "the declaration, the store of sealed secrets and the trust roots hold no sealing key"},
	"github.com/ghbmrk/agentos/broker/clerk.NewExit":                         {nil, []string{"anchors", "d", "roots", "secrets"}, "the declaration, the anchors' public keys, the sealed store and the trust roots hold no sealing key"},
	"github.com/ghbmrk/agentos/broker/clerk.NewSignIn":                       {nil, []string{"d", "roots", "secrets"}, "the declaration, the sealed store and the trust roots hold no sealing key"},
	"github.com/ghbmrk/agentos/broker/clerk.NewSecrets":                      {nil, []string{"s", "write"}, "s is a built sealer and write takes sealed bytes; the key was wiped where s was made"},
	"github.com/ghbmrk/agentos/broker/clerk/inbox.OpenGmail":                 {nil, []string{"base", "grant", "guard", "roots", "token"}, "base and token name the account, grant is sealed into the store it builds, and its sealing key is drawn and wiped inside"},
	"github.com/ghbmrk/agentos/broker/clerk/inbox.NewGmail":                  {nil, []string{"api"}, "api is a built exit; no key"},
	"(*github.com/ghbmrk/agentos/broker/clerk/inbox.Gmail).WithPoster":       {nil, []string{"g", "guard"}, "the mailbox and its network policy; no key"},
	"github.com/ghbmrk/agentos/broker/clerk/line.New":                        {nil, []string{"cfg"}, "the config holds the account's addresses and paths, no sealing key"},
	"(*github.com/ghbmrk/agentos/broker/clerk/line.Clerk).Account":           {nil, []string{"c"}, "returns the clerk's account; no key"},
	"github.com/ghbmrk/agentos/broker/clerk/line.NewSigner":                  {nil, []string{"c"}, "c is a built clerk; no key"},
	"github.com/ghbmrk/agentos/broker/clerk/model.NewAPIs":                   {nil, []string{"decls", "guard", "keys", "roots"}, "declarations, the sealed key store, the network policy and trust roots hold no sealing key"},
	"github.com/ghbmrk/agentos/broker/clerk/model.NewKeys":                   {nil, []string{"s", "write"}, "s is a built sealer and write takes sealed bytes"},
	"github.com/ghbmrk/agentos/broker/clerk/plan.New":                        {nil, []string{"d", "roots", "store"}, "the declaration, the sealed store and trust roots hold no sealing key"},
	"github.com/ghbmrk/agentos/broker/clerk/plan.NewStore":                   {nil, []string{"s", "write"}, "s is a built sealer and write takes sealed bytes"},
	"github.com/ghbmrk/agentos/broker/clerk/run.OpenExit":                    {nil, []string{"anchors", "d", "dir", "roots", "s"}, "dir is a path, s a built sealer, the rest declaration, public anchors and trust roots"},
	"github.com/ghbmrk/agentos/broker/clerk/run.NewExitHost":                 {nil, []string{"anchors", "d", "x"}, "a built exit, its declaration and public anchors; no key"},
	"(*github.com/ghbmrk/agentos/broker/clerk/run.MailHost).heldGmailSignIn": {nil, []string{"h", "hint", "slot"}, "slot and hint name the account; no key"},
	"(*github.com/ghbmrk/agentos/broker/clerk/run.MailHost).newGmailSignIn":  {nil, []string{"h", "hint", "sec", "slot"}, "the sealed store and the account's slot and hint; no key"},
	"(*github.com/ghbmrk/agentos/broker/clerk/run.MailHost).ownGmailSignIn":  {nil, []string{"h"}, "the host alone; its own sealing key is drawn and wiped inside"},
	"github.com/ghbmrk/agentos/broker/clerk/run.gmailBox":                    {nil, []string{"c", "sec", "slot"}, "the sealed store, the account's slot and the mail config; no key"},
	"github.com/ghbmrk/agentos/broker/clerk/run.NewMailHost":                 {nil, []string{"cfg", "ctx", "dir", "sec"}, "ctx, a path, the sealed store and the mail config; no key"},
	"github.com/ghbmrk/agentos/broker/clerk/run.OpenSecrets":                 {nil, []string{"dir", "s"}, "dir is a path and s a built sealer"},
	"github.com/ghbmrk/agentos/broker/clerk/run.openSecrets":                 {nil, []string{"dir", "s", "stop"}, "dir is a path, s a built sealer and stop a test hook"},
	"(github.com/ghbmrk/agentos/broker/clerk/run.SignInSock).Start":          {nil, []string{"ctx", "guest", "planName", "s"}, "returns a worker holding the sign-in host; ctx, the guest, the plan's name and the receiver hold no sealing key"},
	"github.com/ghbmrk/agentos/broker/cmd/agentos-camera.openSecrets":        {nil, []string{"dir", "keyFile"}, "keyFile is the kernel's hand-off; the key read from it is wiped inside"},
	"github.com/ghbmrk/agentos/broker/cmd/agentos-homekit.openSecrets":       {nil, []string{"dir", "keyFile"}, "keyFile is the kernel's hand-off; the key read from it is wiped inside"},
	"github.com/ghbmrk/agentos/broker/cmd/agentos-clerk-model.openStore":     {nil, []string{"dir", "s", "slot", "stop"}, "dir and slot are names, s a built sealer, stop a test hook"},
	"github.com/ghbmrk/agentos/broker/cmd/agentos-clerk-model.openKeys":      {nil, []string{"dir", "s", "stop"}, "dir is a path, s a built sealer, stop a test hook"},
	"github.com/ghbmrk/agentos/broker/cmd/agentos-clerk-model.newLogin":      {nil, []string{"d", "store"}, "the declaration and the sealed store hold no sealing key"},
}

// keyUses names, by types.Func.FullName, each function a listed
// constructor may hand its key to, with why it keeps no reference to the
// slice and returns no key bytes. Nothing but review holds an entry.
var keyUses = map[string]string{
	// Go 1.26 src/crypto/aes/aes.go NewCipher → crypto/internal/fips140/aes
	// newOutlined → newBlockExpanded → expandKeyGeneric, which writes the
	// round keys into the Block's fixed arrays and stores no slice (the
	// boring path is off: the broker builds without GOEXPERIMENT=boringcrypto).
	"crypto/aes.NewCipher": "expands the key into the round keys of the block it returns, the sealer's own state, and keeps no reference to the slice",
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
			ps = append(ps, bodyProblems(l.Fset, f, p.Info, sealers, keyUses, seen)...)
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
	for name, list := range map[string][]string{"sealers": slices.Collect(mapKeys(sealers)), "keyExempt": slices.Collect(mapKeys(keyExempt)), "keyUses": slices.Collect(mapKeys(keyUses)), "unreadOK": slices.Collect(mapKeys(unreadOK))} {
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
			problems = append(problems, line(id)+": "+id.Name+"'s key is not wiped right after the call; write `s, err := "+id.Name+"(k)` then `clear(k)` as the next statement, with k a local variable; a `defer clear(k)` keeps the key live until the function returns")
		}
		return true
	})
	return uses, problems
}

// keyedCall returns the listed callee of s when s is `a, b := f(k)` (or
// =) with f listed, every key argument a local byte slice variable, and
// the statements in rest starting with one builtin clear of each.
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

// clearOf returns the variable s wipes when s is `clear(v)` with the
// builtin clear, else nil. A `defer clear(v)` wipes only at the return, so
// it is no wipe here.
func clearOf(s ast.Stmt, info *types.Info) types.Object {
	e, isExpr := s.(*ast.ExprStmt)
	if !isExpr {
		return nil
	}
	c, _ := ast.Unparen(e.X).(*ast.CallExpr)
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
	named := func(id *ast.Ident, body *ast.BlockStmt) {
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
		if !givesSealer(sig, sealer) && !returnsSealer(body, sig, info, sealer) {
			if listed {
				problems = append(problems, line(id)+": "+name+" is listed in sealers but makes no sealer; remove the entry")
			}
			return
		}
		if len(held) == 0 && !listed {
			return
		}
		if !listed {
			problems = append(problems, line(id)+": "+name+" makes a sealer from a possible key ("+strings.Join(held.names(), ", ")+"); list it in sealers with each classified as a key (each caller wipes it) or not, and why")
			return
		}
		// Every possible key is classified, keys and not alike, so a new
		// parameter that can carry a key fails until a review lists it.
		listedNames := entry.classified()
		if have := held.names(); !slices.Equal(have, listedNames) {
			problems = append(problems, line(id)+": "+name+"'s possible keys are ("+strings.Join(have, ", ")+") but its sealers entry classifies ("+strings.Join(listedNames, ", ")+"); list each in keys or not")
			return
		}
		for _, k := range entry.keys {
			fm := held[k]
			switch {
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
	// A listed constructor with keys builds its sealer in its own body,
	// which bodyProblems holds; a keyless entry's body gets no leave.
	var bodies []ast.Node
	for _, d := range f.Decls {
		if fd, isFn := d.(*ast.FuncDecl); isFn {
			if fn, isFunc := info.Defs[fd.Name].(*types.Func); isFunc {
				if e, listed := keys[fn.FullName()]; listed && len(e.keys) > 0 {
					bodies = append(bodies, fd)
				}
			}
		}
	}
	inListed := func(n ast.Node) bool {
		return slices.ContainsFunc(bodies, func(b ast.Node) bool { return b.Pos() <= n.Pos() && n.End() <= b.End() })
	}
	// carries reports whether e is a value that can hold or produce key
	// bytes and is not itself a sealer: no constant, no sealer re-typed.
	carries := func(e ast.Expr) bool {
		tv, ok := info.Types[e]
		if !ok || tv.Value != nil || tv.IsNil() {
			return false
		}
		return keyForm(tv.Type) != formNone && !holdsSealer(tv.Type, sealer, map[types.Type]bool{})
	}
	// isSealer reports whether t, or its pointer, is a sealer itself (not
	// a wrapper that holds one beside other things).
	isSealer := func(t types.Type) bool {
		return types.Implements(t, sealer) || types.Implements(types.NewPointer(t), sealer)
	}
	owned := map[*ast.FuncType]bool{}
	ast.Inspect(f, func(n ast.Node) bool {
		switch n := n.(type) {
		case *ast.CallExpr:
			// A conversion to a sealer type of a possible key.
			if tv, ok := info.Types[n.Fun]; ok && tv.IsType() && len(n.Args) == 1 && isSealer(tv.Type) && carries(n.Args[0]) && !inListed(n) {
				problems = append(problems, line(n)+": a conversion makes a sealer from a possible key; build it in a listed constructor")
			}
		case *ast.CompositeLit:
			if t := info.TypeOf(n); t != nil && isSealer(t) && !inListed(n) {
				for _, e := range n.Elts {
					if kv, isKV := e.(*ast.KeyValueExpr); isKV {
						e = kv.Value
					}
					if carries(e) {
						problems = append(problems, line(n)+": a composite literal makes a sealer from a possible key; build it in a listed constructor")
						break
					}
				}
			}
		case *ast.Ident:
			fn, isFunc := info.Uses[n].(*types.Func)
			if !isFunc || fn.Pkg() == nil || strings.HasPrefix(fn.Pkg().Path()+"/", tree) {
				return true
			}
			name := fn.Origin().FullName()
			if entry, listed := keys[name]; listed {
				seen[name] = true
				if have, cl := possibleKeys(fn.Origin().Type().(*types.Signature)).names(), entry.classified(); !slices.Equal(have, cl) {
					problems = append(problems, line(n)+": "+name+"'s possible keys are ("+strings.Join(have, ", ")+") but its sealers entry classifies ("+strings.Join(cl, ", ")+"); list each in keys or not")
				}
				return true
			}
			if sig := fn.Type().(*types.Signature); givesSealer(sig, sealer) && len(possibleKeys(sig)) > 0 {
				problems = append(problems, line(n)+": "+name+", declared outside the tree the rule reads, makes a sealer from a possible key ("+strings.Join(possibleKeys(sig).names(), ", ")+"); list it in sealers with each classified as a key or not, and why")
			}
		case *ast.FuncDecl:
			owned[n.Type] = true
			named(n.Name, n.Body)
		case *ast.InterfaceType:
			for _, m := range n.Methods.List {
				if ft, isFunc := m.Type.(*ast.FuncType); isFunc && len(m.Names) > 0 {
					owned[ft] = true
					for _, id := range m.Names {
						named(id, nil)
					}
				}
			}
		case *ast.FuncLit:
			owned[n.Type] = true
			if sig, isSig := info.TypeOf(n).(*types.Signature); isSig && (givesSealer(sig, sealer) || returnsSealer(n.Body, sig, info, sealer)) && len(possibleKeys(sig)) > 0 {
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

// bodyProblems returns a problem for each place where the body of a
// listed constructor with keys, declared in f, could keep, copy, build or
// derive a key: a key parameter used other than as the operand of len or
// cap or an argument of a keyUses function, or inside a func literal; a
// keyUses function that returns bytes; and any other expression with
// the type of key bytes, the parameters classified as not keys aside. A
// keyUses function called is marked in seen.
func bodyProblems(fset *token.FileSet, f *ast.File, info *types.Info, keys map[string]sealerKey, uses map[string]string, seen map[string]bool) []string {
	var problems []string
	line := func(n ast.Node) string { return strconv.Itoa(fset.PositionFor(n.Pos(), false).Line) }
	for _, d := range f.Decls {
		fd, isFn := d.(*ast.FuncDecl)
		if !isFn || fd.Body == nil {
			continue
		}
		fn, isFunc := info.Defs[fd.Name].(*types.Func)
		if !isFunc {
			continue
		}
		name := fn.FullName()
		entry, listed := keys[name]
		if !listed || len(entry.keys) == 0 {
			continue
		}
		sig := fn.Type().(*types.Signature)
		key, not := map[types.Object]bool{}, map[types.Object]bool{}
		vars := []*types.Var{}
		if r := sig.Recv(); r != nil {
			vars = append(vars, r) // a receiver key also fails in constructorProblems
		}
		for i := range sig.Params().Len() {
			vars = append(vars, sig.Params().At(i))
		}
		for _, p := range vars {
			switch {
			case slices.Contains(entry.keys, p.Name()):
				key[p] = true
			case slices.Contains(entry.not, p.Name()):
				not[p] = true
			}
		}
		// handed marks each key use that is an operand of len or cap or an
		// argument of a keyUses function, outside any func literal.
		handed := map[*ast.Ident]bool{}
		var lits []ast.Node
		ast.Inspect(fd.Body, func(n ast.Node) bool {
			switch n := n.(type) {
			case *ast.FuncLit:
				lits = append(lits, n)
			case *ast.CallExpr:
				id := callee(n)
				if id == nil {
					return true
				}
				switch obj := info.Uses[id].(type) {
				case *types.Builtin:
					if obj.Name() != "len" && obj.Name() != "cap" {
						return true
					}
				case *types.Func:
					if _, in := uses[obj.Origin().FullName()]; !in {
						return true
					}
					seen[obj.Origin().FullName()] = true
					r := obj.Type().(*types.Signature).Results()
					for i := range r.Len() {
						if bytesIn(r.At(i).Type()) {
							problems = append(problems, line(n)+": "+name+" hands its key to "+obj.Origin().FullName()+", which returns bytes ("+r.At(i).Type().String()+"); remove it from keyUses")
						}
					}
				default:
					return true
				}
				for _, a := range n.Args {
					if v, isID := ast.Unparen(a).(*ast.Ident); isID && key[info.Uses[v]] {
						handed[v] = true
					}
				}
			}
			return true
		})
		inLit := func(n ast.Node) bool {
			return slices.ContainsFunc(lits, func(l ast.Node) bool { return l.Pos() <= n.Pos() && n.End() <= l.End() })
		}
		ast.Inspect(fd.Body, func(n ast.Node) bool {
			e, isExpr := n.(ast.Expr)
			if !isExpr {
				return true
			}
			if id, isID := e.(*ast.Ident); isID {
				switch obj := info.Uses[id]; {
				case key[obj]:
					if !handed[id] || inLit(id) {
						problems = append(problems, line(id)+": "+name+" uses its key "+id.Name+" other than in len, cap or a call of a keyUses function, so it could keep or copy it; hand the key only to a function listed in keyUses")
					}
					return false
				case not[obj]:
					return false
				}
			}
			tv, ok := info.Types[e]
			if !ok || tv.IsType() || tv.Value != nil || tv.IsNil() {
				return true
			}
			if bytesIn(tv.Type) {
				problems = append(problems, line(e)+": "+name+" holds bytes that are not its key parameters ("+types.ExprString(e)+"), so it builds or derives a key no caller wipes; a listed constructor takes its key bytes only from its callers")
				return false
			}
			return true
		})
	}
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

// givesSealer reports whether a result of sig holds a sealer: a type
// that is or implements the sealer interface, as itself or through its
// pointer, anywhere inside it (a struct field, pointer, slice, array,
// map, channel, or a func's results).
func givesSealer(sig *types.Signature, sealer *types.Interface) bool {
	seen := map[types.Type]bool{}
	for i := range sig.Results().Len() {
		if holdsSealer(sig.Results().At(i).Type(), sealer, seen) {
			return true
		}
	}
	return false
}

// returnsSealer reports whether body, of a function of sig, returns a
// value holding a sealer as a result sig declares as an interface (any):
// the sealer leaves under a type givesSealer cannot see.
func returnsSealer(body *ast.BlockStmt, sig *types.Signature, info *types.Info, sealer *types.Interface) bool {
	if body == nil {
		return false
	}
	found := false
	ast.Inspect(body, func(n ast.Node) bool {
		switch n := n.(type) {
		case *ast.FuncLit:
			return false // its own returns are its own
		case *ast.ReturnStmt:
			if len(n.Results) != sig.Results().Len() {
				return true // a bare return, or one call's results: that callee is held itself
			}
			for i, e := range n.Results {
				if _, isIface := sig.Results().At(i).Type().Underlying().(*types.Interface); !isIface {
					continue
				}
				if t := info.TypeOf(e); t != nil && holdsSealer(t, sealer, map[types.Type]bool{}) {
					found = true
				}
			}
		}
		return !found
	})
	return found
}

func holdsSealer(t types.Type, sealer *types.Interface, seen map[types.Type]bool) bool {
	if seen[t] {
		return false
	}
	seen[t] = true
	if types.Implements(t, sealer) || types.Implements(types.NewPointer(t), sealer) {
		return true
	}
	in := func(ts ...types.Type) bool {
		for _, e := range ts {
			if holdsSealer(e, sealer, seen) {
				return true
			}
		}
		return false
	}
	switch u := t.Underlying().(type) {
	case *types.Pointer:
		return in(u.Elem())
	case *types.Slice:
		return in(u.Elem())
	case *types.Array:
		return in(u.Elem())
	case *types.Map:
		return in(u.Key(), u.Elem())
	case *types.Chan:
		return in(u.Elem())
	case *types.Struct:
		for i := range u.NumFields() {
			if in(u.Field(i).Type()) {
				return true
			}
		}
	case *types.Signature:
		for i := range u.Results().Len() {
			if in(u.Results().At(i).Type()) {
				return true
			}
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
	formUnknown             // holds or can produce key bytes no statement wipes, or a type the lint cannot read
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
		case u.Kind() == types.Invalid, u.Kind() == types.Uintptr, u.Kind() == types.UnsafePointer:
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
	case *types.Interface, *types.Signature, *types.Chan:
		return formUnknown // any value behind it, a func or a channel can carry or produce key bytes
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

// bytesIn reports whether a value of type t holds bytes a statement could
// keep: a string, a byte slice or array, a uintptr or unsafe.Pointer, a
// type parameter that may be one, or a pointer, struct, array, slice, map
// or tuple holding one. It stops at an interface, func or channel, whose
// contents a listed body's review holds (Bound).
func bytesIn(t types.Type) bool { return bytesOf(t, map[types.Type]bool{}) }

func bytesOf(t types.Type, seen map[types.Type]bool) bool {
	if seen[t] {
		return false
	}
	seen[t] = true
	if _, isTP := t.(*types.TypeParam); isTP {
		return keyForm(t) != formNone
	}
	in := func(ts ...types.Type) bool {
		return slices.ContainsFunc(ts, func(e types.Type) bool { return bytesOf(e, seen) })
	}
	switch u := t.Underlying().(type) {
	case *types.Basic:
		return u.Info()&types.IsString != 0 || u.Kind() == types.Uintptr || u.Kind() == types.UnsafePointer || u.Kind() == types.Invalid
	case *types.Slice:
		return isByte(u.Elem()) || in(u.Elem())
	case *types.Array:
		return isByte(u.Elem()) || in(u.Elem())
	case *types.Pointer:
		return in(u.Elem())
	case *types.Map:
		return in(u.Key(), u.Elem())
	case *types.Struct:
		for i := range u.NumFields() {
			if in(u.Field(i).Type()) {
				return true
			}
		}
	case *types.Tuple:
		for i := range u.Len() {
			if in(u.At(i).Type()) {
				return true
			}
		}
	}
	return false
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
	"crypto/aes"
	"crypto/cipher"
	"errors"

	"github.com/ghbmrk/agentos/broker/clerk"
)

func newSealer(a []byte, label string, b []byte) (clerk.Sealer, error) { return nil, nil }
func newGen[K ~[]byte](k K) (clerk.Sealer, error)                      { return nil, nil }
func newNonce(n []byte) (clerk.Sealer, error)                          { return nil, nil }

var _ = errors.New
var _ = aes.NewCipher
var _ = cipher.NewGCM
var sink clerk.Sealer
var pkgKey []byte

type gs struct{ g cipher.AEAD }

func (gs) Seal(plain, aad []byte) ([]byte, error) { return nil, nil }
func (gs) Open(blob, aad []byte) ([]byte, error)  { return nil, nil }

`
	listing := map[string]sealerKey{
		sealerPkg + ".NewAESSealer":      {[]string{"key"}, nil, "case"},
		"example.test/p.newSealer":       {[]string{"a", "b"}, []string{"label"}, "case"},
		"example.test/p.newArr":          {[]string{"k"}, nil, "case"},
		"example.test/p.newGen":          {[]string{"k"}, nil, "case"},
		"example.test/p.newNonce":        {nil, []string{"n"}, "case: n is a nonce"},
		"example.test/p.newStr":          {[]string{"k"}, nil, "case"},
		"example.test/p.newGenStr":       {[]string{"k"}, nil, "case"},
		"example.test/p.newAny":          {[]string{"k"}, nil, "case"},
		"example.test/p.newPtr":          {[]string{"k"}, nil, "case"},
		"example.test/p.newMissing":      {[]string{"key"}, nil, "case"},
		"example.test/p.notSealer":       {[]string{"k"}, nil, "case"},
		"(example.test/p.rawKey).Sealer": {[]string{"r"}, nil, "case"},
		"example.test/q.NewQ":            {[]string{"k"}, nil, "case"},
		"example.test/p.nl":              {nil, nil, "case: listed before k was added"},
		"example.test/p.newOwn6":         {[]string{"k"}, nil, "case"},
		"example.test/p.newB1":           {[]string{"k"}, nil, "case"},
		"example.test/p.newB2":           {[]string{"k"}, nil, "case"},
		"example.test/p.newB3":           {[]string{"k"}, nil, "case"},
		"example.test/p.newB4":           {[]string{"k"}, nil, "case"},
		"example.test/p.newB5":           {[]string{"k"}, nil, "case"},
		"example.test/p.newB6":           {[]string{"k"}, []string{"label"}, "case"},
		"example.test/p.newB7":           {[]string{"k"}, nil, "case"},
		"example.test/p.newB8":           {[]string{"k"}, nil, "case"},
		"example.test/p.newKL":           {nil, []string{"n"}, "case: n is a nonce"},
		"example.test/p.newB9":           {[]string{"k"}, nil, "case"},
		"example.test/p.newB10":          {[]string{"k"}, nil, "case"},
		"example.test/p.newP1":           {[]string{"k"}, nil, "case"},
		"example.test/p.newP2":           {[]string{"k"}, nil, "case"},
		"(example.test/p.rk).Mk":         {[]string{"r"}, nil, "case"},
	}
	uses := map[string]string{"crypto/aes.NewCipher": "case", "example.test/p.leak": "case"}
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
		{"two keys, cleared in either order, the label no key", `func f(a, b []byte) error {
	s, err := newSealer(a, "x", b)
	clear(b)
	clear(a)
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
		clear(k)
		sink = s
	}
}`, 0},
		{"an exempt function's calls are not held", `func probe(k []byte) error {
	s, err := clerk.NewAESSealer(k)
	sink = s
	return err
}`, 0},
		{"a sealer from no possible key is no constructor", `func wrap(n int) clerk.Sealer { return sink }`, 0},
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
		// A defer clear keeps the key until the return (#6383).
		{"defer clear right after the call", `func f(k []byte) (err error) {
	sink, err = clerk.NewAESSealer(k)
	defer clear(k)
	return err
}`, 1},
		{"a defer clear with a long tail after the last use", `func f(k []byte, serve func()) error {
	s, err := clerk.NewAESSealer(k)
	defer clear(k)
	if err != nil {
		return err
	}
	sink = s
	for range 3 {
		serve()
	}
	return nil
}`, 1},
		{"one of two keys deferred", `func f(a, b []byte) error {
	s, err := newSealer(a, "x", b)
	clear(b)
	defer clear(a)
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
		{"a keyless listing that gains a key", `func nl(n int, k []byte) (clerk.Sealer, error) { return nil, nil }`, 1},
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
		// Params that can carry or produce bytes, and results that hold
		// a sealer inside (#6363 L3).
		{"a sealer param is a possible key, unlisted", `func wrap(s clerk.Sealer, n int) clerk.Sealer { return s }`, 1},
		{"a reader, unlisted", `func n1(r interface{ Read([]byte) (int, error) }) (clerk.Sealer, error) { return nil, nil }`, 1},
		{"a func that yields a key, unlisted", `func n2(get func() []byte) (clerk.Sealer, error) { return nil, nil }`, 1},
		{"a channel of keys, unlisted", `func n3(c chan []byte) (clerk.Sealer, error) { return nil, nil }`, 1},
		{"a uintptr, unlisted", `func n7(k uintptr) (clerk.Sealer, error) { return nil, nil }`, 1},
		{"a sealer in a struct result, unlisted", `type box struct{ S clerk.Sealer }

func n5(k []byte) (*box, error) { return nil, nil }`, 1},
		{"a slice of sealers, unlisted", `func n6(k []byte) ([]clerk.Sealer, error) { return nil, nil }`, 1},
		{"a func result yielding a sealer, unlisted", `func n8(k []byte) func() clerk.Sealer { return nil }`, 1},
		{"a key listed as an interface, cannot be wiped", `func newAny(k interface{ Key() []byte }) (clerk.Sealer, error) { return nil, nil }`, 1},
		// Sealers made with no constructor call (#6363 Security).
		{"a conversion inline", `type raw []byte

func (raw) Seal(plain, aad []byte) ([]byte, error) { return nil, nil }
func (raw) Open(blob, aad []byte) ([]byte, error) { return nil, nil }

func f(k []byte) { sink = raw(k) }`, 1},
		{"a composite literal inline", `type own5 struct{ k []byte }

func (*own5) Seal(plain, aad []byte) ([]byte, error) { return nil, nil }
func (*own5) Open(blob, aad []byte) ([]byte, error) { return nil, nil }

func f(k []byte) { sink = &own5{k} }`, 1},
		{"a composite literal in a listed constructor's own body keeps the key", `type own6 struct{ k []byte }

func (*own6) Seal(plain, aad []byte) ([]byte, error) { return nil, nil }
func (*own6) Open(blob, aad []byte) ([]byte, error) { return nil, nil }

func newOwn6(k []byte) (clerk.Sealer, error) { return &own6{k: k}, nil }`, 1},
		{"a wrapper literal beside a built sealer: only its unlisted maker fails", `type host struct {
	s    clerk.Sealer
	name string
}

func f(s clerk.Sealer) *host { return &host{s: s, name: "x"} }`, 1},
		{"a sealer re-typed: only its unlisted maker fails", `func f(s clerk.Sealer) any { return clerk.Sealer(s) }`, 1},
		{"a wrapper struct result", `func n9(k []byte) (*struct{ s clerk.Sealer }, error) { return nil, nil }`, 1},
		{"an any result returning a sealer", `func n10(k []byte) (any, error) {
	s, err := clerk.NewAESSealer(k)
	clear(k)
	return s, err
}`, 1},
		{"an any result returning no sealer", `func n11(k []byte) any { return len(k) }`, 0},
		// A listed constructor's own body (#6383).
		{"a body that hands its key only to a keyUses function", `func newB1(k []byte) (clerk.Sealer, error) {
	if len(k) != 32 || cap(k) < 32 {
		return nil, errors.New("clerk: sealing key must be 32 bytes")
	}
	b, err := aes.NewCipher(k)
	if err != nil {
		return nil, err
	}
	g, err := cipher.NewGCM(b)
	if err != nil {
		return nil, err
	}
	return gs{g}, nil
}`, 0},
		{"a body that keeps a copy of its key", `var kept []byte

func newB2(k []byte) (clerk.Sealer, error) {
	kept = append([]byte(nil), k...)
	return sink, nil
}`, 2},
		{"a body that draws a key of its own", `func newB3(k []byte) (clerk.Sealer, error) {
	own := make([]byte, 32)
	b, err := aes.NewCipher(own)
	if err != nil {
		return nil, err
	}
	g, err := cipher.NewGCM(b)
	return gs{g}, err
}`, 2},
		{"a body that uses its key in a func literal", `func newB4(k []byte) (clerk.Sealer, error) {
	go func() { aes.NewCipher(k) }()
	return sink, nil
}`, 1},
		{"a body that hands on a reslice of its key", `func newB5(k []byte) (clerk.Sealer, error) {
	b, err := aes.NewCipher(k[:16])
	if err != nil {
		return nil, err
	}
	g, err := cipher.NewGCM(b)
	return gs{g}, err
}`, 1},
		{"a body that uses a parameter classified as no key", `func newB6(k []byte, label string) (clerk.Sealer, error) {
	if label == "" {
		return nil, errors.New(label)
	}
	b, err := aes.NewCipher(k)
	if err != nil {
		return nil, err
	}
	g, err := cipher.NewGCM(b)
	return gs{g}, err
}`, 0},
		{"a body that hands its key to a keyUses function returning bytes", `func leak(k []byte) []byte { return k }

func newB7(k []byte) (clerk.Sealer, error) {
	leak(k)
	return sink, nil
}`, 2},
		{"a body that hands its key to an unlisted function", `func expand(k []byte) cipher.Block { return nil }

func newB8(k []byte) (clerk.Sealer, error) {
	g, err := cipher.NewGCM(expand(k))
	return gs{g}, err
}`, 1},
		// Bytes behind a pointer or inside a struct (#6445 Security).
		{"a body that draws its key behind a pointer", `type own9 struct{ p *[32]byte }

func (*own9) Seal(plain, aad []byte) ([]byte, error) { return nil, nil }
func (*own9) Open(blob, aad []byte) ([]byte, error) { return nil, nil }

func fill(p *[32]byte) {}

func newB9(k []byte) (clerk.Sealer, error) {
	p := new([32]byte)
	fill(p)
	return &own9{p}, nil
}`, 3},
		{"a body that takes its key inside a struct", `type kb struct{ b []byte }

type own10 struct{ k kb }

func (*own10) Seal(plain, aad []byte) ([]byte, error) { return nil, nil }
func (*own10) Open(blob, aad []byte) ([]byte, error) { return nil, nil }

func load() kb { return kb{} }

func newB10(k []byte) (clerk.Sealer, error) {
	return &own10{load()}, nil
}`, 1},
		{"a body that builds its block from a key behind a pointer (#6445 L3)", `func fill2(p *[32]byte) {}
func blk(p *[32]byte) cipher.Block { return nil }

func newP1(k []byte) (clerk.Sealer, error) {
	if len(k) != 32 {
		return nil, errors.New("x")
	}
	own := new([32]byte)
	fill2(own)
	g, err := cipher.NewGCM(blk(own))
	return gs{g}, err
}`, 3},
		{"a body that builds its block from a key in a struct (#6445 L3)", `type kb2 struct{ b []byte }

func load2() kb2 { return kb2{} }
func blk2(x kb2) cipher.Block { return nil }

func newP2(k []byte) (clerk.Sealer, error) {
	_ = len(k)
	g, err := cipher.NewGCM(blk2(load2()))
	return gs{g}, err
}`, 1},
		{"a receiver key handed to an unlisted function", `type rk []byte

func keep(b []byte) {}

func (r rk) Mk() (clerk.Sealer, error) {
	keep(r)
	return sink, nil
}`, 2},
		{"a keyless entry's body makes a sealer from bytes", `func newKL(n []byte) (clerk.Sealer, error) {
	_ = n
	return &own7{make([]byte, 32)}, nil
}

type own7 struct{ k []byte }

func (*own7) Seal(plain, aad []byte) ([]byte, error) { return nil, nil }
func (*own7) Open(blob, aad []byte) ([]byte, error) { return nil, nil }`, 1},
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
			got = append(got, bodyProblems(l.Fset, f, info, listing, uses, map[string]bool{})...)
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
		{map[string]sealerKey{sealerPkg + ".NewAESSealer": {[]string{"key"}, nil, "case"}}, 0},
		{map[string]sealerKey{sealerPkg + ".NewAESSealer": {nil, nil, "case: classifies none of key"}}, 1},
	} {
		seen := map[string]bool{}
		got := constructorProblems(l.Fset, f, info, l.sealer, c.listing, "example.test/", seen)
		if len(got) != c.want {
			t.Errorf("listing %v: got %d problems %q; want %d", c.listing, len(got), got, c.want)
		}
		if len(c.listing) > 0 && !seen[sealerPkg+".NewAESSealer"] {
			t.Errorf("a listed constructor from outside the tree was not marked seen")
		}
	}
}
