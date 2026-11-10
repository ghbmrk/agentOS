package call

// REQ: CH-5

import (
	"context"
	"errors"
	"fmt"
	"go/ast"
	"go/importer"
	"go/parser"
	"go/printer"
	"go/token"
	"go/types"
	"io/fs"
	"os"
	"slices"
	"strings"
	"testing"
)

// RunAt lets the package's own tests hold a call at a chosen rung. It is in
// a _test.go file, so no importer of the package can reach it (#4949), and
// the guard below reads only the non-test files.
func RunAt(ctx context.Context, cfg Config, l Line, rung Rung) (Report, error) {
	token := make(chan *grant, 1)
	token <- &grant{r: rung, live: make(chan struct{})}
	return loop(ctx, cfg.withDefaults(), l, token)
}

// The rung is the call's, set by the speed-dial check, never the caller's
// to choose (briefs/VOICE-ro.md rule 4, CH-5, #4949). The answerer learns
// it only from Ask.Rung, which reads the call's grant. So the guard does not
// trace what could carry a rung or a grant. It makes every grant check's,
// by these rules over the type-checked non-test files:
//
//  1. loop is named once, as the callee of a call in Serve's body outside
//     any func literal, so only Serve, which answers only the owner's
//     number, runs a call. check is named only as the callee of calls in
//     token's body, and token, whose ctx is the grant's life, only in
//     Serve's, both outside any func literal, and token is called once.
//     serving, the lock that serves one call at a time, is named only in
//     Serve, which takes it (waiting up to RingWait), defers the unlock,
//     makes the token's ctx and defers its cancel, answers, and only then
//     reads the token on it and defers cancelling it and waiting for the
//     token read, in that order, so keys pressed before a failed answer
//     reach no try, and on any return or panic the grant has died and no
//     Config.Token try is left before the line is free; nothing writes
//     tctx or cancel after that. token
//     defers closing out first, so the wait ends. Serve ends by running
//     the loop, then cancelling tctx (#5259, #5274).
//  2. A grant composite literal appears only in check, outside any func
//     literal, and nothing converts to grant or to a type parameter, and
//     no composite literal has a type parameter as its type. So check is
//     the only source of a grant but the zero value.
//  3. No code writes a grant's fields, or Config.Token: a field is written
//     by assigning it, incrementing it, taking its address, ranging into
//     it, calling a method on it, or naming it as a composite literal key
//     (outside check's grant literal). No Config literal leaves out its
//     keys, and nothing converts to Config, so nothing sets Token unnamed.
//  4. No non-test file imports unsafe, reflect or C.
//
// So a grant is check's or zero, and a whole-value write or copy only
// moves one of those: no write can mint a grant or stretch its life (the
// #5229 Security blocker, a keyed literal that left live nil, is now a
// rule 2 failure, and a zero grant reads P0). What these rules leave to
// review: what check, token and Serve do with their inputs (the Serve and
// token tests pin it), and //go:linkname and assembly (tools/srclint.py
// fails them in CI). A grant kept past its call, in a package var, a field
// or a shared answerer, needs no rule: rule 1 makes Serve the only maker
// of a live grant and kills it before the next call is served, so a kept
// grant reads P0 in every other call (TestOneCallIsServedAtATime, #5232).
// A ctx-ignoring answerer's or synthesizer's call can still run into the
// next call; its Ask reads P0 there, and what it fetched at P2 and keeps
// is VOICE-ro-c's to scope per call (VOICE-ro-a-C2, C8).
// If a refactor keeps the rule but breaks the check, change the check in
// the same PR as the code, with a probe for the new shape, never on its
// own.
func TestOnlyServeChoosesTheRung(t *testing.T) {
	fset := token.NewFileSet()
	imp := importer.ForCompiler(fset, "source", nil) // one importer: dependencies are read once
	type probe struct{ extra, old, new, want string }
	check := func(p probe) []string {
		pkgs, err := parser.ParseDir(fset, ".", func(fi fs.FileInfo) bool { return !strings.HasSuffix(fi.Name(), "_test.go") }, 0)
		if err != nil {
			t.Fatal(err)
		}
		var files []*ast.File
		edited := 0
		for name, f := range pkgs["call"].Files {
			if p.old != "" {
				b, err := os.ReadFile(name)
				if err != nil {
					t.Fatal(err)
				}
				if n := strings.Count(string(b), p.old); n > 0 {
					edited += n
					if f, err = parser.ParseFile(fset, name, strings.Replace(string(b), p.old, p.new, 1), 0); err != nil {
						t.Fatal(err)
					}
				}
			}
			files = append(files, f)
		}
		if len(files) == 0 {
			t.Fatal("no source files read")
		}
		if p.old != "" && edited != 1 {
			t.Fatalf("probe edit %q occurs %d times, not once", p.old, edited)
		}
		if p.extra != "" {
			f, err := parser.ParseFile(fset, "probe.go", "package call\n"+p.extra, 0)
			if err != nil {
				t.Fatal(err)
			}
			files = append(files, f)
		}
		info := &types.Info{Uses: map[*ast.Ident]types.Object{}, Defs: map[*ast.Ident]types.Object{}, Types: map[ast.Expr]types.TypeAndValue{}}
		pkg, err := (&types.Config{Importer: imp}).Check("call", fset, files, info)
		if err != nil {
			t.Fatal(err)
		}
		fn := func(name string) types.Object {
			if o, ok := pkg.Scope().Lookup(name).(*types.Func); ok {
				return o
			}
			t.Fatalf("%s is gone or not a plain func: rewrite this check with the code", name)
			return nil
		}
		under := func(name string) *types.Struct {
			if o, ok := pkg.Scope().Lookup(name).(*types.TypeName); ok && !o.IsAlias() {
				if st, ok := o.Type().Underlying().(*types.Struct); ok {
					return st
				}
			}
			t.Fatalf("%s is gone or not a struct: rewrite this check with the code", name)
			return nil
		}
		field := func(st *types.Struct, name string) *types.Var {
			for i := range st.NumFields() {
				if st.Field(i).Name() == name {
					return st.Field(i)
				}
			}
			t.Fatalf("field %s is gone: rewrite this check with the code", name)
			return nil
		}
		serve, loopFn, checkFn := fn("Serve"), fn("loop"), fn("check")
		serving, _ := pkg.Scope().Lookup("serving").(*types.Var)
		if serving == nil {
			t.Fatal("serving is gone: rewrite this check with the code")
		}
		var bad []string
		// Serve takes serving, then makes the token's ctx, then defers its
		// cancel before the unlock, in that order and before anything can
		// return: so a call's grant has died before the next call is
		// served, and every return unlocks (Lens on #5251).
		tokenFn, _, _ := types.LookupFieldOrMethod(pkg.Scope().Lookup("Config").Type(), false, pkg, "token")
		if _, ok := tokenFn.(*types.Func); !ok {
			t.Fatal("Config.token is gone: rewrite this check with the code")
		}
		body := func(fn types.Object) (text []string, stmts []ast.Stmt) {
			for _, f := range files {
				for _, d := range f.Decls {
					if fd, ok := d.(*ast.FuncDecl); ok && info.Defs[fd.Name] == fn {
						for _, st := range fd.Body.List {
							var b strings.Builder
							printer.Fprint(&b, fset, st)
							text = append(text, strings.Join(strings.Fields(b.String()), " "))
							stmts = append(stmts, st)
						}
					}
				}
			}
			return text, stmts
		}
		serveBody, serveStmts := body(serve)
		// The take: at once if no call is served, else waiting up to
		// RingWait for the call before to end (#5252). The unlock is
		// deferred at once, so a panic after the take (a nil ctx) frees
		// the line (#5274).
		pinned := []string{
			"select { case serving <- struct{}{}: default: select { case serving <- struct{}{}: case <-cfg.After(cfg.RingWait): return Report{}, ErrBusy case <-c.Ended(): return Report{}, ErrBusy case <-ctx.Done(): return Report{}, ctx.Err() } }",
			"defer func() { <-serving }()",
			"tctx, cancel := context.WithTimeoutCause(ctx, cfg.MaxCall, ErrTooLong)",
			"defer cancel()",
		}
		// tctx and cancel are set once, by the pinned statement, and
		// never written after it (#5251 reviews).
		var tctx, cancel types.Object
		// The rest, right after: the answer; only then the token read on
		// tctx, so keys pressed before an Answer that fails reach no try;
		// its end and await in a defer that runs before the unlock, so on
		// every return or panic the grant has died and no Config.Token try
		// is left; the loop; then tctx cancelled before the hang-up
		// (#5259, #5274).
		tail := []string{
			"if err := c.Answer(tctx); err != nil { return Report{}, overrun(ctx, tctx, c, err) }",
			"token := make(chan *grant, 1)",
			"go cfg.token(tctx, c, token)",
			"defer func() { cancel() for range token { } }()",
			"rep, err := loop(tctx, cfg, c, token)",
			"cancel()",
			"return rep, overrun(ctx, tctx, c, err)",
		}
		i := slices.Index(serveBody, pinned[0])
		if i < 0 || i+len(pinned) > len(serveBody) || !slices.Equal(serveBody[i:i+len(pinned)], pinned) {
			bad = append(bad, "Serve does not take serving, defer the unlock, make tctx and defer its cancel, in that order")
		} else if !slices.Equal(serveBody[i+len(pinned):], tail) {
			bad = append(bad, "Serve does not then answer, then read the token with tctx and defer cancelling tctx and waiting for the token read, then run the loop, then cancelling tctx")
		}
		if i >= 0 && i+3 <= len(serveBody) && serveBody[i+2] == pinned[2] {
			lhs := serveStmts[i+2].(*ast.AssignStmt).Lhs
			tctx, cancel = info.Defs[lhs[0].(*ast.Ident)], info.Defs[lhs[1].(*ast.Ident)]
		}
		// token closes out once its one check is done, on every path, so
		// Serve's await ends (#5259, #5274).
		if tb, _ := body(tokenFn); len(tb) == 0 || tb[0] != "defer close(out)" {
			bad = append(bad, "token does not defer closing out first")
		}
		for _, st := range serveBody[:max(slices.Index(serveBody, pinned[0]), 0)] {
			if strings.Contains(st, "return") && st != "if ownerNumber == \"\" || c.Number() != ownerNumber { return Report{}, ErrNotOwner }" {
				bad = append(bad, "Serve returns before it takes serving other than for ErrNotOwner")
			}
		}
		servingNames := 0
		gSt, cfgSt := under("grant"), under("Config")
		// Each guarded call, and the one func that may make it; and the
		// fields nothing may write.
		callIn := map[types.Object]types.Object{loopFn: serve, checkFn: tokenFn, tokenFn: serve}
		gr, gl, tok := field(gSt, "r"), field(gSt, "live"), field(cfgSt, "Token")
		guarded := func(t types.Type) string {
			if p, ok := t.Underlying().(*types.Pointer); ok {
				t = p.Elem()
			}
			switch {
			case func() bool { _, ok := t.(*types.TypeParam); return ok }():
				return "a type parameter"
			case types.Identical(t.Underlying(), gSt):
				return "grant"
			case types.Identical(t.Underlying(), cfgSt):
				return "Config"
			}
			return ""
		}

		isKey := func(e ast.Expr) bool { _, ok := e.(*ast.KeyValueExpr); return ok }
		at := func(n ast.Node, msg string, a ...any) {
			bad = append(bad, fset.Position(n.Pos()).String()+": "+fmt.Sprintf(msg, a...))
		}
		calls, tokenCalls := 0, 0
		for _, f := range files {
			for _, imp := range f.Imports {
				if p := strings.Trim(imp.Path.Value, `"`); p == "unsafe" || p == "reflect" || p == "C" {
					at(imp, "imports %s", p)
				}
			}
			for _, d := range f.Decls {
				var encl types.Object
				if fd, ok := d.(*ast.FuncDecl); ok {
					encl = info.Defs[fd.Name]
				}
				var stack []ast.Node
				ast.Inspect(d, func(n ast.Node) bool {
					if n == nil {
						stack = stack[:len(stack)-1]
						return true
					}
					stack = append(stack, n)
					parent := func(i int) ast.Node { // i-th node above n, skipping parens
						for j := len(stack) - 2; j >= 0; j-- {
							if _, ok := stack[j].(*ast.ParenExpr); ok {
								continue
							}
							if i--; i == 0 {
								return stack[j]
							}
						}
						return nil
					}
					lit := slices.ContainsFunc(stack, func(n ast.Node) bool { _, ok := n.(*ast.FuncLit); return ok })
					switch n := n.(type) {
					case *ast.CompositeLit:
						switch g := guarded(info.Types[n].Type); {
						case g == "a type parameter":
							at(n, "composite literal of a type parameter")
						case g == "grant" && (encl != checkFn || lit):
							at(n, "grant literal outside check")
						case g != "" && len(n.Elts) > 0 && !isKey(n.Elts[0]):
							at(n, "%s literal without keys", g)
						}
					case *ast.CallExpr:
						if tv := info.Types[n.Fun]; tv.IsType() {
							if g := guarded(tv.Type); g != "" {
								at(n, "conversion to %s", g)
							}
						}
					case *ast.Ident:
						obj := info.Uses[n]
						if obj == serving {
							if servingNames++; encl != serve {
								at(n, "serving is named outside Serve")
							}
						}
						if in, ok := callIn[obj]; ok {
							fun, up := ast.Node(n), parent(1)
							if sel, ok := up.(*ast.SelectorExpr); ok && sel.Sel == n { // a method
								fun, up = sel, parent(2)
							}
							call, isCall := up.(*ast.CallExpr)
							if encl == in && isCall && call.Fun == fun && !lit {
								switch obj {
								case loopFn:
									calls++
								case tokenFn:
									tokenCalls++
								}
							} else {
								at(n, "%s is named other than as a direct call in %s", obj.Name(), in.Name())
							}
						}
						if obj != nil && (obj == tctx || obj == cancel) {
							var write bool
							switch up := parent(1).(type) {
							case *ast.AssignStmt:
								write = slices.ContainsFunc(up.Lhs, func(x ast.Expr) bool { return ast.Unparen(x) == n })
							case *ast.UnaryExpr:
								write = up.Op == token.AND
							case *ast.RangeStmt:
								write = ast.Unparen(up.Key) == n || ast.Unparen(up.Value) == n
							}
							if write {
								at(n, "writes %s", obj.Name())
							}
						}
						if obj == gr || obj == gl || obj == tok {
							e, up := ast.Node(n), parent(1)
							if kv, ok := up.(*ast.KeyValueExpr); ok && kv.Key == n {
								up = kv // a composite literal key sets the field
							} else if sel, ok := up.(*ast.SelectorExpr); ok && sel.Sel == n {
								e, up = sel, parent(2)
							}
							var write bool
							switch up := up.(type) {
							case *ast.KeyValueExpr: // a grant literal is rule 2's
								write = up.Key == n && obj == tok
							case *ast.AssignStmt:
								write = slices.ContainsFunc(up.Lhs, func(x ast.Expr) bool { return ast.Unparen(x) == e })
							case *ast.IncDecStmt, *ast.StarExpr, *ast.IndexExpr, *ast.SliceExpr:
								write = true
							case *ast.UnaryExpr:
								write = up.Op == token.AND
							case *ast.RangeStmt:
								write = ast.Unparen(up.Key) == e || ast.Unparen(up.Value) == e
							case *ast.SelectorExpr:
								write = ast.Unparen(up.X) == e // a method on the field may take its address
							}
							if write {
								at(n, "writes %s", obj.Name())
							}
						}
					}
					return true
				})
			}
		}
		if calls != 1 {
			bad = append(bad, fmt.Sprintf("Serve calls loop %d times", calls))
		}
		if tokenCalls != 1 {
			bad = append(bad, fmt.Sprintf("Serve calls token %d times", tokenCalls))
		}
		if servingNames != 3 {
			bad = append(bad, fmt.Sprintf("serving is named %d times, not 3", servingNames))
		}
		return bad
	}

	if bad := check(probe{}); len(bad) != 0 {
		t.Errorf("a grant can be made other than by check, or the loop entered other than through Serve:\n%s\n"+
			"Rule: only check makes a grant, nothing writes one, only token calls check, only Serve calls token and loop and holds serving. If a refactor keeps that rule, change this check with the code, with a probe for the new shape.", strings.Join(bad, "\n"))
	}
	const answerThenToken = "\tif err := c.Answer(tctx); err != nil {\n\t\treturn Report{}, overrun(ctx, tctx, c, err)\n\t}\n\t// The token is read only once the call is answered, so keys pressed\n\t// before then reach no try if it never is.\n\ttoken := make(chan *grant, 1)\n\tgo cfg.token(tctx, c, token)\n"
	const tokenThenAnswer = "\ttoken := make(chan *grant, 1)\n\tgo cfg.token(tctx, c, token)\n\tif err := c.Answer(tctx); err != nil {\n\t\treturn Report{}, overrun(ctx, tctx, c, err)\n\t}\n"
	const twin = "type twin struct { r Rung; live <-chan struct{} }\n"
	for _, p := range []probe{
		// Lens and Security on #5211, and main's old Run: loop named
		// outside Serve.
		{extra: "var Run = loop", want: "loop is named"},
		{extra: "func Run(ctx context.Context, cfg Config, l Line) (Report, error) { return loop(ctx, cfg, l, nil) }", want: "loop is named"},
		{extra: "func Runner() func(context.Context, Config, Line, <-chan *grant) (Report, error) { return loop }", want: "loop is named"},
		{extra: "type ctl struct{}\nfunc (ctl) Run(ctx context.Context, cfg Config, l Line) (Report, error) { return loop(ctx, cfg, l, nil) }", want: "loop is named"},
		{extra: "func init() { go loop(context.Background(), Config{}, nil, nil) }", want: "loop is named"},
		{extra: "func (cfg Config) Serve(ctx context.Context, l Line) (Report, error) { return loop(ctx, cfg, l, nil) }", want: "loop is named"},
		// #5219 item 1: inside Serve, but not a direct call.
		{old: "rep, err := loop(tctx, cfg, c, token)", new: "keep = func() { loop(tctx, cfg, c, token) }\n\trep, err := Report{}, error(nil)", extra: "var keep func()", want: "loop is named"},
		{old: "rep, err := loop(tctx, cfg, c, token)", new: "rep, err := id(loop)(tctx, cfg, c, token)", extra: "func id[T any](t T) T { return t }", want: "loop is named"},
		{old: "rep, err := loop(tctx, cfg, c, token)", new: "loop(tctx, cfg, c, token)\n\trep, err := loop(tctx, cfg, c, token)", want: "Serve calls loop 2 times"},
		// check named outside token, or not as a direct call.
		{extra: "var Check = check", want: "check is named"},
		{extra: "func raise(cfg Config, l Incoming) *grant { return check(cfg, nil, l.Number()) }", want: "check is named"},
		{old: "out <- check(cfg, ctx.Done(), cfg.keys(ctx, l))", new: "keepCheck = func(k string) *grant { return check(cfg, nil, k) }\n\tout <- nil", extra: "var keepCheck func(string) *grant", want: "check is named"},
		// #5232 R3: token, whose ctx is the grant's life, named outside
		// Serve or not as a direct call there.
		{extra: "func raise(cfg Config, l Line, out chan<- *grant) { cfg.token(context.Background(), l, out) }", want: "token is named"},
		{extra: "var Token = Config.token", want: "token is named"},
		{extra: "func raise(cfg Config) func(context.Context, Line, chan<- *grant) { return cfg.token }", want: "token is named"},
		{old: "go cfg.token(tctx, c, token)", new: "go func() { cfg.token(tctx, c, token) }()", want: "token is named"},
		// #5251 reviews: a second token read, on a ctx the call does not
		// end, makes a grant that outlives the call.
		{old: "go cfg.token(tctx, c, token)", new: "go cfg.token(tctx, c, token)\n\tgo cfg.token(ctx, c, token)", want: "Serve calls token 2 times"},
		// #5259: Serve returns only once the token read has ended, so no
		// Config.Token try follows the call; #5274: on a panic as well.
		{old: "\t\tfor range token {\n\t\t}\n", new: "", want: "waiting for the token read"},
		{old: "\t\tcancel()\n\t\tfor range token {", new: "\t\tfor range token {", want: "waiting for the token read"},
		{old: "\t\tcancel()\n\t\tfor range token {\n\t\t}\n", new: "\t\tfor range token {\n\t\t}\n\t\tcancel()\n", want: "waiting for the token read"},
		{old: "\t\tfor range token {\n\t\t}\n", new: "\t\tgo func() {\n\t\t\tfor range token {\n\t\t\t}\n\t\t}()\n", want: "waiting for the token read"},
		{old: "\tdefer func() {\n\t\tcancel()\n\t\tfor range token {\n\t\t}\n\t}()\n", new: "", want: "waiting for the token read"},
		{old: "\trep, err := loop(tctx, cfg, c, token)\n", new: "\trep, err := loop(tctx, cfg, c, token)\n\tfor range token {\n\t}\n", want: "then cancelling tctx"},
		{old: "\tcancel() // the call is over", new: "\t_ = 0 // the call is over", want: "then cancelling tctx"},
		// #5274: deleting token's close of out leaves Serve's await hung.
		{old: "\tdefer close(out)\n\tout <- check", new: "\tout <- check", want: "token does not defer closing out first"},
		{old: "\tdefer close(out)\n\tout <- check", new: "\tdefer func() { close(out) }()\n\tout <- check", want: "token does not defer closing out first"},
		// #5232 R1: serving is Serve's alone, so one call is served at a time.
		{extra: "func free() { <-serving }", want: "serving is named outside Serve"},
		{extra: "var held = &serving", want: "serving is named outside Serve"},
		// Lens on #5251: the unlock before the cancel lets the next call
		// start while this call's grant still reads P2. #5274: an unlock
		// deferred after tctx is made leaves the line held on a panic there
		// (a nil ctx).
		{old: "\tdefer func() {\n\t\tcancel()\n\t\tfor range token {", new: "\tdefer func() {\n\t\t<-serving\n\t\tcancel()\n\t\tfor range token {", want: "waiting for the token read"},
		{old: "\tdefer func() { <-serving }()\n", new: "", want: "in that order"},
		{old: "\tdefer func() { <-serving }()\n", new: "\tdefer func() { <-serving; <-serving }()\n", want: "in that order"},
		{old: "\tdefer func() { <-serving }()\n", new: "\tif ctx == nil {\n\t\t<-serving\n\t\treturn Report{}, nil\n\t}\n", want: "in that order"},
		{old: "go cfg.token(tctx, c, token)", new: "go cfg.token(ctx, c, token)\n\t_ = tctx", want: "waiting for the token read"},
		// #5274 fix-list: the token read starts only once the call is
		// answered, and tctx's cancel is deferred before the answer.
		{old: "\tdefer cancel()\n\tif err := c.Answer", new: "\tif err := c.Answer", want: "in that order"},
		{old: answerThenToken, new: tokenThenAnswer, want: "waiting for the token read"},
		{old: "\tcfg = cfg.withDefaults()\n", new: "\tif c.Number() == \"\" {\n\t\treturn Report{}, nil\n\t}\n\tcfg = cfg.withDefaults()\n", want: "returns before it takes serving"},
		{old: "defer func() { <-serving }()", new: "defer func() { <-serving }()\n\t_ = len(serving)", want: "serving is named 4 times"},
		// #5252: the take waits for the call before, never past RingWait.
		{old: "\tdefault: // another call is served: wait for it to end, up to RingWait\n", new: "\tdefault:\n\t\treturn Report{}, ErrBusy\n\t}\n\tif false {\n", want: "in that order"},
		{old: "case <-cfg.After(cfg.RingWait):", new: "case <-cfg.After(cfg.MaxCall):", want: "in that order"},
		{old: "tctx, cancel := context.WithTimeoutCause(ctx, cfg.MaxCall, ErrTooLong)", new: "tctx, cancel := context.WithCancel(ctx)", want: "in that order"},
		// #5251 reviews: tctx and cancel, the grant's life and its end,
		// are set once and never written.
		{old: "rep, err := loop(tctx, cfg, c, token)", new: "tctx = ctx\n\trep, err := loop(tctx, cfg, c, token)", want: "writes tctx"},
		{old: "rep, err := loop(tctx, cfg, c, token)", new: "tctx, again := ctx, 0\n\t_ = again\n\trep, err := loop(tctx, cfg, c, token)", want: "writes tctx"},
		{old: "rep, err := loop(tctx, cfg, c, token)", new: "p := &tctx\n\t*p = ctx\n\trep, err := loop(tctx, cfg, c, token)", want: "writes tctx"},
		{old: "rep, err := loop(tctx, cfg, c, token)", new: "for _, tctx = range []context.Context{ctx} {\n\t}\n\trep, err := loop(tctx, cfg, c, token)", want: "writes tctx"},
		{old: "rep, err := loop(tctx, cfg, c, token)", new: "cancel = func() {}\n\trep, err := loop(tctx, cfg, c, token)", want: "writes cancel"},
		{old: "rep, err := loop(tctx, cfg, c, token)", new: "keepCancel(&cancel)\n\trep, err := loop(tctx, cfg, c, token)", extra: "import \"context\"\nfunc keepCancel(c *context.CancelFunc) { *c = func() {} }", want: "writes cancel"},
		// A grant made outside check, or by a fill that names no field;
		// Security's #5229 blocker first.
		{extra: "func unlive(g *grant) { *g = grant{r: g.r} }", want: "grant literal outside check"},
		{extra: "func mint() *grant { return &grant{r: P2, live: make(chan struct{})} }", want: "grant literal outside check"},
		{extra: "var minted = &grant{r: P2}", want: "grant literal outside check"},
		{extra: "func mint() grant { return grant{P2, nil} }", want: "grant literal outside check"},
		{extra: "type alias = grant\nfunc mint() []alias { return []alias{{P2, nil}} }", want: "grant literal outside check"},
		{old: "return &grant{r: P2, live: live}", new: "keepMint = func() *grant { return &grant{r: P2} }\n\t\treturn nil", extra: "var keepMint func() *grant", want: "grant literal outside check"},
		{extra: twin + "func mint() grant { return grant(twin{r: P2}) }", want: "conversion to grant"},
		{extra: twin + "func mint() *grant { return (*grant)(&twin{r: P2}) }", want: "conversion to grant"},
		{extra: "func mint[T ~struct { r Rung; live <-chan struct{} }]() T { return T{r: P2} }", want: "composite literal of a type parameter"},
		{extra: twin + "func conv[T, U ~struct { r Rung; live <-chan struct{} }](u U) T { return T(u) }", want: "conversion to a type parameter"},
		// Every way Go writes a field, on a grant.
		{extra: "func raise(g *grant) { g.r = P2 }", want: "writes r"},
		{extra: "func raise(g *grant) { g.r++ }", want: "writes r"},
		{extra: "func raise(g *grant) { g.r += 2 }", want: "writes r"},
		{extra: "func raise(g *grant) { p := &g.r; *p = P2 }", want: "writes r"},
		{extra: "func raise(g *grant) { for _, (g.r) = range []Rung{P2} {} }", want: "writes r"},
		{extra: "func raise(g *grant, c chan Rung) { select { case g.r = <-c: } }", want: "writes r"},
		{extra: "func (r *Rung) up() { *r = P2 }\nfunc raise(g *grant) { g.r.up() }", want: "writes r"},
		{extra: "type outer struct{ grant }\nfunc raise(o *outer) { o.r = P2 }", want: "writes r"},
		{extra: "func forever(g *grant) { g.live = make(chan struct{}) }", want: "writes live"},
		{old: "if g == nil || g.live == nil {", new: "if g == nil {\n\t\tg.live = nil", want: "writes live"},
		{old: "return &grant{r: P2, live: live}", new: "g := &grant{r: P2, live: live}\n\t\tg.live = nil\n\t\treturn g", want: "writes live"},
		// The kernel's Token.
		{extra: "func open(c *Config) { c.Token = func(string) bool { return true } }", want: "writes Token"},
		{old: "cfg = cfg.withDefaults()", new: "cfg = cfg.withDefaults()\n\tcfg.Token = func(k string) bool { return k == c.Number() }", want: "writes Token"},
		{extra: "func open(cfg Config) Config { return Config{Answerer: cfg.Answerer, Token: func(string) bool { return true }} }", want: "writes Token"},
		{extra: "var Open = Config{Token: func(string) bool { return true }}", want: "writes Token"},
		{extra: "func open(c Config) Config { return Config{c.Recognizer, c.Answerer, c.Synthesizer, c.Clips, c.Hold, 0, nil, nil, nil, 0, 0, 0, nil} }", want: "Config literal without keys"},
		{extra: "type cfgTwin struct { Recognizer Recognizer; Answerer Answerer; Synthesizer Synthesizer; Clips Clips; Hold func(string) bool; OneMomentAfter time.Duration; Now func() time.Time; After func(time.Duration) <-chan time.Time; Token func(keys string) bool; TokenWindow time.Duration; RingWait time.Duration; MaxCall time.Duration; Done func(Turn) }\nfunc open(c Config) Config { t := cfgTwin(c); t.Token = nil; return Config(t) }", want: "conversion to Config"},
		// Out of the type system's sight.
		{extra: "import \"unsafe\"\nvar _ unsafe.Pointer", want: "imports unsafe"},
		{extra: "import \"reflect\"\nvar _ reflect.Value", want: "imports reflect"},
	} {
		if strings.Contains(p.extra, "context.") && !strings.Contains(p.extra, "import") {
			p.extra = "import \"context\"\n" + p.extra
		}
		if strings.Contains(p.extra, "time.") && !strings.Contains(p.extra, "import") {
			p.extra = "import \"time\"\n" + p.extra
		}
		bad := check(p)
		if !slices.ContainsFunc(bad, func(b string) bool { return strings.Contains(b, p.want) }) {
			t.Errorf("probe %q %q -> %q: want %q, got %q", p.extra, p.old, p.new, p.want, bad)
		}
	}
	// A Rung is a label: holding, passing or returning one, from anywhere,
	// sets no call's rung. So these pass, and the check is not "no Rung
	// anywhere" (the inputs #5225's three rounds chased).
	for _, p := range []probe{
		{extra: "var Floor = P2"},
		{extra: "func Hook() Rung { return P2 }"},
		{extra: "type floored struct{ Config; Floor Rung }"},
		{extra: "func peek(g *grant) (Rung, bool) { return g.r, g.live == nil }"},
		{extra: "func keys(cfg Config) bool { return cfg.Token != nil && cfg.Token(\"1\") }"},
		// A whole-value write or copy moves only check's grants or zero
		// ones (Security on #5229, M2 and M4).
		{extra: "func copyOf(g *grant, src *grant) { *g = *src }"},
		{extra: "func copyAll(dst, src []grant) int { return copy(dst, src) }"},
		{extra: "func zero(g *grant) { var z grant; *g = z }"},
		// A grant kept past its call, by a package var (Security's M3 on
		// #5229) or a field: one call is served at a time and a grant dies
		// with its call, so it reads P0 in every later one
		// (TestAKeptGrantIsP0InTheNextCall).
		{extra: "var hot *grant\nfunc keep(a Ask) { hot = a.rung }\nfunc reuse(t string) Ask { return Ask{Text: t, rung: hot} }"},
		{extra: "type stash struct{ g *grant }\nvar kept stash\nfunc keep(a Ask) { kept.g = a.rung }"},
	} {
		if bad := check(p); len(bad) != 0 {
			t.Errorf("probe %q flagged: %q", p.extra, bad)
		}
	}
}

// An error that reaches the turn after it was stopped is a stop, not a
// failure: no error recorded and no failed clip. Through RunAt the stop must
// land between the turn's receive and its check, which no test can order,
// so this calls take directly with the call's context already done.
func TestErrorAfterAStopIsNotAFailure(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var played [][]byte
	play := func(pcm []byte, _ bool) bool { played = append(played, pcm); return true }
	cfg := Config{Clips: Clips{Failed: []byte("CLIP:failed")}}
	var tu Turn
	if cfg.take(ctx, sound{err: errors.New("boom")}, true, &tu, play) {
		t.Fatal("the answer went on after an error")
	}
	if tu.Err != nil || len(played) != 0 {
		t.Fatalf("stopped turn: err %v, played %q", tu.Err, played)
	}

	// The same error with the call still up is a failure.
	if cfg.take(context.Background(), sound{err: errors.New("boom")}, true, &tu, play) {
		t.Fatal("the answer went on after an error")
	}
	if tu.Err == nil || len(played) != 1 || string(played[0]) != "CLIP:failed" {
		t.Fatalf("failed turn: err %v, played %q", tu.Err, played)
	}
}

// A grant says P2 while its call is live and P0 after; no grant, and a
// zero one, say P0 (a zero grant's live is nil, which never closes).
func TestAGrantLivesWithItsCall(t *testing.T) {
	live := make(chan struct{})
	g := &grant{r: P2, live: live}
	for _, c := range []struct {
		g    *grant
		want Rung
	}{{nil, P0}, {&grant{}, P0}, {&grant{r: P2}, P0}, {g, P2}} {
		if got := c.g.level(); got != c.want {
			t.Fatalf("%+v says %v, want %v", c.g, got, c.want)
		}
	}
	close(live)
	if got := g.level(); got != P0 {
		t.Fatalf("a grant whose call ended says %v", got)
	}
}
