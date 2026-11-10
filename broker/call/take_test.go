package call

// REQ: CH-5

import (
	"context"
	"errors"
	"fmt"
	"go/ast"
	"go/importer"
	"go/parser"
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
//     token's body outside any func literal.
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
// token tests pin it); //go:linkname and assembly (tools/srclint.py fails
// them in CI); and a grant from one live call used in another live call.
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
		gSt, cfgSt := under("grant"), under("Config")
		tokenFn, _, _ := types.LookupFieldOrMethod(pkg.Scope().Lookup("Config").Type(), false, pkg, "token")
		if _, ok := tokenFn.(*types.Func); !ok {
			t.Fatal("Config.token is gone: rewrite this check with the code")
		}
		// Each guarded call, and the one func that may make it; and the
		// fields nothing may write.
		callIn := map[types.Object]types.Object{loopFn: serve, checkFn: tokenFn}
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
		var bad []string
		at := func(n ast.Node, msg string, a ...any) {
			bad = append(bad, fset.Position(n.Pos()).String()+": "+fmt.Sprintf(msg, a...))
		}
		calls := 0
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
						if in, ok := callIn[obj]; ok {
							call, isCall := parent(1).(*ast.CallExpr)
							if encl == in && isCall && call.Fun == n && !lit {
								if obj == loopFn {
									calls++
								}
							} else {
								at(n, "%s is named other than as a direct call in %s", obj.Name(), in.Name())
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
		return bad
	}

	if bad := check(probe{}); len(bad) != 0 {
		t.Errorf("a grant can be made other than by check, or the loop entered other than through Serve:\n%s\n"+
			"Rule: only check makes a grant, nothing writes one, only token calls check, and only Serve calls loop. If a refactor keeps that rule, change this check with the code, with a probe for the new shape.", strings.Join(bad, "\n"))
	}
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
		{old: "return loop(ctx, cfg, c, token)", new: "keep = func() { loop(ctx, cfg, c, token) }\n\treturn Report{}, nil", extra: "var keep func()", want: "loop is named"},
		{old: "return loop(ctx, cfg, c, token)", new: "return id(loop)(ctx, cfg, c, token)", extra: "func id[T any](t T) T { return t }", want: "loop is named"},
		{old: "return loop(ctx, cfg, c, token)", new: "loop(ctx, cfg, c, token)\n\treturn loop(ctx, cfg, c, token)", want: "Serve calls loop 2 times"},
		// check named outside token, or not as a direct call.
		{extra: "var Check = check", want: "check is named"},
		{extra: "func raise(cfg Config, l Incoming) *grant { return check(cfg, nil, l.Number()) }", want: "check is named"},
		{old: "return check(cfg, ctx.Done(), b.String())\n\t\tcase <-ctx", new: "keepCheck = func(k string) *grant { return check(cfg, nil, k) }\n\t\t\treturn nil\n\t\tcase <-ctx", extra: "var keepCheck func(string) *grant", want: "check is named"},
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
		{extra: "func open(c Config) Config { return Config{c.Recognizer, c.Answerer, c.Synthesizer, c.Clips, c.Hold, 0, nil, nil, nil, 0, nil} }", want: "Config literal without keys"},
		{extra: "type cfgTwin struct { Recognizer Recognizer; Answerer Answerer; Synthesizer Synthesizer; Clips Clips; Hold func(string) bool; OneMomentAfter time.Duration; Now func() time.Time; After func(time.Duration) <-chan time.Time; Token func(keys string) bool; TokenWindow time.Duration; Done func(Turn) }\nfunc open(c Config) Config { t := cfgTwin(c); t.Token = nil; return Config(t) }", want: "conversion to Config"},
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
