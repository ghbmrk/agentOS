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
	"time"
)

// RunAt lets the package's own tests hold a call at a chosen rung. It is in
// a _test.go file, so no importer of the package can reach it (#4949), and
// the guard below reads only the non-test files.
func RunAt(ctx context.Context, cfg Config, l Line, rung Rung) (Report, error) {
	cr := &callRung{ready: make(chan struct{}), r: rung}
	close(cr.ready)
	return loop(ctx, cfg.withDefaults(), l, cr)
}

// The rung is the call's, set by the speed-dial check, never the caller's
// to choose (briefs/VOICE-ro.md rule 4, CH-5, #4949). The answerer learns
// it only from Ask.Rung, which reads the call's callRung. So the guard does
// not trace what could carry a rung; it pins the few names that can make
// one, by the rules below, over the type-checked non-test files:
//
//  1. loop is named once, as the callee of a call in Serve's body outside
//     any func literal, so only Serve, which answers only the owner's
//     number, runs a call. check is named only as the callee of calls in
//     token's body outside any func literal.
//  2. callRung.r is written only in check and callRung.live only in Serve,
//     outside any func literal, and Config.Token is written nowhere: a
//     field is written by assigning it, incrementing it, taking its
//     address, ranging into it, calling a method on it, or naming it as a
//     composite literal key.
//  3. No callRung or Config literal leaves out its keys, nothing converts
//     to either (or to a pointer to either), and no composite literal or
//     conversion has a type parameter as its type. Those are the ways Go
//     fills a struct without naming its fields.
//  4. No non-test file imports unsafe, reflect or C.
//
// callRung is unexported, so no other package can make one, and Ask's
// rung is unexported, so no other package can set it. An Ask kept from a
// call reads P0 once Serve returns. What these rules leave to review:
// what check, token and Serve do with their inputs (the Serve and token
// tests pin it); //go:linkname and assembly (tools/srclint.py fails them in
// CI); and an Ask from one live call fed into another live call. If a
// refactor keeps the rule but breaks the check, change the check in the
// same PR as the code, with a probe for the new shape, never on its own.
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
		crSt, cfgSt := under("callRung"), under("Config")
		tokenFn, _, _ := types.LookupFieldOrMethod(pkg.Scope().Lookup("Config").Type(), false, pkg, "token")
		if _, ok := tokenFn.(*types.Func); !ok {
			t.Fatal("Config.token is gone: rewrite this check with the code")
		}
		// Each guarded name, and the one func that may use it (nil: none).
		callIn := map[types.Object]types.Object{loopFn: serve, checkFn: tokenFn}
		writeIn := map[types.Object]types.Object{field(crSt, "r"): checkFn, field(crSt, "live"): serve, field(cfgSt, "Token"): nil}
		guarded := func(t types.Type) string {
			if p, ok := t.Underlying().(*types.Pointer); ok {
				t = p.Elem()
			}
			switch {
			case func() bool { _, ok := t.(*types.TypeParam); return ok }():
				return "a type parameter"
			case types.Identical(t.Underlying(), crSt):
				return "callRung"
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
						if in, ok := writeIn[obj]; ok {
							e, up := ast.Node(n), parent(1)
							if kv, ok := up.(*ast.KeyValueExpr); ok && kv.Key == n {
								up = kv // a composite literal key sets the field
							} else if sel, ok := up.(*ast.SelectorExpr); ok && sel.Sel == n {
								e, up = sel, parent(2)
							}
							var write bool
							switch up := up.(type) {
							case *ast.KeyValueExpr:
								write = up.Key == n
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
							if write && (in == nil || encl != in || lit) {
								where := "outside any func"
								if in != nil {
									where = "outside " + in.Name()
								}
								at(n, "writes %s %s", obj.Name(), where)
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
		t.Errorf("the call's rung can be set other than by check, or the loop entered other than through Serve:\n%s\n"+
			"Rule: only check sets a call's rung, only token calls check, and only Serve calls loop. If a refactor keeps that rule, change this check with the code, with a probe for the new shape.", strings.Join(bad, "\n"))
	}
	const cr3 = "type twin struct { ready chan struct{}; r Rung; live <-chan struct{} }\n"
	for _, p := range []probe{
		// Lens and Security on #5211, and main's old Run: loop named
		// outside Serve.
		{extra: "var Run = loop", want: "loop is named"},
		{extra: "func Run(ctx context.Context, cfg Config, l Line) (Report, error) { return loop(ctx, cfg, l, nil) }", want: "loop is named"},
		{extra: "func Runner() func(context.Context, Config, Line, *callRung) (Report, error) { return loop }", want: "loop is named"},
		{extra: "type ctl struct{}\nfunc (ctl) Run(ctx context.Context, cfg Config, l Line) (Report, error) { return loop(ctx, cfg, l, nil) }", want: "loop is named"},
		{extra: "func init() { go loop(context.Background(), Config{}, nil, nil) }", want: "loop is named"},
		{extra: "func (cfg Config) Serve(ctx context.Context, l Line) (Report, error) { return loop(ctx, cfg, l, nil) }", want: "loop is named"},
		// #5219 item 1: inside Serve, but not a direct call.
		{old: "return loop(ctx, cfg, c, cr)", new: "keep = func() { loop(ctx, cfg, c, cr) }\n\treturn Report{}, nil", extra: "var keep func()", want: "loop is named"},
		{old: "return loop(ctx, cfg, c, cr)", new: "return id(loop)(ctx, cfg, c, cr)", extra: "func id[T any](t T) T { return t }", want: "loop is named"},
		{old: "return loop(ctx, cfg, c, cr)", new: "loop(ctx, cfg, c, cr)\n\treturn loop(ctx, cfg, c, cr)", want: "Serve calls loop 2 times"},
		// check named outside token, or not as a direct call.
		{extra: "var Check = check", want: "check is named"},
		{extra: "func raise(cfg Config, cr *callRung, l Incoming) { check(cfg, cr, l.Number()) }", want: "check is named"},
		{old: "check(cfg, cr, b.String())\n\t\t\treturn\n\t\tcase", new: "keepCheck = func(k string) { check(cfg, cr, k) }\n\t\t\treturn\n\t\tcase", extra: "var keepCheck func(string)", want: "check is named"},
		// The rung set outside check: every way Go writes a field.
		{extra: "func raise(cr *callRung) { cr.r = P2 }", want: "writes r outside check"},
		{extra: "func raise(cr *callRung) { cr.r++ }", want: "writes r outside check"},
		{extra: "func raise(cr *callRung) { cr.r += 2 }", want: "writes r outside check"},
		{extra: "func raise(cr *callRung) { p := &cr.r; *p = P2 }", want: "writes r outside check"},
		{extra: "func raise(cr *callRung) { for _, (cr.r) = range []Rung{P2} {} }", want: "writes r outside check"},
		{extra: "func raise(cr *callRung, c chan Rung) { select { case cr.r = <-c: } }", want: "writes r outside check"},
		{extra: "func (r *Rung) up() { *r = P2 }\nfunc raise(cr *callRung) { cr.r.up() }", want: "writes r outside check"},
		{extra: "func mint() *callRung { c := &callRung{ready: make(chan struct{}), r: P2}; close(c.ready); return c }", want: "writes r outside check"},
		{extra: "type outer struct{ callRung }\nfunc raise(o *outer) { o.r = P2 }", want: "writes r outside check"},
		{old: "cr.r = P2", new: "keepRaise = func(c *callRung) { c.r = P2 }", extra: "var keepRaise func(*callRung)", want: "writes r outside check"},
		{old: "return cr.r\n", new: "cr.r = P2\n\t\treturn cr.r\n", want: "writes r outside check"},
		// Struct fills that name no field.
		{extra: "func mint() callRung { return callRung{nil, P2, nil} }", want: "callRung literal without keys"},
		{extra: "type alias = callRung\nfunc mint() []alias { return []alias{{nil, P2, nil}} }", want: "callRung literal without keys"},
		{extra: cr3 + "func mint() callRung { return callRung(twin{r: P2}) }", want: "conversion to callRung"},
		{extra: cr3 + "func mint() *callRung { return (*callRung)(&twin{r: P2}) }", want: "conversion to callRung"},
		{extra: "func mint[T ~struct { ready chan struct{}; r Rung; live <-chan struct{} }]() T { return T{r: P2} }", want: "composite literal of a type parameter"},
		{extra: cr3 + "func conv[T, U ~struct { ready chan struct{}; r Rung; live <-chan struct{} }](u U) T { return T(u) }", want: "conversion to a type parameter"},
		// A call that outlives its Serve, and the kernel's Token.
		{extra: "func forever(cr *callRung) { cr.live = nil }", want: "writes live outside Serve"},
		{extra: "func open(c *Config) { c.Token = func(string) bool { return true } }", want: "writes Token outside any func"},
		{old: "cfg = cfg.withDefaults()", new: "cfg = cfg.withDefaults()\n\tcfg.Token = func(k string) bool { return k == c.Number() }", want: "writes Token outside any func"},
		{extra: "func open(cfg Config) Config { return Config{Answerer: cfg.Answerer, Token: func(string) bool { return true }} }", want: "writes Token outside any func"},
		{extra: "var Open = Config{Token: func(string) bool { return true }}", want: "writes Token outside any func"},
		{extra: "var minted = &callRung{r: P2}", want: "writes r outside check"},
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
		{extra: "func peek(cr *callRung) (Rung, bool) { return cr.r, cr.live == nil }"},
		{extra: "func keys(cfg Config) bool { return cfg.Token != nil && cfg.Token(\"1\") }"},
		{extra: "func copyOf(cr *callRung) callRung { return *cr }"},
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

// A callRung whose token is still being read is P0, at once: check sets r
// before ready closes, so r means nothing until then.
func TestARungNotYetReadIsP0(t *testing.T) {
	cr := &callRung{ready: make(chan struct{}), r: P2}
	got := make(chan Rung, 1)
	go func() { got <- cr.level() }()
	select {
	case r := <-got:
		if r != P0 {
			t.Fatalf("a rung still being read says %v", r)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("level waited for the token")
	}
	close(cr.ready)
	if r := cr.level(); r != P2 {
		t.Fatalf("a read rung says %v", r)
	}
}
