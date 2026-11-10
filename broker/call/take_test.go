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
	"os"
	"slices"
	"strings"
	"testing"
)

// RunAt lets the package's own tests hold a call at a chosen rung. It is in
// a _test.go file, so no importer of the package can reach it (#4949).
func RunAt(ctx context.Context, cfg Config, l Line, rung Rung) (Report, error) {
	token := make(chan Rung, 1)
	token <- rung
	return loop(ctx, cfg.withDefaults(), l, token)
}

// The rung is the call's, read from the token by Serve, never the caller's
// to choose (briefs/VOICE-ro.md rule 4, #4949). The check type-checks the
// package's non-test files and holds three rules, each a fixed rule rather
// than a list of evasions:
//
//   - loop is named exactly once, as the callee of a call in Serve's own
//     body, outside any func literal. loop is a plain unexported function,
//     so no importer can name it, and Go code gets a func only by naming
//     it: no interface, constraint, method value or embedding reaches it.
//     Serve is a function with no receiver, so no method value or interface
//     carries Serve either.
//   - Nothing loop or Serve can read, but loop's token channel, has a type
//     that can yield a Rung (#5217). Their inputs are their parameters
//     (Config, the Line, Incoming, the context, any added later) and the
//     package's variables; a type parameter counts by its constraint. A
//     type yields a Rung through pointers, slices, maps, chans, arrays,
//     structs, type arguments, func results, interface method results and
//     type terms, or a func param the reader hands out (a callback, or a
//     pointer the callee fills). A Rung the loop only hands out, as Ask does
//     to the answerer, is allowed. No generic is instantiated with a type
//     that carries a Rung, or with Config.
//   - Config.Token is only read: called, or compared with nil, and no Config
//     is built without field names or converted to or from another type. So
//     no non-test code in the package sets it, and only the wiring does
//     (#5219).
//
// What the check does not see, and review does: unsafe and reflection, and
// what loop or Serve compute from what they read, such as a conversion, a
// type assertion, a method of a named type, or a type defined from Rung.
// The Serve tests pin what Serve passes loop. A //go:linkname directive or
// an assembly file in a non-test file under broker/ (outside vendor/,
// third_party/, testdata/ and its allow list) is a tools/srclint.py failure
// in CI. Each probe below edits the package or adds a file, and must fail
// the check with the rule it names, so each rule's every condition bites.
func TestOnlyServeChoosesTheRung(t *testing.T) {
	fset := token.NewFileSet()
	imp := importer.ForCompiler(fset, "source", nil) // one importer: dependencies are read once
	// check applies each edit (old, new pairs: old must be in exactly one
	// file, and every occurrence there is replaced), adds extra as one more
	// file, and returns what breaks a rule.
	check := func(extra string, edits ...string) []string {
		ents, err := os.ReadDir(".")
		if err != nil {
			t.Fatal(err)
		}
		var names []string
		srcs := map[string]string{}
		for _, e := range ents {
			name := e.Name()
			if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
				continue
			}
			src, err := os.ReadFile(name)
			if err != nil {
				t.Fatal(err)
			}
			names, srcs[name] = append(names, name), string(src)
		}
		for i := 0; i+1 < len(edits); i += 2 {
			n := 0
			for _, name := range names {
				if strings.Contains(srcs[name], edits[i]) {
					srcs[name], n = strings.ReplaceAll(srcs[name], edits[i], edits[i+1]), n+1
				}
			}
			if n != 1 {
				t.Fatalf("probe edit %q is in %d files, not one", edits[i], n)
			}
		}
		if extra != "" {
			if strings.Contains(extra, "context.") {
				extra = "import \"context\"\n" + extra
			}
			names, srcs["probe.go"] = append(names, "probe.go"), "package call\n"+extra
		}
		var files []*ast.File
		for _, name := range names {
			f, err := parser.ParseFile(fset, name, srcs[name], 0)
			if err != nil {
				t.Fatal(err)
			}
			files = append(files, f)
		}
		if len(files) < 2 {
			t.Fatal("no source files read")
		}
		info := &types.Info{Uses: map[*ast.Ident]types.Object{}, Types: map[ast.Expr]types.TypeAndValue{}, Instances: map[*ast.Ident]types.Instance{}}
		pkg, err := (&types.Config{Importer: imp}).Check("call", fset, files, info)
		if err != nil {
			t.Fatal(err)
		}
		loopFn, _ := pkg.Scope().Lookup("loop").(*types.Func)
		serveFn, _ := pkg.Scope().Lookup("Serve").(*types.Func)
		rung, _ := pkg.Scope().Lookup("Rung").(*types.TypeName)
		cfgName, _ := pkg.Scope().Lookup("Config").(*types.TypeName)
		if loopFn == nil || serveFn == nil || rung == nil || cfgName == nil {
			t.Fatal("loop, Serve, Rung or Config is gone or changed kind: rewrite this check with the code, never the check alone")
		}
		cfgNamed, _ := cfgName.Type().(*types.Named)
		cfg, ok := cfgName.Type().Underlying().(*types.Struct)
		if !ok || cfgNamed == nil || cfgNamed.TypeParams().Len() > 0 {
			t.Fatal("Config is no longer a plain struct: rewrite this check with the code, never the check alone")
		}
		isCfg := func(t types.Type) bool {
			return t != nil && (types.Identical(t, cfgNamed) || types.Identical(t, types.NewPointer(cfgNamed)))
		}
		var bad []string

		// carries reports whether t can yield a Rung to the code holding a
		// value of it; out flips to "can be handed one" at each func param.
		type key struct {
			t   types.Type
			out bool
		}
		var seen map[key]bool // cycle stop, fresh for each input
		var carries func(t types.Type, out bool) bool
		both := func(t types.Type) bool { return carries(t, true) || carries(t, false) }
		carries = func(t types.Type, out bool) bool {
			k := key{t, out}
			if seen[k] {
				return false
			}
			seen[k] = true
			switch t := t.(type) {
			case *types.Alias:
				return carries(types.Unalias(t), out)
			case *types.Named:
				if t.Obj() == rung {
					return out
				}
				for i := 0; i < t.TypeArgs().Len(); i++ {
					if both(t.TypeArgs().At(i)) {
						return true
					}
				}
				return carries(t.Underlying(), out)
			case *types.TypeParam:
				return carries(t.Constraint(), out)
			case *types.Pointer: // the elements below can be written by either side
				return both(t.Elem())
			case *types.Slice:
				return both(t.Elem())
			case *types.Map:
				return both(t.Key()) || both(t.Elem())
			case *types.Chan:
				return both(t.Elem())
			case *types.Array:
				return carries(t.Elem(), out)
			case *types.Struct:
				for i := 0; i < t.NumFields(); i++ {
					if carries(t.Field(i).Type(), out) {
						return true
					}
				}
			case *types.Signature:
				for i := 0; i < t.Results().Len(); i++ {
					if carries(t.Results().At(i).Type(), out) {
						return true
					}
				}
				for i := 0; i < t.Params().Len(); i++ {
					if carries(t.Params().At(i).Type(), !out) {
						return true
					}
				}
			case *types.Interface:
				for i := 0; i < t.NumMethods(); i++ {
					if carries(t.Method(i).Type(), out) {
						return true
					}
				}
				for i := 0; i < t.NumEmbeddeds(); i++ {
					if carries(t.EmbeddedType(i), out) {
						return true
					}
				}
			case *types.Union:
				for i := 0; i < t.Len(); i++ {
					if carries(t.Term(i).Type(), out) {
						return true
					}
				}
			}
			return false
		}
		input := func(what string, pos token.Pos, typ types.Type) {
			seen = map[key]bool{}
			if carries(typ, true) {
				bad = append(bad, fmt.Sprintf("%s: %s (%s) carries a Rung", fset.Position(pos), what, typ))
			}
		}
		for _, fn := range []*types.Func{loopFn, serveFn} {
			for i := 0; i < fn.Signature().Params().Len(); i++ {
				p := fn.Signature().Params().At(i)
				if ch, ok := p.Type().(*types.Chan); ok && fn == loopFn && p.Name() == "token" && ch.Dir() == types.RecvOnly && types.Identical(ch.Elem(), rung.Type()) {
					continue
				}
				input(fn.Name()+"'s input "+p.Name(), p.Pos(), p.Type())
			}
		}
		for _, name := range pkg.Scope().Names() {
			if v, ok := pkg.Scope().Lookup(name).(*types.Var); ok {
				input("package variable "+name, v.Pos(), v.Type())
			}
		}
		for id, inst := range info.Instances {
			for i := 0; i < inst.TypeArgs.Len(); i++ {
				seen = map[key]bool{}
				if a := inst.TypeArgs.At(i); isCfg(a) || both(a) {
					bad = append(bad, fmt.Sprintf("%s: %s instantiated with %s", fset.Position(id.Pos()), id.Name, a))
				}
			}
		}
		var tokenField *types.Var
		for i := 0; i < cfg.NumFields(); i++ {
			if cfg.Field(i).Name() == "Token" {
				tokenField = cfg.Field(i)
			}
		}
		if tokenField == nil {
			t.Fatal("Config.Token is gone: rewrite this check with the code, never the check alone")
		}

		calls := 0
		for _, f := range files {
			for _, d := range f.Decls {
				fd, ok := d.(*ast.FuncDecl)
				serve := ok && fd.Recv == nil && fd.Name.Name == "Serve"
				var stack []ast.Node
				ast.Inspect(d, func(n ast.Node) bool {
					if n == nil {
						stack = stack[:len(stack)-1]
						return true
					}
					stack = append(stack, n)
					// A Config built without field names, or converted to or
					// from another type, can set or copy Token unnamed.
					switch n := n.(type) {
					case *ast.CompositeLit:
						if isCfg(info.TypeOf(n)) && len(n.Elts) > 0 {
							if _, keyed := n.Elts[0].(*ast.KeyValueExpr); !keyed {
								bad = append(bad, fset.Position(n.Pos()).String()+": Config literal without field names")
							}
						}
					case *ast.CallExpr:
						if tv := info.Types[n.Fun]; tv.IsType() && len(n.Args) == 1 && (isCfg(tv.Type) || isCfg(info.TypeOf(n.Args[0]))) && !types.Identical(tv.Type, info.TypeOf(n.Args[0])) {
							bad = append(bad, fset.Position(n.Pos()).String()+": Config converted to or from another type")
						}
					}
					id, ok := n.(*ast.Ident)
					if !ok {
						return true
					}
					parent := stack[len(stack)-2]
					switch info.Uses[id] {
					case loopFn:
						call, ok := parent.(*ast.CallExpr)
						lit := slices.ContainsFunc(stack, func(n ast.Node) bool { _, ok := n.(*ast.FuncLit); return ok })
						if serve && ok && call.Fun == id && !lit {
							calls++
						} else {
							bad = append(bad, fset.Position(id.Pos()).String()+": loop named outside a direct call in Serve")
						}
					case tokenField:
						sel, ok := parent.(*ast.SelectorExpr)
						read := false
						if ok && len(stack) > 2 {
							switch up := stack[len(stack)-3].(type) {
							case *ast.CallExpr:
								read = up.Fun == sel
							case *ast.BinaryExpr:
								nilID, isID := up.Y.(*ast.Ident)
								read = up.X == sel && isID && nilID.Name == "nil" && (up.Op == token.EQL || up.Op == token.NEQ)
							}
						}
						if !read {
							bad = append(bad, fset.Position(id.Pos()).String()+": Config.Token used other than called or compared with nil")
						}
					}
					return true
				})
			}
		}
		if calls != 1 {
			bad = append(bad, fmt.Sprintf("loop named outside a direct call in Serve: Serve calls loop %d times", calls))
		}
		return bad
	}

	if bad := check(""); len(bad) != 0 {
		t.Errorf("only Serve may choose the call's rung (briefs/VOICE-ro.md rule 4): loop is named once, as a direct call in Serve's body; nothing loop or Serve reads but token carries a Rung; Config.Token is only called or nil-checked, and Config is never unkeyed or converted. "+
			"If a refactor keeps that rule, change this check in the same PR as the code and add a probe for the new shape; never change the check alone.\n%s", strings.Join(bad, "\n"))
	}
	const sig = "func(context.Context, Config, Line, <-chan Rung) (Report, error)"
	const twin = "import \"time\"\ntype twin struct {\n\tRecognizer Recognizer\n\tAnswerer Answerer\n\tSynthesizer Synthesizer\n\tClips Clips\n\tHold func(string) bool\n\tOneMomentAfter time.Duration\n\tNow func() time.Time\n\tAfter func(time.Duration) <-chan time.Time\n\tToken func(string) bool\n\tTokenWindow time.Duration\n\tDone func(Turn)\n}\n"
	const loopSig = "func loop(ctx context.Context, cfg Config, l Line, token <-chan Rung)"
	const direct = "return loop(ctx, cfg, c, token)"
	type probe struct {
		want, extra string // want is in the failure the probe must cause
		edits       []string
	}
	probes := []probe{
		// Lens and Security on #5211, and main's old Run.
		{want: "loop named", extra: "var Run = loop"},
		{want: "loop named", extra: "func Run(ctx context.Context, cfg Config, l Line, r Rung) (Report, error) { c := make(chan Rung, 1); c <- r; return loop(ctx, cfg, l, c) }"},
		{want: "loop named", extra: "func RunP(ctx context.Context, cfg Config, l Line, r *Rung) (Report, error) { c := make(chan Rung, 1); c <- *r; return loop(ctx, cfg, l, c) }"},
		{want: "loop named", extra: "func RunU(ctx context.Context, cfg Config, l Line, u interface{ R() Rung }) (Report, error) { c := make(chan Rung, 1); c <- u.R(); return loop(ctx, cfg, l, c) }"},
		{want: "loop named", extra: "type Rs = []Rung\nfunc RunS(ctx context.Context, cfg Config, l Line, r Rs) (Report, error) { c := make(chan Rung, 1); c <- r[0]; return loop(ctx, cfg, l, c) }"},
		{want: "loop named", extra: "func RunG[T ~int](ctx context.Context, cfg Config, l Line, r T) (Report, error) { c := make(chan Rung, 1); c <- Rung(r); return loop(ctx, cfg, l, c) }"},
		{want: "loop named", extra: "func Runner() " + sig + " { return loop }"},
		{want: "loop named", extra: "type ctl struct{}\nfunc (ctl) Run(ctx context.Context, cfg Config, l Line, r Rung) (Report, error) { c := make(chan Rung, 1); c <- r; return loop(ctx, cfg, l, c) }\nfunc Ctl() ctl { return ctl{} }"},
		// Security on #5211 at e104cea: the interface and constraint routes
		// to a method. loop is a func, so each has to name it.
		{want: "loop named", extra: "type runner " + sig + "\nfunc (f runner) run(ctx context.Context, cfg Config, l Line, c <-chan Rung) (Report, error) { return f(ctx, cfg, l, c) }\ntype runs interface{ run(context.Context, Config, Line, <-chan Rung) (Report, error) }\nfunc ServeAt(ctx context.Context, cfg Config, l Line, r Rung) (Report, error) { var x runs = runner(loop); c := make(chan Rung, 1); c <- r; return x.run(ctx, cfg, l, c) }"},
		{want: "loop named", extra: "func serveGen[T ~" + sig + "](ctx context.Context, f T, cfg Config, l Line, r Rung) (Report, error) { c := make(chan Rung, 1); c <- r; return f(ctx, cfg, l, c) }\nfunc ServeGen(ctx context.Context, cfg Config, l Line, r Rung) (Report, error) { return serveGen(ctx, loop, cfg, l, r) }"},
		// No new export, but loop named outside Serve's body.
		{want: "loop named", extra: "var hook = loop"},
		{want: "loop named", extra: "func init() { go loop(context.Background(), Config{}, nil, nil) }"},
		{want: "loop named", extra: "func (cfg Config) Serve(ctx context.Context, l Line, r Rung) (Report, error) { c := make(chan Rung, 1); c <- r; return loop(ctx, cfg, l, c) }"},
		// Serve's body edited (#5219): loop inside a func literal that
		// escapes, and loop as an argument rather than the callee.
		{want: "loop named", extra: "var kept func() (Report, error)", edits: []string{direct, "kept = func() (Report, error) { return loop(ctx, cfg, c, token) }\n\treturn Report{}, nil"}},
		{want: "loop named", extra: "var kept " + sig + "\nfunc keep(f " + sig + ") " + sig + " { kept = f; return f }", edits: []string{direct, "return keep(loop)(ctx, cfg, c, token)"}},

		// An input of loop or Serve carries a Rung (#5217; Security and L3 on
		// #5225): the line, Incoming, a new or renamed parameter, a token
		// that is not a receive-only Rung channel, a type parameter by
		// method or by term, and package variables.
		{want: "loop's input l", edits: []string{"type Line interface {\n", "type Line interface {\n\tFloor() Rung\n"}},
		{want: "Serve's input c", edits: []string{"type Incoming interface {\n", "type Incoming interface {\n\tFloor() Rung\n"}},
		{want: "Serve's input c", edits: []string{"type Line interface {\n", "type Line interface {\n\tFloor() Rung\n"}}, // each input is walked afresh
		{want: "Serve's input token", edits: []string{"c Incoming, ownerNumber string)", "c Incoming, ownerNumber string, token <-chan Rung)",
			"token := make(chan Rung, 1)\n\tgo func() { token <- cfg.token(tctx, c) }()", "_ = tctx"}},
		{want: "loop's input floor", edits: []string{"token <-chan Rung)", "token <-chan Rung, floor ...func() Rung)"}},
		{want: "loop's input tok", extra: "var token chan Rung", edits: []string{"l Line, token <-chan Rung)", "l Line, tok <-chan Rung)"}},
		{want: "loop's input token", edits: []string{"l Line, token <-chan Rung)", "l Line, token chan Rung)"}},
		{want: "loop's input token", extra: "type fl Rung\nfunc (f fl) Floor() Rung { return Rung(f) }", edits: []string{
			"token <-chan Rung)", "token <-chan interface{ Floor() Rung })", "known(r)", "known(r.Floor())",
			"token := make(chan Rung, 1)\n\tgo func() { token <- cfg.token(tctx, c) }()", "token := make(chan interface{ Floor() Rung }, 1)\n\tgo func() { token <- fl(cfg.token(tctx, c)) }()"}},
		{want: "loop's input f", extra: "type fl Rung\nfunc (f fl) Floor() Rung { return Rung(f) }", edits: []string{
			loopSig, "func loop[F interface{ Floor() Rung }](ctx context.Context, cfg Config, l Line, token <-chan Rung, f F)", direct, "return loop(ctx, cfg, c, token, fl(P0))"}},
		{want: "loop's input f", edits: []string{loopSig, "func loop[F interface{ ~float64 | Rung }](ctx context.Context, cfg Config, l Line, token <-chan Rung, f F)", direct, "return loop(ctx, cfg, c, token, P0)"}},
		{want: "loop's input l", edits: []string{loopSig, "func loop[T interface{ Line; Floor() Rung }](ctx context.Context, cfg Config, l T, token <-chan Rung)", "type Incoming interface {\n", "type Incoming interface {\n\tFloor() Rung\n"}},
		{want: "loop's input f", extra: "type floorer interface{ Floor() Rung }\ntype fl Rung\nfunc (f fl) Floor() Rung { return Rung(f) }", edits: []string{
			loopSig, "func loop[F floorer](ctx context.Context, cfg Config, l Line, token <-chan Rung, f F)", direct, "return loop(ctx, cfg, c, token, fl(P0))"}},
		{want: "package variable Floor ", extra: "var Floor = P0"},
		{want: "package variable floorFn", extra: "var floorFn func() Rung\nfunc SetFloor(f func() Rung) { floorFn = f }"},
		{want: "package variable FloorFn", extra: "var FloorFn = func() Rung { return P0 }"},
		{want: "package variable Floors", extra: "var Floors = make(chan Rung, 1)"},
		{want: "package variable floorR", extra: "var floorR Rung\nfunc SetFloor(r Rung) { floorR = r }"},
		{want: "instantiated with", extra: "func pick[T any](v T) T { return v }\nvar _ = pick[Rung]"},

		// Config.Token set or copied in the package (#5219; Security and L3
		// on #5225), named or not.
		{want: "Config.Token used", extra: "var _ = Config{Token: func(string) bool { return true }}"},
		{want: "Config.Token used", extra: "func open(cfg *Config) { cfg.Token = func(string) bool { return true } }"},
		{want: "Config.Token used", extra: "func tok(cfg Config) func(string) bool { return cfg.Token }"},
		{want: "Config.Token used", extra: "func leak(cfg Config) []func(string) bool { return append([]func(string) bool{}, cfg.Token) }"},
		{want: "Config.Token used", extra: "func g(func(string) bool) {}\nfunc pass(cfg Config) { g(cfg.Token) }"},
		{want: "Config.Token used", edits: []string{"cfg = cfg.withDefaults()", "cfg = cfg.withDefaults()\n\tcfg.Token = func(string) bool { return true }"}},
		{want: "Config literal without field names", edits: []string{"cfg = cfg.withDefaults()", "cfg = cfg.withDefaults()\n\tcfg = Config{cfg.Recognizer, cfg.Answerer, cfg.Synthesizer, cfg.Clips, cfg.Hold, cfg.OneMomentAfter, cfg.Now, cfg.After, func(k string) bool { return k == c.Number() }, cfg.TokenWindow, cfg.Done}"}},
		{want: "Config converted", extra: twin + "func peek(c Config) func(string) bool { return twin(c).Token }"},
		{want: "Config converted", extra: twin + "func mk() Config { return Config(twin{Token: func(string) bool { return true }}) }"},
		{want: "Config converted", extra: twin + "func poke(c *Config) { (*twin)(c).Token = nil }"},
		{want: "instantiated with", extra: twin + "func conv[T, U Config | twin](t T) U { return U(t) }\nfunc peek(c Config) func(string) bool { return conv[Config, twin](c).Token }"},
	}
	// Config carries a Rung (#5217), one field of each shape.
	for _, f := range []string{
		"Rung", "*Rung", "[]Rung", "[1]Rung", "map[string]Rung", "map[Rung]bool", "<-chan Rung", "chan<- Rung",
		"struct{ R Rung }", "*Report", "func() Rung", "func() (int, Rung)", "interface{ R() Rung }",
		"func(func(Rung))", "func(*Rung)", "func(...Rung)", "func(map[string]Rung)", "func(chan Rung)", "tag[func(Rung)]", "floor", "atomicRung", "holder[Rung]", "tag[Rung]",
	} {
		probes = append(probes, probe{want: "loop's input cfg",
			extra: "import \"sync/atomic\"\ntype floor = struct{ get func() Rung }\ntype atomicRung = atomic.Pointer[Rung]\ntype holder[T any] struct{ f func() T }\ntype tag[T any] struct{ p *int }",
			edits: []string{"type Config struct {\n", "type Config struct {\n\tX " + f + "\n"}})
	}
	for _, p := range probes {
		if bad := strings.Join(check(p.extra, p.edits...), "\n"); !strings.Contains(bad, p.want) {
			t.Errorf("the check does not fail with %q for %q + %q; it gives:\n%s", p.want, p.edits, p.extra, bad)
		}
	}
	// What the loop only hands out is allowed: the guard is not "no Rung
	// anywhere", which Ask to the answerer would fail.
	for _, p := range []probe{
		{edits: []string{"type Config struct {\n", "type Config struct {\n\tX func(Rung)\n"}},
		{edits: []string{"type Config struct {\n", "type Config struct {\n\tX func(Ask) error\n"}},
		{edits: []string{"type Config struct {\n", "type Config struct {\n\tX interface{ Set(Rung) }\n"}},
		{extra: "var sink func(Rung)"},
	} {
		if bad := check(p.extra, p.edits...); len(bad) != 0 {
			t.Errorf("the check fails a Rung the loop only hands out, %q + %q: %v", p.edits, p.extra, bad)
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
