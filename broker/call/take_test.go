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
//   - Config's fields carry no Rung: no field's type yields one to the loop,
//     through pointers, slices, maps, chans, arrays, structs, type arguments,
//     func results, interface method results, or a func param the loop hands
//     out (a callback or a pointer the callee fills). A Rung the loop only
//     passes out, as Ask does to the answerer, is allowed (#5217).
//   - Config.Token is only read: called, or compared with nil. No non-test
//     code in the package sets it, so only the wiring does (#5219).
//
// What the check does not see: unsafe and reflection, and what loop or
// Serve compute from their inputs (a conversion, a type assertion), which
// are review's, with the Serve tests pinning what Serve passes loop. A
// //go:linkname directive or an assembly file, in this package or another,
// is a tools/srclint.py failure in CI. Each probe below edits the package
// or adds a file, and must fail the check, so each rule is shown to bite.
func TestOnlyServeChoosesTheRung(t *testing.T) {
	fset := token.NewFileSet()
	imp := importer.ForCompiler(fset, "source", nil) // one importer: dependencies are read once
	// check applies the edit old -> new (old must occur once in the
	// package), adds extra as one more file, and returns what breaks a rule.
	check := func(old, new, extra string) []string {
		ents, err := os.ReadDir(".")
		if err != nil {
			t.Fatal(err)
		}
		var files []*ast.File
		edited := old == ""
		for _, e := range ents {
			name := e.Name()
			if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
				continue
			}
			src, err := os.ReadFile(name)
			if err != nil {
				t.Fatal(err)
			}
			if old != "" && strings.Contains(string(src), old) {
				if edited || strings.Count(string(src), old) != 1 {
					t.Fatalf("probe edit %q does not occur exactly once", old)
				}
				src, edited = []byte(strings.Replace(string(src), old, new, 1)), true
			}
			f, err := parser.ParseFile(fset, name, src, 0)
			if err != nil {
				t.Fatal(err)
			}
			files = append(files, f)
		}
		if len(files) == 0 || !edited {
			t.Fatalf("no source files read, or probe edit %q not found", old)
		}
		if extra != "" {
			f, err := parser.ParseFile(fset, "probe.go", "package call\n"+extra, 0)
			if err != nil {
				t.Fatal(err)
			}
			files = append(files, f)
		}
		info := &types.Info{Uses: map[*ast.Ident]types.Object{}}
		pkg, err := (&types.Config{Importer: imp}).Check("call", fset, files, info)
		if err != nil {
			t.Fatal(err)
		}
		loopFn, _ := pkg.Scope().Lookup("loop").(*types.Func)
		rung, _ := pkg.Scope().Lookup("Rung").(*types.TypeName)
		cfgName, _ := pkg.Scope().Lookup("Config").(*types.TypeName)
		if loopFn == nil || rung == nil || cfgName == nil {
			t.Fatal("loop, Rung or Config is gone or changed kind: rewrite this check with the code, never the check alone")
		}
		cfg, ok := cfgName.Type().Underlying().(*types.Struct)
		if !ok {
			t.Fatal("Config is no longer a struct: rewrite this check with the code, never the check alone")
		}
		var bad []string

		// carries reports whether t can yield a Rung to the code holding a
		// value of it; out flips to "can be handed one" at each func param.
		type key struct {
			t   types.Type
			out bool
		}
		seen := map[key]bool{}
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
			}
			return false
		}
		var tokenField *types.Var
		for i := 0; i < cfg.NumFields(); i++ {
			f := cfg.Field(i)
			if carries(f.Type(), true) {
				bad = append(bad, fset.Position(f.Pos()).String()+": Config."+f.Name()+" carries a Rung")
			}
			if f.Name() == "Token" {
				tokenField = f
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
			bad = append(bad, fmt.Sprintf("Serve calls loop %d times", calls))
		}
		return bad
	}

	if bad := check("", "", ""); len(bad) != 0 {
		t.Errorf("only Serve may choose the call's rung (briefs/VOICE-ro.md rule 4): loop is named once, as a direct call in Serve's body; Config carries no Rung; Config.Token is only called or nil-checked. "+
			"If a refactor keeps that rule, change this check in the same PR as the code and add a probe for the new shape; never change the check alone.\n%s", strings.Join(bad, "\n"))
	}
	const sig = "func(context.Context, Config, Line, <-chan Rung) (Report, error)"
	type probe struct{ old, new, extra string }
	var probes []probe
	for _, p := range []string{
		// Lens and Security on #5211, and main's old Run.
		"var Run = loop",
		"func Run(ctx context.Context, cfg Config, l Line, r Rung) (Report, error) { c := make(chan Rung, 1); c <- r; return loop(ctx, cfg, l, c) }",
		"func RunP(ctx context.Context, cfg Config, l Line, r *Rung) (Report, error) { c := make(chan Rung, 1); c <- *r; return loop(ctx, cfg, l, c) }",
		"func RunU(ctx context.Context, cfg Config, l Line, u interface{ R() Rung }) (Report, error) { c := make(chan Rung, 1); c <- u.R(); return loop(ctx, cfg, l, c) }",
		"type Rs = []Rung\nfunc RunS(ctx context.Context, cfg Config, l Line, r Rs) (Report, error) { c := make(chan Rung, 1); c <- r[0]; return loop(ctx, cfg, l, c) }",
		"func RunG[T ~int](ctx context.Context, cfg Config, l Line, r T) (Report, error) { c := make(chan Rung, 1); c <- Rung(r); return loop(ctx, cfg, l, c) }",
		"func Runner() " + sig + " { return loop }",
		"type ctl struct{}\nfunc (ctl) Run(ctx context.Context, cfg Config, l Line, r Rung) (Report, error) { c := make(chan Rung, 1); c <- r; return loop(ctx, cfg, l, c) }\nfunc Ctl() ctl { return ctl{} }",
		// Security on #5211 at e104cea: the interface and constraint routes
		// to a method. loop is a func, so each has to name it.
		"type runner " + sig + "\nfunc (f runner) run(ctx context.Context, cfg Config, l Line, c <-chan Rung) (Report, error) { return f(ctx, cfg, l, c) }\ntype runs interface{ run(context.Context, Config, Line, <-chan Rung) (Report, error) }\nfunc ServeAt(ctx context.Context, cfg Config, l Line, r Rung) (Report, error) { var x runs = runner(loop); c := make(chan Rung, 1); c <- r; return x.run(ctx, cfg, l, c) }",
		"func serveGen[T ~" + sig + "](ctx context.Context, f T, cfg Config, l Line, r Rung) (Report, error) { c := make(chan Rung, 1); c <- r; return f(ctx, cfg, l, c) }\nfunc ServeGen(ctx context.Context, cfg Config, l Line, r Rung) (Report, error) { return serveGen(ctx, loop, cfg, l, r) }",
		// No new export, but loop named outside Serve's body.
		"var hook = loop",
		"func init() { go loop(context.Background(), Config{}, nil, nil) }",
		"func (cfg Config) Serve(ctx context.Context, l Line, r Rung) (Report, error) { c := make(chan Rung, 1); c <- r; return loop(ctx, cfg, l, c) }",
		// Config.Token set in the package (#5219).
		"var _ = Config{Token: func(string) bool { return true }}",
		"func open(cfg *Config) { cfg.Token = func(string) bool { return true } }",
		"func tok(cfg Config) func(string) bool { return cfg.Token }",
		"func leak(cfg Config) []func(string) bool { return append([]func(string) bool{}, cfg.Token) }",
	} {
		probes = append(probes, probe{extra: p})
	}
	// Serve's body edited (#5219): loop inside a func literal that escapes,
	// and loop as an argument rather than the callee.
	direct := "return loop(ctx, cfg, c, token)"
	probes = append(probes,
		probe{direct, "kept = func() (Report, error) { return loop(ctx, cfg, c, token) }\n\treturn Report{}, nil", "var kept func() (Report, error)"},
		probe{direct, "return keep(loop)(ctx, cfg, c, token)", "var kept " + sig + "\nfunc keep(f " + sig + ") " + sig + " { kept = f; return f }"},
		probe{"cfg = cfg.withDefaults()", "cfg = cfg.withDefaults()\n\tcfg.Token = func(string) bool { return true }", ""},
	)
	// Config carries a Rung (#5217), one field of each shape.
	for _, f := range []string{
		"Rung", "*Rung", "[]Rung", "[1]Rung", "map[string]Rung", "map[Rung]bool", "<-chan Rung", "chan<- Rung",
		"struct{ R Rung }", "*Report", "func() Rung", "func() (int, Rung)", "interface{ R() Rung }",
		"func(func(Rung))", "func(*Rung)", "func(...Rung)", "floor", "atomicRung", "holder[Rung]", "tag[Rung]",
	} {
		probes = append(probes, probe{"type Config struct {\n", "type Config struct {\n\tX " + f + "\n",
			"import \"sync/atomic\"\ntype floor = struct{ get func() Rung }\ntype atomicRung = atomic.Pointer[Rung]\ntype holder[T any] struct{ f func() T }\ntype tag[T any] struct{ p *int }"})
	}
	for _, p := range probes {
		if strings.Contains(p.extra, "context.") {
			p.extra = "import \"context\"\n" + p.extra
		}
		if len(check(p.old, p.new, p.extra)) == 0 {
			t.Errorf("the check passes a way to choose the rung: %q -> %q + %q", p.old, p.new, p.extra)
		}
	}
	// What the loop only hands out is allowed: the guard is not "no Rung
	// anywhere", which Ask to the answerer would fail.
	for _, f := range []string{"func(Rung)", "func(Ask) error", "interface{ Set(Rung) }"} {
		if bad := check("type Config struct {\n", "type Config struct {\n\tX "+f+"\n", ""); len(bad) != 0 {
			t.Errorf("the check fails a Rung the loop only hands out, %s: %v", f, bad)
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
