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
// to choose (briefs/VOICE-ro.md rule 4, #4949). loop is the call, and its
// one rung input is the token channel. It is a plain unexported function,
// so no importer can name it, and no interface, constraint, method value or
// embedding inside the package reaches it: Go code gets a func only by
// naming it. So the package's non-test files are type-checked and the test
// fails unless loop is named exactly once, as the callee of a call in
// Serve's own body, outside any func literal. Any other entry, whatever its
// shape or rung, has to name loop somewhere else. What Serve passes loop is
// review's, and the Serve tests pin it. Each probe must fail the check, so
// the check is shown to bite.
func TestOnlyServeChoosesTheRung(t *testing.T) {
	fset := token.NewFileSet()
	imp := importer.ForCompiler(fset, "source", nil) // one importer: dependencies are read once
	check := func(probe string) []string {
		pkgs, err := parser.ParseDir(fset, ".", func(fi fs.FileInfo) bool { return !strings.HasSuffix(fi.Name(), "_test.go") }, 0)
		if err != nil {
			t.Fatal(err)
		}
		var files []*ast.File
		for _, f := range pkgs["call"].Files {
			files = append(files, f)
		}
		if len(files) == 0 {
			t.Fatal("no source files read")
		}
		if probe != "" {
			if strings.Contains(probe, "context.") {
				probe = "import \"context\"\n" + probe
			}
			f, err := parser.ParseFile(fset, "probe.go", "package call\n"+probe, 0)
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
		var bad []string
		loopFn := pkg.Scope().Lookup("loop")
		if _, ok := loopFn.(*types.Func); !ok {
			t.Fatal("loop is gone or not a plain func: rewrite this check for the new loop")
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
					if !ok || info.Uses[id] != loopFn {
						return true
					}
					call, ok := stack[len(stack)-2].(*ast.CallExpr)
					lit := slices.ContainsFunc(stack, func(n ast.Node) bool { _, ok := n.(*ast.FuncLit); return ok })
					if serve && ok && call.Fun == id && !lit {
						calls++
					} else {
						bad = append(bad, fset.Position(id.Pos()).String()+": loop")
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

	if bad := check(""); len(bad) != 0 {
		t.Errorf("the loop is entered other than through Serve:\n%s", strings.Join(bad, "\n"))
	}
	for _, probe := range []string{
		// Lens and Security on #5211, and main's old Run.
		"var Run = loop",
		"func Run(ctx context.Context, cfg Config, l Line, r Rung) (Report, error) { c := make(chan Rung, 1); c <- r; return loop(ctx, cfg, l, c) }",
		"func RunP(ctx context.Context, cfg Config, l Line, r *Rung) (Report, error) { c := make(chan Rung, 1); c <- *r; return loop(ctx, cfg, l, c) }",
		"func RunU(ctx context.Context, cfg Config, l Line, u interface{ R() Rung }) (Report, error) { c := make(chan Rung, 1); c <- u.R(); return loop(ctx, cfg, l, c) }",
		"type Rs = []Rung\nfunc RunS(ctx context.Context, cfg Config, l Line, r Rs) (Report, error) { c := make(chan Rung, 1); c <- r[0]; return loop(ctx, cfg, l, c) }",
		"func RunG[T ~int](ctx context.Context, cfg Config, l Line, r T) (Report, error) { c := make(chan Rung, 1); c <- Rung(r); return loop(ctx, cfg, l, c) }",
		"func Runner() func(context.Context, Config, Line, <-chan Rung) (Report, error) { return loop }",
		"type ctl struct{}\nfunc (ctl) Run(ctx context.Context, cfg Config, l Line, r Rung) (Report, error) { c := make(chan Rung, 1); c <- r; return loop(ctx, cfg, l, c) }\nfunc Ctl() ctl { return ctl{} }",
		// Security on #5211 at e104cea: the interface and constraint routes
		// to a method. loop is a func, so each has to name it.
		"type runner func(context.Context, Config, Line, <-chan Rung) (Report, error)\nfunc (f runner) run(ctx context.Context, cfg Config, l Line, c <-chan Rung) (Report, error) { return f(ctx, cfg, l, c) }\ntype runs interface{ run(context.Context, Config, Line, <-chan Rung) (Report, error) }\nfunc ServeAt(ctx context.Context, cfg Config, l Line, r Rung) (Report, error) { var x runs = runner(loop); c := make(chan Rung, 1); c <- r; return x.run(ctx, cfg, l, c) }",
		"func serveGen[T ~func(context.Context, Config, Line, <-chan Rung) (Report, error)](ctx context.Context, f T, cfg Config, l Line, r Rung) (Report, error) { c := make(chan Rung, 1); c <- r; return f(ctx, cfg, l, c) }\nfunc ServeGen(ctx context.Context, cfg Config, l Line, r Rung) (Report, error) { return serveGen(ctx, loop, cfg, l, r) }",
		// No new export, but loop named outside Serve's body.
		"var hook = loop",
		"func init() { go loop(context.Background(), Config{}, nil, nil) }",
		"func (cfg Config) Serve(ctx context.Context, l Line, r Rung) (Report, error) { c := make(chan Rung, 1); c <- r; return loop(ctx, cfg, l, c) }",
	} {
		if len(check(probe)) == 0 {
			t.Errorf("the check passes an entry to the loop: %s", probe)
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
