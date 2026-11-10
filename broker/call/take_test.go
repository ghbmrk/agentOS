package call

// REQ: CH-5

import (
	"context"
	"errors"
	"go/ast"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	"io/fs"
	"strings"
	"testing"
)

// RunAt lets the package's own tests hold a call at a chosen rung. It is in
// a _test.go file, so no importer of the package can reach it (#4949).
var RunAt = runAt

// The rung is the call's, read from the token by Serve, never the caller's
// to choose (briefs/VOICE-ro.md rule 4, #4949). Every way into the loop
// goes through runAt, which takes a rung, or the Config.run method, which
// takes the rung and the token channel. So the package's non-test files
// are type-checked and the test fails if runAt is referenced anywhere in
// them, or Config.run anywhere but in Serve and runAt. Whatever shape a new
// entry takes (an exported func, method, var, getter, alias, generic or
// interface, or none, at a fixed rung), it has to reference one of the two.
// The probes are such entries, Lens's and Security's on #5211 among them:
// each must fail the check, so the check is shown to bite.
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
		runAt := pkg.Scope().Lookup("runAt")
		run, _, _ := types.LookupFieldOrMethod(pkg.Scope().Lookup("Config").Type(), false, pkg, "run")
		if runAt == nil || run == nil {
			t.Fatal("runAt or Config.run is gone: rewrite this check for the new entry")
		}
		var bad []string
		for _, f := range files {
			for _, d := range f.Decls {
				in := "" // the top-level func d is, if it is one
				if fd, ok := d.(*ast.FuncDecl); ok && fd.Recv == nil {
					in = fd.Name.Name
				}
				ast.Inspect(d, func(n ast.Node) bool {
					id, ok := n.(*ast.Ident)
					if !ok {
						return true
					}
					switch o := info.Uses[id]; {
					case o == runAt:
						bad = append(bad, fset.Position(id.Pos()).String()+": runAt")
					case o == run && in != "Serve" && in != "runAt":
						bad = append(bad, fset.Position(id.Pos()).String()+": Config.run")
					}
					return true
				})
			}
		}
		return bad
	}

	if bad := check(""); len(bad) != 0 {
		t.Errorf("the loop is entered other than through Serve: %v", bad)
	}
	for _, probe := range []string{
		// Lens on #5211, and main's old Run.
		"var Run = runAt",
		"func RunP(ctx context.Context, cfg Config, l Line, r *Rung) (Report, error) { return runAt(ctx, cfg, l, *r) }",
		"func Run(ctx context.Context, cfg Config, l Line, r Rung) (Report, error) { return runAt(ctx, cfg, l, r) }",
		"func RunU(ctx context.Context, cfg Config, l Line, u interface{ R() Rung }) (Report, error) { return runAt(ctx, cfg, l, u.R()) }",
		// Security on #5211.
		"type Rs = []Rung\nfunc RunS(ctx context.Context, cfg Config, l Line, r Rs) (Report, error) { return runAt(ctx, cfg, l, r[0]) }",
		"func RunG[T ~int](ctx context.Context, cfg Config, l Line, r T) (Report, error) { return runAt(ctx, cfg, l, Rung(r)) }",
		"func RunI(ctx context.Context, cfg Config, l Line, r int) (Report, error) { return runAt(ctx, cfg, l, Rung(r)) }",
		"func RunAny(ctx context.Context, cfg Config, l Line, x any) (Report, error) { return runAt(ctx, cfg, l, x.(Rung)) }",
		"func ServeTrusted(ctx context.Context, cfg Config, l Line) (Report, error) { return runAt(ctx, cfg, l, P2) }",
		"func Runner() func(context.Context, Config, Line, Rung) (Report, error) { return runAt }",
		"type ctl struct{}\nfunc (ctl) Run(ctx context.Context, cfg Config, l Line, r Rung) (Report, error) { return runAt(ctx, cfg, l, r) }\nfunc Ctl() ctl { return ctl{} }",
		"func RunC(ctx context.Context, cfg Config, l Line) (Report, error) { c := make(chan Rung, 1); c <- P2; return cfg.run(ctx, l, P2, c) }",
		"var hook = Config.run",
	} {
		if len(check(probe)) == 0 {
			t.Errorf("the check passes an entry to the loop: %s", probe)
		}
	}
}

// An error that reaches the turn after it was stopped is a stop, not a
// failure: no error recorded and no failed clip. Through runAt the stop must
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
