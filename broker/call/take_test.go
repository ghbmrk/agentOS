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
// to choose (briefs/VOICE-ro.md rule 4, #4949). The package is type-checked
// and nothing an importer can reach may hand the loop a Rung: no parameter
// of an exported func, method or func-typed var, no exported var, and no
// field of Config (the one input wiring fills), whose type mentions Rung
// anywhere it flows in: behind a pointer, slice, map or chan, in a struct's
// fields, or as a result of a func or interface method the package calls.
// Values flowing out (a callback's parameters, a receiver such as Report's,
// the constants P0 and P2) are not inputs. The probes are regressions the
// check must catch, Lens's on #5211 among them, so it is shown to bite.
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
		conf := types.Config{Importer: imp}
		pkg, err := conf.Check("call", fset, files, nil)
		if err != nil {
			t.Fatal(err)
		}
		rung := pkg.Scope().Lookup("Rung").Type()
		seen := map[types.Type]bool{}
		var in func(types.Type) bool // does a value of this type carry a Rung in?
		in = func(ty types.Type) bool {
			if types.Identical(ty, rung) {
				return true
			}
			if seen[ty] {
				return false
			}
			seen[ty] = true
			switch u := ty.(type) {
			case *types.Named:
				if i, ok := u.Underlying().(*types.Interface); ok {
					for m := range i.Methods() { // the package calls them: results flow in
						if in(m.Type().(*types.Signature).Results()) {
							return true
						}
					}
					return false
				}
				return in(u.Underlying())
			case *types.Pointer:
				return in(u.Elem())
			case *types.Slice:
				return in(u.Elem())
			case *types.Array:
				return in(u.Elem())
			case *types.Chan:
				return in(u.Elem())
			case *types.Map:
				return in(u.Key()) || in(u.Elem())
			case *types.Struct:
				for f := range u.Fields() {
					if in(f.Type()) {
						return true
					}
				}
			case *types.Signature: // a func handed in: the package calls it
				return in(u.Results())
			case *types.Tuple:
				for v := range u.Variables() {
					if in(v.Type()) {
						return true
					}
				}
			}
			return false
		}
		takes := func(sig *types.Signature) bool { return in(sig.Params()) }
		var bad []string
		for _, name := range pkg.Scope().Names() {
			switch o := pkg.Scope().Lookup(name).(type) {
			case *types.Func:
				if o.Exported() && takes(o.Type().(*types.Signature)) {
					bad = append(bad, "func "+name)
				}
			case *types.Var:
				if sig, ok := o.Type().Underlying().(*types.Signature); o.Exported() && (in(o.Type()) || ok && takes(sig)) {
					bad = append(bad, "var "+name)
				}
			case *types.TypeName:
				if !o.Exported() || types.IsInterface(o.Type()) {
					continue
				}
				ms := types.NewMethodSet(types.NewPointer(o.Type()))
				for sel := range ms.Methods() {
					if sel.Obj().Exported() && takes(sel.Type().(*types.Signature)) {
						bad = append(bad, "method "+name+"."+sel.Obj().Name())
					}
				}
			}
		}
		if in(pkg.Scope().Lookup("Config").Type()) {
			bad = append(bad, "Config")
		}
		return bad
	}

	if bad := check(""); len(bad) != 0 {
		t.Errorf("an importer can hand the loop a rung through %v", bad)
	}
	for _, probe := range []string{
		"var Run = runAt",
		"func RunP(ctx context.Context, cfg Config, l Line, r *Rung) (Report, error) { return runAt(ctx, cfg, l, *r) }",
		"func Run(ctx context.Context, cfg Config, l Line, r Rung) (Report, error) { return runAt(ctx, cfg, l, r) }",
		"func (c Config) At(r []Rung) {}",
		"type Hold struct{ R Rung }\nfunc RunH(h map[string]Hold) {}",
		"var Pick func() Rung",
		"var Floor Rung",
		"type Up interface{ Rung() Rung }\nfunc RunU(u Up) {}",
	} {
		if len(check(probe)) == 0 {
			t.Errorf("the check passes a rung input: %s", probe)
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
