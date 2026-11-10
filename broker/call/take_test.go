package call

// REQ: CH-5

import (
	"context"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"strings"
	"testing"
)

// RunAt lets the package's own tests hold a call at a chosen rung. It is in
// a _test.go file, so no importer of the package can reach it (#4949).
var RunAt = runAt

// The rung is the call's, read from the token by Serve, never the caller's
// to choose (briefs/VOICE-ro.md rule 4, #4949): no exported function or
// method of the package takes a Rung, and Config, the one input wiring
// fills, has no Rung in it. The modem wiring (VOICE-ro-d) can then reach the
// loop only through Serve, so a caller-ID call never runs above P0.
func TestOnlyServeChoosesTheRung(t *testing.T) {
	pkgs, err := parser.ParseDir(token.NewFileSet(), ".", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	rung := func(e ast.Expr) bool { id, ok := e.(*ast.Ident); return ok && id.Name == "Rung" }
	files := 0
	for name, f := range pkgs["call"].Files {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		files++
		for _, d := range f.Decls {
			switch d := d.(type) {
			case *ast.FuncDecl:
				if !d.Name.IsExported() {
					continue
				}
				for _, p := range d.Type.Params.List {
					if rung(p.Type) {
						t.Errorf("%s: exported %s takes a Rung", name, d.Name.Name)
					}
				}
			case *ast.GenDecl:
				for _, sp := range d.Specs {
					ts, ok := sp.(*ast.TypeSpec)
					if !ok || ts.Name.Name != "Config" {
						continue
					}
					for _, fl := range ts.Type.(*ast.StructType).Fields.List {
						if rung(fl.Type) {
							t.Errorf("%s: Config holds a Rung", name)
						}
					}
				}
			}
		}
	}
	if files == 0 {
		t.Fatal("no source files read")
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
