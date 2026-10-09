package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"testing"

	"github.com/ghbmrk/agentos/broker/change"
)

// After wireDigest, a live forget purges the digest's Ready batch at once
// (CAP-3), not at the next reopen. Dropping `f.digest = dg.forget` from
// wireDigest passes every other agentosd test.
// REQ: CAP-3 (W5-Dc-r11 f)
func TestWireDigestMakesALiveForgetPurgeAtOnce(t *testing.T) {
	r, _, _ := readyNotes(t, &change.MemStore{})
	fr := restartRig(t, &change.MemStore{})
	fr.f.forget = func(string) error { return nil }
	fr.f.wireDigest(r.d, tombstone(t, &change.MemStore{}).goals)
	if err := fr.f.forgetAll("owner:a"); err != nil {
		t.Fatal(err)
	}
	if r.holding("owner:a") != 0 {
		t.Fatal("a Ready batch still holds the forgotten reference after a live forget")
	}
}

// The digest's purge is wired in one place: nothing in agentosd assigns an
// ownerForget's digest field but wireDigest, and main wires through it.
// REQ: CAP-3 (W5-Dc-r11 f)
func TestDigestPurgeIsWiredOnlyThroughWireDigest(t *testing.T) {
	srcs := agentosdSources(t)
	fset := token.NewFileSet()
	calls := 0
	for name, src := range srcs {
		if name == "evidence.go" {
			continue // its own digest field, not the forget owner's
		}
		f, err := parser.ParseFile(fset, name, src, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, d := range f.Decls {
			fn, _ := d.(*ast.FuncDecl)
			ast.Inspect(d, func(n ast.Node) bool {
				switch n := n.(type) {
				case *ast.AssignStmt:
					for _, l := range n.Lhs {
						if s, ok := l.(*ast.SelectorExpr); ok && s.Sel.Name == "digest" && !(fn != nil && fn.Name.Name == "wireDigest") {
							t.Errorf("%s: digest assigned outside wireDigest", fset.Position(l.Pos()))
						}
					}
				case *ast.CallExpr:
					if s, ok := n.Fun.(*ast.SelectorExpr); ok && s.Sel.Name == "wireDigest" && name == "main.go" {
						calls++
					}
				}
				return true
			})
		}
	}
	if calls != 1 {
		t.Errorf("main wires the digest %d times, want once through wireDigest", calls)
	}
}
