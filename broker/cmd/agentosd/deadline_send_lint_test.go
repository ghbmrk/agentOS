package main

// REQ: CH-15, CAP-10

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Deadline-send lint (#1563; second PR with this finding after #989): a
// text whose deadline starts when it is sent must never go through the
// owner channel's holding path (Notify, NotifyAs, Post, Inform). That
// path holds a non-urgent text in quiet hours, past the allowance or
// behind a held text, and returns nil, so the deadline runs on a text
// the owner has not seen. Such a sender paces itself and sends through
// owner.Channel.NotifyNow, which never holds.

// deadlineSenders names, per config type, the field that sends a
// deadline-bearing text: an owner question's wait starts at its text.
var deadlineSenders = map[string]string{"question.Config": "Send"}

// nonHolding is the owner channel's never-held send path for agent text.
var nonHolding = map[string]bool{"NotifyNow": true}

// TestDeadlineTextsNeverUseTheHoldingPath checks every deadline sender
// in agentosd's non-test files is wired to a non-holding send.
func TestDeadlineTextsNeverUseTheHoldingPath(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	found := 0
	fset := token.NewFileSet()
	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		src, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		file, err := parser.ParseFile(fset, name, src, 0)
		if err != nil {
			t.Fatal(err)
		}
		ast.Inspect(file, func(n ast.Node) bool {
			lit, ok := n.(*ast.CompositeLit)
			if !ok {
				return true
			}
			sel, ok := lit.Type.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			pkg, ok := sel.X.(*ast.Ident)
			if !ok {
				return true
			}
			field, ok := deadlineSenders[pkg.Name+"."+sel.Sel.Name]
			if !ok {
				return true
			}
			found++
			for _, el := range lit.Elts {
				kv, ok := el.(*ast.KeyValueExpr)
				if !ok {
					continue
				}
				if key, ok := kv.Key.(*ast.Ident); !ok || key.Name != field {
					continue
				}
				if v, ok := kv.Value.(*ast.SelectorExpr); ok && nonHolding[v.Sel.Name] {
					return true
				}
				t.Errorf("%s: %s.%s is not a non-holding send (owner.Channel.NotifyNow)", fset.Position(kv.Pos()), pkg.Name+"."+sel.Sel.Name, field)
				return true
			}
			t.Errorf("%s: %s.%s %s not set", fset.Position(lit.Pos()), pkg.Name, sel.Sel.Name, field)
			return true
		})
	}
	if found == 0 {
		t.Fatal("no deadline sender found; the lint is checking nothing")
	}
}
