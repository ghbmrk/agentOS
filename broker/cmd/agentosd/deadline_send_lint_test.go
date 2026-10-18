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

// deadlineSenders names, per config type, the fields that send a
// deadline-bearing text and the owner channel's never-held send each
// must call: an owner question's wait starts at its text, pushed or, in
// an open task chat, as conversation (#2363).
var deadlineSenders = map[string]map[string]string{
	"question.Config": {"Send": "NotifyNow", "Converse": "Converse"},
}

// sendWrappers are the agentosd helpers a send may be wrapped in: they
// only map its errors (questionSend, #2363).
var sendWrappers = map[string]bool{"questionSend": true}

// nonHoldingSend reports whether v is the send want, alone or wrapped.
func nonHoldingSend(v ast.Expr, want string) bool {
	if call, ok := v.(*ast.CallExpr); ok {
		fn, ok := call.Fun.(*ast.Ident)
		if !ok || !sendWrappers[fn.Name] || len(call.Args) != 1 {
			return false
		}
		v = call.Args[0]
	}
	sel, ok := v.(*ast.SelectorExpr)
	return ok && sel.Sel.Name == want
}

// selfPacing names, per config type, the fields through which the sender
// paces itself and the agentosd helper each must call: without them a
// non-holding send would text in the owner's quiet hours (M9-M11).
var selfPacing = map[string]map[string]string{
	"question.Config": {"Quiet": "questionQuiet", "QuietHours": "questionQuietHours"},
}

// TestDeadlineTextsNeverUseTheHoldingPath checks every deadline sender
// in agentosd's non-test files is wired to a non-holding send and paces
// itself through the tested quiet-hours helpers.
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
			typ := pkg.Name + "." + sel.Sel.Name
			fields, ok := deadlineSenders[typ]
			if !ok {
				return true
			}
			found++
			checkPacing(t, fset, lit, typ)
			for field, want := range fields {
				set := false
				for _, el := range lit.Elts {
					kv, ok := el.(*ast.KeyValueExpr)
					if !ok {
						continue
					}
					if key, ok := kv.Key.(*ast.Ident); !ok || key.Name != field {
						continue
					}
					set = true
					if !nonHoldingSend(kv.Value, want) {
						t.Errorf("%s: %s.%s is not a non-holding send (owner.Channel.%s)", fset.Position(kv.Pos()), typ, field, want)
					}
				}
				if !set {
					t.Errorf("%s: %s %s not set", fset.Position(lit.Pos()), typ, field)
				}
			}
			return true
		})
	}
	if found == 0 {
		t.Fatal("no deadline sender found; the lint is checking nothing")
	}
}

// checkPacing reports each self-pacing field of lit that is unset or not
// a call to its helper.
func checkPacing(t *testing.T, fset *token.FileSet, lit *ast.CompositeLit, typ string) {
	t.Helper()
	for field, helper := range selfPacing[typ] {
		set := false
		for _, el := range lit.Elts {
			kv, ok := el.(*ast.KeyValueExpr)
			if !ok {
				continue
			}
			if key, ok := kv.Key.(*ast.Ident); !ok || key.Name != field {
				continue
			}
			set = true
			var fn *ast.Ident
			if call, ok := kv.Value.(*ast.CallExpr); ok {
				fn, _ = call.Fun.(*ast.Ident)
			}
			if fn == nil || fn.Name != helper {
				t.Errorf("%s: %s.%s is not %s(...)", fset.Position(kv.Pos()), typ, field, helper)
			}
		}
		if !set {
			t.Errorf("%s: %s.%s not set", fset.Position(lit.Pos()), typ, field)
		}
	}
}
