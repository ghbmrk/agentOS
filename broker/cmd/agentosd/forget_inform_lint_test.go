package main

// REQ: CH-12

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"testing"
)

// CH-12-lint (W3-forget-b2c-2; L3 on #425, second PR with this finding):
// a done text goes to the owner only through done or say, which report a
// failed send and keep the text owed; inform sends and forgets, so a done
// text there is lost to a down modem or a restart.

// doneTexts names the done texts and the functions that build them.
var doneTexts = map[string]bool{"forgetDone": true, "forgetDoneRest": true, "doneLater": true,
	"forgetAgentDone": true, "forgetOwedLost": true}

// directInforms reports each inform call in src whose argument names a
// done text, by line.
func directInforms(t *testing.T, src []byte) []int {
	t.Helper()
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "forget.go", src, 0)
	if err != nil {
		t.Fatal(err)
	}
	var lines []int
	ast.Inspect(file, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != "inform" {
			return true
		}
		for _, arg := range call.Args {
			ast.Inspect(arg, func(m ast.Node) bool {
				if id, ok := m.(*ast.Ident); ok && doneTexts[id.Name] {
					lines = append(lines, fset.Position(call.Pos()).Line)
				}
				return true
			})
		}
		return true
	})
	return lines
}

func TestNoDoneTextReachesInformDirectly(t *testing.T) {
	src, err := os.ReadFile("forget.go")
	if err != nil {
		t.Fatal(err)
	}
	if lines := directInforms(t, src); len(lines) != 0 {
		t.Fatalf("forget.go sends a done text through inform at lines %v; use done", lines)
	}
}

// The mutant: one done site changed back to inform is caught, as is a
// done text built inline.
func TestNoDoneTextReachesInformDirectlyCatchesAMutant(t *testing.T) {
	for _, mutant := range []string{
		"f.inform(forgetAgentDone)",
		"f.inform(forgetDone(undone, back, logged))",
		`f.inform("x" + f.doneLater(0, since, false, false))`,
		"f.inform(forgetOwedLost)",
	} {
		src := "package main\nfunc (f *ownerForget) x() {\n\t" + mutant + "\n}\n"
		if lines := directInforms(t, []byte(src)); len(lines) != 1 || lines[0] != 3 {
			t.Fatalf("%s: caught at %v", mutant, lines)
		}
	}
	if lines := directInforms(t, []byte("package main\nfunc x() { f.inform(forgetAgentNotYet) }\n")); len(lines) != 0 {
		t.Fatalf("a promise was caught: %v", lines)
	}
}
