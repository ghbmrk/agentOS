package main

// REQ: CH-12

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"sort"
	"testing"
)

// CH-12-lint (W3-forget-b2c-2; L3 on #425, second PR with this finding):
// a done text goes to the owner only through done, which reports a failed
// send and keeps the text owed; inform, promise and say send and forget,
// so a done text there is lost to a down modem or a restart.
// W3-forget-b2c-f1 F1-5 (security 4a on #541, P1): any call but done is
// caught, by a selector (recalltool.TakenBack) or through a local variable
// assigned from a done text too.

// doneTexts names the done texts and the functions that build them.
var doneTexts = map[string]bool{"forgetDone": true, "forgetDoneRest": true, "doneLater": true,
	"forgetAgentDone": true, "forgetOwedLost": true, "TakenBack": true}

// directInforms reports, by line, each call in src other than done whose
// arguments name a done text, directly, by selector or through a local
// variable assigned from one in the same function.
func directInforms(t *testing.T, src []byte) []int {
	t.Helper()
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "forget.go", src, 0)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[int]bool{}
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}
		tainted := map[string]bool{}
		names := func(e ast.Node) bool {
			found := false
			ast.Inspect(e, func(m ast.Node) bool {
				if id, ok := m.(*ast.Ident); ok && (doneTexts[id.Name] || tainted[id.Name]) {
					found = true
				}
				return !found
			})
			return found
		}
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			switch n := n.(type) {
			case *ast.AssignStmt:
				for i, rhs := range n.Rhs {
					if id, ok := n.Lhs[min(i, len(n.Lhs)-1)].(*ast.Ident); ok && names(rhs) {
						tainted[id.Name] = true
					}
				}
			case *ast.ValueSpec:
				for _, v := range n.Values {
					if names(v) {
						for _, id := range n.Names {
							tainted[id.Name] = true
						}
					}
				}
			case *ast.CallExpr:
				callee := ""
				switch fun := n.Fun.(type) {
				case *ast.Ident:
					callee = fun.Name
				case *ast.SelectorExpr:
					callee = fun.Sel.Name
				}
				if callee == "done" {
					return true
				}
				for _, arg := range n.Args {
					if names(arg) {
						seen[fset.Position(n.Pos()).Line] = true
					}
				}
			}
			return true
		})
	}
	var lines []int
	for l := range seen {
		lines = append(lines, l)
	}
	sort.Ints(lines)
	return lines
}

func TestNoDoneTextReachesInformDirectly(t *testing.T) {
	src, err := os.ReadFile("forget.go")
	if err != nil {
		t.Fatal(err)
	}
	if lines := directInforms(t, src); len(lines) != 0 {
		t.Fatalf("forget.go sends a done text outside done at lines %v; use done", lines)
	}
}

// The mutants: one done site changed back to inform is caught, as is a
// done text built inline, one named by recalltool's selector, one through
// a local variable, and one sent by promise or say (#541 M2).
func TestNoDoneTextReachesInformDirectlyCatchesAMutant(t *testing.T) {
	for _, mutant := range []string{
		"f.inform(forgetAgentDone)",
		"f.inform(forgetDone(undone, back, logged))",
		`f.inform("x" + f.doneLater(0, since, false, false))`,
		"f.inform(forgetOwedLost)",
		"f.inform(recalltool.TakenBack)",
		"f.promise(forgetAgentDone)",
		"f.say(recalltool.TakenBack)",
		"_ = f.say(forgetDone(0, false, false))",
	} {
		src := "package main\nfunc (f *ownerForget) x() {\n\t" + mutant + "\n}\n"
		if lines := directInforms(t, []byte(src)); len(lines) != 1 || lines[0] != 3 {
			t.Fatalf("%s: caught at %v", mutant, lines)
		}
	}
	for _, mutant := range []string{
		"text := forgetAgentDone\n\tf.inform(text)",
		"var text = recalltool.TakenBack\n\tf.promise(text)",
		"text := \"x\"\n\ttext = f.doneLater(0, since, false, false)\n\tf.say(text)",
	} {
		src := "package main\nfunc (f *ownerForget) x() {\n\t" + mutant + "\n}\n"
		if lines := directInforms(t, []byte(src)); len(lines) != 1 {
			t.Fatalf("%q: caught at %v", mutant, lines)
		}
	}
	for _, ok := range []string{
		"func x() { f.inform(forgetAgentNotYet) }",
		"func x() { f.done(ctx, id, forgetAgentDone, owedForget{Agent: true}) }",
		"func x() { f.done(ctx, g, f.doneLater(e.Undone, e.Since, e.Back, e.Logged), e) }",
		"func (f *ownerForget) done(ctx context.Context, goal, text string, e owedForget) { f.say(text) }",
	} {
		if lines := directInforms(t, []byte("package main\n"+ok+"\n")); len(lines) != 0 {
			t.Fatalf("%s: caught at %v", ok, lines)
		}
	}
}
