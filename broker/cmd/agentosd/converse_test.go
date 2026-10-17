package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"

	ownerch "github.com/ghbmrk/agentos/broker/owner"
)

// REQ: CH-15
// An agent reply from the evidence outbox, wired by wireOwner as attach
// wires it, is conversation: in quiet hours and with the hour's texts
// spent it goes at once behind the agent prefix, and with no owner
// channel yet it fails rather than sends. The source check pins that
// attach wires through wireOwner and that nothing else sets e.notify, so
// reverting attach to the paced Notify fails here.
func TestAgentReplyIsConversation(t *testing.T) {
	r := pacedOwner(t, quiet22to7(), at23)
	for i := 0; i < ownerch.DefaultTextsPerHour; i++ {
		if err := r.ch.Post(ownerch.ClassSecurity, "Alert."); err != nil {
			t.Fatal(err)
		}
	}
	r.sent()
	ev := &evidence{logf: t.Logf}
	ev.wireOwner(func() *ownerch.Channel { return r.ch })
	ev.send("agent", "Your invoice is drafted.")
	if got := r.sent(); len(got) != 1 || got[0] != ownerch.AgentPrefix+"Your invoice is drafted." {
		t.Fatalf("agent reply in quiet hours past the allowance: %q, want it sent at once", got)
	}
	ev.wireOwner(func() *ownerch.Channel { return nil })
	if err := ev.notify("x"); err == nil || !strings.Contains(err.Error(), "no owner channel") {
		t.Fatalf("no channel: %v", err)
	}
	if bad := notifyWiring(t); len(bad) != 0 {
		t.Fatalf("reply wiring: %v", bad)
	}
}

// notifyWiring checks the package's non-test sources: evidence.attach
// calls e.wireOwner(d.Owner), and only wireOwner assigns a notify field.
func notifyWiring(t *testing.T) []string {
	t.Helper()
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	var bad []string
	wired := false
	fs := token.NewFileSet()
	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		src, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		f, err := parser.ParseFile(fs, name, src, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, d := range f.Decls {
			fn, ok := d.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			isEvidence := fn.Recv != nil && strings.Contains(string(src[fs.Position(fn.Recv.Pos()).Offset:fs.Position(fn.Recv.End()).Offset]), "evidence")
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				switch n := n.(type) {
				case *ast.AssignStmt:
					for _, l := range n.Lhs {
						if s, ok := l.(*ast.SelectorExpr); ok && s.Sel.Name == "notify" && !(isEvidence && fn.Name.Name == "wireOwner") {
							bad = append(bad, fs.Position(n.Pos()).String()+": notify set outside wireOwner")
						}
					}
				case *ast.CallExpr:
					if s, ok := n.Fun.(*ast.SelectorExpr); ok && s.Sel.Name == "wireOwner" && isEvidence && fn.Name.Name == "attach" &&
						len(n.Args) == 1 && strings.TrimSpace(string(src[fs.Position(n.Args[0].Pos()).Offset:fs.Position(n.Args[0].End()).Offset])) == "d.Owner" {
						wired = true
					}
				}
				return true
			})
		}
	}
	if !wired {
		bad = append(bad, "evidence.attach does not call e.wireOwner(d.Owner)")
	}
	return bad
}
