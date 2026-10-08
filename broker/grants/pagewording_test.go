package grants

// REQ: CH-3, CH-20, CHG-4

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// TestReasonsNameTheWiFiPage: every reason the gate gives the agent names
// the page as the owner does, "the box's Wi-Fi page" (CH-12, UX run 2),
// and none says the build lacks it: the page ships (P2-2w), so without it
// the box is only not serving it (UX on the P2-2w turn-on list).
func TestReasonsNameTheWiFiPage(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		ast.Inspect(f, func(n ast.Node) bool {
			lit, ok := n.(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				return true
			}
			s, err := strconv.Unquote(lit.Value)
			if err != nil {
				t.Fatalf("%s: %v", fset.Position(lit.Pos()), err)
			}
			if strings.Contains(s, "local page") || strings.Contains(s, "does not have yet") {
				t.Errorf("%s: %q", fset.Position(lit.Pos()), s)
			}
			return true
		})
	}
	for _, s := range []string{NoPageGrant, NoPageEvidence, NoPageFollow, NoPageSharing} {
		if !strings.Contains(s, "the box's Wi-Fi page, which is not running") {
			t.Errorf("%q", s)
		}
	}
}
