package loops

// REQ: LOOP-3

import (
	"go/ast"
	"go/parser"
	"go/token"
	"regexp"
	"strconv"
	"testing"
)

// banned is loop 2's forbidden owner vocabulary (P3-4b item 8): whole
// words only, so "finding" stays allowed.
var banned = regexp.MustCompile(`(?i)\b(find|finds|hunt|hunts|detect|detects|detector)\b`)

// ownerTables are the files holding loop 2's owner text: the plain names
// of findings and the settings help. Loop 2's notices, digest and STATUS
// lines went with the Guard and the change pipeline (#2785).
var ownerTables = []string{"plainname.go", "settings.go"}

// scanWording returns every string literal in src that uses the banned
// vocabulary.
func scanWording(t *testing.T, name string, src any) []string {
	t.Helper()
	f, err := parser.ParseFile(token.NewFileSet(), name, src, 0)
	if err != nil {
		t.Fatal(err)
	}
	var bad []string
	ast.Inspect(f, func(n ast.Node) bool {
		if lit, ok := n.(*ast.BasicLit); ok && lit.Kind == token.STRING {
			if s, err := strconv.Unquote(lit.Value); err == nil && banned.MatchString(s) {
				bad = append(bad, s)
			}
		}
		return true
	})
	return bad
}

// Owner text describes loop 2 as checking the box against known problems
// and repairing what it can; it never says loop 2 finds, hunts or detects.
func TestOwnerWordingNeverClaimsDetection(t *testing.T) {
	for _, name := range ownerTables {
		if bad := scanWording(t, name, nil); len(bad) > 0 {
			t.Errorf("%s: %q", name, bad)
		}
	}
	// The scan catches a planted string, and lets "finding" through.
	planted := "package loops\nconst a = \"Loop 2 detects attacks.\"\nconst b = \"Security finding on x.\"\n"
	if bad := scanWording(t, "planted.go", planted); len(bad) != 1 || bad[0] != "Loop 2 detects attacks." {
		t.Fatalf("planted scan: %q", bad)
	}
}
