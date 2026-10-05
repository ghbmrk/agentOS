package question

import (
	"go/parser"
	"go/token"
	"os"
	"strconv"
	"strings"
	"testing"
)

// REQ: CAP-10, REV-2

// TestNoPathToAuthority: the package cannot reach the journal, the grants
// gate, or the owner channel's decisions, so nothing it holds, a default
// or an answer, can become an approval. Its only outputs are a text to
// the owner, a status to the guest, and digest lines.
func TestNoPathToAuthority(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	banned := []string{"/broker/journal", "/broker/grants", "/broker/owner", "/broker/control", "/broker/vault", "/broker/egress"}
	fset := token.NewFileSet()
	for _, e := range entries {
		n := e.Name()
		if !strings.HasSuffix(n, ".go") || strings.HasSuffix(n, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, n, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatal(err)
		}
		for _, imp := range f.Imports {
			path, _ := strconv.Unquote(imp.Path.Value)
			for _, b := range banned {
				if strings.HasSuffix(path, b) || strings.Contains(path, b+"/") {
					t.Errorf("%s imports %s", n, path)
				}
			}
		}
	}
}
