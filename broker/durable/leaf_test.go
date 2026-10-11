package durable

// REQ: OP-4, RES-4

import (
	"go/parser"
	"go/token"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// TestLeaf keeps durable a leaf of the standard library's file calls, so
// the import fences of the vault, pubid and owner packages, which allow it,
// still hold: no broker package, no third party, no network or processes.
func TestLeaf(t *testing.T) {
	allowed := map[string]bool{"errors": true, "fmt": true, "os": true, "path/filepath": true}
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		af, err := parser.ParseFile(token.NewFileSet(), f, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatal(err)
		}
		for _, im := range af.Imports {
			if p, _ := strconv.Unquote(im.Path.Value); !allowed[p] {
				t.Errorf("%s imports %s; durable imports only %v", f, p, allowed)
			}
		}
	}
}
