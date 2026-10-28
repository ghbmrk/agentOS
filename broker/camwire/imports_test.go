package camwire

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// REQ: KRN-2

// TestImportsStandardLibraryOnly: the package imports only the standard
// library, and nothing that opens a socket, a file or a process, so the
// node and the core link the same small codec and it can do no I/O of its
// own. Revert mutant: an "os" or "net" import in a non-test file.
func TestImportsStandardLibraryOnly(t *testing.T) {
	allowed := map[string]bool{
		"bytes": true, "crypto/ecdsa": true, "crypto/ed25519": true, "crypto/elliptic": true,
		"crypto/sha256": true, "encoding/base64": true, "encoding/binary": true,
		"encoding/json": true, "errors": true, "io": true,
	}
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	fs := token.NewFileSet()
	seen := 0
	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		src, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		f, err := parser.ParseFile(fs, name, src, parser.ImportsOnly)
		if err != nil {
			t.Fatal(err)
		}
		seen++
		for _, im := range f.Imports {
			p, _ := strconv.Unquote(im.Path.Value)
			if !allowed[p] {
				t.Errorf("%s imports %s", name, p)
			}
		}
	}
	if seen == 0 {
		t.Fatal("no source files read")
	}
}
