package retrieve

import (
	"go/parser"
	"go/token"
	"os"
	"strconv"
	"strings"
	"testing"
)

// The index runs in the archive clerk's process and talks to nothing but
// its two seams, so it links the standard library only, and none of the
// parts that reach out of the process or around the type system.
func TestImportsStandardLibraryOnly(t *testing.T) {
	banned := map[string]bool{"net": true, "os/exec": true, "syscall": true, "unsafe": true, "plugin": true, "C": true}
	files, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, f := range files {
		name := f.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		n++
		af, err := parser.ParseFile(token.NewFileSet(), name, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatal(err)
		}
		for _, im := range af.Imports {
			p, _ := strconv.Unquote(im.Path.Value)
			first, _, _ := strings.Cut(p, "/")
			if strings.Contains(first, ".") || banned[p] || strings.HasPrefix(p, "net/") {
				t.Errorf("%s imports %s", name, p)
			}
		}
	}
	if n == 0 {
		t.Fatal("no source files checked")
	}
}
