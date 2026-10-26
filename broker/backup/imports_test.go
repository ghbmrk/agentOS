package backup

// REQ: BAK-1

import (
	"go/parser"
	"go/token"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// The package links only the standard library and broker/kernel: not
// kernel/proc, broker/recovery, broker/card or any clerk. Tests may link
// kernel/proc.
func TestBackupImportsOnlyKernelAndStd(t *testing.T) {
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
			p, _ := strconv.Unquote(im.Path.Value)
			std := !strings.Contains(strings.SplitN(p, "/", 2)[0], ".")
			if p != "github.com/ghbmrk/agentos/broker/kernel" && !std {
				t.Errorf("%s imports %s", f, p)
			}
			if std && (p == "net" || strings.HasPrefix(p, "net/") || p == "os/exec" || p == "unsafe" || p == "reflect") {
				t.Errorf("%s imports %s", f, p)
			}
		}
	}
}
