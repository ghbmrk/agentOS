package daemon

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// REQ: ARC-2

// The control path is every package that STOP, RESUME, STATUS, HELP, and
// admission run through. ARC-2 says none of it may invoke inference. Model
// access needs a network client or a child process, so the control path may
// import neither, and may import only these broker packages. A future model
// egress package lives outside this list; wiring it into the control path
// fails this test.
var controlPath = map[string][]string{
	"journal":      {},
	"control":      {"journal"},
	"admission":    {},
	"sockets":      {},
	"daemon":       {"journal", "control", "admission", "sockets"},
	"cmd/agentosd": {"daemon"},
}

var forbiddenStd = []string{"net/http", "net/rpc", "net/smtp", "os/exec", "plugin", "syscall"}

const module = "github.com/ghbmrk/agentos/broker/"

func TestARC2ControlPathCannotReachInference(t *testing.T) {
	root := ".."
	for pkg, allowed := range controlPath {
		files, err := filepath.Glob(filepath.Join(root, pkg, "*.go"))
		if err != nil || len(files) == 0 {
			t.Fatalf("%s: no sources (%v)", pkg, err)
		}
		for _, f := range files {
			if strings.HasSuffix(f, "_test.go") {
				continue
			}
			src, err := os.ReadFile(f)
			if err != nil {
				t.Fatal(err)
			}
			af, err := parser.ParseFile(token.NewFileSet(), f, src, parser.ImportsOnly)
			if err != nil {
				t.Fatal(err)
			}
			for _, im := range af.Imports {
				p, _ := strconv.Unquote(im.Path.Value)
				switch {
				case strings.HasPrefix(p, module):
					if !contains(allowed, strings.TrimPrefix(p, module)) {
						t.Errorf("%s imports %s, outside the control path", f, p)
					}
				case strings.Contains(strings.SplitN(p, "/", 2)[0], "."):
					t.Errorf("%s imports third-party %s (DEP-1, ARC-2)", f, p)
				case p == "syscall" && pkg == "cmd/agentosd":
					// Signal numbers for shutdown only.
				case contains(forbiddenStd, p):
					t.Errorf("%s imports %s; the control path may not open network clients or child processes", f, p)
				}
			}
		}
	}
}

func contains(ss []string, s string) bool {
	for _, x := range ss {
		if x == s {
			return true
		}
	}
	return false
}
