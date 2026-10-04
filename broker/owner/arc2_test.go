package owner

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// REQ: ARC-2, CH-2

// The owner channel is on the control path: STOP, RESUME, and every code
// check run through it. Like daemon/arc2_test.go, it may not import a
// network client, a process launcher, a third-party module, or a broker
// package outside the control path, so nothing here can reach a model.
var ownerPath = map[string][]string{
	"owner": {"control", "modem"},
	"modem": {},
}

var forbiddenStd = []string{"net", "net/http", "net/rpc", "net/smtp", "os/exec", "plugin", "syscall"}

const module = "github.com/ghbmrk/agentos/broker/"

func TestARC2OwnerChannelCannotReachInference(t *testing.T) {
	for pkg, allowed := range ownerPath {
		files, err := filepath.Glob(filepath.Join("..", pkg, "*.go"))
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
					if !has(allowed, strings.TrimPrefix(p, module)) {
						t.Errorf("%s imports %s, outside the control path", f, p)
					}
				case strings.Contains(strings.SplitN(p, "/", 2)[0], "."):
					t.Errorf("%s imports third-party %s (DEP-1, ARC-2)", f, p)
				case has(forbiddenStd, p):
					t.Errorf("%s imports %s", f, p)
				}
			}
		}
	}
}

func has(ss []string, s string) bool {
	for _, x := range ss {
		if x == s {
			return true
		}
	}
	return false
}
