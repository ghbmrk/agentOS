package recovery

import (
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// REQ: ARC-1, CRED-1

// This package opens the vault and handles the recovery key, so it belongs
// to the vault process alone: only cmd/agentos-egress (and the A8 audit
// tool, cmd/agentos-a8scan) may import it, and
// it reaches no network and starts no process.
func TestOnlyTheVaultProcessImportsRecovery(t *testing.T) {
	const self = "github.com/ghbmrk/agentos/broker/recovery"
	err := filepath.WalkDir("..", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return err
		}
		if strings.Contains(filepath.ToSlash(path), "/vendor/") {
			return nil
		}
		af, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.ImportsOnly)
		if err != nil {
			return err
		}
		pkg, _ := filepath.Rel("..", filepath.Dir(path))
		pkg = filepath.ToSlash(pkg)
		for _, im := range af.Imports {
			p, _ := strconv.Unquote(im.Path.Value)
			if p == self && pkg != "cmd/agentos-egress" && pkg != "cmd/agentos-a8scan" {
				t.Errorf("%s imports recovery; only the vault process and the A8 scan may", path)
			}
			if pkg == "recovery" && (p == "net" || strings.HasPrefix(p, "net/") && p != "net/url" || p == "os/exec") {
				t.Errorf("recovery imports %s", p)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
