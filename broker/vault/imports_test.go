package vault

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// REQ: ARC-1, CRED-1

// Only the egress proxy and the vault process that holds the vault and
// constructs it (cmd/agentos-egress, P2-4a) may import the vault. Every other broker package, and above all anything
// a guest's socket reaches, gets no code path to a credential value. The
// daemon (cmd/agentosd) is on the ARC-2 control path and may not. The
// recovery package (P2-8) runs inside the vault process, and agentos-a8scan
// is A8's audit tool run by hand on a drive; recovery's imports test keeps
// every other package from importing it.
var vaultImporters = map[string]bool{"egress": true, "cmd/agentos-egress": true, "recovery": true, "cmd/agentos-a8scan": true}

const vaultPkg = "github.com/ghbmrk/agentos/broker/vault"

func TestOnlyEgressImportsVault(t *testing.T) {
	root := ".."
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return err
		}
		af, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.ImportsOnly)
		if err != nil {
			return err
		}
		pkg, _ := filepath.Rel(root, filepath.Dir(path))
		pkg = filepath.ToSlash(pkg)
		for _, im := range af.Imports {
			p, _ := strconv.Unquote(im.Path.Value)
			if p == vaultPkg && !vaultImporters[pkg] {
				t.Errorf("%s imports the vault; only %v may", path, vaultImporters)
			}
			if pkg == "vault" && ((p == "net" || strings.HasPrefix(p, "net/") && p != "net/url") || p == "os/exec" || strings.HasPrefix(p, "github.com/ghbmrk/agentos/broker/") && p != durablePkg) {
				t.Errorf("vault imports %s; it must stay a leaf with no I/O but its file", p)
			}
			// Argon2id (CRED-8) is the one third-party import: the Go
			// project's own x/crypto, pinned in go.sum, rather than
			// hand-rolled key derivation.
			if pkg == "vault" && strings.Contains(strings.SplitN(p, "/", 2)[0], ".") && p != "golang.org/x/crypto/argon2" && p != durablePkg {
				t.Errorf("vault imports third-party %s; only golang.org/x/crypto/argon2 is allowed", p)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// Rebase resets the rollback binding (V6). Only the recovery-key restore
// (package recovery, P2-8) may call it; anything else could turn an old
// copy into one the counter accepts (security review of #45, F2).
var rebaseCallers = map[string]bool{"vault": true, "recovery": true}

func TestOnlyRecoveryCallsRebase(t *testing.T) {
	root := ".."
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() && d.Name() == "vendor" {
			return filepath.SkipDir
		}
		if d.IsDir() || !strings.HasSuffix(path, ".go") {
			return nil
		}
		pkg, _ := filepath.Rel(root, filepath.Dir(path))
		if rebaseCallers[filepath.ToSlash(pkg)] {
			return nil
		}
		af, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
		if err != nil {
			return err
		}
		ast.Inspect(af, func(n ast.Node) bool {
			if s, ok := n.(*ast.SelectorExpr); ok && s.Sel.Name == "Rebase" {
				t.Errorf("%s uses Rebase; only %v may", path, rebaseCallers)
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// durablePkg is the one broker package the vault imports: it writes the
// vault's own file and imports only the standard library (durable.TestLeaf).
const durablePkg = "github.com/ghbmrk/agentos/broker/durable"
