package vault

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
			if pkg == "vault" && ((p == "net" || strings.HasPrefix(p, "net/") && p != "net/url") || p == "os/exec" || strings.HasPrefix(p, "github.com/ghbmrk/agentos/broker/")) {
				t.Errorf("vault imports %s; it must stay a leaf with no I/O but its file", p)
			}
			// Argon2id (CRED-8) is the one third-party import: the Go
			// project's own x/crypto, pinned in go.sum, rather than
			// hand-rolled key derivation.
			if pkg == "vault" && strings.Contains(strings.SplitN(p, "/", 2)[0], ".") && p != "golang.org/x/crypto/argon2" {
				t.Errorf("vault imports third-party %s; only golang.org/x/crypto/argon2 is allowed", p)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
