package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// digestGate checks the digest's send paths structurally (DC-5, DC-6,
// DC-8): SendReceipt is used in one place, newDigestTransport in
// digest.go; the transport it builds is set only in main and read only by
// openLocked, which hands it to digestqueue.NewSender; the outage line and
// the owner channel's Inform are reached in digest.go only from
// sendOutage. files maps a broker-relative path to its source.
func digestGate(files map[string]string) []string {
	var bad []string
	fset := token.NewFileSet()
	for path, src := range files {
		f, err := parser.ParseFile(fset, path, src, 0)
		if err != nil {
			bad = append(bad, path+": "+err.Error())
			continue
		}
		for _, decl := range f.Decls {
			fn, _ := decl.(*ast.FuncDecl)
			name := ""
			if fn != nil {
				name = fn.Name.Name
			}
			ast.Inspect(decl, func(n ast.Node) bool {
				switch n := n.(type) {
				case *ast.SelectorExpr:
					switch {
					case n.Sel.Name == "SendReceipt" && (path != "cmd/agentosd/digest.go" || name != "newDigestTransport"):
						bad = append(bad, path+": SendReceipt in "+name)
					case n.Sel.Name == "Inform" && path == "cmd/agentosd/digest.go" && name != "sendOutage":
						bad = append(bad, path+": Inform in "+name)
					case n.Sel.Name == "Transport" && isCfg(n.X) && strings.HasPrefix(path, "cmd/agentosd/") &&
						!(path == "cmd/agentosd/digest.go" && name == "openLocked") &&
						!(path == "cmd/agentosd/main.go" && name == "main"):
						bad = append(bad, path+": digest transport in "+name)
					}
				case *ast.Ident:
					if n.Name == "newDigestTransport" && fn != nil && name != "newDigestTransport" &&
						!(path == "cmd/agentosd/main.go" && name == "main") {
						bad = append(bad, path+": newDigestTransport in "+name)
					}
					if n.Name == "digestOutageLine" && fn != nil && name != "sendOutage" && name != "digestLineTexts" {
						bad = append(bad, path+": outage line in "+name)
					}
				}
				return true
			})
		}
	}
	return bad
}

// isCfg reports whether x is a selector ending in .cfg (d.cfg, dg.cfg).
func isCfg(x ast.Expr) bool {
	s, ok := x.(*ast.SelectorExpr)
	return ok && s.Sel.Name == "cfg"
}

func brokerSources(t *testing.T) map[string]string {
	t.Helper()
	root := filepath.Join("..", "..")
	files := map[string]string{}
	err := filepath.WalkDir(root, func(p string, e fs.DirEntry, err error) error {
		if err != nil || e.IsDir() || !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
			return err
		}
		rel, _ := filepath.Rel(root, p)
		if strings.HasPrefix(rel, "modemlink"+string(filepath.Separator)) {
			return nil // SendReceipt's own package
		}
		b, err := os.ReadFile(p)
		files[filepath.ToSlash(rel)] = string(b)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return files
}

// REQ: OP-2, OP-9
func TestDigestGate(t *testing.T) {
	files := brokerSources(t)
	if _, ok := files["cmd/agentosd/digest.go"]; !ok {
		t.Fatal("digest.go not found")
	}
	if bad := digestGate(files); len(bad) != 0 {
		t.Fatalf("digest gate: %q", bad)
	}
}

// The gate catches a second SendReceipt file, an Inform beside the outage
// path, the outage line sent from elsewhere and the transport reached
// outside main and openLocked.
// REQ: OP-2, OP-9
func TestDigestGateCatchesViolations(t *testing.T) {
	cases := map[string]map[string]string{
		"second file":     {"cmd/agentosd/other.go": "package main\nfunc f(l *L) { l.SendReceipt(\"o\", \"t\") }\n"},
		"second func":     {"cmd/agentosd/digest.go": "package main\nfunc g(l *L) { _ = l.SendReceipt }\n"},
		"inform":          {"cmd/agentosd/digest.go": "package main\nfunc (d *D) daily() { d.cfg.Inform(\"x\") }\n"},
		"outage line":     {"cmd/agentosd/learn.go": "package main\nfunc h() string { return digestOutageLine }\n"},
		"transport read":  {"cmd/agentosd/digest.go": "package main\nfunc (d *D) daily() { _ = d.cfg.Transport }\n"},
		"transport built": {"cmd/agentosd/learn.go": "package main\nfunc h() { _ = newDigestTransport(nil, \"o\") }\n"},
	}
	for name, files := range cases {
		if bad := digestGate(files); len(bad) == 0 {
			t.Errorf("%s: not caught", name)
		}
	}
}
