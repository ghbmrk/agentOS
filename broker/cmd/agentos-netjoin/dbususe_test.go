package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// REQ: ONB-3, CRED-1, ARC-2

const godbus = "github.com/godbus/dbus/v5"

// dbusUse is every godbus identifier the helper's shipped code may name.
// It dials the system bus only: godbus reaches os/exec solely through the
// session bus's autolaunch (dbus-launch, launchctl), so a SessionBus*,
// ConnectSessionBus, Connect or Dial use here would undo the childproc
// gate's exemption of godbus (D-108).
var dbusUse = map[string]bool{
	"BusObject": true, "ConnectSystemBus": true, "Error": true,
	"MakeVariant": true, "ObjectPath": true, "Store": true, "Variant": true,
}

// TestOnlyTheHelperImportsGodbus walks the broker module, vendor aside,
// and fails on any file outside cmd/agentos-netjoin that imports godbus.
func TestOnlyTheHelperImportsGodbus(t *testing.T) {
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	var bad []string
	err = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if path != root && (d.Name() == "vendor" || d.Name() == "testdata" || strings.HasPrefix(d.Name(), ".")) {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}
		f, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.ImportsOnly)
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, path)
		for _, im := range f.Imports {
			if p, _ := strconv.Unquote(im.Path.Value); p == godbus && filepath.Dir(rel) != filepath.Join("cmd", "agentos-netjoin") {
				bad = append(bad, rel)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(bad) > 0 {
		t.Fatalf("only cmd/agentos-netjoin may import godbus (D-108):\n%s", strings.Join(bad, "\n"))
	}
}

// TestTheHelperUsesOnlyTheSystemBus fails when the helper's non-test code
// names a godbus identifier outside dbusUse, or imports godbus under a dot
// or blank name the check could not follow.
func TestTheHelperUsesOnlyTheSystemBus(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	var bad []string
	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(token.NewFileSet(), name, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		local := ""
		for _, im := range f.Imports {
			if p, _ := strconv.Unquote(im.Path.Value); p != godbus {
				continue
			}
			local = "dbus"
			if im.Name != nil {
				local = im.Name.Name
			}
			if local == "." || local == "_" {
				bad = append(bad, name+": imports godbus as "+local)
			}
		}
		if local == "" {
			continue
		}
		ast.Inspect(f, func(n ast.Node) bool {
			sel, ok := n.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			if id, ok := sel.X.(*ast.Ident); ok && id.Name == local && id.Obj == nil {
				seen[sel.Sel.Name] = true
				if !dbusUse[sel.Sel.Name] {
					bad = append(bad, name+": names dbus."+sel.Sel.Name)
				}
			}
			return true
		})
	}
	if len(bad) > 0 {
		sort.Strings(bad)
		t.Fatalf("the helper may use only the system bus (D-108):\n%s", strings.Join(bad, "\n"))
	}
	if !seen["ConnectSystemBus"] {
		t.Fatal("the helper no longer names dbus.ConnectSystemBus: the check is reading the wrong code")
	}
}
