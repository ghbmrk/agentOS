package main

// REQ: ARC-1, CH-7

import (
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os/user"
	"strings"
	"testing"
)

// hostapd runs as its own user (#1426): the loader looks it up at each
// start and refuses to run hostapd as root, or at all without the user.
func TestNewHostapdRunsHostapdAsItsUser(t *testing.T) {
	lookup := func(u *user.User, err error) func(string) (*user.User, error) {
		return func(name string) (*user.User, error) {
			if name != hostapdUser {
				t.Fatalf("looked up %q, want %q", name, hostapdUser)
			}
			return u, err
		}
	}
	h, err := newHostapd("/run/agentos-ap", lookup(&user.User{Uid: "991", Gid: "990"}, nil))
	if err != nil {
		t.Fatal(err)
	}
	if h.User == nil || h.User.UID != 991 || h.User.GID != 990 || h.Dir != "/run/agentos-ap" {
		t.Fatalf("newHostapd = %+v (user %+v), want uid 991 gid 990", h, h.User)
	}
	for name, l := range map[string]func(string) (*user.User, error){
		"missing":  lookup(nil, user.UnknownUserError(hostapdUser)),
		"failing":  lookup(nil, errors.New("nss down")),
		"root uid": lookup(&user.User{Uid: "0", Gid: "990"}, nil),
		"root gid": lookup(&user.User{Uid: "991", Gid: "0"}, nil),
		"bad uid":  lookup(&user.User{Uid: "x", Gid: "990"}, nil),
		"bad gid":  lookup(&user.User{Uid: "991", Gid: "-1"}, nil),
	} {
		if h, err := newHostapd("/run/agentos-ap", l); err == nil {
			t.Errorf("%s: newHostapd = %+v, nil; want an error", name, h)
		}
	}
}

// The loader builds its access point only through newHostapd, which
// always sets User (#1426). Across every non-test file of the package,
// the one localui.Hostapd literal is newHostapd's, with User, there is no
// new(localui.Hostapd), and main passes newHostapd the real user lookup.
// (Hostapd's asCaller, which runs hostapd as root, is unexported: no file
// here can name it.)
func TestMainBuildsHostapdOnlyThroughNewHostapd(t *testing.T) {
	pkgs, err := parser.ParseDir(token.NewFileSet(), ".", func(fi fs.FileInfo) bool {
		return !strings.HasSuffix(fi.Name(), "_test.go")
	}, 0)
	if err != nil {
		t.Fatal(err)
	}
	pkg, ok := pkgs["main"]
	if !ok || len(pkgs) != 1 {
		t.Fatalf("packages %v, want main alone", pkgs)
	}
	isHostapd := func(e ast.Expr) bool {
		sel, ok := e.(*ast.SelectorExpr)
		return ok && sel.Sel.Name == "Hostapd"
	}
	var lits, news, calls []string
	for name, f := range pkg.Files {
		ast.Inspect(f, func(n ast.Node) bool {
			if _, ok := n.(*ast.FuncDecl); ok {
				return false // inspected below, with its name
			}
			switch n := n.(type) {
			case *ast.CompositeLit:
				if isHostapd(n.Type) {
					lits = append(lits, name+": outside any function")
				}
			case *ast.CallExpr:
				if id, ok := n.Fun.(*ast.Ident); ok && id.Name == "new" && len(n.Args) == 1 && isHostapd(n.Args[0]) {
					news = append(news, name+": outside any function")
				}
			}
			return true
		})
		for _, d := range f.Decls {
			fn, ok := d.(*ast.FuncDecl)
			if !ok {
				continue
			}
			ast.Inspect(fn, func(n ast.Node) bool {
				switch n := n.(type) {
				case *ast.CompositeLit:
					if isHostapd(n.Type) {
						keys := map[string]bool{}
						for _, e := range n.Elts {
							if kv, ok := e.(*ast.KeyValueExpr); ok {
								if id, ok := kv.Key.(*ast.Ident); ok {
									keys[id.Name] = true
								}
							}
						}
						if !keys["User"] {
							t.Errorf("%s: %s: a Hostapd literal with keys %v; want User", name, fn.Name.Name, keys)
						}
						lits = append(lits, fn.Name.Name)
					}
				case *ast.CallExpr:
					if id, ok := n.Fun.(*ast.Ident); ok && id.Name == "new" && len(n.Args) == 1 && isHostapd(n.Args[0]) {
						news = append(news, name+": "+fn.Name.Name)
					}
					if id, ok := n.Fun.(*ast.Ident); ok && id.Name == "newHostapd" && len(n.Args) == 2 {
						if sel, ok := n.Args[1].(*ast.SelectorExpr); ok && sel.Sel.Name == "Lookup" {
							calls = append(calls, fn.Name.Name)
						}
					}
				}
				return true
			})
		}
	}
	if len(lits) != 1 || lits[0] != "newHostapd" {
		t.Errorf("Hostapd literals in %v, want one, in newHostapd", lits)
	}
	if len(news) != 0 {
		t.Errorf("new(localui.Hostapd) in %v; build it through newHostapd", news)
	}
	if len(calls) != 1 || calls[0] != "main" {
		t.Errorf("newHostapd(dir, user.Lookup) called from %v, want main alone", calls)
	}
}
