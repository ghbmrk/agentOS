package main

// REQ: ARC-1, CH-7

import (
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"os/user"
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
// always sets User (#1426): main.go holds one localui.Hostapd literal, in
// newHostapd, with User and without AsCaller, and main passes it the real
// user lookup.
func TestMainBuildsHostapdOnlyThroughNewHostapd(t *testing.T) {
	f, err := parser.ParseFile(token.NewFileSet(), "main.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	var lits []string
	var calls []string
	for _, d := range f.Decls {
		fn, ok := d.(*ast.FuncDecl)
		if !ok {
			continue
		}
		ast.Inspect(fn, func(n ast.Node) bool {
			switch n := n.(type) {
			case *ast.CompositeLit:
				if sel, ok := n.Type.(*ast.SelectorExpr); ok && sel.Sel.Name == "Hostapd" {
					keys := map[string]bool{}
					for _, e := range n.Elts {
						if kv, ok := e.(*ast.KeyValueExpr); ok {
							if id, ok := kv.Key.(*ast.Ident); ok {
								keys[id.Name] = true
							}
						}
					}
					if !keys["User"] || keys["AsCaller"] {
						t.Errorf("%s: a Hostapd literal with keys %v; want User and no AsCaller", fn.Name.Name, keys)
					}
					lits = append(lits, fn.Name.Name)
				}
			case *ast.CallExpr:
				if id, ok := n.Fun.(*ast.Ident); ok && id.Name == "newHostapd" && len(n.Args) == 2 {
					if sel, ok := n.Args[1].(*ast.SelectorExpr); ok && sel.Sel.Name == "Lookup" {
						calls = append(calls, fn.Name.Name)
					}
				}
			case *ast.Ident:
				if n.Name == "AsCaller" {
					t.Errorf("%s names AsCaller, which runs hostapd as root", fn.Name.Name)
				}
			}
			return true
		})
	}
	if len(lits) != 1 || lits[0] != "newHostapd" {
		t.Errorf("Hostapd literals in %v, want one, in newHostapd", lits)
	}
	if len(calls) != 1 || calls[0] != "main" {
		t.Errorf("newHostapd(dir, user.Lookup) called from %v, want main alone", calls)
	}
}
