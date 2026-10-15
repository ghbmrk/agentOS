package main

// REQ: REC-4, ARC-1

import (
	"go/ast"
	"go/parser"
	"go/token"
	"strconv"
	"testing"
)

// P-2 on #1614: main hands pageSocket the Wi-Fi file and the vault
// process's verify socket from their flags, in that order, and both
// flags name a path by default, so the hand-off is wired unless the
// operator turns it off.
func TestMainPassesThePageSocketItsFlags(t *testing.T) {
	f, err := parser.ParseFile(token.NewFileSet(), "main.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	var args []string
	defaults := map[string]string{}
	ast.Inspect(f, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		switch fn := call.Fun.(type) {
		case *ast.Ident:
			if fn.Name == "pageSocket" {
				if args != nil {
					t.Fatal("main builds the page socket twice")
				}
				args = []string{}
				for _, a := range call.Args {
					id, _ := a.(*ast.Ident)
					if id == nil {
						t.Fatalf("pageSocket argument is not a variable: %T", a)
					}
					args = append(args, id.Name)
				}
			}
		case *ast.SelectorExpr:
			if fn.Sel.Name != "StringVar" || len(call.Args) != 4 {
				return true
			}
			u, _ := call.Args[0].(*ast.UnaryExpr)
			if u == nil {
				return true
			}
			id, _ := u.X.(*ast.Ident)
			if id == nil {
				return true
			}
			switch v := call.Args[2].(type) {
			case *ast.BasicLit:
				defaults[id.Name], _ = strconv.Unquote(v.Value)
			case *ast.SelectorExpr:
				defaults[id.Name] = v.Sel.Name
			}
		}
		return true
	})
	want := []string{"localUIUID", "gid", "apNetPath", "verifySocket"}
	if len(args) != len(want) {
		t.Fatalf("pageSocket(%v), want %v", args, want)
	}
	for i := range want {
		if args[i] != want[i] {
			t.Fatalf("pageSocket(%v), want %v", args, want)
		}
	}
	for _, v := range want[2:] {
		if defaults[v] == "" {
			t.Fatalf("flag %s has no default path", v)
		}
	}
}
