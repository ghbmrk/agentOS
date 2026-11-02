// Command mutgate_stmts lists the statements tools/mutgate.py's deletion pass deletes, one at a
// time (MUTGATE-stmt-delete, #4573): gremlins v0.6.0 has no mutator that deletes a statement.
//
//	go run mutgate_stmts.go FILE.go...
//
// It prints one JSON array: {"file", "line", "col", "start", "end"} for every statement in a
// statement list (a block, or a case or select clause body) of each file, where file is the base
// name, line and col are where the statement starts and start/end are its byte offsets.
// Declarations (`var`, `const`, `type`, `:=`) and empty statements are left out: deleting one
// never compiles or changes nothing.
// It reads the files as data with go/parser and runs nothing in them.
package main

import (
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
)

type site struct {
	File  string `json:"file"`
	Line  int    `json:"line"`
	Col   int    `json:"col"`
	Start int    `json:"start"`
	End   int    `json:"end"`
}

func deletable(s ast.Stmt) bool {
	switch s := s.(type) {
	case *ast.DeclStmt, *ast.EmptyStmt:
		return false
	case *ast.AssignStmt:
		return s.Tok != token.DEFINE
	}
	return true
}

func main() {
	sites := []site{}
	fset := token.NewFileSet()
	for _, path := range os.Args[1:] {
		f, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		add := func(list []ast.Stmt) {
			for _, s := range list {
				if deletable(s) {
					p, e := fset.Position(s.Pos()), fset.Position(s.End())
					sites = append(sites, site{filepath.Base(path), p.Line, p.Column, p.Offset, e.Offset})
				}
			}
		}
		ast.Inspect(f, func(n ast.Node) bool {
			switch n := n.(type) {
			case *ast.BlockStmt:
				add(n.List)
			case *ast.CaseClause:
				add(n.Body)
			case *ast.CommClause:
				add(n.Body)
			}
			return true
		})
	}
	if err := json.NewEncoder(os.Stdout).Encode(sites); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
