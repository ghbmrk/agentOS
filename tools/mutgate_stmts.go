// Command mutgate_stmts lists the statements tools/mutgate.py's deletion pass deletes, one at a
// time (MUTGATE-stmt-delete, #4573): gremlins v0.6.0 has no mutator that deletes a statement.
//
//	go run mutgate_stmts.go FILE.go...
//
// It prints one JSON array: {"file", "line", "col", "start", "end"} for every statement in a
// statement list (a block, a case or select clause body, and the clauses of a switch or select)
// of each file, where file is the base name, line and col are where the statement starts in the
// file's own lines and start/end are its byte offsets; cover_line and cover_col are where coverage
// is judged.
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
	// Where coverage is judged: the statement's start, or for a case or select clause (whose
	// cover block starts after its colon, or is empty) the start of its switch or select.
	CoverLine int `json:"cover_line"`
	CoverCol  int `json:"cover_col"`
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
		// PositionFor(..., false): the file's own lines, which the diff numbers; a `//line`
		// directive would otherwise renumber a site out of the added-line match.
		pos := func(p token.Pos) token.Position { return fset.PositionFor(p, false) }
		add := func(list []ast.Stmt, cover token.Pos) {
			for _, s := range list {
				_, caseClause := s.(*ast.CaseClause)
				_, commClause := s.(*ast.CommClause)
				if deletable(s) && (caseClause || commClause) == cover.IsValid() {
					p, e, c := pos(s.Pos()), pos(s.End()), pos(s.Pos())
					if cover.IsValid() {
						c = pos(cover)
					}
					sites = append(sites, site{filepath.Base(path), p.Line, p.Column, p.Offset, e.Offset, c.Line, c.Column})
				}
			}
		}
		ast.Inspect(f, func(n ast.Node) bool {
			switch n := n.(type) {
			case *ast.SwitchStmt:
				add(n.Body.List, n.Pos())
			case *ast.TypeSwitchStmt:
				add(n.Body.List, n.Pos())
			case *ast.SelectStmt:
				add(n.Body.List, n.Pos())
			case *ast.BlockStmt: // a switch or select body's clauses are added above
				add(n.List, token.NoPos)
			case *ast.CaseClause:
				add(n.Body, token.NoPos)
			case *ast.CommClause:
				add(n.Body, token.NoPos)
			}
			return true
		})
	}
	if err := json.NewEncoder(os.Stdout).Encode(sites); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
