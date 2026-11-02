// Command mutgate_stmts lists the statements tools/mutgate.py's deletion pass deletes, one at a
// time (MUTGATE-stmt-delete, #4573): gremlins v0.6.0 has no mutator that deletes a statement.
//
//	go run mutgate_stmts.go FILE.go...
//
// It prints one JSON array of sites, one for every statement in a statement list (a block, a
// case or select clause body, and the clauses of a switch or select): file is the base name, line
// and col where the statement starts in the file's own lines, start/end its byte offsets,
// cover_line/cover_col where coverage is judged, and keep_at/keep_default where the keep-alive
// of a deleted clause goes (see site). Declarations (`var`, `const`, `type`, `:=`) and empty
// statements are left out: deleting one never compiles or changes nothing. A file holding a
// `//line` directive is refused.
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
	"strings"
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
	// Where a deleted clause's keep-alive statements (`_ = NAME`) go, since a switch or select
	// body takes only clauses: right after the colon of another clause of a switch (where its init
	// and type-switch variables are in scope), or before a select (labels included), whose clause
	// variables are each clause's own. -1 for any other site, whose keep-alive takes its place.
	KeepAt int `json:"keep_at"`
	// A switch clause with no sibling is replaced by `default:` and its keep-alive.
	KeepDefault bool `json:"keep_default"`
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
		f, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution|parser.ParseComments)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		// PositionFor(..., false): the file's own lines, which the diff numbers; a `//line`
		// directive would otherwise renumber a site out of the added-line match.
		pos := func(p token.Pos) token.Position { return fset.PositionFor(p, false) }
		// A `//line` directive also renames or renumbers the file in the cover profile, so its
		// sites could not be judged: the file is refused rather than read as NOT COVERED.
		for _, g := range f.Comments {
			for _, c := range g.List {
				if strings.HasPrefix(c.Text, "//line ") || strings.HasPrefix(c.Text, "/*line ") {
					fmt.Fprintf(os.Stderr, "%s:%d: a //line directive; mutgate cannot judge its coverage\n", path, pos(c.Pos()).Line)
					os.Exit(1)
				}
			}
		}
		add := func(s ast.Stmt, cover token.Pos, keepAt int, keepDefault bool) {
			if deletable(s) {
				p, e, c := pos(s.Pos()), pos(s.End()), pos(s.Pos())
				if cover.IsValid() {
					c = pos(cover)
				}
				sites = append(sites, site{filepath.Base(path), p.Line, p.Column, p.Offset, e.Offset, c.Line, c.Column, keepAt, keepDefault})
			}
		}
		addList := func(list []ast.Stmt) {
			for _, s := range list {
				add(s, token.NoPos, -1, false)
			}
		}
		// A switch's clauses: the keep-alive goes after another clause's colon, or replaces the
		// clause with `default:` when it has no sibling.
		switchClauses := func(sw ast.Stmt, body *ast.BlockStmt) {
			for i, s := range body.List {
				keepAt := -1
				for j, o := range body.List {
					if j != i {
						keepAt = pos(o.(*ast.CaseClause).Colon).Offset + 1
						break
					}
				}
				add(s, sw.Pos(), keepAt, keepAt < 0)
			}
		}
		labeled := map[ast.Stmt]token.Pos{}
		ast.Inspect(f, func(n ast.Node) bool {
			switch n := n.(type) {
			case *ast.LabeledStmt:
				labeled[n.Stmt] = n.Pos()
			case *ast.SwitchStmt:
				switchClauses(n, n.Body)
			case *ast.TypeSwitchStmt:
				switchClauses(n, n.Body)
			case *ast.SelectStmt:
				before := n.Pos()
				if l, ok := labeled[n]; ok {
					before = l
				}
				for _, s := range n.Body.List {
					add(s, n.Pos(), pos(before).Offset, false)
				}
			case *ast.BlockStmt:
				if len(n.List) > 0 {
					switch n.List[0].(type) {
					case *ast.CaseClause, *ast.CommClause: // a switch or select body: added above
						return true
					}
				}
				addList(n.List)
			case *ast.CaseClause:
				addList(n.Body)
			case *ast.CommClause:
				addList(n.Body)
			}
			return true
		})
	}
	if err := json.NewEncoder(os.Stdout).Encode(sites); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
