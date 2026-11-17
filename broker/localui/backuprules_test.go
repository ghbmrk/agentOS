package localui

import (
	"go/ast"
	"go/parser"
	"go/printer"
	"go/token"
	"net/url"
	"strings"
	"testing"

	"github.com/ghbmrk/agentos/broker/localapi"
)

// REQ: BAK-1, CH-12

// The place refusal names every rule the kernel's BackupTarget shape()
// and addable() apply to the name and folder, so following the text
// clears the refusal (BAK-1, CH-12, #5949). The rules are read from the
// kernel's source: a rule added, changed or dropped there fails here until
// this table, and so the text, follows it. A rule the page itself keeps is
// checked on formPlace instead. It reads backupText alone; the stop-flow
// test above checks the page shows backupText's text for every refusal.
func TestBackupTextNamesEveryKernelPlaceRule(t *testing.T) {
	text := backupText(Refused(localapi.ErrBackupPlace))
	limits, rules := kernelPlaceRules(t)
	for _, c := range []string{"MaxTargetName", "MaxLocator"} {
		if limits[c] == "" || !strings.Contains(text, limits[c]+" characters") {
			t.Errorf("place refusal lacks %s (%q): %q", c, limits[c], text)
		}
	}
	messy := formPlace(url.Values{"name": {"d"}, "locator": {" /media//d/x/../agentos/ "}})
	page := map[string]bool{
		// formPlace cleans the typed folder, and sends only a folder.
		"path.Clean(t.Locator) == t.Locator": messy.Locator == "/media/d/agentos",
		"case KindDir":                       messy.Kind == localapi.BackupKindDir,
	}
	words := map[string]string{
		"len(t.Name) == 0":                                  "1 to 64 characters",
		"len(t.Name) > MaxTargetName":                       "1 to 64 characters",
		"len(t.Locator) == 0":                               "full path starting with /",
		"len(t.Locator) > MaxLocator":                       "at most 1024 characters",
		"!utf8.ValidString(t.Locator)":                      "no hidden or control characters",
		"slices.ContainsFunc([]rune(t.Locator), invisible)": "no hidden or control characters",
		"t.Name[0] == '.'":                                  "not start with a dot",
		"strings.ContainsFunc(t.Name, func(c rune) bool {\n\treturn !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_' || c == '.')\n})": "only letters, digits, dots, dashes or underscores",
		"path.IsAbs(t.Locator)": "full path starting with /",
		"!slices.ContainsFunc(strings.Split(t.Locator, \"/\"), padded)": "no folder in its path starting or ending with a space",
	}
	seen := map[string]bool{}
	for _, r := range rules {
		seen[r] = true
		if ok, kept := page[r]; kept {
			if !ok {
				t.Errorf("the page no longer keeps kernel rule %q", r)
			}
			continue
		}
		w, named := words[r]
		if !named {
			t.Errorf("kernel place rule %q has no wording in this table", r)
		} else if !strings.Contains(text, w) {
			t.Errorf("place refusal lacks %q for kernel rule %q: %q", w, r, text)
		}
	}
	for r := range words {
		if !seen[r] {
			t.Errorf("table names %q, which the kernel no longer applies", r)
		}
	}
	for r := range page {
		if !seen[r] {
			t.Errorf("table names %q, which the kernel no longer applies", r)
		}
	}
}

// kernelPlaceRules reads broker/kernel/backuptarget.go: the target limits'
// values, and each rule shape() and addable() apply, printed as source. A
// statement it cannot read fails the test rather than hiding a rule.
func kernelPlaceRules(t *testing.T) (map[string]string, []string) {
	t.Helper()
	fs := token.NewFileSet()
	f, err := parser.ParseFile(fs, "../kernel/backuptarget.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	src := func(n ast.Node) string {
		var b strings.Builder
		if err := printer.Fprint(&b, fs, n); err != nil {
			t.Fatal(err)
		}
		return b.String()
	}
	var split func(e ast.Expr, op token.Token) []ast.Expr
	split = func(e ast.Expr, op token.Token) []ast.Expr {
		if p, ok := e.(*ast.ParenExpr); ok {
			e = p.X
		}
		if b, ok := e.(*ast.BinaryExpr); ok && b.Op == op {
			return append(split(b.X, op), split(b.Y, op)...)
		}
		return []ast.Expr{e}
	}
	limits := map[string]string{}
	var rules []string
	ret := func(s ast.Stmt) (ast.Expr, bool) {
		r, ok := s.(*ast.ReturnStmt)
		if !ok || len(r.Results) != 1 {
			return nil, false
		}
		return r.Results[0], true
	}
	for _, d := range f.Decls {
		switch d := d.(type) {
		case *ast.GenDecl:
			for _, sp := range d.Specs {
				if v, ok := sp.(*ast.ValueSpec); ok && len(v.Names) == 1 && len(v.Values) == 1 {
					limits[v.Names[0].Name] = src(v.Values[0])
				}
			}
		case *ast.FuncDecl:
			if d.Recv == nil || (d.Name.Name != "shape" && d.Name.Name != "addable") {
				continue
			}
			for _, s := range d.Body.List {
				switch s := s.(type) {
				case *ast.IfStmt:
					if len(s.Body.List) != 1 || s.Init != nil || s.Else != nil {
						t.Fatalf("%s: unread if: %s", d.Name.Name, src(s))
					}
					if e, ok := ret(s.Body.List[0]); !ok || src(e) != "false" {
						t.Fatalf("%s: unread if: %s", d.Name.Name, src(s))
					}
					for _, e := range split(s.Cond, token.LOR) {
						rules = append(rules, src(e))
					}
				case *ast.SwitchStmt:
					if src(s.Tag) != "t.Kind" {
						t.Fatalf("%s: unread switch: %s", d.Name.Name, src(s))
					}
					for _, c := range s.Body.List {
						cc := c.(*ast.CaseClause)
						if len(cc.List) != 1 || len(cc.Body) != 1 {
							t.Fatalf("%s: unread case: %s", d.Name.Name, src(cc))
						}
						e, ok := ret(cc.Body[0])
						if !ok {
							t.Fatalf("%s: unread case: %s", d.Name.Name, src(cc))
						}
						rules = append(rules, "case "+src(cc.List[0]))
						for _, e := range split(e, token.LAND) {
							rules = append(rules, src(e))
						}
					}
				case *ast.ReturnStmt:
					e, _ := ret(s)
					for _, e := range split(e, token.LAND) {
						if r := src(e); r != "false" && r != "t.shape()" {
							rules = append(rules, r)
						}
					}
				default:
					t.Fatalf("%s: unread statement: %s", d.Name.Name, src(s))
				}
			}
		}
	}
	return limits, rules
}
