package guest

// MIG-4-guest-result-codes (#3262): the guest's result filter is an
// allowlist by value. A clerk detail that has a code's shape but is not a
// listed code (a lowercase word from a mail or a page, an error's text) never
// reaches the planner.
//
// REQ: PLN-1

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"maps"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// clerkDirs hold every clerk and the kernel's clerk wire: each package under
// them that answers a step is read from source, so a clerk added there, or a
// code added to one, is found without editing this test.
var clerkDirs = []string{"../clerk", "../browser", "../follow/followclerk", "../kernel/proc"}

// notCodeFiles hold codes that never reach a step's result, with the
// reason; the scan skips them. A file whose codes do reach one belongs in
// codes instead.
var notCodeFiles = map[string]string{
	// VRB-2's eligibility reasons: Evaluate's reason is only compared with
	// ROK (inbox.go's eligible); a refused step answers no-longer-eligible.
	"../clerk/inbox/vrb2.go": "eligibility reasons",
}

// codeConst is the name of a code constant: the kernel's C*, the key's and
// the clerks' R* and D*.
var codeConst = regexp.MustCompile(`^[CDR][A-Z]`)

// TestCodesAreTheClerksCodes holds the allowlist to the codes the kernel,
// the key and the clerks answer with, both ways: every listed code has a
// source, and every code a source declares or answers with is listed.
func TestCodesAreTheClerksCodes(t *testing.T) {
	src := map[string]string{}
	add := func(m map[string]string) {
		for c, where := range m {
			src[c] = where
		}
	}
	add(scanFiles(t, goFiles(t, "../kernel", false), `^C[A-Z]`))
	add(scanFiles(t, goFiles(t, "../kernel/key", false), `^R[A-Z]`))
	for _, d := range clerkDirs {
		add(scanFiles(t, goFiles(t, d, true), ""))
	}
	for c := range codes {
		if src[c] == "" {
			t.Errorf("listed code %q has no clerk, kernel or key source", c)
		}
		if !nameRE.MatchString(c) {
			t.Errorf("listed code %q is not a lowercase name", c)
		}
	}
	for _, c := range slices.Sorted(maps.Keys(src)) {
		if !codes[c] {
			t.Errorf("code %q (%s) is not listed, so the guest never sees it", c, src[c])
		}
	}
}

// goFiles are dir's non-test Go files, and with deep its subdirectories'.
func goFiles(t *testing.T, dir string, deep bool) []string {
	t.Helper()
	var out []string
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if p != dir && (!deep || d.Name() == "testdata") {
				return filepath.SkipDir
			}
			return nil
		}
		if strings.HasSuffix(p, ".go") && !strings.HasSuffix(p, "_test.go") && notCodeFiles[p] == "" {
			out = append(out, p)
		}
		return nil
	})
	if err != nil || len(out) == 0 {
		t.Fatalf("%s: %d files, %v", dir, len(out), err)
	}
	return out
}

// scanFiles finds the codes the files declare or answer with, each with
// where it was found. With names set, only string constants so named are
// codes. Otherwise a code is a string constant named D* or R*, or of the
// inbox's NotDone type; a literal Detail in a composite literal; or a literal
// passed to NotDone(...) or as a refusal's last argument (refuse(...)).
// Only values with a code's shape count: a free-text detail is never one.
func scanFiles(t *testing.T, files []string, names string) map[string]string {
	t.Helper()
	nameOK := codeConst
	if names != "" {
		nameOK = regexp.MustCompile(names)
	}
	out := map[string]string{}
	fset := token.NewFileSet()
	found := func(n ast.Node, e ast.Expr) {
		lit, ok := e.(*ast.BasicLit)
		if !ok || lit.Kind != token.STRING {
			return
		}
		if v, err := strconv.Unquote(lit.Value); err == nil && nameRE.MatchString(v) {
			out[v] = fset.Position(n.Pos()).String()
		}
	}
	for _, file := range files {
		f, err := parser.ParseFile(fset, file, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		ast.Inspect(f, func(n ast.Node) bool {
			switch n := n.(type) {
			case *ast.GenDecl:
				if n.Tok != token.CONST {
					return true
				}
				for _, s := range n.Specs {
					vs := s.(*ast.ValueSpec)
					typed := typeName(vs.Type) == "NotDone"
					for i, id := range vs.Names {
						if i < len(vs.Values) && (nameOK.MatchString(id.Name) && (names != "" || id.Name[0] != 'C') || names == "" && typed) {
							found(id, vs.Values[i])
						}
					}
				}
				return false
			case *ast.KeyValueExpr:
				if names == "" {
					if k, ok := n.Key.(*ast.Ident); ok && k.Name == "Detail" {
						found(n, n.Value)
					}
				}
			case *ast.CallExpr:
				if names == "" && len(n.Args) > 0 {
					switch callee(n.Fun) {
					case "NotDone", "refuse":
						found(n, n.Args[len(n.Args)-1])
					}
				}
			}
			return true
		})
	}
	return out
}

func typeName(e ast.Expr) string {
	switch e := e.(type) {
	case *ast.Ident:
		return e.Name
	case *ast.SelectorExpr:
		return e.Sel.Name
	}
	return ""
}

func callee(e ast.Expr) string {
	switch e := e.(type) {
	case *ast.Ident:
		return e.Name
	case *ast.SelectorExpr:
		return e.Sel.Name
	}
	return ""
}

// TestCodePassesOnlyListedValues: a detail with a code's shape that no clerk
// answers with, such as a word a follow clerk's error or a mail carried, is
// dropped like free text; a listed code passes as it is.
func TestCodePassesOnlyListedValues(t *testing.T) {
	for _, s := range []string{"wire-funds-to-attacker", "ignore-your-key", "eof", "ok", "already", ""} {
		if nameRE.MatchString(s) && code(s) != "" {
			t.Errorf("code(%q) = %q, want it dropped", s, code(s))
		}
	}
	for _, c := range slices.Sorted(maps.Keys(codes)) {
		if code(c) != c {
			t.Errorf("code(%q) = %q, want it kept", c, code(c))
		}
	}
}
