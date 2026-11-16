package driver

// REQ: PLN-4, EVL-3

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// The kernel's sources, read from this package's directory (UPD-5r-b7f-1).
const (
	kernelDir      = "../../../kernel"
	keyDir         = "../../../kernel/key"
	assumptionsMD  = "../ASSUMPTIONS.md"
	stepCodesStart = "`kernel.Admit` checks the steps in order"
	stepCodesEnd   = "(`duplicate`)."
)

// TestTheAssumptionNamesTheKernelsStepChecks pins row UPD-5r-b7f-1's list of
// step-level refusals to the code: the codes the row names equal the codes
// kernel.Admit can refuse a step with, inside its loop over the steps and
// through key.Authorize. A check added to or removed from either fails here
// until the row says so, so a probe built against the row cannot miss one.
func TestTheAssumptionNamesTheKernelsStepChecks(t *testing.T) {
	row := rowStepCodes(t, readFile(t, assumptionsMD))
	code := kernelStepCodes(t)
	if !slices.Equal(row, code) {
		t.Fatalf("row UPD-5r-b7f-1 names %v; kernel.Admit refuses a step with %v", row, code)
	}
}

// TestTheStepCheckPinCatchesDrift is the pin's mutant: a code added to or
// dropped from either side is a difference.
func TestTheStepCheckPinCatchesDrift(t *testing.T) {
	md := readFile(t, assumptionsMD)
	row := rowStepCodes(t, md)
	extra := strings.Replace(md, stepCodesEnd, "(`extra-check`) or "+stepCodesEnd, 1)
	if got := rowStepCodes(t, extra); slices.Equal(got, row) {
		t.Fatal("a code added to the row was not read")
	}
	fewer := strings.Replace(md, "(`spend-task`, `spend-day`, `rate`, `uses`)", "(`spend-task`, `spend-day`, `rate`)", 1)
	if got := rowStepCodes(t, fewer); slices.Equal(got, row) {
		t.Fatal("a code dropped from the row was not read")
	}
	src := readFile(t, filepath.Join(keyDir, "authorize.go"))
	more := strings.Replace(src, "\treturn v.caps(s, c, false)\n}",
		"\tif s.Amount > 1 {\n\t\treturn refuse(\"new-check\", \"x\")\n\t}\n\treturn v.caps(s, c, false)\n}", 1)
	less := strings.Replace(src, "return refuse(RRate, \"%s cap %d\", cp.Kind, cp.N)", "return nil", 1)
	for name, mutant := range map[string]string{"added": more, "dropped": less} {
		if mutant == src {
			t.Fatalf("the %s mutant did not apply", name)
		}
		if got := stepCodesWith(t, map[string]string{filepath.Join(keyDir, "authorize.go"): mutant}); slices.Equal(got, kernelStepCodes(t)) {
			t.Fatalf("a check %s in key.Authorize was not read", name)
		}
	}
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// rowStepCodes is the sorted set of codes row UPD-5r-b7f-1's sentence on
// kernel.Admit names, each in backticks.
func rowStepCodes(t *testing.T, md string) []string {
	t.Helper()
	var row string
	for _, l := range strings.Split(md, "\n") {
		if strings.HasPrefix(l, "| UPD-5r-b7f-1 |") {
			row = l
		}
	}
	i := strings.Index(row, stepCodesStart)
	j := strings.Index(row, stepCodesEnd)
	if row == "" || i < 0 || j < i {
		t.Fatalf("row UPD-5r-b7f-1 has no sentence from %q to %q", stepCodesStart, stepCodesEnd)
	}
	seg := row[i+len(stepCodesStart) : j+len(stepCodesEnd)]
	var codes []string
	for _, m := range regexp.MustCompile("`([^`]+)`").FindAllStringSubmatch(seg, -1) {
		codes = append(codes, m[1])
	}
	return sortedSet(codes)
}

func sortedSet(s []string) []string {
	slices.Sort(s)
	return slices.Compact(s)
}

func kernelStepCodes(t *testing.T) []string { return stepCodesWith(t, nil) }

// pkgSrc is one parsed package: its functions and methods by name, and its
// string constants.
type pkgSrc struct {
	name   string
	funcs  map[string]*ast.FuncDecl // "Name" or "Recv.Name"
	consts map[string]string
}

func parsePkg(t *testing.T, dir string, override map[string]string) *pkgSrc {
	t.Helper()
	files, err := filepath.Glob(filepath.Join(dir, "*.go"))
	if err != nil {
		t.Fatal(err)
	}
	p := &pkgSrc{funcs: map[string]*ast.FuncDecl{}, consts: map[string]string{}}
	fset := token.NewFileSet()
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		var src any
		if s, ok := override[f]; ok {
			src = s
		}
		af, err := parser.ParseFile(fset, f, src, 0)
		if err != nil {
			t.Fatal(err)
		}
		p.name = af.Name.Name
		for _, d := range af.Decls {
			switch d := d.(type) {
			case *ast.FuncDecl:
				p.funcs[funcKey(d)] = d
			case *ast.GenDecl:
				if d.Tok != token.CONST {
					continue
				}
				for _, s := range d.Specs {
					vs := s.(*ast.ValueSpec)
					for k, n := range vs.Names {
						if k < len(vs.Values) {
							if lit, ok := vs.Values[k].(*ast.BasicLit); ok && lit.Kind == token.STRING {
								v, _ := strconv.Unquote(lit.Value)
								p.consts[n.Name] = v
							}
						}
					}
				}
			}
		}
	}
	return p
}

func funcKey(d *ast.FuncDecl) string {
	if d.Recv == nil || len(d.Recv.List) == 0 {
		return d.Name.Name
	}
	typ := d.Recv.List[0].Type
	if s, ok := typ.(*ast.StarExpr); ok {
		typ = s.X
	}
	return typ.(*ast.Ident).Name + "." + d.Name.Name
}

// returnsRefusal says whether d returns a refusal: only such a call can carry
// a refusal code to the step.
func returnsRefusal(d *ast.FuncDecl) bool {
	if d.Type.Results == nil {
		return false
	}
	for _, r := range d.Type.Results.List {
		if s, ok := r.Type.(*ast.StarExpr); ok {
			switch x := s.X.(type) {
			case *ast.Ident:
				if x.Name == "Refusal" {
					return true
				}
			case *ast.SelectorExpr:
				if x.Sel.Name == "Refusal" {
					return true
				}
			}
		}
	}
	return false
}

// codeParam is the index of d's parameter that d puts in a refusal's Code
// field, or -1 (key's refuse takes its code this way).
func codeParam(d *ast.FuncDecl) int {
	idx := -1
	var params []string
	for _, f := range d.Type.Params.List {
		for _, n := range f.Names {
			params = append(params, n.Name)
		}
	}
	ast.Inspect(d.Body, func(n ast.Node) bool {
		if kv, ok := n.(*ast.KeyValueExpr); ok {
			if k, ok := kv.Key.(*ast.Ident); ok && k.Name == "Code" {
				if v, ok := kv.Value.(*ast.Ident); ok {
					if i := slices.Index(params, v.Name); i >= 0 {
						idx = i
					}
				}
			}
		}
		return true
	})
	return idx
}

// stepCodesWith reads the step-level refusal codes from the kernel's sources,
// with override's files in place of the ones on disk: every code in admit's
// loop over the plan's steps, following each call into the kernel or key
// package that returns a refusal, key.Authorize among them.
func stepCodesWith(t *testing.T, override map[string]string) []string {
	t.Helper()
	kern := parsePkg(t, kernelDir, override)
	keyp := parsePkg(t, keyDir, override)
	pkgs := map[string]*pkgSrc{kern.name: kern, keyp.name: keyp}

	admit := kern.funcs["admit"]
	if admit == nil {
		t.Fatal("kernel has no admit")
	}
	var loop *ast.RangeStmt
	ast.Inspect(admit.Body, func(n ast.Node) bool {
		if r, ok := n.(*ast.RangeStmt); ok && loop == nil {
			if s, ok := r.X.(*ast.SelectorExpr); ok && s.Sel.Name == "Steps" {
				loop = r
			}
		}
		return loop == nil
	})
	if loop == nil {
		t.Fatal("kernel admit has no loop over the plan's steps")
	}

	codes := map[string]bool{}
	seen := map[*ast.FuncDecl]bool{}
	// resolve is the constant e names in p, failing on anything else.
	resolve := func(p *pkgSrc, e ast.Expr) string {
		switch e := e.(type) {
		case *ast.Ident:
			if v, ok := p.consts[e.Name]; ok {
				return v
			}
		case *ast.SelectorExpr:
			if x, ok := e.X.(*ast.Ident); ok {
				if q := pkgs[x.Name]; q != nil {
					if v, ok := q.consts[e.Sel.Name]; ok {
						return v
					}
				}
			}
		case *ast.BasicLit:
			if v, err := strconv.Unquote(e.Value); err == nil {
				return v
			}
		}
		t.Fatalf("refusal code %T at %v is no string constant", e, e.Pos())
		return ""
	}
	// callee is the refusal-returning function or method a call names.
	callee := func(p *pkgSrc, c *ast.CallExpr) (*pkgSrc, *ast.FuncDecl) {
		var cands []*ast.FuncDecl
		switch f := c.Fun.(type) {
		case *ast.Ident:
			cands = append(cands, p.funcs[f.Name])
		case *ast.SelectorExpr:
			if x, ok := f.X.(*ast.Ident); ok && pkgs[x.Name] != nil && x.Obj == nil {
				return pkgs[x.Name], pkgs[x.Name].funcs[f.Sel.Name]
			}
			for _, q := range []*pkgSrc{p, kern, keyp} {
				for k, d := range q.funcs {
					if strings.HasSuffix(k, "."+f.Sel.Name) && returnsRefusal(d) {
						return q, d
					}
				}
			}
		}
		if len(cands) == 1 && cands[0] != nil {
			return p, cands[0]
		}
		return nil, nil
	}
	var walk func(p *pkgSrc, body ast.Node)
	walk = func(p *pkgSrc, body ast.Node) {
		ast.Inspect(body, func(n ast.Node) bool {
			switch n := n.(type) {
			case *ast.CompositeLit:
				for _, el := range n.Elts {
					if kv, ok := el.(*ast.KeyValueExpr); ok {
						if k, ok := kv.Key.(*ast.Ident); ok && k.Name == "Code" {
							if v, ok := kv.Value.(*ast.Ident); ok && p.consts[v.Name] == "" && v.Obj != nil && v.Obj.Kind == ast.Var {
								continue // a parameter: its callers name the code
							}
							codes[resolve(p, kv.Value)] = true
						}
					}
				}
			case *ast.CallExpr:
				q, d := callee(p, n)
				if d == nil || !returnsRefusal(d) {
					return true
				}
				if i := codeParam(d); i >= 0 && i < len(n.Args) {
					codes[resolve(p, n.Args[i])] = true
				}
				if !seen[d] {
					seen[d] = true
					walk(q, d.Body)
				}
			}
			return true
		})
	}
	walk(kern, loop.Body)
	if len(codes) == 0 {
		t.Fatal("no step-level refusal codes read")
	}
	var out []string
	for c := range codes {
		out = append(out, c)
	}
	return sortedSet(out)
}
