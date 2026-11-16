package driver

// REQ: PLN-4, EVL-3

import (
	"errors"
	"fmt"
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
		if got, err := stepCodesWith(t, map[string]string{filepath.Join(keyDir, "authorize.go"): mutant}); err == nil && slices.Equal(got, kernelStepCodes(t)) {
			t.Fatalf("a check %s in key.Authorize was not read", name)
		}
	}
	// Every way to write a step refusal's code either is read (the set
	// changes) or fails the read; none is skipped (L3 6923594464 and
	// 6923997232 on #5997). Each mutant is a step refusal added before the
	// irreversibility check in admit's loop, or an edit to key's refuse.
	const at = "\t\tif c.Irreversible() {"
	step := func(body string) map[string]string {
		return map[string]string{filepath.Join(kernelDir, "kernel.go"): "\t\tif st.Amount > 1<<40 {\n" + body + "\n\t\t}\n" + at}
	}
	ksrc := readFile(t, filepath.Join(kernelDir, "kernel.go"))
	const refuseBody = "\treturn &Refusal{Code: code, Detail: fmt.Sprintf(f, a...)}"
	base := kernelStepCodes(t)
	for name, c := range map[string]struct {
		edit   map[string]string // file -> replacement for its anchor
		anchor string
		tail   string // appended to the file, for a new function
		read   bool   // read as a new code, rather than an error
	}{
		"a local variable":              {edit: step(`			nc := "new-check"; return key.ID{}, nil, on(&key.Refusal{Code: nc, Detail: "x"}, &i)`), anchor: at},
		"an assigned Code field":        {edit: step(`			r := &key.Refusal{Detail: "x"}; r.Code = "new-check"; return key.ID{}, nil, on(r, &i)`), anchor: at, read: true},
		"a Code field set from a local": {edit: step(`			r := &key.Refusal{Detail: "x"}; nc := "new-check"; r.Code = nc; return key.ID{}, nil, on(r, &i)`), anchor: at},
		"a Code field appended to":      {edit: step(`			r := &key.Refusal{Code: key.RRate}; r.Code += "x"; return key.ID{}, nil, on(r, &i)`), anchor: at},
		"an unkeyed literal":            {edit: step(`			return key.ID{}, nil, on(&key.Refusal{"new-check", "x"}, &i)`), anchor: at},
		"a local shadowing a constant":  {edit: map[string]string{filepath.Join(keyDir, "authorize.go"): "\tif len(a) > 99 {\n\t\tRRate := \"new-check\"\n\t\treturn &Refusal{Code: RRate}\n\t}\n" + refuseBody}, anchor: refuseBody},
		"a local shadowing the package": {edit: step(`			key := struct{ RRate string }{"new-check"}; var r Refusal; r.Code = key.RRate; _ = r`), anchor: at},
		"a helper returning a value": {edit: step(`			r := newCheck(); return key.ID{}, nil, on(&r, &i)`), anchor: at,
			tail: "\nfunc newCheck() key.Refusal { return key.Refusal{Code: \"new-check\", Detail: \"x\"} }\n", read: true},
		"a helper assigning the field": {edit: step(`			var r key.Refusal; setCheck(&r); return key.ID{}, nil, on(&r, &i)`), anchor: at,
			tail: "\nfunc setCheck(r *key.Refusal) { r.Code = \"new-check\" }\n", read: true},
		"a closure bound in reach": {edit: step(`			mk := func() *key.Refusal { return &key.Refusal{Code: "new-check"} }; return key.ID{}, nil, on(mk(), &i)`), anchor: at, read: true},
		"a closure bound before the loop": {edit: map[string]string{filepath.Join(kernelDir, "kernel.go"): "on := func(r *key.Refusal, step *int) *Refusal {\n\t\tif step == nil {\n\t\t\tr = &key.Refusal{Code: \"new-check\"}\n\t\t}\n\t\treturn &Refusal{*r, step, v.Limits.Task}\n\t}"},
			anchor: "on := func(r *key.Refusal, step *int) *Refusal { return &Refusal{*r, step, v.Limits.Task} }", read: true},
		"a rebound closure":               {edit: step(`			on = func(r *key.Refusal, step *int) *Refusal { return &Refusal{key.Refusal{Code: "new-check"}, step, 0} }; return key.ID{}, nil, on(&key.Refusal{Code: key.RRate}, &i)`), anchor: at},
		"a func value of unknown binding": {edit: step(`			var mk func() *key.Refusal; return key.ID{}, nil, on(mk(), &i)`), anchor: at},
		"a reassigned code parameter":     {edit: map[string]string{filepath.Join(keyDir, "authorize.go"): "\tif code == RRate && len(a) > 99 {\n\t\tcode = \"new-check\"\n\t}\n" + refuseBody}, anchor: refuseBody},
		"a code parameter by address":     {edit: map[string]string{filepath.Join(keyDir, "authorize.go"): "\tsetCode(&code)\n" + refuseBody}, anchor: refuseBody},
	} {
		t.Run(name, func(t *testing.T) {
			over := map[string]string{}
			for f, rep := range c.edit {
				src := readFile(t, f)
				if f == filepath.Join(kernelDir, "kernel.go") {
					src = ksrc
				}
				m := strings.Replace(src, c.anchor, rep, 1)
				if m == src {
					t.Fatalf("the mutant did not apply to %s", f)
				}
				if f == filepath.Join(kernelDir, "kernel.go") {
					m += c.tail
				}
				over[f] = m
			}
			got, err := stepCodesWith(t, over)
			switch {
			case c.read && err != nil:
				t.Fatalf("want the new code read, got %v", err)
			case c.read && !slices.Contains(got, "new-check"):
				t.Fatalf("the new code was not read: %v", got)
			case !c.read && err == nil:
				t.Fatalf("want the read to fail; it read %v (base %v)", got, base)
			}
		})
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

func kernelStepCodes(t *testing.T) []string {
	t.Helper()
	codes, err := stepCodesWith(t, nil)
	if err != nil {
		t.Fatal(err)
	}
	return codes
}

// pkgSrc is one parsed package: its functions and methods by name, and its
// string constants.
type pkgSrc struct {
	name   string
	funcs  map[string]*ast.FuncDecl // "Name" or "Recv.Name"
	consts map[string]string
	files  []*ast.File
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
		p.files = append(p.files, af)
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

// isRefusalType says whether e names the Refusal type, here or as key's.
func isRefusalType(e ast.Expr) bool {
	switch x := e.(type) {
	case *ast.Ident:
		return x.Name == "Refusal"
	case *ast.SelectorExpr:
		return x.Sel.Name == "Refusal"
	}
	return false
}

// isCodeRefusal says whether e, in p, names key's Refusal, the struct that
// holds a Code (kernel's Refusal wraps one).
func isCodeRefusal(p *pkgSrc, e ast.Expr) bool {
	switch x := e.(type) {
	case *ast.Ident:
		return x.Name == "Refusal" && p.name == "key"
	case *ast.SelectorExpr:
		k, ok := x.X.(*ast.Ident)
		return ok && k.Name == "key" && x.Sel.Name == "Refusal"
	}
	return false
}

// buildsRefusal says whether d returns a refusal or builds one (a Refusal
// literal, or an assignment to a Code field): only such a call can carry a
// refusal code to the step, whatever it returns it as.
func buildsRefusal(d *ast.FuncDecl) bool {
	if returnsRefusal(d) {
		return true
	}
	found := false
	ast.Inspect(d.Body, func(n ast.Node) bool {
		switch n := n.(type) {
		case *ast.CompositeLit:
			found = found || isRefusalType(n.Type)
		case *ast.AssignStmt:
			for _, l := range n.Lhs {
				if s, ok := l.(*ast.SelectorExpr); ok && s.Sel.Name == "Code" {
					found = true
				}
			}
		}
		return !found
	})
	return found
}

// codeParam is the index of d's parameter that d puts in a refusal's Code
// field, or -1 (key's refuse takes its code this way).
func codeParam(d *ast.FuncDecl) int {
	idx := -1
	params := paramIdents(d)
	ast.Inspect(d.Body, func(n ast.Node) bool {
		if kv, ok := n.(*ast.KeyValueExpr); ok {
			if k, ok := kv.Key.(*ast.Ident); ok && k.Name == "Code" {
				if v, ok := kv.Value.(*ast.Ident); ok {
					if i := slices.IndexFunc(params, func(p *ast.Ident) bool { return p.Obj != nil && p.Obj == v.Obj }); i >= 0 {
						idx = i
					}
				}
			}
		}
		return true
	})
	return idx
}

// boundFuncLit is the func literal f was bound to by := or =, or nil; nil
// too when any other statement in p rebinds f, so the call may run another.
func boundFuncLit(p *pkgSrc, f *ast.Ident) *ast.FuncLit {
	a, ok := f.Obj.Decl.(*ast.AssignStmt)
	if !ok || len(a.Lhs) != len(a.Rhs) {
		return nil
	}
	rebound := false
	for _, af := range p.files {
		ast.Inspect(af, func(n ast.Node) bool {
			if b, ok := n.(*ast.AssignStmt); ok && b != a {
				for _, l := range b.Lhs {
					if id, ok := l.(*ast.Ident); ok && id.Obj == f.Obj {
						rebound = true
					}
				}
			}
			if u, ok := n.(*ast.UnaryExpr); ok && u.Op == token.AND {
				if id, ok := u.X.(*ast.Ident); ok && id.Obj == f.Obj {
					rebound = true // its address lets a callee rebind it
				}
			}
			return !rebound
		})
	}
	if rebound {
		return nil
	}
	for i, l := range a.Lhs {
		if id, ok := l.(*ast.Ident); ok && id.Name == f.Name {
			lit, _ := a.Rhs[i].(*ast.FuncLit)
			return lit
		}
	}
	return nil
}

// paramIdents is d's parameters in order.
func paramIdents(d *ast.FuncDecl) []*ast.Ident {
	var ps []*ast.Ident
	for _, f := range d.Type.Params.List {
		ps = append(ps, f.Names...)
	}
	return ps
}

// stepCodesWith reads the step-level refusal codes from the kernel's sources,
// with override's files in place of the ones on disk: every code in admit's
// loop over the plan's steps, following each call into the kernel or key
// package that builds a refusal, key.Authorize among them, and each closure
// bound in reach. A code is read from a Code: key or a Code field
// assignment; one it cannot read as a package-level string constant is an
// error, never skipped, as are an unkeyed key.Refusal literal, a reassigned
// or addressed code parameter and a call of a func value it cannot follow.
// The only identifier it leaves to the callers is the parameter codeParam
// names.
func stepCodesWith(t *testing.T, override map[string]string) ([]string, error) {
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
	seenLit := map[*ast.FuncLit]bool{}
	var bad []error
	// resolve is the constant e names in p, failing on anything else. A
	// name is read by its binding: a package-level constant (declared in
	// this file, an ast.Con, or in another, left unresolved), never a local
	// that shadows one.
	resolve := func(p *pkgSrc, e ast.Expr) string {
		switch e := e.(type) {
		case *ast.Ident:
			if v, ok := p.consts[e.Name]; ok && (e.Obj == nil || e.Obj.Kind == ast.Con) {
				return v
			}
		case *ast.SelectorExpr:
			if x, ok := e.X.(*ast.Ident); ok && x.Obj == nil {
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
		bad = append(bad, fmt.Errorf("refusal code %T %v at %v is no string constant", e, e, e.Pos()))
		return ""
	}
	type fn struct {
		p *pkgSrc
		d *ast.FuncDecl
	}
	// callees is every function or method that builds a refusal a call may
	// name:
	// a method call names each method of that name in either package, since
	// the receiver's type is not read.
	callees := func(p *pkgSrc, c *ast.CallExpr) []fn {
		var out []fn
		switch f := c.Fun.(type) {
		case *ast.Ident:
			if d := p.funcs[f.Name]; d != nil && buildsRefusal(d) {
				out = append(out, fn{p, d})
			}
		case *ast.SelectorExpr:
			if x, ok := f.X.(*ast.Ident); ok && pkgs[x.Name] != nil && x.Obj == nil {
				if d := pkgs[x.Name].funcs[f.Sel.Name]; d != nil && buildsRefusal(d) {
					out = append(out, fn{pkgs[x.Name], d})
				}
				return out
			}
			for _, q := range []*pkgSrc{kern, keyp} {
				for k, d := range q.funcs {
					if strings.HasSuffix(k, "."+f.Sel.Name) && buildsRefusal(d) {
						out = append(out, fn{q, d})
					}
				}
			}
		}
		return out
	}
	// walk reads the codes in body; param is the parameter of the function
	// walked that codeParam names (nil for none), whose callers name its code.
	var walk func(p *pkgSrc, body ast.Node, param *ast.Ident)
	walk = func(p *pkgSrc, body ast.Node, param *ast.Ident) {
		ast.Inspect(body, func(n ast.Node) bool {
			switch n := n.(type) {
			case *ast.AssignStmt:
				// A code set by assignment is read like a Code: key; the
				// code parameter is never reassigned.
				for i, l := range n.Lhs {
					switch l := l.(type) {
					case *ast.SelectorExpr:
						if l.Sel.Name != "Code" {
							continue
						}
						if n.Tok != token.ASSIGN || len(n.Rhs) != len(n.Lhs) {
							bad = append(bad, fmt.Errorf("a Code field set by %s at %v", n.Tok, n.Pos()))
							continue
						}
						codes[resolve(p, n.Rhs[i])] = true
					case *ast.Ident:
						if param != nil && l.Obj != nil && l.Obj == param.Obj {
							bad = append(bad, fmt.Errorf("the code parameter %s is reassigned at %v", l.Name, n.Pos()))
						}
					}
				}
			case *ast.UnaryExpr:
				// The code parameter's address lets a callee rewrite it.
				if v, ok := n.X.(*ast.Ident); ok && n.Op == token.AND && param != nil && v.Obj != nil && v.Obj == param.Obj {
					bad = append(bad, fmt.Errorf("the code parameter %s escapes by address at %v", v.Name, n.Pos()))
				}
			case *ast.CompositeLit:
				if isCodeRefusal(p, n.Type) {
					for _, el := range n.Elts {
						if _, ok := el.(*ast.KeyValueExpr); !ok {
							bad = append(bad, fmt.Errorf("an unkeyed Refusal literal at %v", n.Pos()))
							break
						}
					}
				}
				for _, el := range n.Elts {
					if kv, ok := el.(*ast.KeyValueExpr); ok {
						if k, ok := kv.Key.(*ast.Ident); ok && k.Name == "Code" {
							if v, ok := kv.Value.(*ast.Ident); ok && param != nil && v.Obj != nil && v.Obj == param.Obj {
								continue // the code parameter: its callers name the code
							}
							codes[resolve(p, kv.Value)] = true
						}
					}
				}
			case *ast.CallExpr:
				// A call of a func value: a closure bound in reach is
				// walked; any other (a parameter, a field, a result) is
				// no code the read can follow, so it fails.
				if f, ok := n.Fun.(*ast.Ident); ok && f.Obj != nil && f.Obj.Kind == ast.Var {
					lit := boundFuncLit(p, f)
					switch {
					case lit == nil:
						bad = append(bad, fmt.Errorf("a call of the func value %s at %v, which the read cannot follow", f.Name, n.Pos()))
					case !seenLit[lit]:
						seenLit[lit] = true
						walk(p, lit.Body, nil)
					}
				}
				for _, c := range callees(p, n) {
					var cp *ast.Ident
					if i := codeParam(c.d); i >= 0 {
						cp = paramIdents(c.d)[i]
						if i >= len(n.Args) {
							bad = append(bad, fmt.Errorf("call at %v passes no code", n.Pos()))
						} else {
							codes[resolve(p, n.Args[i])] = true
						}
					}
					if !seen[c.d] {
						seen[c.d] = true
						walk(c.p, c.d.Body, cp)
					}
				}
			}
			return true
		})
	}
	walk(kern, loop.Body, nil)
	if err := errors.Join(bad...); err != nil {
		return nil, err
	}
	if len(codes) == 0 {
		t.Fatal("no step-level refusal codes read")
	}
	var out []string
	for c := range codes {
		out = append(out, c)
	}
	return sortedSet(out), nil
}
