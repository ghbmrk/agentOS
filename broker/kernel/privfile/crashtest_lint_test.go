package privfile

// The crash-path lint (REV-CHK-save, #3903). WriteAtomic takes a stop hook
// that ends the write after a step as a crash would, but nothing required a
// caller's package to test it: #3311, #3444, #3476, #3434, #3868 and #3881
// were each a save whose failure path no test reached until review found it.
// So every WriteAtomic call in a non-test file under broker/ (this package
// aside) passes stop as a struct field or as a parameter of the function the
// call is in, and a _test.go file in the caller's directory sets it: a
// non-nil value keyed or assigned to that field's name, or a non-nil argument
// in that parameter's place in a call of that function. A directory that
// fails today has a pending line in crashPending naming the issue that adds
// its seam and test; a pending line for a directory that passes fails, so the
// list only shrinks.
//
// Bound: the check is by name, not by type or flow. A test that sets a field
// of the same name on another type, or calls another function of the same
// name, passes it, and nothing here shows the test runs the save or checks
// that memory, disk and what the owner was told agree after the stop (held by
// review, the substance of #3311, #3476, #3868 and #3881). A stop forwarded
// through a second function is not followed: a test sets the field, or calls
// the function, that the WriteAtomic call reads. A local or package variable
// shadowing the privfile import, calls in a pending directory, and Go outside
// broker/ or under broker/third_party are outside the check.

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// crashPending names the directories whose WriteAtomic calls fail the check
// on main, each with the issue that gives its calls a seam and a test.
const crashPending = `
pending broker/kernel/proc #4190 nil stop on main when the lint landed
pending broker/clerk/camera #4191 nil stop on main when the lint landed
pending broker/clerk/codecheck #4191 nil stop on main when the lint landed
pending broker/clerk/run #4191 nil stop on main when the lint landed
pending broker/cmd/agentos-camera #4192 nil stop on main when the lint landed
pending broker/cmd/agentos-clerk-model #4192 nil stop on main when the lint landed
pending broker/cmd/agentos-enroll #4192 nil stop on main when the lint landed
pending broker/cmd/agentos-homekit #4192 nil stop on main when the lint landed
pending broker/cmd/agentos-unlock #4192 nil stop on main when the lint landed
pending broker/update #4192 nil stop on main when the lint landed
pending broker/cmd/agentosd #4193 nil stop on main when the lint landed
pending broker/localsrv #4193 nil stop on main when the lint landed
pending broker/owner #4193 nil stop on main when the lint landed
pending broker/question #4193 nil stop on main when the lint landed
`

func TestEveryWriteAtomicCallerTestsACrash(t *testing.T) {
	const call = "package side\n\nimport \"example.test/broker/kernel/privfile\"\n\n"
	field := call + "type S struct{ dir string; stop func(int) bool }\n\nfunc (s *S) Save(b []byte) error { return privfile.WriteAtomic(s.dir, \"f\", b, s.stop) }\n"
	param := call + "func Save(dir string, b []byte, stop func(int) bool) error { return privfile.WriteAtomic(dir, \"f\", b, stop) }\n"
	lint := func(t *testing.T, files map[string]string, pending string) []string {
		t.Helper()
		problems, err := crashLint(fakeRepo(t, files), pending)
		if err != nil {
			t.Fatal(err)
		}
		return problems
	}
	one := func(t *testing.T, problems []string, want string) {
		t.Helper()
		if len(problems) != 1 || !strings.Contains(problems[0], want) {
			t.Fatalf("got %q, want one problem naming %q", problems, want)
		}
	}
	t.Run("a nil stop and no test fails", func(t *testing.T) {
		src := call + "func Save(dir string, b []byte) error { return privfile.WriteAtomic(dir, \"f\", b, nil) }\n"
		one(t, lint(t, map[string]string{"broker/side/side.go": src}, ""), "broker/side/side.go:5: Save")
		one(t, lint(t, map[string]string{"broker/side/side.go": src, "broker/side/side_test.go": "package side\n"}, ""), "nil stop")
	})
	t.Run("a test-set stop field passes", func(t *testing.T) {
		for name, test := range map[string]string{
			"keyed":    "package side\n\nvar _ = S{stop: func(i int) bool { return i == 2 }}\n",
			"assigned": "package side\n\nfunc f(s *S) { s.stop = func(i int) bool { return i == 2 } }\n",
		} {
			t.Run(name, func(t *testing.T) {
				files := map[string]string{"broker/side/side.go": field, "broker/side/side_test.go": test}
				if problems := lint(t, files, ""); len(problems) != 0 {
					t.Fatalf("got %q, want none", problems)
				}
			})
		}
	})
	t.Run("a field no test sets fails", func(t *testing.T) {
		for name, test := range map[string]string{
			"no test":       "",
			"set to nil":    "package side\n\nfunc f(s *S) { s.stop = nil }\n",
			"keyed nil":     "package side\n\nvar _ = S{stop: nil}\n",
			"another field": "package side\n\nfunc f(s *S) { s.dir = \"x\" }\n",
		} {
			t.Run(name, func(t *testing.T) {
				files := map[string]string{"broker/side/side.go": field}
				if test != "" {
					files["broker/side/side_test.go"] = test
				}
				one(t, lint(t, files, ""), "no test in broker/side sets the stop field")
			})
		}
	})
	t.Run("a test-set stop parameter passes", func(t *testing.T) {
		files := map[string]string{"broker/side/side.go": param, "broker/side/side_test.go": "package side\n\nfunc f() { Save(\"d\", nil, func(int) bool { return true }) }\n"}
		if problems := lint(t, files, ""); len(problems) != 0 {
			t.Fatalf("got %q, want none", problems)
		}
		files["broker/side/side_test.go"] = "package side_test\n\nimport \"example.test/broker/side\"\n\nfunc f() { side.Save(\"d\", nil, func(int) bool { return true }) }\n"
		if problems := lint(t, files, ""); len(problems) != 0 {
			t.Fatalf("an external test package: got %q, want none", problems)
		}
		files["broker/side/side_test.go"] = "package side\n\nfunc f() { Save(\"d\", nil, nil); Other(\"d\", nil, func(int) bool { return true }) }\n"
		one(t, lint(t, files, ""), "no test in broker/side calls Save with a non-nil stop")
	})
	t.Run("a parameter seen through a closure passes", func(t *testing.T) {
		src := call + "func Save(dir string, stop func(int) bool) error {\n\tw := func() error { return privfile.WriteAtomic(dir, \"f\", nil, stop) }\n\treturn w()\n}\n"
		files := map[string]string{"broker/side/side.go": src, "broker/side/side_test.go": "package side\n\nfunc f() { Save(\"d\", func(int) bool { return true }) }\n"}
		if problems := lint(t, files, ""); len(problems) != 0 {
			t.Fatalf("got %q, want none", problems)
		}
	})
	t.Run("a stop that is not a field or a named function's parameter fails", func(t *testing.T) {
		for name, body := range map[string]string{
			"a local":          "func Save(dir string) error { stop := func(int) bool { return false }; return privfile.WriteAtomic(dir, \"f\", nil, stop) }\n",
			"a literal":        "func Save(dir string) error { return privfile.WriteAtomic(dir, \"f\", nil, func(int) bool { return false }) }\n",
			"a closure's own":  "var Save = func(dir string, stop func(int) bool) error { return privfile.WriteAtomic(dir, \"f\", nil, stop) }\n",
			"a package var":    "var stop func(int) bool\n\nfunc Save(dir string) error { return privfile.WriteAtomic(dir, \"f\", nil, stop) }\n",
			"a call's result":  "func hook() func(int) bool { return nil }\n\nfunc Save(dir string) error { return privfile.WriteAtomic(dir, \"f\", nil, hook()) }\n",
			"a wrong arg list": "func Save(dir string) error { return privfile.WriteAtomic(dir, \"f\", nil) }\n",
		} {
			t.Run(name, func(t *testing.T) {
				files := map[string]string{"broker/side/side.go": call + body, "broker/side/side_test.go": "package side\n\nvar _ = S{stop: func(int) bool { return true }}\n\nfunc f() { Save(\"d\", func(int) bool { return true }) }\n"}
				one(t, lint(t, files, ""), "broker/side/side.go")
			})
		}
	})
	t.Run("an aliased import is seen; a dot import or a WriteAtomic value fails", func(t *testing.T) {
		alias := "package side\n\nimport pf \"example.test/broker/kernel/privfile\"\n\nfunc Save(dir string) error { return pf.WriteAtomic(dir, \"f\", nil, nil) }\n"
		one(t, lint(t, map[string]string{"broker/side/side.go": alias}, ""), "nil stop")
		dot := "package side\n\nimport . \"example.test/broker/kernel/privfile\"\n\nfunc Save(dir string) error { return WriteAtomic(dir, \"f\", nil, nil) }\n"
		one(t, lint(t, map[string]string{"broker/side/side.go": dot}, ""), "dot import")
		value := call + "var w = privfile.WriteAtomic\n"
		one(t, lint(t, map[string]string{"broker/side/side.go": value}, ""), "not called")
	})
	t.Run("test files and privfile itself are outside", func(t *testing.T) {
		files := map[string]string{
			"broker/side/side_test.go":            call + "func f() { privfile.WriteAtomic(\"d\", \"f\", nil, nil) }\n",
			"broker/kernel/privfile/privfile.go":  "package privfile\n\nfunc WriteAtomic(dir, name string, b []byte, stop func(int) bool) error { return nil }\n\nfunc g() { WriteAtomic(\"d\", \"f\", nil, nil) }\n",
			"broker/third_party/x/x.go":           call + "func f() { privfile.WriteAtomic(\"d\", \"f\", nil, nil) }\n",
			"broker/side/testdata/fixture/fix.go": call + "func f() { privfile.WriteAtomic(\"d\", \"f\", nil, nil) }\n",
		}
		if problems := lint(t, files, ""); len(problems) != 0 {
			t.Fatalf("got %q, want none", problems)
		}
	})
	t.Run("a pending directory passes until it is clean", func(t *testing.T) {
		nilCall := call + "func Save(dir string) error { return privfile.WriteAtomic(dir, \"f\", nil, nil) }\n"
		if problems := lint(t, map[string]string{"broker/side/side.go": nilCall}, "pending broker/side #1 its seam\n"); len(problems) != 0 {
			t.Fatalf("pending: got %q, want none", problems)
		}
		files := map[string]string{"broker/side/side.go": field, "broker/side/side_test.go": "package side\n\nvar _ = S{stop: func(int) bool { return true }}\n"}
		one(t, lint(t, files, "pending broker/side #1 its seam\n"), "stale pending line for broker/side")
		for name, text := range map[string]string{
			"a missing issue": "pending broker/side its seam\n",
			"a doubled line":  "pending broker/side #1 a\npending broker/side #1 b\n",
			"another word":    "allow broker/side #1 a\n",
		} {
			t.Run(name, func(t *testing.T) {
				if problems := lint(t, map[string]string{"broker/side/side.go": nilCall}, text); len(problems) == 0 {
					t.Fatalf("%q was accepted", text)
				}
			})
		}
	})
	t.Run("main", func(t *testing.T) {
		problems, err := crashLint(repoRoot(t), crashPending)
		if err != nil {
			t.Fatal(err)
		}
		if len(problems) != 0 {
			t.Fatalf("%d WriteAtomic call(s) no test reaches with a non-nil stop (pending lines are in broker/kernel/privfile/crashtest_lint_test.go):\n%s",
				len(problems), strings.Join(problems, "\n"))
		}
	})
}

// crashLint returns one line per problem: a WriteAtomic call outside a
// pending directory whose stop no test sets, or a pending line that is
// malformed or matches no failing directory.
func crashLint(root, pendingText string) ([]string, error) {
	mod, err := os.ReadFile(filepath.Join(root, "broker", "go.mod"))
	if err != nil {
		return nil, err
	}
	modPath := strings.TrimPrefix(strings.SplitN(string(mod), "\n", 2)[0], "module ")
	importPath := strings.TrimSpace(modPath) + "/kernel/privfile"

	var problems []string
	pending := map[string]bool{}
	for i, line := range strings.Split(pendingText, "\n") {
		f := strings.Fields(line)
		switch {
		case len(f) == 0:
		case f[0] == "pending" && len(f) >= 4 && len(f[2]) > 1 && strings.HasPrefix(f[2], "#"):
			if pending[f[1]] {
				problems = append(problems, fmt.Sprintf("crashPending line %d: a second pending line for %s", i+1, f[1]))
			}
			pending[f[1]] = true
		default:
			problems = append(problems, fmt.Sprintf("crashPending line %d: want \"pending <dir> #<issue> <reason>\", got %q", i+1, line))
		}
	}

	failing := map[string]bool{}
	err = filepath.WalkDir(filepath.Join(root, "broker"), func(p string, d os.DirEntry, err error) error {
		if err != nil || !d.IsDir() {
			return err
		}
		rel := filepath.ToSlash(strings.TrimPrefix(p, root+string(filepath.Separator)))
		switch {
		case rel == "broker/third_party", d.Name() == "testdata", d.Name() == "vendor", strings.HasPrefix(d.Name(), ".") && rel != "broker":
			return filepath.SkipDir
		case rel == "broker/kernel/privfile":
			return nil
		}
		found, err := crashLintDir(p, rel, importPath)
		if err != nil {
			return err
		}
		if len(found) == 0 {
			return nil
		}
		failing[rel] = true
		if !pending[rel] {
			problems = append(problems, found...)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	for dir := range pending {
		if !failing[dir] {
			problems = append(problems, fmt.Sprintf("stale pending line for %s: every WriteAtomic call there has a stop a test sets, or it has none", dir))
		}
	}
	sort.Strings(problems)
	return problems, nil
}

// stopSeam is where the stop of the WriteAtomic call at pos, in function
// caller, comes from: a field of that name, or the parameter at index of the
// named function fn.
type stopSeam struct {
	field, fn string
	index     int
	pos       token.Pos
	caller    string
}

// crashLintDir checks the WriteAtomic calls in one directory's non-test files
// against what its test files set.
func crashLintDir(dir, rel, importPath string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	fset := token.NewFileSet()
	var srcs, tests []*ast.File
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") {
			continue
		}
		f, err := parser.ParseFile(fset, filepath.Join(dir, e.Name()), nil, parser.SkipObjectResolution)
		if err != nil {
			return nil, err
		}
		if strings.HasSuffix(e.Name(), "_test.go") {
			tests = append(tests, f)
		} else {
			srcs = append(srcs, f)
		}
	}
	var problems []string
	report := func(pos token.Pos, fn, msg string) {
		p := fset.Position(pos)
		problems = append(problems, fmt.Sprintf("%s/%s:%d: %s %s", rel, filepath.Base(p.Filename), p.Line, fn, msg))
	}
	var seams []stopSeam
	for _, f := range srcs {
		name := ""
		for _, imp := range f.Imports {
			if path, _ := strconv.Unquote(imp.Path.Value); path == importPath {
				name = "privfile"
				if imp.Name != nil {
					name = imp.Name.Name
				}
			}
		}
		switch name {
		case "", "_":
			continue
		case ".":
			report(f.Package, "the file", "has a dot import of privfile; import it by name so the lint sees its WriteAtomic calls")
			continue
		}
		var stack []ast.Node // enclosing *ast.FuncDecl and *ast.FuncLit, innermost last
		called := map[*ast.SelectorExpr]bool{}
		ast.Inspect(f, func(n ast.Node) bool {
			if n == nil {
				return true
			}
			switch n := n.(type) {
			case *ast.CallExpr:
				if sel, ok := n.Fun.(*ast.SelectorExpr); ok {
					called[sel] = true
				}
			}
			return true
		})
		var walk func(n ast.Node)
		walk = func(n ast.Node) {
			ast.Inspect(n, func(c ast.Node) bool {
				if c == n {
					return true
				}
				switch c := c.(type) {
				case *ast.FuncDecl, *ast.FuncLit:
					stack = append(stack, c)
					walk(c)
					stack = stack[:len(stack)-1]
					return false
				case *ast.CallExpr:
					if sel, ok := c.Fun.(*ast.SelectorExpr); ok && isPrivfile(sel, name) {
						fn := enclosingName(stack)
						if len(c.Args) != 4 {
							report(c.Pos(), fn, "calls privfile.WriteAtomic without its four arguments")
						} else if s, msg := seamOf(c.Args[3], stack); msg != "" {
							report(c.Pos(), fn, msg)
						} else {
							s.pos, s.caller = c.Pos(), fn
							seams = append(seams, s)
						}
					}
				case *ast.SelectorExpr:
					if isPrivfile(c, name) && !called[c] {
						report(c.Pos(), enclosingName(stack), "uses privfile.WriteAtomic but not called; call it directly so the lint sees its stop")
					}
				}
				return true
			})
		}
		walk(f)
	}
	fields, calls := testSets(tests)
	for _, s := range seams {
		switch {
		case s.field != "" && !fields[s.field]:
			report(s.pos, s.caller, fmt.Sprintf("calls privfile.WriteAtomic with stop field %s, but no test in %s sets the stop field %s to a non-nil value", s.field, rel, s.field))
		case s.fn != "" && !calls[s.fn][s.index]:
			report(s.pos, s.caller, fmt.Sprintf("calls privfile.WriteAtomic with its parameter as stop, but no test in %s calls %s with a non-nil stop", rel, s.fn))
		}
	}
	return problems, nil
}

func isPrivfile(sel *ast.SelectorExpr, name string) bool {
	x, ok := sel.X.(*ast.Ident)
	return ok && x.Name == name && sel.Sel.Name == "WriteAtomic"
}

// seamOf returns where stop comes from, or why it is refused.
func seamOf(stop ast.Expr, stack []ast.Node) (stopSeam, string) {
	const want = "; pass a struct field or a parameter that a test sets"
	switch e := stop.(type) {
	case *ast.SelectorExpr:
		return stopSeam{field: e.Sel.Name}, ""
	case *ast.Ident:
		if e.Name == "nil" {
			return stopSeam{}, "calls privfile.WriteAtomic with a nil stop" + want
		}
		for i := len(stack) - 1; i >= 0; i-- {
			var params *ast.FieldList
			switch fn := stack[i].(type) {
			case *ast.FuncDecl:
				params = fn.Type.Params
			case *ast.FuncLit:
				params = fn.Type.Params
			}
			index := 0
			for _, field := range params.List {
				names := field.Names
				if len(names) == 0 {
					index++
					continue
				}
				for _, n := range names {
					if n.Name == e.Name {
						if fd, ok := stack[i].(*ast.FuncDecl); ok {
							return stopSeam{fn: fd.Name.Name, index: index}, ""
						}
						return stopSeam{}, "calls privfile.WriteAtomic with stop " + e.Name + ", a function literal's parameter that no test can name" + want
					}
					index++
				}
			}
		}
		return stopSeam{}, "calls privfile.WriteAtomic with stop " + e.Name + ", a local or package variable" + want
	}
	return stopSeam{}, "calls privfile.WriteAtomic with a stop that is not a field or a parameter" + want
}

func enclosingName(stack []ast.Node) string {
	for i := len(stack) - 1; i >= 0; i-- {
		if fd, ok := stack[i].(*ast.FuncDecl); ok {
			return fd.Name.Name
		}
	}
	return "package scope"
}

// testSets returns the field names the tests key or assign a non-nil value
// to, and for each function or method name the argument places a test call
// fills with a non-nil value.
func testSets(tests []*ast.File) (fields map[string]bool, calls map[string]map[int]bool) {
	fields, calls = map[string]bool{}, map[string]map[int]bool{}
	nonNil := func(e ast.Expr) bool {
		id, ok := e.(*ast.Ident)
		return !ok || id.Name != "nil"
	}
	for _, f := range tests {
		ast.Inspect(f, func(n ast.Node) bool {
			switch n := n.(type) {
			case *ast.KeyValueExpr:
				if k, ok := n.Key.(*ast.Ident); ok && nonNil(n.Value) {
					fields[k.Name] = true
				}
			case *ast.AssignStmt:
				if len(n.Lhs) == len(n.Rhs) {
					for i, l := range n.Lhs {
						if sel, ok := l.(*ast.SelectorExpr); ok && nonNil(n.Rhs[i]) {
							fields[sel.Sel.Name] = true
						}
					}
				}
			case *ast.CallExpr:
				var name string
				switch fn := n.Fun.(type) {
				case *ast.Ident:
					name = fn.Name
				case *ast.SelectorExpr:
					name = fn.Sel.Name
				}
				if name == "" {
					return true
				}
				for i, a := range n.Args {
					if nonNil(a) {
						if calls[name] == nil {
							calls[name] = map[int]bool{}
						}
						calls[name][i] = true
					}
				}
			}
			return true
		})
	}
	return fields, calls
}
