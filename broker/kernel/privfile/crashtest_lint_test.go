package privfile

// The crash-path lint (REV-CHK-save, #3903). WriteAtomic takes a stop hook
// that ends the write after a step as a crash would, but nothing required a
// caller's package to test it: #3311, #3444, #3476, #3434, #3868 and #3881
// were each a save whose failure path no test reached until review found it.
// So every WriteAtomic call in a non-test file under broker/ (this package
// aside) passes stop as a struct field or as a parameter of the function or
// method the call is in, and a _test.go file in the caller's directory that
// the per-PR race run compiles (raceRun) sets it: a non-nil value keyed or
// assigned to that field's name, or a non-nil argument in that parameter's
// place in a call of that function, after the receiver in a method
// expression. A nil in parentheses, converted to any type (generic and
// imported ones too), given alone to another package's function, or held in
// a variable nothing assigns counts as nil (nilish). A directory that fails
// today has a pending line in crashPending naming the issue that adds its
// seam and test; the line covers every call there, new ones included, as the
// path lint's pending lines do. A pending line for a directory that passes
// fails, so the list only shrinks.
//
// Bound: the check is by name, not by type or flow. A test that sets a field
// of the same name on another type, or calls another function of the same
// name, passes it, and nothing here shows the test runs the save or checks
// that memory, disk and what the owner was told agree after the stop (held by
// review, the substance of #3311, #3476, #3868 and #3881). A stop forwarded
// through a second function is not followed: a test sets the field, or calls
// the function, that the WriteAtomic call reads. A nil that only flow shows
// (a variable assigned nil after its declaration, a function of this
// directory returning nil, a field of a nil-valued struct, *new(T), a
// missing map entry) counts as set, as does a package variable when any
// variable of its name is assigned; a method value (f := (*S).Save) is not
// seen as one. A local or package variable shadowing
// the privfile import, calls in a pending directory, Go outside broker/, and
// broker/third_party and every vendor, testdata and dot-named directory at
// any depth are outside the check.

import (
	"fmt"
	"go/ast"
	"go/build"
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
	t.Run("a test file the per-PR race run does not compile does not count", func(t *testing.T) {
		set := "package side\n\nvar _ = S{stop: func(int) bool { return true }}\n"
		for name, file := range map[string]string{
			"an underscore name":      "_side_test.go",
			"a dot name":              ".side_test.go",
			"go:build ignore":         "side_test.go",
			"a tag CI sets elsewhere": "side_test.go",
			"another GOARCH":          "side_arm64_test.go",
			"another GOOS":            "side_windows_test.go",
		} {
			t.Run(name, func(t *testing.T) {
				test := set
				switch name {
				case "go:build ignore":
					test = "//go:build ignore\n\n" + set
				case "a tag CI sets elsewhere":
					test = "//go:build sitl\n\n" + set
				}
				files := map[string]string{"broker/side/side.go": field, "broker/side/" + file: test}
				one(t, lint(t, files, ""), "no test in broker/side sets the stop field")
			})
		}
		files := map[string]string{"broker/side/side.go": field, "broker/side/side_linux_test.go": "//go:build linux && amd64 && race\n\n" + set}
		if problems := lint(t, files, ""); len(problems) != 0 {
			t.Fatalf("a file the race run compiles: got %q, want none", problems)
		}
	})
	t.Run("a nil the test spells another way does not count", func(t *testing.T) {
		for name, test := range map[string]string{
			"parenthesised":                  "var _ = S{stop: (nil)}\n",
			"assigned in parentheses":        "func f(s *S) { s.stop = ((nil)) }\n",
			"a func-type conversion":         "var _ = S{stop: (func(int) bool)(nil)}\n",
			"a named-type conversion":        "type hook func(int) bool\n\nvar _ = S{stop: hook(nil)}\n",
			"a generic type's conversion":    "type hook[T any] func(int) bool\n\nvar _ = S{stop: hook[int](nil)}\n",
			"an imported type's conversion":  "import \"example.test/broker/hooks\"\n\nvar _ = S{stop: hooks.Hook(nil)}\n",
			"an imported function given nil": "import \"example.test/broker/hooks\"\n\nvar _ = S{stop: (hooks.Wrap)(nil)}\n",
			"a local never set":              "func f() { var h func(int) bool; _ = S{stop: h} }\n",
			"a local set to nil":             "func f() { h := (func(int) bool)(nil); _ = S{stop: h} }\n",
			"a package var never set":        "var h func(int) bool\n\nvar _ = S{stop: h}\n",
			"a chain of nil variables":       "var h func(int) bool\n\nfunc f() { g := h; _ = S{stop: g} }\n",
		} {
			t.Run(name, func(t *testing.T) {
				files := map[string]string{"broker/side/side.go": field, "broker/side/side_test.go": "package side\n\n" + test}
				one(t, lint(t, files, ""), "no test in broker/side sets the stop field")
			})
		}
		files := map[string]string{"broker/side/side.go": param, "broker/side/side_test.go": "package side\n\nfunc f() { var h func(int) bool; Save(\"d\", nil, (h)) }\n"}
		one(t, lint(t, files, ""), "no test in broker/side calls Save with a non-nil stop")
		for name, test := range map[string]string{
			"a local set to a func":           "func f() { h := func(int) bool { return true }; _ = S{stop: h} }\n",
			"a local assigned later":          "func f() { var h func(int) bool; h = func(int) bool { return true }; _ = S{stop: h} }\n",
			"a local set through &":           "func set(p *func(int) bool) {}\n\nfunc f() { var h func(int) bool; set(&h); _ = S{stop: h} }\n",
			"a package var set later":         "var h func(int) bool\n\nfunc init() { h = func(int) bool { return true } }\n\nvar _ = S{stop: h}\n",
			"a call given nil":                "func wrap(func(int) bool) func(int) bool { return func(int) bool { return true } }\n\nvar _ = S{stop: wrap(nil)}\n",
			"a local's method given nil":      "type W struct{}\n\nfunc (W) Wrap(func(int) bool) func(int) bool { return func(int) bool { return true } }\n\nfunc f() { var w W; _ = S{stop: w.Wrap(nil)} }\n",
			"a generic function given nil":    "func wrap[T any](func(int) bool) func(int) bool { return func(int) bool { return true } }\n\nvar _ = S{stop: wrap[int](nil)}\n",
			"a conversion of a hook":          "type hook func(int) bool\n\nvar _ = S{stop: hook(func(int) bool { return true })}\n",
			"a local redeclared by :=":        "func g() (func(int) bool, error) { return func(int) bool { return true }, nil }\n\nfunc f() { h := (func(int) bool)(nil); h, err := g(); _, _ = err, S{stop: h} }\n",
			"a local set by range =":          "func f(hs []func(int) bool) { var h func(int) bool; for _, h = range hs {}; _ = S{stop: h} }\n",
			"a field assigned in parentheses": "func f(s *S) { (s.stop) = func(int) bool { return true } }\n",
		} {
			t.Run(name, func(t *testing.T) {
				files := map[string]string{"broker/side/side.go": field, "broker/side/side_test.go": "package side\n\n" + test}
				if problems := lint(t, files, ""); len(problems) != 0 {
					t.Fatalf("got %q, want none", problems)
				}
			})
		}
	})
	t.Run("a package var set in another test file, or a parenthesised callee, counts", func(t *testing.T) {
		files := map[string]string{
			"broker/side/side.go":   field,
			"broker/side/a_test.go": "package side\n\nvar h func(int) bool\n\nvar _ = S{stop: h}\n",
			"broker/side/b_test.go": "package side\n\nfunc init() { h = func(int) bool { return true } }\n",
		}
		if problems := lint(t, files, ""); len(problems) != 0 {
			t.Fatalf("got %q, want none", problems)
		}
		files = map[string]string{"broker/side/side.go": param, "broker/side/side_test.go": "package side\n\nfunc f() { (Save)(\"d\", nil, func(int) bool { return true }) }\n"}
		if problems := lint(t, files, ""); len(problems) != 0 {
			t.Fatalf("got %q, want none", problems)
		}
	})
	t.Run("a method expression call's receiver argument is not the stop", func(t *testing.T) {
		method := call + "type S struct{ dir string }\n\nfunc (s *S) Save(b []byte, stop func(int) bool) error { return privfile.WriteAtomic(s.dir, \"f\", b, stop) }\n\ntype T struct{}\n\nfunc (T) Save(b []byte, stop func(int) bool) error { return nil }\n"
		hook := "func(int) bool { return true }"
		for name, test := range map[string]string{
			"(*S).Save with a nil stop":            "package side\n\nfunc f(s *S) { (*S).Save(s, []byte{1}, nil) }\n",
			"another type's method expression":     "package side\n\nfunc f(t T) { T.Save(t, nil, " + hook + ") }\n",
			"an external (*side.S).Save, nil stop": "package side_test\n\nimport \"example.test/broker/side\"\n\nfunc f(s *side.S) { (*side.S).Save(s, []byte{1}, nil) }\n",
		} {
			t.Run(name, func(t *testing.T) {
				files := map[string]string{"broker/side/side.go": method, "broker/side/side_test.go": test}
				one(t, lint(t, files, ""), "no test in broker/side calls Save with a non-nil stop")
			})
		}
		for name, test := range map[string]string{
			"(*S).Save with a stop":          "package side\n\nfunc f(s *S) { (*S).Save(s, nil, " + hook + ") }\n",
			"an external (*side.S).Save":     "package side_test\n\nimport \"example.test/broker/side\"\n\nfunc f(s *side.S) { (*side.S).Save(s, nil, " + hook + ") }\n",
			"a method call on a dereference": "package side\n\nfunc f(s *S) { (*s).Save(nil, " + hook + ") }\n",
		} {
			t.Run(name, func(t *testing.T) {
				files := map[string]string{"broker/side/side.go": method, "broker/side/side_test.go": test}
				if problems := lint(t, files, ""); len(problems) != 0 {
					t.Fatalf("got %q, want none", problems)
				}
			})
		}
		generic := call + "type S[T any] struct{ dir string }\n\nfunc (s *S[T]) Save(b []byte, stop func(int) bool) error { return privfile.WriteAtomic(s.dir, \"f\", b, stop) }\n"
		files := map[string]string{"broker/side/side.go": generic, "broker/side/side_test.go": "package side\n\nfunc f(s *S[int]) { (*S[int]).Save(s, []byte{1}, nil) }\n"}
		one(t, lint(t, files, ""), "no test in broker/side calls Save with a non-nil stop")
		files["broker/side/side_test.go"] = "package side_test\n\nimport \"example.test/broker/side\"\n\nfunc f(s *side.S[int]) { (*side.S[int]).Save(s, nil, " + hook + ") }\n"
		if problems := lint(t, files, ""); len(problems) != 0 {
			t.Fatalf("a generic method expression with a stop: got %q, want none", problems)
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
// named function or method fn.
type stopSeam struct {
	field, fn string
	recv      string // fn's receiver type name, if fn is a method
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
		test := strings.HasSuffix(e.Name(), "_test.go")
		mode := parser.SkipObjectResolution
		if test {
			ok, err := raceRun.MatchFile(dir, e.Name())
			if err != nil {
				return nil, err
			}
			if !ok {
				continue
			}
			mode = 0 // test files keep the parser's scopes, which nilish reads
		}
		f, err := parser.ParseFile(fset, filepath.Join(dir, e.Name()), nil, mode)
		if err != nil {
			return nil, err
		}
		if test {
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
	fields, calls := testSets(tests, newDirDecls(append(srcs, tests...)))
	for _, s := range seams {
		switch {
		case s.field != "" && !fields[s.field]:
			report(s.pos, s.caller, fmt.Sprintf("calls privfile.WriteAtomic with stop field %s, but no test in %s sets the stop field %s to a non-nil value", s.field, rel, s.field))
		case s.fn != "" && !calls.sets(s):
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
							s := stopSeam{fn: fd.Name.Name, index: index}
							if fd.Recv != nil && len(fd.Recv.List) == 1 {
								s.recv = typeName(fd.Recv.List[0].Type)
							}
							return s, ""
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

// raceRun is the build the per-PR race run (ci.yml: `go test -race` on an
// amd64 Linux runner, no -tags) gives each package. A test file it does not
// compile (a _ or . name, `//go:build ignore`, a tag only another workflow
// sets, another GOOS or GOARCH) runs on no PR's required check, so it cannot
// carry the crash test.
var raceRun = func() build.Context {
	c := build.Default
	c.GOOS, c.GOARCH, c.CgoEnabled = "linux", "amd64", true
	c.BuildTags = []string{"race"}
	return c
}()

// typeName is the name a receiver type ends in: S for S, *S, (*S), S[T]
// and *S[T, U]; "" for anything else.
func typeName(e ast.Expr) string {
	for {
		switch x := ast.Unparen(e).(type) {
		case *ast.StarExpr:
			e = x.X
		case *ast.IndexExpr:
			e = x.X
		case *ast.IndexListExpr:
			e = x.X
		case *ast.Ident:
			return x.Name
		default:
			return ""
		}
	}
}

// dirDecls is what nilish and methodExprType know about one directory's
// package-level names, by name across its source and test files.
type dirDecls struct {
	types    map[string]bool      // type names
	funcs    map[string]bool      // function names (not methods)
	pkgObjs  map[*ast.Object]bool // test files' package-level objects, which nilish reads by name
	vars     map[string]ast.Expr  // var name to its value; nil when declared without one
	assigned map[string]bool      // names assigned with = or whose address is taken anywhere
	objs     map[*ast.Object]bool // test-file locals assigned with = or whose address is taken
}

func newDirDecls(files []*ast.File) dirDecls {
	d := dirDecls{types: map[string]bool{}, funcs: map[string]bool{}, pkgObjs: map[*ast.Object]bool{}, vars: map[string]ast.Expr{}, assigned: map[string]bool{}, objs: map[*ast.Object]bool{}}
	mark := func(e ast.Expr) {
		if id, ok := ast.Unparen(e).(*ast.Ident); ok {
			d.assigned[id.Name] = true
			if id.Obj != nil {
				d.objs[id.Obj] = true
			}
		}
	}
	for _, f := range files {
		if f.Scope != nil {
			for _, o := range f.Scope.Objects {
				d.pkgObjs[o] = true
			}
		}
		for _, decl := range f.Decls {
			if fd, ok := decl.(*ast.FuncDecl); ok && fd.Recv == nil {
				d.funcs[fd.Name.Name] = true
			}
			g, ok := decl.(*ast.GenDecl)
			if !ok {
				continue
			}
			for _, spec := range g.Specs {
				switch sp := spec.(type) {
				case *ast.TypeSpec:
					d.types[sp.Name.Name] = true
				case *ast.ValueSpec:
					if g.Tok != token.VAR {
						continue
					}
					for i, n := range sp.Names {
						switch len(sp.Values) {
						case 0:
							d.vars[n.Name] = nil
						case len(sp.Names):
							d.vars[n.Name] = sp.Values[i]
						default: // one multi-value call: unknown
							mark(n)
						}
					}
				}
			}
		}
		ast.Inspect(f, func(n ast.Node) bool {
			switch n := n.(type) {
			case *ast.AssignStmt:
				for _, l := range n.Lhs {
					// := assigns a name it does not declare here (h, err := ...)
					if id, ok := l.(*ast.Ident); n.Tok != token.DEFINE || ok && id.Obj != nil && id.Obj.Decl != n {
						mark(l)
					}
				}
			case *ast.RangeStmt:
				if n.Tok == token.ASSIGN {
					for _, l := range []ast.Expr{n.Key, n.Value} {
						if l != nil {
							mark(l)
						}
					}
				}
			case *ast.UnaryExpr:
				if n.Op == token.AND {
					mark(n.X)
				}
			}
			return true
		})
	}
	return d
}

// nilish reports whether a test's value is nil however it is spelled: nil in
// parentheses, a call given only a nil value whose callee isFunc does not
// show to be a function (so every conversion, and also an imported
// function's call), or a variable that no statement assigns and whose
// declaration gives it no value or a nil one.
func (d dirDecls) nilish(e ast.Expr, seen map[string]bool) bool {
	switch x := ast.Unparen(e).(type) {
	case *ast.Ident:
		if x.Name == "nil" {
			return true
		}
		if seen[x.Name] {
			return false
		}
		seen[x.Name] = true
		if x.Obj == nil || d.pkgObjs[x.Obj] { // package level, declared in this file or another
			v, ok := d.vars[x.Name]
			return ok && !d.assigned[x.Name] && (v == nil || d.nilish(v, seen))
		}
		if x.Obj.Kind != ast.Var || d.objs[x.Obj] {
			return false
		}
		switch decl := x.Obj.Decl.(type) {
		case *ast.ValueSpec:
			if decl == nil {
				return false
			}
			for i, n := range decl.Names {
				if n.Obj == x.Obj {
					switch len(decl.Values) {
					case 0:
						return true
					case len(decl.Names):
						return d.nilish(decl.Values[i], seen)
					}
				}
			}
		case *ast.AssignStmt:
			if len(decl.Lhs) == len(decl.Rhs) {
				for i, l := range decl.Lhs {
					if id, ok := l.(*ast.Ident); ok && id.Obj == x.Obj {
						return d.nilish(decl.Rhs[i], seen)
					}
				}
			}
		}
		return false
	case *ast.CallExpr:
		return len(x.Args) == 1 && d.nilish(x.Args[0], seen) && !d.isFunc(x.Fun)
	}
	return false
}

// isFunc reports whether a call's callee is known to be a function rather
// than a type: a function literal, a function or function variable declared
// in a test's scope or in the directory, or a method of a value. Anything
// else (a type expression, a generic instantiation of one, or a name from
// another package, function or type alike) is not.
func (d dirDecls) isFunc(fun ast.Expr) bool {
	fun = ast.Unparen(fun)
	switch e := fun.(type) {
	case *ast.IndexExpr:
		fun = ast.Unparen(e.X)
	case *ast.IndexListExpr:
		fun = ast.Unparen(e.X)
	}
	switch e := fun.(type) {
	case *ast.FuncLit:
		return true
	case *ast.Ident:
		if e.Obj != nil && !d.pkgObjs[e.Obj] {
			return e.Obj.Kind == ast.Fun || e.Obj.Kind == ast.Var
		}
		_, v := d.vars[e.Name]
		return d.funcs[e.Name] || v
	case *ast.SelectorExpr:
		id, ok := ast.Unparen(e.X).(*ast.Ident)
		if !ok {
			return true // a method of a computed value
		}
		if id.Obj != nil && !d.pkgObjs[id.Obj] {
			return id.Obj.Kind == ast.Var // a method of a local value
		}
		_, v := d.vars[id.Name]
		return v // a method of a package variable; else another package's name
	}
	return false
}

// testCall is one call a test makes of a function or method: recv names the
// type when the call is a method expression such as (*S).Save(s, b, stop),
// whose first argument is the receiver; set holds the argument places given
// a non-nil value, counted after any receiver.
type testCall struct {
	recv string
	set  map[int]bool
}

type testCalls map[string][]testCall

// sets reports whether a test call of s.fn gives its stop parameter a
// non-nil value. A method expression of another type is another function.
func (c testCalls) sets(s stopSeam) bool {
	for _, call := range c[s.fn] {
		if (call.recv == "" || call.recv == s.recv) && call.set[s.index] {
			return true
		}
	}
	return false
}

// testSets returns the field names the tests key or assign a non-nil value
// to, and for each function or method name the calls the tests make of it.
func testSets(tests []*ast.File, d dirDecls) (fields map[string]bool, calls testCalls) {
	fields, calls = map[string]bool{}, testCalls{}
	nonNil := func(e ast.Expr) bool { return !d.nilish(e, map[string]bool{}) }
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
						if sel, ok := ast.Unparen(l).(*ast.SelectorExpr); ok && nonNil(n.Rhs[i]) {
							fields[sel.Sel.Name] = true
						}
					}
				}
			case *ast.CallExpr:
				var name string
				var c testCall
				args := n.Args
				switch fn := ast.Unparen(n.Fun).(type) {
				case *ast.Ident:
					name = fn.Name
				case *ast.SelectorExpr:
					name = fn.Sel.Name
					if r := d.methodExprType(fn.X); r != "" && len(args) > 0 {
						c.recv, args = r, args[1:]
					}
				}
				if name == "" {
					return true
				}
				c.set = map[int]bool{}
				for i, a := range args {
					if nonNil(a) {
						c.set[i] = true
					}
				}
				calls[name] = append(calls[name], c)
			}
			return true
		})
	}
	return fields, calls
}

// methodExprType returns the type a method expression's operand names: S in
// S.Save, (*S).Save, (*S[int]).Save and (*pkg.S).Save, when the directory declares a type of
// that name and the operand is not a local value, as s is in (*s).Save.
func (d dirDecls) methodExprType(x ast.Expr) string {
	for {
		switch e := ast.Unparen(x).(type) {
		case *ast.StarExpr:
			x = e.X
			continue
		case *ast.IndexExpr: // a generic type's instantiation, S[int]
			x = e.X
			continue
		case *ast.IndexListExpr:
			x = e.X
			continue
		case *ast.Ident:
			if (e.Obj == nil || e.Obj.Kind == ast.Typ) && d.types[e.Name] {
				return e.Name
			}
		case *ast.SelectorExpr:
			if id, ok := e.X.(*ast.Ident); ok && id.Obj == nil && d.types[e.Sel.Name] {
				return e.Sel.Name
			}
		}
		return ""
	}
}
