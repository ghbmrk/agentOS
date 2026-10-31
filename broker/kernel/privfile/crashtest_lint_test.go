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
// expression. Names resolve as the go tool would within the test file's own
// package (the directory's package, or its external _test package, which
// also sees the directory's package through its import), not across the two;
// a name another package declares cannot be resolved, so a call through one
// (other.X.Save) counts only if its stop is set whether or not other.X is a
// type. A nil in parentheses, converted to any type, given alone to a function
// of another package, or held in a variable nothing in its package assigns
// counts as nil (nilish). A directory that fails
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
// (a variable assigned nil after its declaration, a function returning
// nil, a field of a nil-valued struct, *new(T), a
// missing map entry) counts as set, as does a package variable when any
// variable of its name in that package is assigned; a method value
// (f := (*S).Save) is not seen as one. A local or package variable shadowing
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
			"parenthesised":                     "var _ = S{stop: (nil)}\n",
			"assigned in parentheses":           "func f(s *S) { s.stop = ((nil)) }\n",
			"a func-type conversion":            "var _ = S{stop: (func(int) bool)(nil)}\n",
			"a named-type conversion":           "type hook func(int) bool\n\nvar _ = S{stop: hook(nil)}\n",
			"a generic type's conversion":       "type hook[T any] func(int) bool\n\nvar _ = S{stop: hook[int](nil)}\n",
			"an imported type's conversion":     "import \"example.test/broker/hooks\"\n\nvar _ = S{stop: hooks.Hook(nil)}\n",
			"an imported function given nil":    "import \"example.test/broker/hooks\"\n\nvar _ = S{stop: (hooks.Wrap)(nil)}\n",
			"a local never set":                 "func f() { var h func(int) bool; _ = S{stop: h} }\n",
			"a local set to nil":                "func f() { h := (func(int) bool)(nil); _ = S{stop: h} }\n",
			"a local var given nil":             "func f() { var h = (func(int) bool)(nil); _ = S{stop: h} }\n",
			"a typed local var given nil":       "func f() { var h func(int) bool = nil; _ = S{stop: h} }\n",
			"a local copying a nil package var": "var h func(int) bool\n\nfunc f() { h := h; _ = S{stop: h} }\n",
			"a package var never set":           "var h func(int) bool\n\nvar _ = S{stop: h}\n",
			"a chain of nil variables":          "var h func(int) bool\n\nfunc f() { g := h; _ = S{stop: g} }\n",
		} {
			t.Run(name, func(t *testing.T) {
				files := map[string]string{"broker/side/side.go": field, "broker/side/side_test.go": "package side\n\n" + test}
				one(t, lint(t, files, ""), "no test in broker/side sets the stop field")
			})
		}
		files := map[string]string{"broker/side/side.go": param, "broker/side/side_test.go": "package side\n\nfunc f() { var h func(int) bool; Save(\"d\", nil, (h)) }\n"}
		one(t, lint(t, files, ""), "no test in broker/side calls Save with a non-nil stop")
		for name, test := range map[string]string{
			"a local set to a func":                      "func f() { h := func(int) bool { return true }; _ = S{stop: h} }\n",
			"a local assigned later":                     "func f() { var h func(int) bool; h = func(int) bool { return true }; _ = S{stop: h} }\n",
			"a local set through &":                      "func set(p *func(int) bool) {}\n\nfunc f() { var h func(int) bool; set(&h); _ = S{stop: h} }\n",
			"a package var set later":                    "var h func(int) bool\n\nfunc init() { h = func(int) bool { return true } }\n\nvar _ = S{stop: h}\n",
			"a call given nil":                           "func wrap(func(int) bool) func(int) bool { return func(int) bool { return true } }\n\nvar _ = S{stop: wrap(nil)}\n",
			"a local's method given nil":                 "type W struct{}\n\nfunc (W) Wrap(func(int) bool) func(int) bool { return func(int) bool { return true } }\n\nfunc f() { var w W; _ = S{stop: w.Wrap(nil)} }\n",
			"a generic function given nil":               "func wrap[T any](func(int) bool) func(int) bool { return func(int) bool { return true } }\n\nvar _ = S{stop: wrap[int](nil)}\n",
			"a conversion of a hook":                     "type hook func(int) bool\n\nvar _ = S{stop: hook(func(int) bool { return true })}\n",
			"a local redeclared by :=":                   "func g() (func(int) bool, error) { return func(int) bool { return true }, nil }\n\nfunc f() { h := (func(int) bool)(nil); h, err := g(); _, _ = err, S{stop: h} }\n",
			"a local set by range =":                     "func f(hs []func(int) bool) { var h func(int) bool; for _, h = range hs {}; _ = S{stop: h} }\n",
			"a field assigned in parentheses":            "func f(s *S) { (s.stop) = func(int) bool { return true } }\n",
			"a function literal given nil":               "var _ = S{stop: func(func(int) bool) func(int) bool { return func(int) bool { return true } }(nil)}\n",
			"a local function variable given nil":        "func wrap(func(int) bool) func(int) bool { return func(int) bool { return true } }\n\nfunc f() { w := wrap; _ = S{stop: w(nil)} }\n",
			"a computed value's method given nil":        "type W struct{}\n\nfunc (W) Wrap(func(int) bool) func(int) bool { return func(int) bool { return true } }\n\nfunc mk() W { return W{} }\n\nvar _ = S{stop: mk().Wrap(nil)}\n",
			"a package var's method given nil":           "type W struct{}\n\nfunc (W) Wrap(func(int) bool) func(int) bool { return func(int) bool { return true } }\n\nvar w W\n\nvar _ = S{stop: w.Wrap(nil)}\n",
			"a two-parameter generic function given nil": "func wrap[T, U any](func(int) bool) func(int) bool { return func(int) bool { return true } }\n\nvar _ = S{stop: wrap[int, string](nil)}\n",
			"a local assigned in parentheses":            "func f() { var h func(int) bool; (h) = func(int) bool { return true }; _ = S{stop: h} }\n",
			"a package var from a multi-value call":      "func g() (func(int) bool, error) { return func(int) bool { return true }, nil }\n\nvar h, err = g()\n\nvar _ = S{stop: h}\n",
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
	t.Run("names resolve in the test file's own package, values are never receivers", func(t *testing.T) {
		store := call + "type S struct{ dir string; stop func(int) bool }\n\nfunc (s *S) Put(b []byte) error { return privfile.WriteAtomic(s.dir, \"f\", b, s.stop) }\n\ntype Store struct{ dir string }\n\nfunc (s *Store) Save(b []byte, stop func(int) bool, n int) error { return privfile.WriteAtomic(s.dir, \"f\", b, stop) }\n\nfunc hook(f func(int) bool) func(int) bool { return f }\n\nfunc Hook(f func(int) bool) func(int) bool { return func(int) bool { return true } }\n\nvar hooks int\n\nvar NoStop func(int) bool\n\nvar none func(int) bool\n\nvar Chain = none\n"
		ext := "package side_test\n\nimport \"example.test/broker/side\"\n\n"
		setField := "package side\n\nvar _ = S{stop: func(int) bool { return true }}\n"
		setSave := "package side\n\nfunc g(s *Store) { s.Save(nil, func(int) bool { return true }, 3) }\n"
		const field, save = "sets the stop field stop", "calls Save with a non-nil stop"
		for name, c := range map[string]struct{ a, b, want string }{
			"an index of a package var's field":                            {"package side\n\ntype fixture struct{ Store []*Store }\n\nvar fx fixture\n", "package side\n\nfunc f(b []byte) { fx.Store[0].Save(b, nil, 3) }\n", save},
			"a package var's field":                                        {"package side\n\ntype fixture struct{ Store *Store }\n\nvar fx fixture\n", "package side\n\nfunc f() { fx.Store.Save(nil, nil, 3) }\n", save},
			"an external package var named as the type":                    {ext + "var Store = &side.Store{}\n", "package side_test\n\nfunc f() { Store.Save(nil, nil, 3) }\n", save},
			"another package's operand, nil either way":                    {"", "package side\n\nimport \"example.test/broker/other\"\n\nfunc f() { other.Store.Save(nil, nil, 3) }\n", save},
			"an external test's own type, named as the package's function": {"", ext + "type hook func(int) bool\n\nvar _ = side.S{stop: hook(nil)}\n", field},
			"an import named as the package's var":                         {"", ext + "import \"example.test/broker/hooks\"\n\nvar _ = side.S{stop: hooks.Hook(nil)}\n", field},
			"the package's nil var, from an external test":                 {"", ext + "var _ = side.S{stop: side.NoStop}\n", field},
			"the package's var copying its nil var, from an external test": {"", ext + "var _ = side.S{stop: side.Chain}\n", field},
			"the package's nil var, dot-imported":                          {"", "package side_test\n\nimport . \"example.test/broker/side\"\n\nvar _ = S{stop: NoStop}\n", field},
		} {
			t.Run(name, func(t *testing.T) {
				other := setField
				if c.want == field {
					other = setSave
				}
				files := map[string]string{"broker/side/side.go": store, "broker/side/b_test.go": c.b, "broker/side/c_test.go": other}
				if c.a != "" {
					files["broker/side/a_test.go"] = c.a
				}
				one(t, lint(t, files, ""), c.want)
			})
		}
		hook := "func(int) bool { return true }"
		for name, c := range map[string]struct{ b, other string }{
			"the package's function given nil, from an external test": {ext + "var _ = side.S{stop: side.Hook(nil)}\n", setSave},
			"another package's operand, set either way":               {"package side\n\nimport \"example.test/broker/other\"\n\nfunc f() { other.Store.Save(nil, " + hook + ", " + hook + ") }\n", setField},
			"a method expression of the external type":                {ext + "func f(s *side.Store) { (*side.Store).Save(s, nil, " + hook + ", 3) }\n", setField},
			"a method expression of the dot-imported type":            {"package side_test\n\nimport . \"example.test/broker/side\"\n\nfunc f(s *Store) { (*Store).Save(s, nil, " + hook + ", 3) }\n", setField},
		} {
			t.Run(name, func(t *testing.T) {
				files := map[string]string{"broker/side/side.go": store, "broker/side/b_test.go": c.b, "broker/side/c_test.go": c.other}
				if problems := lint(t, files, ""); len(problems) != 0 {
					t.Fatalf("got %q, want none", problems)
				}
			})
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
		generic2 := call + "type S[T, U any] struct{ dir string }\n\nfunc (s *S[T, U]) Save(b []byte, stop func(int) bool) error { return privfile.WriteAtomic(s.dir, \"f\", b, stop) }\n"
		files = map[string]string{"broker/side/side.go": generic2, "broker/side/side_test.go": "package side\n\nfunc f(s *S[int, string]) { (*S[int, string]).Save(s, []byte{1}, nil) }\n"}
		one(t, lint(t, files, ""), "no test in broker/side calls Save with a non-nil stop")
		files["broker/side/side_test.go"] = "package side\n\nfunc f(s *S[int, string]) { (*S[int, string]).Save(s, nil, " + hook + ") }\n"
		if problems := lint(t, files, ""); len(problems) != 0 {
			t.Fatalf("a two-parameter generic method expression with a stop: got %q, want none", problems)
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
	self := strings.TrimSuffix(importPath, "/kernel/privfile") + strings.TrimPrefix(rel, "broker")
	fields, calls := testSets(tests, newDirDecls(srcs, tests, self))
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

// pkgDecls is one package's package-level names, read across its files: the
// directory's package (source and in-package test files) or its external
// _test package.
type pkgDecls struct {
	types    map[string]bool     // type names
	values   map[string]bool     // function, variable and constant names
	vars     map[string]ast.Expr // var name to its value; nil when declared without one
	assigned map[string]bool     // names assigned with = or whose address is taken anywhere in the package
}

// dirDecls is what the resolution below knows about one directory. A name
// resolves in the package of the file that uses it, never across the
// directory's two packages, and a name another package declares is known
// only when that package is the directory's own (an external test's import).
type dirDecls struct {
	pkgs map[string]*pkgDecls // by package name
	self string               // the directory's import path
	src  string               // the directory's non-test package name
	objs map[*ast.Object]bool // test-file locals assigned with = or whose address is taken
	pkgL map[*ast.Object]bool // test files' package-level objects, which resolve by name
}

func newDirDecls(srcs, tests []*ast.File, self string) dirDecls {
	d := dirDecls{pkgs: map[string]*pkgDecls{}, self: self, objs: map[*ast.Object]bool{}, pkgL: map[*ast.Object]bool{}}
	if len(srcs) > 0 {
		d.src = srcs[0].Name.Name
	}
	for _, f := range append(append([]*ast.File{}, srcs...), tests...) {
		p := d.pkg(f)
		if f.Scope != nil {
			for _, o := range f.Scope.Objects {
				d.pkgL[o] = true
			}
		}
		mark := func(e ast.Expr) {
			if id, ok := ast.Unparen(e).(*ast.Ident); ok {
				p.assigned[id.Name] = true
				if id.Obj != nil {
					d.objs[id.Obj] = true
				}
			}
		}
		for _, decl := range f.Decls {
			if fd, ok := decl.(*ast.FuncDecl); ok {
				if fd.Recv == nil {
					p.values[fd.Name.Name] = true
				}
				continue
			}
			g := decl.(*ast.GenDecl)
			for _, spec := range g.Specs {
				switch sp := spec.(type) {
				case *ast.TypeSpec:
					p.types[sp.Name.Name] = true
				case *ast.ValueSpec:
					for i, n := range sp.Names {
						p.values[n.Name] = true
						if g.Tok != token.VAR {
							continue
						}
						switch len(sp.Values) {
						case 0:
							p.vars[n.Name] = nil
						case len(sp.Names):
							p.vars[n.Name] = sp.Values[i]
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

func (d dirDecls) pkg(f *ast.File) *pkgDecls {
	p := d.pkgs[f.Name.Name]
	if p == nil {
		p = &pkgDecls{types: map[string]bool{}, values: map[string]bool{}, vars: map[string]ast.Expr{}, assigned: map[string]bool{}}
		d.pkgs[f.Name.Name] = p
	}
	return p
}

// kind is what an expression resolves to.
type kind int

const (
	unknown kind = iota // another package's name, a builtin, or unresolved
	isType
	isValue
	isImport
)

// fileRes resolves names as one test file sees them.
type fileRes struct {
	d       dirDecls
	p       *pkgDecls
	imports map[string]string // import name to path
	dot     *pkgDecls         // the directory's package, when this file dot-imports it
}

func (d dirDecls) file(f *ast.File) fileRes {
	r := fileRes{d: d, p: d.pkg(f), imports: map[string]string{}}
	for _, imp := range f.Imports {
		path, _ := strconv.Unquote(imp.Path.Value)
		name := path[strings.LastIndex(path, "/")+1:]
		if imp.Name != nil {
			name = imp.Name.Name
		}
		if name == "." && path == d.self && d.src != "" && d.pkgs[d.src] != r.p {
			r.dot = d.pkgs[d.src]
		}
		r.imports[name] = path
	}
	return r
}

// ident resolves a name: a local by its object, a package-level name in this
// file's package or in the directory's package when the file dot-imports it,
// else an import name of this file.
func (r fileRes) ident(id *ast.Ident) kind {
	if id.Obj != nil && !r.d.pkgL[id.Obj] {
		switch id.Obj.Kind {
		case ast.Typ:
			return isType
		case ast.Var, ast.Fun, ast.Con:
			return isValue
		}
		return unknown
	}
	switch {
	case r.p.types[id.Name]:
		return isType
	case r.p.values[id.Name]:
		return isValue
	case r.dot != nil && r.dot.types[id.Name]:
		return isType
	case r.dot != nil && r.dot.values[id.Name]:
		return isValue
	case r.imports[id.Name] != "":
		return isImport
	}
	return unknown
}

// selfDecls is the directory's own package as an external test reaches it
// through the import named pkg, or nil.
func (r fileRes) selfDecls(pkg *ast.Ident) *pkgDecls {
	if r.ident(pkg) == isImport && r.imports[pkg.Name] == r.d.self && r.d.src != "" {
		return r.d.pkgs[r.d.src]
	}
	return nil
}

// classify says whether e is a type or a value, and the type's name: S for
// S, *S, S[int], S[int, string], (*S) and, from an external test, side.S.
func (r fileRes) classify(e ast.Expr) (kind, string) {
	switch x := ast.Unparen(e).(type) {
	case *ast.Ident:
		return r.ident(x), x.Name
	case *ast.StarExpr:
		return r.classify(x.X)
	case *ast.IndexExpr:
		return r.classify(x.X) // a type's instantiation or a value's index
	case *ast.IndexListExpr:
		return r.classify(x.X)
	case *ast.SelectorExpr:
		pkg, ok := ast.Unparen(x.X).(*ast.Ident)
		if !ok || r.ident(pkg) != isImport {
			return isValue, "" // a field or method of a value, or a method expression
		}
		if p := r.selfDecls(pkg); p != nil {
			switch {
			case p.types[x.Sel.Name]:
				return isType, x.Sel.Name
			case p.values[x.Sel.Name]:
				return isValue, ""
			}
		}
		return unknown, "" // another package's name
	case *ast.FuncLit, *ast.CallExpr, *ast.CompositeLit, *ast.BasicLit, *ast.TypeAssertExpr, *ast.UnaryExpr, *ast.BinaryExpr, *ast.SliceExpr:
		return isValue, ""
	case *ast.FuncType, *ast.ArrayType, *ast.MapType, *ast.ChanType, *ast.InterfaceType, *ast.StructType:
		return isType, ""
	}
	return unknown, ""
}

// nilish reports whether a test's value is nil however it is spelled: nil in
// parentheses; a call given only a nil value whose callee does not resolve to
// a value (a conversion to any type, and also a call of a function from a
// package other than the directory's own, which cannot be resolved); or a
// variable no statement assigns whose declaration gives it no value or a nil
// one, including the directory's own package variable read from an external
// test.
func (r fileRes) nilish(e ast.Expr, seen map[any]bool) bool {
	switch x := ast.Unparen(e).(type) {
	case *ast.Ident:
		if x.Name == "nil" {
			return true
		}
		if x.Obj == nil || r.d.pkgL[x.Obj] { // package level, declared in this file or another
			p := r.p
			if !p.types[x.Name] && !p.values[x.Name] && r.dot != nil {
				p = r.dot
			}
			return r.pkgVarNil(p, x.Name, seen)
		}
		if seen[x.Obj] || x.Obj.Kind != ast.Var || r.d.objs[x.Obj] {
			return false
		}
		seen[x.Obj] = true
		switch decl := x.Obj.Decl.(type) {
		case *ast.ValueSpec:
			for i, n := range decl.Names {
				if n.Obj == x.Obj {
					switch len(decl.Values) {
					case 0:
						return true
					case len(decl.Names):
						return r.nilish(decl.Values[i], seen)
					}
				}
			}
		case *ast.AssignStmt:
			if len(decl.Lhs) == len(decl.Rhs) {
				for i, l := range decl.Lhs {
					if id, ok := l.(*ast.Ident); ok && id.Obj == x.Obj {
						return r.nilish(decl.Rhs[i], seen)
					}
				}
			}
		}
		return false
	case *ast.SelectorExpr:
		if pkg, ok := ast.Unparen(x.X).(*ast.Ident); ok {
			if p := r.selfDecls(pkg); p != nil {
				return r.pkgVarNil(p, x.Sel.Name, seen)
			}
		}
		return false
	case *ast.CallExpr:
		if len(x.Args) != 1 || !r.nilish(x.Args[0], seen) {
			return false
		}
		k, _ := r.classify(x.Fun)
		return k != isValue
	}
	return false
}

// pkgVarNil reports whether package p's variable name is nil: declared with
// no value or a nil one, and assigned nowhere in p. The directory's own
// package's values are read in its own scope.
func (r fileRes) pkgVarNil(p *pkgDecls, name string, seen map[any]bool) bool {
	key := [2]any{p, name}
	if seen[key] {
		return false
	}
	seen[key] = true
	v, ok := p.vars[name]
	if !ok || p.assigned[name] {
		return false
	}
	if v == nil {
		return true
	}
	if p != r.p { // the directory's package, read from its external test
		return fileRes{d: r.d, p: p, imports: map[string]string{}}.nilish(v, seen)
	}
	return r.nilish(v, seen)
}

// testCall is one call a test makes of a function or method: set holds the
// argument places given a non-nil value. recv names the type when the call
// is a method expression such as (*S).Save(s, b, stop), whose first argument
// is the receiver, and set is counted after it. When the operand is another
// package's name (pkg.X.Save), either reading may be the real one, so shifted
// holds the places counted after the first argument and the call counts only
// where both readings give a non-nil value.
type testCall struct {
	recv         string
	either       bool
	set, shifted map[int]bool
}

type testCalls map[string][]testCall

// sets reports whether a test call of s.fn gives its stop parameter a
// non-nil value. A method expression of another type is another function.
func (c testCalls) sets(s stopSeam) bool {
	for _, call := range c[s.fn] {
		switch {
		case call.either:
			if call.set[s.index] && call.shifted[s.index] {
				return true
			}
		case call.recv == "" || call.recv == s.recv:
			if call.set[s.index] {
				return true
			}
		}
	}
	return false
}

// testSets returns the field names the tests key or assign a non-nil value
// to, and for each function or method name the calls the tests make of it.
func testSets(tests []*ast.File, d dirDecls) (fields map[string]bool, calls testCalls) {
	fields, calls = map[string]bool{}, testCalls{}
	for _, f := range tests {
		r := d.file(f)
		nonNil := func(e ast.Expr) bool { return !r.nilish(e, map[any]bool{}) }
		places := func(args []ast.Expr) map[int]bool {
			set := map[int]bool{}
			for i, a := range args {
				if nonNil(a) {
					set[i] = true
				}
			}
			return set
		}
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
					if pkg, ok := ast.Unparen(fn.X).(*ast.Ident); ok && r.ident(pkg) == isImport {
						break // pkg.F(...), a package's function
					}
					switch k, t := r.classify(fn.X); {
					case k == isType && len(args) > 0:
						c.recv, args = t, args[1:]
					case k == unknown && len(args) > 0:
						c.either, c.shifted = true, places(args[1:])
					}
				}
				if name == "" {
					return true
				}
				c.set = places(args)
				calls[name] = append(calls[name], c)
			}
			return true
		})
	}
	return fields, calls
}
