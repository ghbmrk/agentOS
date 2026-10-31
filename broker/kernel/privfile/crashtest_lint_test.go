package privfile

// The crash-path lint (REV-CHK-save, #3903). WriteAtomic takes a stop hook
// that ends the write after a step as a crash would, but nothing required a
// caller's package to test it: #3311, #3444, #3476, #3434, #3868 and #3881
// were each a save whose failure path no test reached until review found it.
// So every WriteAtomic call in a non-test file under broker/ (this package
// aside) passes stop as a struct field or as a parameter of the function or
// method the call is in, and a _test.go file in the caller's directory that
// the per-PR race run compiles (raceRun) sets it to a provably non-nil value:
// keyed or assigned to that field's name, or in that parameter's place in a
// call the type checker resolves to a function or method of that name (after
// the receiver of a method expression).
//
// The proof fails closed (REV-CHK-save-later, #4214). The directory's
// package, with its in-package tests, and then its external test package are
// type-checked with go/types, and every other import is left unresolved, so
// nothing declared outside this directory is ever proof. A stop is set only
// when it is a function literal, a function or method the checker resolves,
// a local declared with one of these and never assigned, address-taken or
// selected afterwards, or a call of a function this directory declares whose
// whole body is one return of one of these, so no defer can recover a panic
// into nil (nonNil). A method promoted from an embedded type is refused,
// since a field of an unloaded embedded type could shadow it. Every other
// shape, nil spelled any way included, counts as nil: a package variable, a
// parameter, a conversion, any other call. A hook the lint cannot prove is a
// false fail, which the test fixes by writing the hook inline.
//
// A directory that fails today has a pending line in crashPending naming the
// issue that adds its seam and test; the line covers every call there, new
// ones included, as the path lint's pending lines do. A pending line for a
// directory that passes fails, so the list only shrinks.
//
// Bound: the seam is matched by name, not by object (#4273). A test that
// sets a field of the same name on another type, or calls another function
// of the same name, passes it, and nothing here shows the test runs the save
// or checks that memory, disk and what the owner was told agree after the
// stop (held by review, the substance of #3311, #3476, #3868 and #3881). A
// stop forwarded through a second function is not followed: a test sets the
// field, or calls the function, that the WriteAtomic call reads. A source
// local shadowing the stop parameter's name, a local or package variable
// shadowing the privfile import, calls in a pending
// directory, Go outside broker/, and broker/third_party and every vendor,
// testdata and dot-named directory at any depth are outside the check.

import (
	"fmt"
	"go/ast"
	"go/build"
	"go/parser"
	"go/token"
	"go/types"
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
		for name, c := range map[string]struct{ file, head string }{
			"an underscore name":      {"_side_test.go", ""},
			"a dot name":              {".side_test.go", ""},
			"go:build ignore":         {"side_test.go", "//go:build ignore\n\n"},
			"a tag CI sets elsewhere": {"side_test.go", "//go:build sitl\n\n"},
			"another GOARCH":          {"side_arm64_test.go", ""},
			"another GOOS":            {"side_windows_test.go", ""},
		} {
			t.Run(name, func(t *testing.T) {
				files := map[string]string{"broker/side/side.go": field, "broker/side/" + c.file: c.head + set}
				one(t, lint(t, files, ""), "no test in broker/side sets the stop field")
			})
		}
		files := map[string]string{"broker/side/side.go": field, "broker/side/side_linux_test.go": "//go:build linux && amd64 && race\n\n" + set}
		if problems := lint(t, files, ""); len(problems) != 0 {
			t.Fatalf("a file the race run compiles: got %q, want none", problems)
		}
	})
	t.Run("a stop counts only when it is provably non-nil", func(t *testing.T) {
		// side.go declares the field seam S.stop and, for the external and
		// cross-file shapes, a hooks import, package variables and functions.
		src := field + "\nvar NoStop func(int) bool\n\nvar Set = func(int) bool { return true }\n\nfunc Hook(f func(int) bool) func(int) bool { return f }\n\nfunc StopAt(i int) func(int) bool { return func(j int) bool { return j == i } }\n"
		ext := "package side_test\n\nimport \"example.test/broker/side\"\n\n"
		hooks := "import \"example.test/broker/hooks\"\n\n"
		fails := map[string][]string{
			"parenthesised nil":                    {"package side\n\nvar _ = S{stop: (nil)}\n"},
			"nil assigned in parentheses":          {"package side\n\nfunc f(s *S) { (s.stop) = ((nil)) }\n"},
			"a func-type conversion":               {"package side\n\nvar _ = S{stop: (func(int) bool)(nil)}\n"},
			"a named-type conversion":              {"package side\n\ntype hook func(int) bool\n\nvar _ = S{stop: hook(nil)}\n"},
			"a generic type's conversion":          {"package side\n\ntype hook[T any] func(int) bool\n\nvar _ = S{stop: hook[int](nil)}\n"},
			"a conversion of a literal":            {"package side\n\ntype hook func(int) bool\n\nvar _ = S{stop: hook(func(int) bool { return true })}\n"},
			"an imported type's conversion":        {"package side\n\n" + hooks + "var _ = S{stop: hooks.Hook(nil)}\n"},
			"an imported function":                 {"package side\n\n" + hooks + "var _ = S{stop: hooks.Always}\n"},
			"an imported function's result":        {"package side\n\n" + hooks + "var _ = S{stop: hooks.At(2)}\n"},
			"a local never set":                    {"package side\n\nfunc f() { var h func(int) bool; _ = S{stop: h} }\n"},
			"a local declared nil":                 {"package side\n\nfunc f() { var h func(int) bool = nil; _ = S{stop: h} }\n"},
			"a local assigned after":               {"package side\n\nfunc f() { h := func(int) bool { return true }; h = nil; _ = S{stop: h} }\n"},
			"a local assigned in parentheses":      {"package side\n\nfunc f() { h := func(int) bool { return true }; (h) = nil; _ = S{stop: h} }\n"},
			"a local assigned in a closure":        {"package side\n\nfunc f() { h := func(int) bool { return true }; func() { h = nil }(); _ = S{stop: h} }\n"},
			"a local set through &":                {"package side\n\nfunc clear(p *func(int) bool) { *p = nil }\n\nfunc f() { h := func(int) bool { return true }; clear(&h); _ = S{stop: h} }\n"},
			"a local redeclared by :=":             {"package side\n\nfunc g() (func(int) bool, error) { return nil, nil }\n\nfunc f() { h := func(int) bool { return true }; h, err := g(); _, _ = err, S{stop: h} }\n"},
			"a local set by range =":               {"package side\n\nfunc f(hs []func(int) bool) { h := func(int) bool { return true }; for _, h = range hs {}; _ = S{stop: h} }\n"},
			"a local from a multi-value call":      {"package side\n\nfunc g() (func(int) bool, error) { return nil, nil }\n\nfunc f() { h, _ := g(); _ = S{stop: h} }\n"},
			"a local copying a package var":        {"package side\n\nfunc f() { h := Set; _ = S{stop: h} }\n"},
			"a parameter":                          {"package side\n\nfunc f(h func(int) bool) { _ = S{stop: h} }\n"},
			"a package var":                        {"package side\n\nvar _ = S{stop: Set}\n"},
			"a package var given a hook later":     {"package side\n\nvar h func(int) bool\n\nfunc init() { h = func(int) bool { return true } }\n\nvar _ = S{stop: h}\n"},
			"a call that may return nil":           {"package side\n\nfunc g(ok bool) func(int) bool { if ok { return func(int) bool { return true } }; return nil }\n\nvar _ = S{stop: g(true)}\n"},
			"a call that passes its argument on":   {"package side\n\nvar _ = S{stop: Hook(nil)}\n"},
			"a local cleared by a pointer method":  {"package side\n\ntype hook func(int) bool\n\nfunc (h *hook) clear() { *h = nil }\n\nfunc f() { var h hook = func(int) bool { return true }; h.clear(); _ = S{stop: h} }\n"},
			"a call that recovers a panic":         {"package side\n\nfunc g() func(int) bool { defer func() { recover() }(); panic(1) }\n\nvar _ = S{stop: g()}\n"},
			"a call that recovers before a return": {"package side\n\nfunc g() func(int) bool { defer func() { recover() }(); var m map[int]int; m[0] = 1; return func(int) bool { return true } }\n\nvar _ = S{stop: g()}\n"},
			"a call with an empty body":            {"package side\n\nfunc g() func(int) bool { for {} }\n\nvar _ = S{stop: g()}\n"},
			"a method an unloaded embed shadows":   {"package side\n\n" + hooks + "type inner struct{}\n\nfunc (inner) Stop(int) bool { return true }\n\ntype deep struct{ inner }\n\ntype W struct {\n\thooks.Base\n\tdeep\n}\n\nvar _ = S{stop: W{}.Stop}\n"},
			"a call an unloaded embed shadows":     {"package side\n\n" + hooks + "type inner struct{}\n\nfunc (inner) At(i int) func(int) bool { return func(j int) bool { return j == i } }\n\ntype deep struct{ inner }\n\ntype W struct {\n\thooks.Base\n\tdeep\n}\n\nvar _ = S{stop: W{}.At(2)}\n"},
			"a call with a named result":           {"package side\n\nfunc g() (h func(int) bool) { defer func() { h = nil }(); return func(int) bool { return true } }\n\nvar _ = S{stop: g()}\n"},
			"a local function variable's result":   {"package side\n\nfunc f() { g := StopAt; _ = S{stop: g(2)} }\n"},
			"a field of a value":                   {"package side\n\ntype hooks struct{ h func(int) bool }\n\nvar _ = S{stop: hooks{}.h}\n"},
			"the package's nil var, external":      {ext + "var _ = side.S{stop: side.NoStop}\n"},
			"the package's var, dot-imported":      {"package side_test\n\nimport . \"example.test/broker/side\"\n\nvar _ = S{stop: NoStop}\n"},
			"an external test's own conversion":    {ext + "type hook func(int) bool\n\nvar _ = side.S{stop: hook(nil)}\n"},
			"a nil var declared in another file":   {"package side\n\n" + hooks + "var none = hooks.Hook(nil)\n", "package side\n\nvar _ = S{stop: none}\n"},
			"a nil var a dot import declares":      {"package side_test\n\nimport . \"example.test/broker/side\"\n\nvar h = NoStop\n", "package side_test\n\nimport \"example.test/broker/side\"\n\nvar _ = side.S{stop: h}\n"},
			"a hook only an ignored file defines":  {"//go:build ignore\n\npackage side\n\nfunc always(int) bool { return true }\n", "package side\n\nvar _ = S{stop: always}\n"},
		}
		for name, tests := range fails {
			t.Run(name, func(t *testing.T) {
				files := map[string]string{"broker/side/side.go": src}
				for i, test := range tests {
					files[fmt.Sprintf("broker/side/t%d_test.go", i)] = test
				}
				one(t, lint(t, files, ""), "no test in broker/side sets the stop field")
			})
		}
		hook := "func(int) bool { return true }"
		passes := map[string]string{
			"a literal":                       "package side\n\nvar _ = S{stop: " + hook + "}\n",
			"a literal in parentheses":        "package side\n\nfunc f(s *S) { (s.stop) = (" + hook + ") }\n",
			"a declared function":             "package side\n\nfunc always(int) bool { return true }\n\nvar _ = S{stop: always}\n",
			"a source function, external":     ext + "var _ = side.S{stop: side.StopAt(2)}\n",
			"a source function, dot-imported": "package side_test\n\nimport . \"example.test/broker/side\"\n\nvar _ = S{stop: StopAt(2)}\n",
			"a method value":                  "package side\n\ntype at int\n\nfunc (a at) stop(i int) bool { return i == int(a) }\n\nfunc f() { var a at; _ = S{stop: a.stop} }\n",
			"a method expression value":       "package side\n\ntype at int\n\nfunc (a at) stop(i int) bool { return i == int(a) }\n\nfunc f(s *S) { s.stop = at(2).stop; _ = at.stop }\n",
			"a local set once to a literal":   "package side\n\nfunc f() { h := " + hook + "; _ = S{stop: h} }\n",
			"a local var set once":            "package side\n\nfunc f() { var h = " + hook + "; h(1); _ = S{stop: h} }\n",
			"a chain of locals":               "package side\n\nfunc f() { h := " + hook + "; g := h; _ = S{stop: g} }\n",
			"a call returning a literal":      "package side\n\nfunc stopAt(i int) func(int) bool { return func(j int) bool { return j == i } }\n\nvar _ = S{stop: stopAt(2)}\n",
			"a call returning a function":     "package side\n\nfunc always(int) bool { return true }\n\nfunc hook() func(int) bool { return always }\n\nvar _ = S{stop: hook()}\n",
			"a generic call returning one":    "package side\n\nfunc at[T any](i int) func(int) bool { return func(j int) bool { return j == i } }\n\nvar _ = S{stop: at[string](2)}\n",
			"a method returning a literal":    "package side\n\ntype W struct{}\n\nfunc (W) At(i int) func(int) bool { return func(j int) bool { return j == i } }\n\nfunc f() { var w W; _ = S{stop: w.At(2)} }\n",
		}
		for name, test := range passes {
			t.Run(name, func(t *testing.T) {
				files := map[string]string{"broker/side/side.go": src, "broker/side/side_test.go": test}
				if problems := lint(t, files, ""); len(problems) != 0 {
					t.Fatalf("got %q, want none", problems)
				}
			})
		}
	})
	t.Run("a stop parameter counts only from a call the checker resolves", func(t *testing.T) {
		method := call + "type S struct{ dir string }\n\nfunc (s *S) Save(b []byte, stop func(int) bool) error { return privfile.WriteAtomic(s.dir, \"f\", b, stop) }\n\ntype T struct{}\n\nfunc (T) Save(b []byte, stop func(int) bool) error { return nil }\n"
		hook := "func(int) bool { return true }"
		ext := "package side_test\n\nimport \"example.test/broker/side\"\n\n"
		for name, test := range map[string]string{
			"(*S).Save with a nil stop":            "package side\n\nfunc f(s *S) { (*S).Save(s, []byte{1}, nil) }\n",
			"a method expression's receiver":       "package side\n\nfunc f(s *S) { (*S).Save(s, nil, nil) }\n",
			"an external (*side.S).Save, nil stop": ext + "func f(s *side.S) { (*side.S).Save(s, []byte{1}, nil) }\n",
			"another package's Save":               "package side\n\nimport \"example.test/broker/other\"\n\nfunc f() { other.Store.Save(nil, " + hook + ") }\n",
			"a Save on an unresolved value":        "package side\n\nfunc f() { undeclared.Save(nil, " + hook + ") }\n",
			"a func-valued variable named Save":    "package side\n\nvar Save = func([]byte, func(int) bool) {}\n\nfunc f() { Save(nil, " + hook + ") }\n",
		} {
			t.Run(name, func(t *testing.T) {
				files := map[string]string{"broker/side/side.go": method, "broker/side/side_test.go": test}
				one(t, lint(t, files, ""), "no test in broker/side calls Save with a non-nil stop")
			})
		}
		for name, test := range map[string]string{
			"a method call":                  "package side\n\nfunc f(s *S) { s.Save(nil, " + hook + ") }\n",
			"(*S).Save with a stop":          "package side\n\nfunc f(s *S) { (*S).Save(s, nil, " + hook + ") }\n",
			"an external (*side.S).Save":     ext + "func f(s *side.S) { (*side.S).Save(s, nil, " + hook + ") }\n",
			"an external method call":        ext + "func f() { new(side.S).Save(nil, " + hook + ") }\n",
			"a method call on a dereference": "package side\n\nfunc f(s *S) { (*s).Save(nil, " + hook + ") }\n",
			"a parenthesised callee":         "package side\n\nfunc f(s *S) { (s.Save)(nil, " + hook + ") }\n",
		} {
			t.Run(name, func(t *testing.T) {
				files := map[string]string{"broker/side/side.go": method, "broker/side/side_test.go": test}
				if problems := lint(t, files, ""); len(problems) != 0 {
					t.Fatalf("got %q, want none", problems)
				}
			})
		}
		generic := call + "type S[T, U any] struct{ dir string }\n\nfunc (s *S[T, U]) Save(b []byte, stop func(int) bool) error { return privfile.WriteAtomic(s.dir, \"f\", b, stop) }\n"
		files := map[string]string{"broker/side/side.go": generic, "broker/side/side_test.go": "package side\n\nfunc f(s *S[int, string]) { (*S[int, string]).Save(s, []byte{1}, nil) }\n"}
		one(t, lint(t, files, ""), "no test in broker/side calls Save with a non-nil stop")
		files["broker/side/side_test.go"] = ext + "func f(s *side.S[int, string]) { (*side.S[int, string]).Save(s, nil, " + hook + ") }\n"
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
	modPath := strings.TrimSpace(strings.TrimPrefix(strings.SplitN(string(mod), "\n", 2)[0], "module "))
	importPath := modPath + "/kernel/privfile"

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
		found, err := crashLintDir(p, rel, modPath, importPath)
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
func crashLintDir(dir, rel, modPath, importPath string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	fset := token.NewFileSet()
	// srcs is every non-test file; tests, inPkg (the package's compiled source
	// and in-package tests), ext (the external tests) and compiled (all of
	// those) hold only what the race run compiles.
	var srcs, tests, inPkg, ext, compiled []*ast.File
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") {
			continue
		}
		test := strings.HasSuffix(e.Name(), "_test.go")
		ok, err := raceRun.MatchFile(dir, e.Name())
		if err != nil {
			return nil, err
		}
		if test && !ok {
			continue
		}
		f, err := parser.ParseFile(fset, filepath.Join(dir, e.Name()), nil, parser.SkipObjectResolution)
		if err != nil {
			return nil, err
		}
		if ok {
			compiled = append(compiled, f)
		}
		switch {
		case !test:
			srcs = append(srcs, f)
			if ok {
				inPkg = append(inPkg, f)
			}
		case strings.HasSuffix(f.Name.Name, "_test"):
			tests, ext = append(tests, f), append(ext, f)
		default:
			tests, inPkg = append(tests, f), append(inPkg, f)
		}
	}
	self := modPath + strings.TrimPrefix(rel, "broker")
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
	fields, calls := testSets(typeCheck(fset, self, inPkg, ext), tests, compiled)
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

// typeCheck type-checks the directory's package (the source and in-package
// test files the race run compiles) and then its external test package,
// which imports it, into one Info. Every other import fails on purpose, so a
// name another package declares stays unresolved and its value counts as
// nil; errors are ignored for the same reason: what the checker cannot
// resolve is never proof of a stop.
func typeCheck(fset *token.FileSet, self string, inPkg, ext []*ast.File) *types.Info {
	info := &types.Info{
		Defs:       map[*ast.Ident]types.Object{},
		Uses:       map[*ast.Ident]types.Object{},
		Selections: map[*ast.SelectorExpr]*types.Selection{},
	}
	var pkg *types.Package
	conf := types.Config{
		Importer: importerFunc(func(path string) (*types.Package, error) {
			if path == self && pkg != nil {
				return pkg, nil
			}
			return nil, fmt.Errorf("%s is not loaded", path)
		}),
		Error: func(error) {},
	}
	pkg, _ = conf.Check(self, fset, inPkg, info)
	if len(ext) > 0 {
		conf.Check(self+"_test", fset, ext, info)
	}
	return info
}

type importerFunc func(path string) (*types.Package, error)

func (f importerFunc) Import(path string) (*types.Package, error) { return f(path) }

// proof decides whether a test's stop value is provably non-nil. Anything it
// cannot prove counts as nil, so a shape it does not know fails the lint
// rather than passing it.
type proof struct {
	info    *types.Info
	written map[types.Object]bool     // locals assigned, address-taken or selected after their declaration
	value   map[types.Object]ast.Expr // locals declared with exactly one value
	decl    map[*types.Func]*ast.FuncDecl
}

func newProof(info *types.Info, files []*ast.File) *proof {
	p := &proof{info: info, written: map[types.Object]bool{}, value: map[types.Object]ast.Expr{}, decl: map[*types.Func]*ast.FuncDecl{}}
	mark := func(e ast.Expr) {
		if id, ok := ast.Unparen(e).(*ast.Ident); ok && info.Uses[id] != nil {
			p.written[info.Uses[id]] = true
		}
	}
	declare := func(names []*ast.Ident, values []ast.Expr) {
		for i, id := range names {
			if o := info.Defs[id]; o != nil && len(values) == len(names) {
				p.value[o] = values[i]
			}
		}
	}
	for _, f := range files {
		ast.Inspect(f, func(n ast.Node) bool {
			switch n := n.(type) {
			case *ast.AssignStmt:
				var defined []*ast.Ident
				for _, l := range n.Lhs {
					if id, ok := l.(*ast.Ident); ok && n.Tok == token.DEFINE && info.Defs[id] != nil {
						defined = append(defined, id)
					} else {
						mark(l)
					}
				}
				if len(defined) == len(n.Lhs) {
					declare(defined, n.Rhs)
				}
			case *ast.RangeStmt:
				if n.Tok == token.ASSIGN {
					mark(n.Key)
					mark(n.Value)
				}
			case *ast.IncDecStmt:
				mark(n.X)
			case *ast.UnaryExpr:
				if n.Op == token.AND {
					mark(n.X)
				}
			case *ast.SelectorExpr:
				if info.Selections[n] != nil {
					mark(n.X) // a method on the variable may take its address
				}
			case *ast.FuncDecl:
				if fn, ok := info.Defs[n.Name].(*types.Func); ok && n.Body != nil {
					p.decl[fn] = n
				}
			case *ast.GenDecl:
				if n.Tok == token.VAR {
					for _, s := range n.Specs {
						vs := s.(*ast.ValueSpec)
						declare(vs.Names, vs.Values)
					}
				}
			}
			return true
		})
	}
	return p
}

// nonNil reports whether e is provably a non-nil function: a function
// literal; a function or method the checker resolves (F, side.F, a method
// value x.M, a method expression (*T).M, but not one promoted from an
// embedded type); a local variable declared with one such value and never
// assigned, address-taken or selected afterwards; or a call of a function or
// method this directory declares whose whole body is `return v` with v one
// such value (stopAt(2), where stopAt returns a function literal). A package
// variable, a parameter, any other call, a conversion and every name the
// checker leaves unresolved count as nil.
func (p *proof) nonNil(e ast.Expr) bool { return p.proved(e, 0) }

func (p *proof) proved(e ast.Expr, depth int) bool {
	for ; depth < 16; depth++ {
		switch x := ast.Unparen(e).(type) {
		case *ast.FuncLit:
			return true
		case *ast.CallExpr:
			// A call of a function the directory declares whose body is one
			// return statement, so no defer can recover a panic into a nil
			// result and no other path returns.
			if sel, ok := ast.Unparen(x.Fun).(*ast.SelectorExpr); ok && !p.direct(sel) {
				return false
			}
			fn, _ := callee(p.info, x)
			if fn == nil || p.decl[fn.Origin()] == nil {
				return false
			}
			body := p.decl[fn.Origin()].Body.List
			if len(body) != 1 {
				return false
			}
			ret, ok := body[0].(*ast.ReturnStmt)
			if !ok || len(ret.Results) != 1 {
				return false
			}
			e = ret.Results[0]
			continue
		case *ast.SelectorExpr:
			if s := p.info.Selections[x]; s != nil {
				return p.direct(x) && (s.Kind() == types.MethodVal || s.Kind() == types.MethodExpr)
			}
			_, ok := p.info.Uses[x.Sel].(*types.Func)
			return ok
		case *ast.Ident:
			switch o := p.info.Uses[x].(type) {
			case *types.Func:
				return true
			case *types.Var:
				v, ok := p.value[o]
				if !ok || p.written[o] || o.IsField() || o.Pkg() == nil || o.Parent() == o.Pkg().Scope() {
					return false
				}
				e = v
				continue
			}
			return false
		default:
			return false
		}
	}
	return false
}

// callee is the function or method the checker resolves call's callee to,
// or nil, and skip is 1 when the call is a method expression's, whose first
// argument is the receiver.
func callee(info *types.Info, call *ast.CallExpr) (fn *types.Func, skip int) {
	fun := ast.Unparen(call.Fun)
	switch x := fun.(type) {
	case *ast.IndexExpr:
		fun = x.X
	case *ast.IndexListExpr:
		fun = x.X
	}
	var obj types.Object
	switch x := fun.(type) {
	case *ast.Ident:
		obj = info.Uses[x]
	case *ast.SelectorExpr:
		if s := info.Selections[x]; s != nil {
			obj = s.Obj()
			if s.Kind() == types.MethodExpr {
				skip = 1
			}
		} else {
			obj = info.Uses[x.Sel]
		}
	}
	fn, _ = obj.(*types.Func)
	return fn, skip
}

// direct reports whether sel is not a selection, or selects a field or
// method the receiver's type declares itself. A promoted one is refused: a
// shallower field of an embedded type the checker could not load (every
// import but the directory's own) would shadow it in the real build.
func (p *proof) direct(sel *ast.SelectorExpr) bool {
	s := p.info.Selections[sel]
	return s == nil || len(s.Index()) == 1
}

// testSets returns the field names the tests key or assign a provably
// non-nil value to, and for each function or method the checker resolves a
// test call to, by name, the argument places that call fills with one (after
// the receiver of a method expression).
func testSets(info *types.Info, tests, all []*ast.File) (fields map[string]bool, calls map[string]map[int]bool) {
	fields, calls = map[string]bool{}, map[string]map[int]bool{}
	p := newProof(info, all)
	for _, f := range tests {
		ast.Inspect(f, func(n ast.Node) bool {
			switch n := n.(type) {
			case *ast.KeyValueExpr:
				if k, ok := n.Key.(*ast.Ident); ok && p.nonNil(n.Value) {
					fields[k.Name] = true
				}
			case *ast.AssignStmt:
				if len(n.Lhs) == len(n.Rhs) {
					for i, l := range n.Lhs {
						if sel, ok := ast.Unparen(l).(*ast.SelectorExpr); ok && p.nonNil(n.Rhs[i]) {
							fields[sel.Sel.Name] = true
						}
					}
				}
			case *ast.CallExpr:
				fn, skip := callee(info, n)
				if fn == nil || len(n.Args) < skip {
					return true
				}
				for i, a := range n.Args[skip:] {
					if p.nonNil(a) {
						if calls[fn.Name()] == nil {
							calls[fn.Name()] = map[int]bool{}
						}
						calls[fn.Name()][i] = true
					}
				}
			}
			return true
		})
	}
	return fields, calls
}
