package privfile

// The crash-path lint (REV-CHK-save, #3903). WriteAtomic takes a stop hook
// that ends the write after a step as a crash would, but nothing required a
// caller's package to test it: #3311, #3444, #3476, #3434, #3868 and #3881
// were each a save whose failure path no test reached until review found it.
// So every WriteAtomic call in a non-test file under broker/ (this package
// aside) passes stop as a struct field or as a parameter of the function or
// method the call is in, and a _test.go file in the caller's directory that
// the per-PR race run compiles (raceRun) sets it to a provably non-nil value:
// keyed or assigned to that field, or in that parameter's place in a call
// the type checker resolves to that function or method (after the receiver
// of a method expression).
//
// The proof fails closed (REV-CHK-save-later, #4214). The directory's
// package with its in-package tests, and its external test package, are
// loaded as the race run compiles them through the shared lint loader
// (broker/internal/lintload, #4273), every import resolved, but only what
// this directory declares is ever proof. A stop is set only
// when it is a function literal, a function or method the directory
// declares, a local declared with one of these and never assigned,
// address-taken or selected afterwards, or a call of a function this
// directory declares whose whole body is one return of one of these, so no
// defer can recover a panic into nil (nonNil). A method promoted from an
// embedded type is refused. Every other shape, nil spelled any way
// included, counts as nil: a package variable, a parameter, a conversion,
// any other call. A hook the lint cannot prove is a false fail, which the
// test fixes by writing the hook inline. A non-test file that imports
// privfile and that the race run does not compile fails, since its calls
// go unseen.
//
// A directory that fails today has a pending line in crashPending naming the
// issue that adds its seam and test; the line covers every call there, new
// ones included, as the path lint's pending lines do. A pending line for a
// directory that passes fails, so the list only shrinks.
//
// Bound: the seam is matched by object (#4273), so a field of the same
// name on another type, or another function of the same name, is not it.
// Nothing here shows the test runs the save or checks that memory, disk and
// what the owner was told agree after the stop (held by review, the
// substance of #3311, #3476, #3868 and #3881). A stop forwarded through a
// second function is not followed: a test sets the field, or calls the
// function, that the WriteAtomic call reads. Calls in a pending directory,
// Go outside broker/, and broker/third_party and every vendor, testdata and
// dot-named directory at any depth are outside the check.

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"maps"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/ghbmrk/agentos/broker/internal/lintload"
)

// crashPending names the directories whose WriteAtomic calls fail the check
// on main, each with the issue that gives its calls a seam and a test.
const crashPending = `
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
		files = clone(files)
		if _, ok := files["broker/kernel/privfile/privfile.go"]; !ok {
			files["broker/kernel/privfile/privfile.go"] = "package privfile\n\nfunc WriteAtomic(dir, name string, b []byte, stop func(int) bool) error { return nil }\n"
		}
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
		files["broker/side/side_test.go"] = "package side\n\nfunc Other(string, []byte, func(int) bool) {}\n\nfunc f() { Save(\"d\", nil, nil); Other(\"d\", nil, func(int) bool { return true }) }\n"
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
		// Each test sets whatever the shape lets it set, and the call site
		// is still refused.
		hook := "func(int) bool { return true }"
		for name, c := range map[string]struct{ body, test, want string }{
			"a local":                         {"func Save(dir string) error { stop := func(int) bool { return false }; return privfile.WriteAtomic(dir, \"f\", nil, stop) }\n", "func f() { Save(\"d\") }\n", "a local or package variable"},
			"a literal":                       {"func Save(dir string) error { return privfile.WriteAtomic(dir, \"f\", nil, func(int) bool { return false }) }\n", "func f() { Save(\"d\") }\n", "not a field or a parameter"},
			"a closure's own":                 {"var Save = func(dir string, stop func(int) bool) error { return privfile.WriteAtomic(dir, \"f\", nil, stop) }\n", "func f() { Save(\"d\", " + hook + ") }\n", "a function literal's parameter"},
			"a package var":                   {"var stop func(int) bool\n\nfunc Save(dir string) error { return privfile.WriteAtomic(dir, \"f\", nil, stop) }\n", "func init() { stop = " + hook + " }\n", "a local or package variable"},
			"a call's result":                 {"func hook() func(int) bool { return nil }\n\nfunc Save(dir string) error { return privfile.WriteAtomic(dir, \"f\", nil, hook()) }\n", "var _ = hook()\n", "not a field or a parameter"},
			"a local shadowing the parameter": {"func Save(dir string, stop func(int) bool) error {\n\t{\n\t\tstop := func(int) bool { return false }\n\t\treturn privfile.WriteAtomic(dir, \"f\", nil, stop)\n\t}\n}\n", "func f() { Save(\"d\", " + hook + ") }\n", "a local or package variable"},
		} {
			t.Run(name, func(t *testing.T) {
				files := map[string]string{"broker/side/side.go": call + c.body, "broker/side/side_test.go": "package side\n\n" + c.test}
				one(t, lint(t, files, ""), c.want)
			})
		}
	})
	t.Run("an aliased or dot import is seen; a WriteAtomic value fails", func(t *testing.T) {
		alias := "package side\n\nimport pf \"example.test/broker/kernel/privfile\"\n\nfunc Save(dir string) error { return pf.WriteAtomic(dir, \"f\", nil, nil) }\n"
		one(t, lint(t, map[string]string{"broker/side/side.go": alias}, ""), "nil stop")
		dot := "package side\n\nimport . \"example.test/broker/kernel/privfile\"\n\nfunc Save(dir string) error { return WriteAtomic(dir, \"f\", nil, nil) }\n"
		one(t, lint(t, map[string]string{"broker/side/side.go": dot}, ""), "nil stop")
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
	t.Run("a source file the race run does not compile fails", func(t *testing.T) {
		set := "package side\n\nvar _ = S{stop: func(int) bool { return true }}\n"
		for name, c := range map[string]struct{ file, head string }{
			"a tag":        {"side_e2e.go", "//go:build agentos_e2e\n\n"},
			"another GOOS": {"side_darwin.go", ""},
			"ignore":       {"gen.go", "//go:build ignore\n\n"},
		} {
			t.Run(name, func(t *testing.T) {
				files := map[string]string{"broker/side/side.go": field, "broker/side/side_test.go": set,
					"broker/side/" + c.file: c.head + call + "func Hidden(dir string) error { return privfile.WriteAtomic(dir, \"f\", nil, nil) }\n"}
				one(t, lint(t, files, ""), "broker/side/"+c.file+": imports privfile, but the race run does not compile it")
			})
		}
	})
	t.Run("a stop counts only when it is provably non-nil", func(t *testing.T) {
		// side.go declares the field seam S.stop and, for the external and
		// cross-file shapes, a hooks import, package variables and functions.
		// The field is exported here, so external tests can set it too.
		src := strings.ReplaceAll(field, "stop", "Stop") + "\nvar NoStop func(int) bool\n\nvar Set = func(int) bool { return true }\n\nfunc Hook(f func(int) bool) func(int) bool { return f }\n\nfunc StopAt(i int) func(int) bool { return func(j int) bool { return j == i } }\n"
		ext := "package side_test\n\nimport \"example.test/broker/side\"\n\n"
		hooks := "import \"example.test/broker/hooks\"\n\n"
		// hooks is another package: nothing it declares is proof, and its
		// Base's methods shadow the embedded deep's at a shallower depth.
		hooksPkg := "package hooks\n\ntype Hook func(int) bool\n\nfunc Always(int) bool { return true }\n\nfunc At(i int) func(int) bool { return func(j int) bool { return j == i } }\n\ntype Base struct{}\n\nfunc (Base) Stop(int) bool { return true }\n\nfunc (Base) At(i int) func(int) bool { return func(j int) bool { return j == i } }\n"
		fails := map[string][]string{
			"parenthesised nil":                    {"package side\n\nvar _ = S{Stop: (nil)}\n"},
			"nil assigned in parentheses":          {"package side\n\nfunc f(s *S) { (s.Stop) = ((nil)) }\n"},
			"a func-type conversion":               {"package side\n\nvar _ = S{Stop: (func(int) bool)(nil)}\n"},
			"a named-type conversion":              {"package side\n\ntype hook func(int) bool\n\nvar _ = S{Stop: hook(nil)}\n"},
			"a generic type's conversion":          {"package side\n\ntype hook[T any] func(int) bool\n\nvar _ = S{Stop: hook[int](nil)}\n"},
			"a conversion of a literal":            {"package side\n\ntype hook func(int) bool\n\nvar _ = S{Stop: hook(func(int) bool { return true })}\n"},
			"an imported type's conversion":        {"package side\n\n" + hooks + "var _ = S{Stop: hooks.Hook(nil)}\n"},
			"an imported function":                 {"package side\n\n" + hooks + "var _ = S{Stop: hooks.Always}\n"},
			"an imported function's result":        {"package side\n\n" + hooks + "var _ = S{Stop: hooks.At(2)}\n"},
			"a local never set":                    {"package side\n\nfunc f() { var h func(int) bool; _ = S{Stop: h} }\n"},
			"a local declared nil":                 {"package side\n\nfunc f() { var h func(int) bool = nil; _ = S{Stop: h} }\n"},
			"a local assigned after":               {"package side\n\nfunc f() { h := func(int) bool { return true }; h = nil; _ = S{Stop: h} }\n"},
			"a local assigned in parentheses":      {"package side\n\nfunc f() { h := func(int) bool { return true }; (h) = nil; _ = S{Stop: h} }\n"},
			"a local assigned in a closure":        {"package side\n\nfunc f() { h := func(int) bool { return true }; func() { h = nil }(); _ = S{Stop: h} }\n"},
			"a local set through &":                {"package side\n\nfunc clear(p *func(int) bool) { *p = nil }\n\nfunc f() { h := func(int) bool { return true }; clear(&h); _ = S{Stop: h} }\n"},
			"a local redeclared by :=":             {"package side\n\nfunc g() (func(int) bool, error) { return nil, nil }\n\nfunc f() { h := func(int) bool { return true }; h, err := g(); _, _ = err, S{Stop: h} }\n"},
			"a local set by range =":               {"package side\n\nfunc f(hs []func(int) bool) { h := func(int) bool { return true }; for _, h = range hs {}; _ = S{Stop: h} }\n"},
			"a local from a multi-value call":      {"package side\n\nfunc g() (func(int) bool, error) { return nil, nil }\n\nfunc f() { h, _ := g(); _ = S{Stop: h} }\n"},
			"a local copying a package var":        {"package side\n\nfunc f() { h := Set; _ = S{Stop: h} }\n"},
			"a parameter":                          {"package side\n\nfunc f(h func(int) bool) { _ = S{Stop: h} }\n"},
			"a package var":                        {"package side\n\nvar _ = S{Stop: Set}\n"},
			"a package var given a hook later":     {"package side\n\nvar h func(int) bool\n\nfunc init() { h = func(int) bool { return true } }\n\nvar _ = S{Stop: h}\n"},
			"a call that may return nil":           {"package side\n\nfunc g(ok bool) func(int) bool { if ok { return func(int) bool { return true } }; return nil }\n\nvar _ = S{Stop: g(true)}\n"},
			"a call that passes its argument on":   {"package side\n\nvar _ = S{Stop: Hook(nil)}\n"},
			"a local cleared by a pointer method":  {"package side\n\ntype hook func(int) bool\n\nfunc (h *hook) clear() { *h = nil }\n\nfunc f() { var h hook = func(int) bool { return true }; h.clear(); _ = S{Stop: h} }\n"},
			"a call that recovers a panic":         {"package side\n\nfunc g() func(int) bool { defer func() { recover() }(); panic(1) }\n\nvar _ = S{Stop: g()}\n"},
			"a call that recovers before a return": {"package side\n\nfunc g() func(int) bool { defer func() { recover() }(); var m map[int]int; m[0] = 1; return func(int) bool { return true } }\n\nvar _ = S{Stop: g()}\n"},
			"a call with an empty body":            {"package side\n\nfunc g() func(int) bool { for {} }\n\nvar _ = S{Stop: g()}\n"},
			"a method an imported embed shadows":   {"package side\n\n" + hooks + "type inner struct{}\n\nfunc (inner) Stop(int) bool { return true }\n\ntype deep struct{ inner }\n\ntype W struct {\n\thooks.Base\n\tdeep\n}\n\nvar _ = S{Stop: W{}.Stop}\n"},
			"a call an imported embed shadows":     {"package side\n\n" + hooks + "type inner struct{}\n\nfunc (inner) At(i int) func(int) bool { return func(j int) bool { return j == i } }\n\ntype deep struct{ inner }\n\ntype W struct {\n\thooks.Base\n\tdeep\n}\n\nvar _ = S{Stop: W{}.At(2)}\n"},
			"a call with a named result":           {"package side\n\nfunc g() (h func(int) bool) { defer func() { h = nil }(); return func(int) bool { return true } }\n\nvar _ = S{Stop: g()}\n"},
			"a local function variable's result":   {"package side\n\nfunc f() { g := StopAt; _ = S{Stop: g(2)} }\n"},
			"a field of a value":                   {"package side\n\ntype hooks struct{ h func(int) bool }\n\nvar _ = S{Stop: hooks{}.h}\n"},
			"the package's nil var, external":      {ext + "var _ = side.S{Stop: side.NoStop}\n"},
			"the package's var, dot-imported":      {"package side_test\n\nimport . \"example.test/broker/side\"\n\nvar _ = S{Stop: NoStop}\n"},
			"an external test's own conversion":    {ext + "type hook func(int) bool\n\nvar _ = side.S{Stop: hook(nil)}\n"},
			"a nil var declared in another file":   {"package side\n\n" + hooks + "var none = hooks.Hook(nil)\n", "package side\n\nvar _ = S{Stop: none}\n"},
			"a nil var a dot import declares":      {"package side_test\n\nimport . \"example.test/broker/side\"\n\nvar h = NoStop\n", "package side_test\n\nimport \"example.test/broker/side\"\n\nvar _ = side.S{Stop: h}\n"},
			"a hook only an ignored file sets":     {"//go:build ignore\n\npackage side\n\nfunc always(int) bool { return true }\n\nvar _ = S{Stop: always}\n"},
			"another type's same-named field":      {"package side\n\ntype O struct{ Stop func(int) bool }\n\nvar _ = O{Stop: func(int) bool { return true }}\n\nfunc f(o *O) { o.Stop = func(int) bool { return true } }\n"},
		}
		for name, tests := range fails {
			t.Run(name, func(t *testing.T) {
				files := map[string]string{"broker/side/side.go": src, "broker/hooks/hooks.go": hooksPkg}
				for i, test := range tests {
					files[fmt.Sprintf("broker/side/t%d_test.go", i)] = test
				}
				one(t, lint(t, files, ""), "no test in broker/side sets the stop field Stop")
			})
		}
		hook := "func(int) bool { return true }"
		passes := map[string]string{
			"a literal":                       "package side\n\nvar _ = S{Stop: " + hook + "}\n",
			"a literal in parentheses":        "package side\n\nfunc f(s *S) { (s.Stop) = (" + hook + ") }\n",
			"a declared function":             "package side\n\nfunc always(int) bool { return true }\n\nvar _ = S{Stop: always}\n",
			"a source function, external":     ext + "var _ = side.S{Stop: side.StopAt(2)}\n",
			"a source function, dot-imported": "package side_test\n\nimport . \"example.test/broker/side\"\n\nvar _ = S{Stop: StopAt(2)}\n",
			"a method value":                  "package side\n\ntype at int\n\nfunc (a at) stop(i int) bool { return i == int(a) }\n\nfunc f() { var a at; _ = S{Stop: a.stop} }\n",
			"a method expression value":       "package side\n\ntype at int\n\nfunc (a at) stop(i int) bool { return i == int(a) }\n\nfunc f(s *S) { s.Stop = at(2).stop; _ = at.stop }\n",
			"a local set once to a literal":   "package side\n\nfunc f() { h := " + hook + "; _ = S{Stop: h} }\n",
			"a local var set once":            "package side\n\nfunc f() { var h = " + hook + "; h(1); _ = S{Stop: h} }\n",
			"a chain of locals":               "package side\n\nfunc f() { h := " + hook + "; g := h; _ = S{Stop: g} }\n",
			"a call returning a literal":      "package side\n\nfunc stopAt(i int) func(int) bool { return func(j int) bool { return j == i } }\n\nvar _ = S{Stop: stopAt(2)}\n",
			"a call returning a function":     "package side\n\nfunc always(int) bool { return true }\n\nfunc hook() func(int) bool { return always }\n\nvar _ = S{Stop: hook()}\n",
			"a generic call returning one":    "package side\n\nfunc at[T any](i int) func(int) bool { return func(j int) bool { return j == i } }\n\nvar _ = S{Stop: at[string](2)}\n",
			"a method returning a literal":    "package side\n\ntype W struct{}\n\nfunc (W) At(i int) func(int) bool { return func(j int) bool { return j == i } }\n\nfunc f() { var w W; _ = S{Stop: w.At(2)} }\n",
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
		otherPkg := "package other\n\ntype T struct{}\n\nfunc (T) Save([]byte, func(int) bool) error { return nil }\n\nvar Store T\n"
		for name, test := range map[string]string{
			"(*S).Save with a nil stop":            "package side\n\nfunc f(s *S) { (*S).Save(s, []byte{1}, nil) }\n",
			"a method expression's receiver":       "package side\n\nfunc f(s *S) { (*S).Save(s, nil, nil) }\n",
			"an external (*side.S).Save, nil stop": ext + "func f(s *side.S) { (*side.S).Save(s, []byte{1}, nil) }\n",
			"another package's Save":               "package side\n\nimport \"example.test/broker/other\"\n\nfunc f() { other.Store.Save(nil, " + hook + ") }\n",
			"another type's same-named Save":       "package side\n\nfunc f() { T{}.Save(nil, " + hook + ") }\n",
			"a func-valued variable named Save":    "package side\n\nvar Save = func([]byte, func(int) bool) {}\n\nfunc f() { Save(nil, " + hook + ") }\n",
		} {
			t.Run(name, func(t *testing.T) {
				files := map[string]string{"broker/side/side.go": method, "broker/side/side_test.go": test, "broker/other/other.go": otherPkg}
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

	// The directories whose non-test files import privfile, under any
	// build; only they can call WriteAtomic.
	var dirs []string
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
		ok, err := importsPrivfile(p, importPath)
		if ok {
			dirs = append(dirs, rel)
		}
		return err
	})
	if err != nil {
		return nil, err
	}
	failing := map[string]bool{}
	if len(dirs) > 0 {
		var patterns []string
		for _, d := range dirs {
			patterns = append(patterns, "./"+strings.TrimPrefix(d, "broker/"))
		}
		l, err := lintload.Load(filepath.Join(root, "broker"), raceRun, patterns...)
		if err != nil {
			return nil, err
		}
		byDir := map[string][]*lintload.Package{}
		for _, p := range l.Packages {
			byDir[p.Dir] = append(byDir[p.Dir], p)
		}
		for _, rel := range dirs {
			found, err := crashLintDir(l, byDir[filepath.Join(root, filepath.FromSlash(rel))], root, rel, importPath)
			if err != nil {
				return nil, err
			}
			if len(found) == 0 {
				continue
			}
			failing[rel] = true
			if !pending[rel] {
				problems = append(problems, found...)
			}
		}
	}
	for dir := range pending {
		if !failing[dir] {
			problems = append(problems, fmt.Sprintf("stale pending line for %s: every WriteAtomic call there has a stop a test sets, or it has none", dir))
		}
	}
	sort.Strings(problems)
	return problems, nil
}

// importsPrivfile reports whether a non-test Go file in dir, under any
// build, imports privfile.
func importsPrivfile(dir, importPath string) (bool, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return false, err
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		if ok, err := importsPrivfileFile(filepath.Join(dir, e.Name()), importPath); ok || err != nil {
			return ok, err
		}
	}
	return false, nil
}

// stopSeam is where the stop of the WriteAtomic call at pos, in function
// caller, comes from: the struct field field, or the parameter at index of
// the function or method fn. Both are objects the type checker resolves, so
// a same-named field or function elsewhere is not the seam (#4273).
type stopSeam struct {
	field  *types.Var
	fn     *types.Func
	index  int
	pos    token.Pos
	caller string
}

// crashLintDir checks the WriteAtomic calls in one directory's non-test
// files against what its test files set. pkgs are the directory's loaded
// packages: the package with its in-package tests, and its external test
// package, as the race run compiles them.
func crashLintDir(l *lintload.Loaded, pkgs []*lintload.Package, root, rel, importPath string) ([]string, error) {
	fset := l.Fset
	var problems []string
	report := func(pos token.Pos, fn, msg string) {
		p := fset.PositionFor(pos, false)
		problems = append(problems, fmt.Sprintf("%s/%s:%d: %s %s", rel, filepath.Base(p.Filename), p.Line, fn, msg))
	}
	// A non-test file that imports privfile and that the race run does not
	// compile holds calls the lint cannot see.
	read := map[string]bool{}
	var srcs, tests, all []*ast.File
	info := &types.Info{
		Defs:       map[*ast.Ident]types.Object{},
		Uses:       map[*ast.Ident]types.Object{},
		Selections: map[*ast.SelectorExpr]*types.Selection{},
	}
	self := ""
	for _, p := range pkgs {
		if !p.XTest {
			self = p.Path
		}
		for _, f := range p.Files {
			name := fset.File(f.Pos()).Name()
			read[name] = true
			all = append(all, f)
			if strings.HasSuffix(name, "_test.go") {
				tests = append(tests, f)
			} else {
				srcs = append(srcs, f)
			}
		}
		maps.Copy(info.Defs, p.Info.Defs)
		maps.Copy(info.Uses, p.Info.Uses)
		maps.Copy(info.Selections, p.Info.Selections)
	}
	dir := filepath.Join(root, filepath.FromSlash(rel))
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	for _, e := range entries {
		n := e.Name()
		if e.IsDir() || !strings.HasSuffix(n, ".go") || strings.HasSuffix(n, "_test.go") || read[filepath.Join(dir, n)] {
			continue
		}
		if ok, err := importsPrivfileFile(filepath.Join(dir, n), importPath); err != nil {
			return nil, err
		} else if ok {
			problems = append(problems, fmt.Sprintf("%s/%s: imports privfile, but the race run does not compile it, so the lint cannot see its WriteAtomic calls", rel, n))
		}
	}
	isWriteAtomic := func(o types.Object) bool {
		fn, ok := o.(*types.Func)
		return ok && fn.Pkg() != nil && fn.Pkg().Path() == importPath && fn.Name() == "WriteAtomic"
	}
	var seams []stopSeam
	for _, f := range srcs {
		var stack []ast.Node // enclosing *ast.FuncDecl and *ast.FuncLit, innermost last
		called := map[*ast.Ident]bool{}
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
					if id := calleeIdent(c.Fun); id != nil && isWriteAtomic(info.Uses[id]) {
						called[id] = true
						fn := enclosingName(stack)
						if s, msg := seamOf(info, c.Args[3], stack); msg != "" {
							report(c.Pos(), fn, msg)
						} else {
							s.pos, s.caller = c.Pos(), fn
							seams = append(seams, s)
						}
					}
				case *ast.Ident:
					if isWriteAtomic(info.Uses[c]) && !called[c] {
						report(c.Pos(), enclosingName(stack), "uses privfile.WriteAtomic but not called; call it directly so the lint sees its stop")
					}
				}
				return true
			})
		}
		walk(f)
	}
	fields, calls := testSets(info, self, tests, all)
	for _, s := range seams {
		switch {
		case s.field != nil && !fields[s.field]:
			report(s.pos, s.caller, fmt.Sprintf("calls privfile.WriteAtomic with stop field %s, but no test in %s sets the stop field %s to a non-nil value", s.field.Name(), rel, s.field.Name()))
		case s.fn != nil && !calls[s.fn][s.index]:
			report(s.pos, s.caller, fmt.Sprintf("calls privfile.WriteAtomic with its parameter as stop, but no test in %s calls %s with a non-nil stop", rel, s.fn.Name()))
		}
	}
	return problems, nil
}

// importsPrivfileFile reports whether the Go file at path imports privfile.
func importsPrivfileFile(path, importPath string) (bool, error) {
	f, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.ImportsOnly)
	if err != nil {
		return false, err
	}
	for _, imp := range f.Imports {
		if p, _ := strconv.Unquote(imp.Path.Value); p == importPath {
			return true, nil
		}
	}
	return false, nil
}

// seamOf returns where stop comes from, or why it is refused.
func seamOf(info *types.Info, stop ast.Expr, stack []ast.Node) (stopSeam, string) {
	const want = "; pass a struct field or a parameter that a test sets"
	switch e := ast.Unparen(stop).(type) {
	case *ast.SelectorExpr:
		if s := info.Selections[e]; s != nil && s.Kind() == types.FieldVal {
			return stopSeam{field: s.Obj().(*types.Var).Origin()}, ""
		}
	case *ast.Ident:
		switch o := info.Uses[e].(type) {
		case *types.Nil:
			return stopSeam{}, "calls privfile.WriteAtomic with a nil stop" + want
		case *types.Var:
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
					if len(field.Names) == 0 {
						index++
						continue
					}
					for _, n := range field.Names {
						if info.Defs[n] == o {
							if fd, ok := stack[i].(*ast.FuncDecl); ok {
								fn, _ := info.Defs[fd.Name].(*types.Func)
								return stopSeam{fn: fn, index: index}, ""
							}
							return stopSeam{}, "calls privfile.WriteAtomic with stop " + e.Name + ", a function literal's parameter that no test can name" + want
						}
						index++
					}
				}
			}
			return stopSeam{}, "calls privfile.WriteAtomic with stop " + e.Name + ", a local or package variable" + want
		}
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
var raceRun = lintload.Build{
	Env:   []string{"GOOS=linux", "GOARCH=amd64", "CGO_ENABLED=1"},
	Flags: []string{"-tags=race"},
	Tests: true,
}

// proof decides whether a test's stop value is provably non-nil. Anything it
// cannot prove counts as nil, so a shape it does not know fails the lint
// rather than passing it.
type proof struct {
	self    string // the directory's import path; its external tests' is self+"_test"
	info    *types.Info
	written map[types.Object]bool     // locals assigned, address-taken or selected after their declaration
	value   map[types.Object]ast.Expr // locals declared with exactly one value
	decl    map[*types.Func]*ast.FuncDecl
}

func newProof(info *types.Info, self string, files []*ast.File) *proof {
	p := &proof{self: self, info: info, written: map[types.Object]bool{}, value: map[types.Object]ast.Expr{}, decl: map[*types.Func]*ast.FuncDecl{}}
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
				return p.direct(x) && (s.Kind() == types.MethodVal || s.Kind() == types.MethodExpr) && p.local(s.Obj())
			}
			fn, ok := p.info.Uses[x.Sel].(*types.Func)
			return ok && p.local(fn)
		case *ast.Ident:
			switch o := p.info.Uses[x].(type) {
			case *types.Func:
				return p.local(o)
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

// local reports whether the directory declares o: the loader resolves every
// import, but only the directory's own source is proof (#4214).
func (p *proof) local(o types.Object) bool {
	return o.Pkg() != nil && (o.Pkg().Path() == p.self || o.Pkg().Path() == p.self+"_test")
}

// direct reports whether sel is not a selection, or selects a field or
// method the receiver's type declares itself. A promoted one is refused,
// which keeps the proof to methods the directory's own types declare.
func (p *proof) direct(sel *ast.SelectorExpr) bool {
	s := p.info.Selections[sel]
	return s == nil || len(s.Index()) == 1
}

// testSets returns the struct fields the tests key or assign a provably
// non-nil value to, and for each function or method the checker resolves a
// test call to the argument places that call fills with one (after the
// receiver of a method expression). Fields and functions are objects, not
// names (#4273).
func testSets(info *types.Info, self string, tests, all []*ast.File) (fields map[*types.Var]bool, calls map[*types.Func]map[int]bool) {
	fields, calls = map[*types.Var]bool{}, map[*types.Func]map[int]bool{}
	p := newProof(info, self, all)
	field := func(o types.Object) *types.Var {
		if v, ok := o.(*types.Var); ok && v.IsField() {
			return v.Origin()
		}
		return nil
	}
	for _, f := range tests {
		ast.Inspect(f, func(n ast.Node) bool {
			switch n := n.(type) {
			case *ast.KeyValueExpr:
				if k, ok := n.Key.(*ast.Ident); ok && p.nonNil(n.Value) {
					if v := field(info.Uses[k]); v != nil {
						fields[v] = true
					}
				}
			case *ast.AssignStmt:
				if len(n.Lhs) == len(n.Rhs) {
					for i, l := range n.Lhs {
						if sel, ok := ast.Unparen(l).(*ast.SelectorExpr); ok && info.Selections[sel] != nil && p.nonNil(n.Rhs[i]) {
							if v := field(info.Selections[sel].Obj()); v != nil {
								fields[v] = true
							}
						}
					}
				}
			case *ast.CallExpr:
				fn, skip := callee(info, n)
				if fn == nil || len(n.Args) < skip {
					return true
				}
				fn = fn.Origin()
				for i, a := range n.Args[skip:] {
					if p.nonNil(a) {
						if calls[fn] == nil {
							calls[fn] = map[int]bool{}
						}
						calls[fn][i] = true
					}
				}
			}
			return true
		})
	}
	return fields, calls
}
