package readerwire

// REQ: RES-5

import (
	"context"
	"errors"
	"fmt"
	"go/ast"
	"go/constant"
	"go/parser"
	"go/token"
	"go/types"
	"maps"
	"net"
	"os"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/internal/lintload"
)

// loadOnce lists the package and its dependencies' export data once, so
// each case type-checks its own sources against the same imports.
var loadOnce = sync.OnceValues(func() (*lintload.Loaded, error) {
	return lintload.Load(".", lintload.Build{}, ".")
})

// constProblems type-checks srcs (file name to Go source, the package's
// non-test files) as the package and lists each constant number written
// outside a const declaration that no recorded bound anchors, whatever its
// form: a literal, a rune, a time unit under any import name, len of a
// string, a conversion, or arithmetic on 0s and 1s. The rule, on the widest
// constant expression first:
//   - 0 or 1, by value, passes;
//   - the frame's newline, the literal '\n' alone, passes;
//   - an expression that names one of the package's own package-level
//     constants (bar the frame's version and opRead) is anchored; a const
//     declared inside a function anchors nothing, so it cannot shadow a
//     recorded name with another value (#4874): it passes, and each constant
//     part of it is checked by the same rule, so maxCall+1 passes and
//     maxConns*(1+1) does not;
//   - anything else fails.
//
// A source that does not type-check fails closed. That the package's
// constants are recorded is boundProblems' check.
func constProblems(t *testing.T, srcs map[string]string) []string {
	t.Helper()
	l, err := loadOnce()
	if err != nil {
		t.Fatal(err)
	}
	names := slices.Sorted(func(yield func(string) bool) {
		for n := range srcs {
			if !yield(n) {
				return
			}
		}
	})
	var files []*ast.File
	for _, n := range names {
		f, err := parser.ParseFile(l.Fset, n, srcs[n], parser.SkipObjectResolution)
		if err != nil {
			return []string{err.Error()}
		}
		files = append(files, f)
	}
	pkg, info, err := l.Check("github.com/ghbmrk/agentos/broker/clerk/readerwire", files)
	if err != nil {
		return []string{err.Error()}
	}
	frame := map[types.Object]bool{}
	for _, n := range []string{"version", "opRead"} {
		if o, ok := pkg.Scope().Lookup(n).(*types.Const); ok {
			frame[o] = true
		}
	}
	anchored := func(e ast.Expr) bool {
		var found bool
		ast.Inspect(e, func(n ast.Node) bool {
			if id, ok := n.(*ast.Ident); ok {
				c, ok := info.Uses[id].(*types.Const)
				found = found || ok && c.Parent() == pkg.Scope() && !frame[c]
			}
			return !found
		})
		return found
	}
	zero, one := constant.MakeInt64(0), constant.MakeInt64(1)
	var out []string
	for _, f := range files {
		ast.Inspect(f, func(n ast.Node) bool {
			if d, ok := n.(*ast.GenDecl); ok && d.Tok == token.CONST {
				return false // a const's own expression is what it names
			}
			e, ok := n.(ast.Expr)
			if !ok {
				return true
			}
			v := info.Types[e].Value
			if v == nil {
				return true
			}
			switch v.Kind() {
			case constant.Int, constant.Float, constant.Complex:
			default:
				return true // a string or bool holds no bound itself; len of one is an Int above it
			}
			if constant.Compare(v, token.EQL, zero) || constant.Compare(v, token.EQL, one) {
				return false
			}
			if lit, ok := e.(*ast.BasicLit); ok && lit.Kind == token.CHAR && lit.Value == `'\n'` {
				return false
			}
			if anchored(e) {
				return true
			}
			out = append(out, fmt.Sprintf("%s: %s is the constant %s with no recorded name: make it a recorded constant", l.Fset.Position(e.Pos()), types.ExprString(e), v))
			return false
		})
	}
	return out
}

// TestNoBoundIsBuiltFromAllowedPieces: no constant number in the package's
// non-test files stands outside a const without a recorded bound in it, so
// a cap cannot land as len of a string or arithmetic on 1s (#4857).
// REQ: RES-5
func TestNoBoundIsBuiltFromAllowedPieces(t *testing.T) {
	srcs := packageSources(t)
	if _, ok := srcs["readerwire.go"]; !ok {
		t.Fatal("readerwire.go not read")
	}
	for _, p := range constProblems(t, srcs) {
		t.Error(p)
	}
}

// TestEachConstantFormFails: each form, put in a new file, fails the check,
// and no exemption covers its neighbouring form.
func TestEachConstantFormFails(t *testing.T) {
	withFile := func(src string) map[string]string {
		srcs := packageSources(t)
		srcs["extra.go"] = "package readerwire\n\n" + src
		return srcs
	}
	cases := []struct {
		name, src string
		want      []string // each problem's prefix, in order
	}{
		{"len of a string", "var buf = make([]byte, len(\"xxxxxxxxxxxx\"))\n",
			[]string{`extra.go:3:24: len("xxxxxxxxxxxx") is the constant 12`}},
		{"a shift of 1s", "var buf = make([]byte, 1<<(1+1+1))\n",
			[]string{"extra.go:3:24: 1 << (1 + 1 + 1) is the constant 8"}},
		{"a sum of 1s", "func f(d int) int { return d * (1 + 1) }\n",
			[]string{"extra.go:3:32: (1 + 1) is the constant 2"}},
		{"a conversion", "var n = int64(4096)\n",
			[]string{"extra.go:3:9: int64(4096) is the constant 4096"}},
		{"an array length", "var buf [4096]byte\n",
			[]string{"extra.go:3:10: 4096 is the constant 4096"}},
		{"a time unit", "import \"time\"\n\nvar wait = time.Second\n",
			[]string{"extra.go:5:12: time.Second is the constant 1000000000"}},
		{"a time unit under another name", "import tm \"time\"\n\nvar wait = 5 * tm.Millisecond\n",
			[]string{"extra.go:5:12: 5 * tm.Millisecond is the constant 5000000"}},
		{"a dot-imported time unit", "import . \"time\"\n\nvar wait = Second\n",
			[]string{"extra.go:5:12: Second is the constant 1000000000"}},
		{"a float", "var f = 2.5\n",
			[]string{"extra.go:3:9: 2.5 is the constant 2.5"}},
		{"an imaginary number", "var c = 2i\n",
			[]string{"extra.go:3:9: 2i is the constant (0 + 2i)"}},
		{"a bound inside a constant comparison", "var big = maxConns < 4096\n",
			[]string{"extra.go:3:22: 4096 is the constant 4096"}},
		// Neighbours of each exemption.
		{"a recorded bound scaled by 1s", "func f() int { return maxConns * (1 + 1) }\n",
			[]string{"extra.go:3:34: (1 + 1) is the constant 2"}},
		{"two newlines", "var b = byte('\\n' + '\\n')\n",
			[]string{`extra.go:3:9: byte('\n' + '\n') is the constant 20`}},
		{"a rune that is not the newline", "var b = make([]byte, '\\t')\n",
			[]string{`extra.go:3:22: '\t' is the constant 9`}},
		{"the frame's version summed", "var n = version + version\n",
			[]string{"extra.go:3:9: version + version is the constant 2"}},
		{"a constant named after version", "const v2 = version\n\nvar n = v2 + v2\n",
			nil}, // v2 is a constant of its own, so it anchors; boundProblems asks for its record
		// The literal and unit walk boundProblems kept until #4874.
		{"a bound written as a literal", "import \"time\"\n\nfunc f() []byte {\n\ttime.Sleep(5 * time.Millisecond)\n\treturn make([]byte, 4096)\n}\n",
			[]string{"extra.go:6:13: 5 * time.Millisecond is the constant 5000000", "extra.go:7:22: 4096 is the constant 4096"}},
		{"a time unit alone under another name", "import tm \"time\"\n\nvar wait = tm.Second\n",
			[]string{"extra.go:5:12: tm.Second is the constant 1000000000"}},
		{"a bound written as a rune", "var buf = make([]byte, 'A')\n",
			[]string{"extra.go:3:24: 'A' is the constant 65"}},
		{"a float that is not 2.5", "var f = 1.5\n",
			[]string{"extra.go:3:9: 1.5 is the constant 1.5"}},
		{"a doubling written as 2", "func f(d int) int { return 2 * d }\n",
			[]string{"extra.go:3:28: 2 is the constant 2"}},
		// A const inside a function anchors nothing (#4874).
		{"a local const shadowing a recorded name", "func f() int {\n\tconst maxConns = 4096\n\treturn maxConns\n}\n",
			[]string{"extra.go:5:9: maxConns is the constant 4096"}},
		{"a local const of its own", "func f() int {\n\tconst maxLocal = 3\n\treturn maxLocal\n}\n",
			[]string{"extra.go:5:9: maxLocal is the constant 3"}},
		{"a local const built from a recorded one", "func f() int {\n\tconst n = maxConns\n\treturn n\n}\n",
			[]string{"extra.go:5:9: n is the constant 8"}},
		{"a source that does not type-check", "var n = undefined\n",
			[]string{"type-checking"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := constProblems(t, withFile(c.src))
			if len(got) != len(c.want) {
				t.Fatalf("problems = %q, want %d matching %q", got, len(c.want), c.want)
			}
			for i, w := range c.want {
				if !strings.HasPrefix(got[i], w) {
					t.Errorf("problem %d = %q, want one starting %q", i, got[i], w)
				}
			}
		})
	}
}

// TestTheFrameExemptionIsReaderwireGoOnly: a package-level const named
// version or opRead in another file is a bound like any other and needs a
// record; only readerwire.go's are the frame's.
func TestTheFrameExemptionIsReaderwireGoOnly(t *testing.T) {
	rec, err := os.ReadFile("ASSUMPTIONS.md")
	must(t, err)
	for _, name := range []string{"version", "opRead"} {
		srcs := packageSources(t)
		srcs["extra.go"] = "package readerwire\n\nconst " + name + " = 4096\n"
		got := boundProblems(t, srcs, string(rec))
		if len(got) != 1 || !strings.HasPrefix(got[0], "the bound "+name+" has no record") {
			t.Errorf("a top-level %s in extra.go: problems = %q, want its missing record alone", name, got)
		}
	}
}

// TestServeSleepsAfterAFailedAccept: Serve's accept loop really sleeps after
// each failed accept, the backoff's whole sequence, so an accept that keeps
// failing (out of descriptors) cannot spin; TestAcceptBackoff pins the
// sequence. Several failures make the expected minimum, the sequence's sum,
// twice what a halved sleep would take, far beyond scheduling noise.
// REQ: RES-5
func TestServeSleepsAfterAFailedAccept(t *testing.T) {
	const fails = 5
	fail := errors.New("accept: too many open files")
	var steps []error
	var least time.Duration
	for i, wait := 0, acceptBackoffMin; i < fails; i, wait = i+1, min(wait+wait, acceptBackoffMax) {
		steps = append(steps, fail)
		least += wait
	}
	ln := &scriptedListener{steps: append(steps, net.ErrClosed)}
	start := time.Now()
	must(t, Serve(ln, func(context.Context, string) (string, error) { return "", nil }))
	if d := time.Since(start); d < least {
		t.Fatalf("Serve returned after %v; %d failed accepts sleep at least %v", d, fails, least)
	}
}

// TestEachBoundKeepsItsRecordedValue: each package-level constant has the
// value its ASSUMPTIONS.md bounds row states, and none is left unpinned, so a
// bound cannot change while its record keeps the old value (#4874).
// REQ: RES-5
func TestEachBoundKeepsItsRecordedValue(t *testing.T) {
	ms, s := int64(time.Millisecond), int64(time.Second)
	want := map[string]constant.Value{
		"MaxPrompt":        constant.MakeInt64(24 << 10),
		"MaxReply":         constant.MakeInt64(64),
		"maxCall":          constant.MakeInt64(4*((24<<10+2)/3) + 64),
		"maxAnswer":        constant.MakeInt64(256),
		"DefaultTimeout":   constant.MakeInt64(60 * s),
		"pause":            constant.MakeInt64(60 * s),
		"serveTimeout":     constant.MakeInt64(60 * s),
		"maxConns":         constant.MakeInt64(8),
		"acceptBackoffMin": constant.MakeInt64(5 * ms),
		"acceptBackoffMax": constant.MakeInt64(s),
		"version":          constant.MakeInt64(1),
		"opRead":           constant.MakeString("read"),
	}
	got := packageConsts(t, packageSources(t))
	for name, v := range got {
		w, ok := want[name]
		switch {
		case !ok:
			t.Errorf("%s = %s is not pinned here: add its recorded value", name, v)
		case !constant.Compare(v, token.EQL, w):
			t.Errorf("%s = %s, its record states %s: change both or neither", name, v, w)
		}
	}
	for name := range want {
		if _, ok := got[name]; !ok {
			t.Errorf("%s is pinned here but is no longer a constant of the package", name)
		}
	}
}

// TestAnUnpinnedBoundFails: a new package-level constant, or a pinned one
// with another value, is seen by the pin's reader.
func TestAnUnpinnedBoundFails(t *testing.T) {
	srcs := packageSources(t)
	srcs["extra.go"] = "package readerwire\n\nconst maxExtra = 3\n"
	if v, ok := packageConsts(t, srcs)["maxExtra"]; !ok || v.String() != "3" {
		t.Fatalf("maxExtra = %v (found %v), want 3", v, ok)
	}
	srcs = packageSources(t)
	srcs["readerwire.go"] = strings.Replace(srcs["readerwire.go"], "maxConns = 8", "maxConns = 9", 1)
	if v := packageConsts(t, srcs)["maxConns"]; v == nil || v.String() != "9" {
		t.Fatalf("maxConns = %v after the edit, want 9", v)
	}
}

// packageConsts type-checks srcs as the package and returns each
// package-level constant's value by name.
func packageConsts(t *testing.T, srcs map[string]string) map[string]constant.Value {
	t.Helper()
	l, err := loadOnce()
	if err != nil {
		t.Fatal(err)
	}
	var files []*ast.File
	for _, n := range slices.Sorted(maps.Keys(srcs)) {
		f, err := parser.ParseFile(l.Fset, n, srcs[n], parser.SkipObjectResolution)
		must(t, err)
		files = append(files, f)
	}
	pkg, _, err := l.Check("github.com/ghbmrk/agentos/broker/clerk/readerwire", files)
	must(t, err)
	out := map[string]constant.Value{}
	for _, n := range pkg.Scope().Names() {
		if c, ok := pkg.Scope().Lookup(n).(*types.Const); ok {
			out[n] = c.Val()
		}
	}
	return out
}
