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
//   - an expression that names one of the package's own constants (bar the
//     frame's version and opRead) is anchored: it passes, and each constant
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
				found = found || ok && c.Pkg() == pkg && !frame[c]
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
// a failed accept, at least acceptBackoffMin, so an accept that keeps failing
// (out of descriptors) cannot spin; TestAcceptBackoff pins the sequence.
// REQ: RES-5
func TestServeSleepsAfterAFailedAccept(t *testing.T) {
	ln := &scriptedListener{steps: []error{errors.New("accept: too many open files"), net.ErrClosed}}
	start := time.Now()
	must(t, Serve(ln, func(context.Context, string) (string, error) { return "", nil }))
	if d := time.Since(start); d < acceptBackoffMin {
		t.Fatalf("Serve returned after %v; a failed accept sleeps at least %v", d, acceptBackoffMin)
	}
}
