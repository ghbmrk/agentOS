package childproc

// REQ: CRED-1, ARC-1, LOOP-7

import (
	"bufio"
	"bytes"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"
)

// exempt is the gate's one exemption list: the packages, besides
// childproc, that may reach os/exec or name a launcher selector, each
// with its reason (brief D3). A package listed here is cut from the graph
// like childproc, so its importers do not reach os/exec through it. An
// entry no longer needed fails the gate.
//
// Test files and the test-only graph are out of the gate's scope: go list
// -deps without -test lists neither, and agentosd links neither. The one
// shipped build of test code, the fuzz binaries image/build.sh makes with
// go test -c, runs only as a childproc child, so whatever it starts
// inherits only the checked pairs (#651 Security 4a point 3).
var exempt = map[string]string{
	"golang.org/x/sys/unix":    "defines unix.Exec, a wrapper of syscall.Exec; every use of it is gated",
	"vm/gvisor":                "moves in P3-4b-3r-env-r8b",
	"modem/at":                 "moves in P3-4b-3r-env-r8b",
	"browser":                  "moves in P3-4b-3r-env-r8b",
	"clock":                    "moves in P3-4b-3r-env-r8b",
	"cmd/agentos-guest-bridge": "moves in P3-4b-3r-env-r8b",
	"quota/quotatest":          "moves in P3-4b-3r-env-r8b",
	"tpmseal/swtpm":            "moves in P3-4b-3r-env-r8b",
}

// launchers are the selectors, by import path, that start a process
// without os/exec.
var launchers = map[string]map[string]bool{
	"os":                    {"StartProcess": true},
	"syscall":               {"ForkExec": true, "StartProcess": true, "Exec": true},
	"golang.org/x/sys/unix": {"Exec": true, "ForkExec": true, "StartProcess": true},
}

const module = "github.com/ghbmrk/agentos/broker"

func TestOnlyChildprocStartsAProcess(t *testing.T) {
	start := time.Now()
	bad := gate(t, "..", module, exempt)
	if len(bad) > 0 {
		t.Fatalf("a package outside childproc can start a process (P3-4b-3r-env-r8; start children through childproc):\n%s", strings.Join(bad, "\n"))
	}
	t.Logf("gate ran in %v", time.Since(start))
}

type node struct {
	path, dir string
	std       bool
	imports   []string
	// files are built under some cgo setting; ignored are the rest of
	// the package's non-test files (another GOOS or GOARCH, a tag).
	files, ignored []string
	// extra is listed only because an ignored file imports it.
	extra bool
}

// gate lists the non-test dependency graph of mod's packages and returns
// each violation of brief D3: a non-standard package that reaches
// os/exec once childproc and the exempt packages are cut from the graph,
// or a non-test file that names a launcher selector; and each exemption
// that is no longer needed. A file no linux/amd64 build includes is held
// to both rules too, by its own imports, and reported "(not built)".
func gate(t *testing.T, dir, mod string, exempt map[string]string) []string {
	t.Helper()
	// The graph is the union over both cgo settings: the shipped
	// binaries build with CGO_ENABLED=0 (image/build.sh) and CI's race
	// tests with 1, and a file tagged for one is invisible to go list
	// under the other (#651 Security 4a point 1).
	byPath := map[string]*node{}
	var order []string
	list := func(extra bool, pkgs ...string) {
		for _, cgo := range []string{"0", "1"} {
			args := []string{"list", "-deps", "-f", "{{.ImportPath}}\t{{.Dir}}\t{{.Standard}}\t{{join .Imports \" \"}}\t{{join .GoFiles \" \"}} {{join .CgoFiles \" \"}}\t{{join .IgnoredGoFiles \" \"}}"}
			if extra {
				// A package only another GOOS builds lists with an
				// error; what it imports there is not followed.
				args = append(args, "-e")
			}
			cmd := exec.Command("go", append(args, pkgs...)...)
			cmd.Dir = dir
			cmd.Env = append(os.Environ(), "CGO_ENABLED="+cgo, "GOOS=linux", "GOFLAGS=")
			var stderr bytes.Buffer
			cmd.Stderr = &stderr
			out, err := cmd.Output()
			if err != nil {
				t.Fatalf("go list (CGO_ENABLED=%s): %v\n%s", cgo, err, stderr.String())
			}
			sc := bufio.NewScanner(bytes.NewReader(out))
			sc.Buffer(nil, 1<<20)
			for sc.Scan() {
				f := strings.Split(sc.Text(), "\t")
				if len(f) != 6 {
					t.Fatalf("go list line: %q", sc.Text())
				}
				n := byPath[f[0]]
				if n == nil {
					std, _ := strconv.ParseBool(f[2])
					n = &node{path: f[0], dir: f[1], std: std, extra: extra}
					byPath[f[0]] = n
					order = append(order, f[0])
				}
				add := func(to *[]string, s string) {
					for _, x := range strings.Fields(s) {
						if !slices.Contains(*to, x) {
							*to = append(*to, x)
						}
					}
				}
				add(&n.imports, f[3])
				add(&n.files, f[4])
				add(&n.ignored, f[5])
			}
		}
	}
	list(false, "./...")
	// Ignored files' imports, by file; what they import that the graph
	// lacks is listed too, so a route through it is seen.
	ignoredImports := map[string][]string{}
	var missing []string
	for _, p := range order {
		n := byPath[p]
		n.ignored = slices.DeleteFunc(n.ignored, func(f string) bool {
			return strings.HasSuffix(f, "_test.go") || slices.Contains(n.files, f)
		})
		if n.std {
			n.ignored = nil
		}
		for _, f := range n.ignored {
			path := filepath.Join(n.dir, f)
			ims := fileImports(t, path)
			ignoredImports[path] = ims
			for _, im := range ims {
				if byPath[im] == nil && im != "C" && !slices.Contains(missing, im) {
					missing = append(missing, im)
				}
			}
		}
	}
	if len(missing) > 0 {
		list(true, missing...)
	}
	var nodes []node
	for _, p := range order {
		nodes = append(nodes, *byPath[p])
	}
	key := func(p string) string {
		if r, ok := strings.CutPrefix(p, mod+"/"); ok {
			return r
		}
		return p
	}
	cut := func(p string) bool { return p == mod+"/childproc" || exempt[key(p)] != "" }
	imports := map[string][]string{}
	for _, n := range nodes {
		imports[n.path] = n.imports
	}
	// via[p] is the path from p to os/exec, or nil if p does not reach it.
	via := map[string][]string{}
	var visit func(string) []string
	visit = func(p string) []string {
		if r, ok := via[p]; ok {
			return r
		}
		via[p] = nil
		if p == "os/exec" {
			via[p] = []string{p}
			return via[p]
		}
		for _, im := range imports[p] {
			if cut(im) {
				continue
			}
			if r := visit(im); r != nil {
				via[p] = append([]string{p}, r...)
				break
			}
		}
		return via[p]
	}
	var bad []string
	used := map[string]bool{}
	for _, n := range nodes {
		if n.std || n.extra || n.path == mod+"/childproc" {
			continue
		}
		var found []string
		if r := visit(n.path); r != nil && !cut(n.path) {
			found = append(found, n.path+": reaches os/exec ("+strings.Join(r, " -> ")+")")
		} else if cut(n.path) {
			// An exempt package is cut from others' paths, not its own.
			for _, im := range n.imports {
				if r := visit(im); r != nil || im == "os/exec" {
					used[key(n.path)] = true
				}
			}
		}
		for _, f := range n.files {
			found = append(found, launcherUse(t, filepath.Join(n.dir, f), n.path+"/"+f)...)
		}
		for _, f := range n.ignored {
			path, name := filepath.Join(n.dir, f), n.path+"/"+f+" (not built)"
			found = append(found, launcherUse(t, path, name)...)
			for _, im := range ignoredImports[path] {
				switch {
				case im == "os/exec":
					found = append(found, name+": imports os/exec")
				case !cut(im) && visit(im) != nil:
					found = append(found, name+": imports "+im+", which reaches os/exec")
				}
			}
		}
		if exempt[key(n.path)] != "" {
			if len(found) > 0 {
				used[key(n.path)] = true
			}
			continue
		}
		bad = append(bad, found...)
	}
	for k := range exempt {
		if !used[k] {
			bad = append(bad, "exempt names "+k+", which no longer reaches os/exec or names a launcher: drop it")
		}
	}
	sort.Strings(bad)
	return bad
}

// fileImports are the import paths of the file at path.
func fileImports(t *testing.T, path string) []string {
	t.Helper()
	f, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.ImportsOnly)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, im := range f.Imports {
		p, _ := strconv.Unquote(im.Path.Value)
		out = append(out, p)
	}
	return out
}

// launcherUse reports each launcher selector a file names, called or as a
// value, resolved by import path; a dot import of a launcher package is
// reported outright.
func launcherUse(t *testing.T, path, name string) []string {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
	if err != nil {
		t.Fatal(err)
	}
	local := map[string]string{}
	var bad []string
	for _, im := range f.Imports {
		p, _ := strconv.Unquote(im.Path.Value)
		if launchers[p] == nil {
			continue
		}
		n := p[strings.LastIndex(p, "/")+1:]
		if im.Name != nil {
			n = im.Name.Name
		}
		if n == "." {
			bad = append(bad, name+": dot-imports "+p)
			continue
		}
		local[n] = p
	}
	ast.Inspect(f, func(x ast.Node) bool {
		s, ok := x.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		if id, ok := s.X.(*ast.Ident); ok && launchers[local[id.Name]][s.Sel.Name] {
			bad = append(bad, name+":"+strconv.Itoa(fset.Position(s.Pos()).Line)+": names "+local[id.Name]+"."+s.Sel.Name)
		}
		return true
	})
	return bad
}

// fixture writes a module example.com/m with files and returns its root.
func fixture(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	files["go.mod"] = "module example.com/m\n\ngo 1.25\n"
	for name, src := range files {
		p := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(src), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

// childprocFixture stands in for the real package in a fixture module.
const childprocFixture = `package childproc
import "os/exec"
func Run(name string) error { c := exec.Command(name); c.Env = []string{}; return c.Run() }
`

func TestGateCatchesAChildStartedOutsideChildproc(t *testing.T) {
	root := fixture(t, map[string]string{
		"childproc/c.go": childprocFixture,
		// #621 delta Security 6: a helper hands out a *exec.Cmd and a file
		// without os/exec runs it; the child saw AGENTOS_OWNER.
		"a/a.go": "package a\nimport \"os/exec\"\nfunc New() *exec.Cmd { return exec.Command(\"env\") }\n",
		"b/b.go": "package b\nimport \"example.com/m/a\"\nfunc fresh[T any](c T) T { return c }\nfunc B() { fresh(a.New()).Run() }\n",
		// Stdlib packages that start children without the importer naming
		// os/exec, pinned against the current toolchain.
		"cgi/c.go":      "package cgi\nimport _ \"net/http/cgi\"\n",
		"fcgi/c.go":     "package fcgi\nimport _ \"net/http/fcgi\"\n",
		"build/c.go":    "package build\nimport _ \"go/build\"\n",
		"importer/c.go": "package importer\nimport _ \"go/importer\"\n",
		// Launcher selectors: as a value, through a renamed import, and a
		// dot import.
		"value/v.go":   "package value\nimport \"os\"\nvar start = os.StartProcess\n",
		"renamed/r.go": "package renamed\nimport sc \"syscall\"\nfunc R() { sc.ForkExec(\"/x\", nil, &sc.ProcAttr{Env: []string{}}) }\n",
		"dot/d.go":     "package dot\nimport . \"syscall\"\nfunc D() { Exec(\"/x\", nil, []string{}) }\n",
		// Through childproc only: passes.
		"good/g.go": "package good\nimport \"example.com/m/childproc\"\nfunc G() error { return childproc.Run(\"x\") }\n",
		// A file only one cgo setting builds: the shipped binaries are
		// CGO_ENABLED=0, CI's race tests 1 (#651 Security 4a point 1).
		"nocgo/n.go":   "//go:build !cgo\n\npackage nocgo\nimport \"os/exec\"\nfunc N() { exec.Command(\"env\").Run() }\n",
		"withcgo/w.go": "//go:build cgo\n\npackage withcgo\nimport \"os\"\nvar start = os.StartProcess\n",
		// Files go list ignores under linux/amd64 (another GOARCH, a
		// tag) and a cgo file are scanned too (#651 L3 2, Security
		// round 2): a file built for neither cgo setting is labelled
		// "not built", so a cgo file reported without the label shows
		// that CgoFiles is read.
		"arm/a.go":       "package arm\n",
		"arm/a_arm64.go": "package arm\nimport \"os/exec\"\nfunc A() { exec.Command(\"env\").Run() }\n",
		"arm/b_arm64.go": "package arm\nimport _ \"net/http/cgi\"\n",
		"tag/t.go":       "package tag\n",
		"tag/u.go":       "//go:build sometag\n\npackage tag\nimport \"syscall\"\nfunc U() { syscall.Exec(\"/x\", nil, []string{}) }\n",
		"tag/v.go":       "//go:build sometag\n\npackage tag\nimport \"example.com/m/a\"\nvar _ = a.New\n",
		"cgofile/c.go":   "package cgofile\n",
		"cgofile/d.go":   "package cgofile\n\n// int f(void) { return 0; }\nimport \"C\"\nimport \"os\"\nvar start = os.StartProcess\n",
		// Exempt and still needed: passes.
		"old/o.go":  "package old\nimport \"os/exec\"\nfunc O() { exec.Command(\"x\").Run() }\n",
		"user/u.go": "package user\nimport \"example.com/m/old\"\nfunc U() { old.O() }\n",
	})
	got := gate(t, root, "example.com/m", map[string]string{"old": "moves later", "stale": "gone"})
	want := []string{
		"example.com/m/a: reaches os/exec",
		"example.com/m/b: reaches os/exec (example.com/m/b -> example.com/m/a -> os/exec)",
		"example.com/m/build: reaches os/exec",
		"example.com/m/cgi: reaches os/exec",
		"example.com/m/dot/d.go: dot-imports syscall",
		"example.com/m/fcgi: reaches os/exec",
		"example.com/m/importer: reaches os/exec",
		"example.com/m/nocgo: reaches os/exec",
		"example.com/m/withcgo/w.go:5: names os.StartProcess",
		"example.com/m/renamed/r.go:3: names syscall.ForkExec",
		"example.com/m/value/v.go:3: names os.StartProcess",
		"exempt names stale, which no longer reaches os/exec or names a launcher: drop it",
		"example.com/m/arm/a_arm64.go (not built): imports os/exec",
		"example.com/m/arm/b_arm64.go (not built): imports net/http/cgi, which reaches os/exec",
		"example.com/m/tag/u.go (not built):5: names syscall.Exec",
		"example.com/m/tag/v.go (not built): imports example.com/m/a, which reaches os/exec",
		"example.com/m/cgofile/d.go:6: names os.StartProcess",
	}
	for _, w := range want {
		if !slices.ContainsFunc(got, func(g string) bool { return strings.HasPrefix(g, w) }) {
			t.Errorf("not reported: %s", w)
		}
	}
	for _, g := range got {
		for _, ok := range []string{"/good", "/old", "/user", "/childproc"} {
			if strings.HasPrefix(g, "example.com/m"+ok) {
				t.Errorf("reported, but passes: %s", g)
			}
		}
	}
	if t.Failed() {
		t.Logf("got:\n%s", strings.Join(got, "\n"))
	}
}
