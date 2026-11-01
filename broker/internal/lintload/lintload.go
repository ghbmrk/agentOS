// Package lintload is the one type-checked loader broker's source lints
// share (REV-CHK-lintload, #4273). go list -deps -export lists the named
// packages under one build; each is parsed from the files that build
// compiles into it and type-checked against its dependencies' export data,
// and any type error fails the load. Unread then names each file a lint's
// builds left unread that a build of the same platforms could compile:
// assembly, syso and other non-Go sources, and Go files only another tag
// set (or cgo setting) compiles. Only test code imports it.
package lintload

import (
	"bytes"
	"encoding/json"
	"fmt"
	"go/ast"
	"go/build"
	"go/build/constraint"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
)

// Build is one set of go settings a lint loads under.
type Build struct {
	Env     []string // added to the environment after GOFLAGS= (GOOS, GOARCH, CGO_ENABLED)
	Flags   []string // go list build flags, such as -tags=x or -overlay=file
	Partial bool     // leave out a package that does not compile here, and what imports it
	Tests   bool     // load each named package with its in-package tests, and its external test package
	Also    []string // import paths listed for the importer alone, for a lint's synthetic sources
	Module  bool     // also load each dependency in the main module, not only the packages named
}

// Package is one loaded package.
type Package struct {
	Path    string // import path, without go list's test-variant suffix
	Dir     string
	XTest   bool        // the external test package (Path ends in _test)
	Files   []*ast.File // what the build compiles into it, test files included under Tests
	Types   *types.Package
	Info    *types.Info
	skipped []string // non-Go sources, cgo and ignored Go files, base names
	cgo     []string // the cgo files among them
}

// Loaded is one Load's result.
type Loaded struct {
	Fset     *token.FileSet
	Packages []*Package     // the named packages (and under Module the main module's dependencies), dependencies first
	Importer types.Importer // every listed package, from export data
	Sizes    types.Sizes
	goos     string
	goarch   string
}

type listed struct {
	ImportPath, Dir, Export, ForTest, Name string
	CompiledGoFiles, IgnoredGoFiles        []string
	CgoFiles                               []string
	SFiles, SysoFiles, CFiles, CXXFiles    []string
	HFiles, FFiles, MFiles, SwigFiles      []string
	SwigCXXFiles                           []string
	ImportMap                              map[string]string
	DepOnly                                bool
	Module                                 *struct{ Main bool }
	Error                                  *struct{ Err string }
}

// goVars are the variables the go command reads from the test's
// environment; nothing else reaches it, and GOFLAGS is always empty, so a
// lint loads the same packages wherever it runs. GOOS, GOARCH and
// CGO_ENABLED come from a Build when it sets them, else the host's
// defaults.
var goVars = []string{
	"PATH", "HOME", "TMPDIR", "XDG_CACHE_HOME", "GOROOT", "GOPATH", "GOCACHE", "GOMODCACHE",
	"GOTOOLCHAIN", "GOPROXY", "GOSUMDB", "GONOSUMDB", "GOPRIVATE", "GONOPROXY", "GOINSECURE",
	"HTTPS_PROXY", "HTTP_PROXY", "NO_PROXY", "SSL_CERT_FILE", "SSL_CERT_DIR",
	"CC", "CXX", "PKG_CONFIG", "PKG_CONFIG_PATH", "CGO_CFLAGS", "CGO_LDFLAGS", "CGO_ENABLED",
}

// Load lists patterns under b in dir and type-checks each package they
// name.
func Load(dir string, b Build, patterns ...string) (*Loaded, error) {
	env := []string{"GOFLAGS="}
	for _, k := range goVars {
		if v, ok := os.LookupEnv(k); ok {
			env = append(env, k+"="+v)
		}
	}
	env = append(env, b.Env...)
	goEnv := exec.Command("go", "env", "GOOS", "GOARCH")
	goEnv.Dir, goEnv.Env = dir, env
	out, err := goEnv.Output()
	if err != nil {
		return nil, fmt.Errorf("go env: %v", err)
	}
	platform := strings.Fields(string(out))
	if len(platform) != 2 {
		return nil, fmt.Errorf("go env: unexpected output %q", out)
	}
	args := []string{"list", "-deps", "-export", "-compiled", "-json"}
	if b.Tests {
		args = append(args, "-test")
	}
	if b.Partial {
		args = append(args, "-e")
	}
	args = append(append(append(args, b.Flags...), patterns...), b.Also...)
	also := map[string]bool{}
	for _, a := range b.Also {
		also[a] = true
	}
	cmd := exec.Command("go", args...)
	cmd.Dir, cmd.Env = dir, env
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if out, err = cmd.Output(); err != nil {
		return nil, fmt.Errorf("go list: %v\n%s", err, stderr.String())
	}
	replaced, err := overlay(b.Flags)
	if err != nil {
		return nil, err
	}

	l := &Loaded{Fset: token.NewFileSet(), Sizes: types.SizesFor("gc", platform[1]), goos: platform[0], goarch: platform[1]}
	export := map[string]string{}
	var targets []listed
	dec := json.NewDecoder(bytes.NewReader(out))
	for {
		var p listed
		if err := dec.Decode(&p); err == io.EOF {
			break
		} else if err != nil {
			return nil, err
		}
		if b.Partial && (p.Error != nil || p.Export == "") {
			continue // a dependent of a failed package has no error, only no export data
		}
		if p.Error != nil {
			return nil, fmt.Errorf("go list %s: %s", p.ImportPath, p.Error.Err)
		}
		export[p.ImportPath] = p.Export
		named := !p.DepOnly || b.Module && p.Module != nil && p.Module.Main
		if named && !also[p.ImportPath] && !strings.HasSuffix(p.ImportPath, ".test") {
			targets = append(targets, p)
		}
	}
	lookup := func(m map[string]string) func(string) (io.ReadCloser, error) {
		return func(path string) (io.ReadCloser, error) {
			if v, ok := m[path]; ok {
				path = v
			}
			if export[path] == "" {
				return nil, fmt.Errorf("no export data for %s", path)
			}
			return os.Open(export[path])
		}
	}
	l.Importer = importer.ForCompiler(l.Fset, "gc", lookup(nil))

	// Under Tests a package with tests is loaded once, as its test variant.
	variant := map[string]bool{}
	for _, p := range targets {
		if p.ForTest != "" && !strings.HasSuffix(p.Name, "_test") {
			variant[p.ForTest] = true
		}
	}
	checked := map[string]*types.Package{} // go list import path -> source-checked package
	for _, p := range targets {
		if p.ForTest == "" && variant[p.ImportPath] {
			continue
		}
		path, _, _ := strings.Cut(p.ImportPath, " ")
		lp := &Package{Path: path, Dir: p.Dir, XTest: p.ForTest != "" && strings.HasSuffix(p.Name, "_test")}
		for _, name := range p.CompiledGoFiles {
			if !filepath.IsAbs(name) {
				name = filepath.Join(p.Dir, name)
			}
			src := name
			if r, ok := replaced[name]; ok {
				src = r
			}
			text, err := os.ReadFile(src)
			if err != nil {
				return nil, err
			}
			f, err := parser.ParseFile(l.Fset, name, text, parser.ParseComments|parser.SkipObjectResolution)
			if err != nil {
				return nil, err
			}
			lp.Files = append(lp.Files, f)
		}
		// A cgo file's C is out of go/types' sight, whichever build reads
		// its Go.
		lp.cgo = p.CgoFiles
		for _, set := range [][]string{p.CgoFiles, p.SFiles, p.SysoFiles, p.CFiles, p.CXXFiles, p.HFiles, p.FFiles, p.MFiles, p.SwigFiles, p.SwigCXXFiles} {
			lp.skipped = append(lp.skipped, set...)
		}
		for _, n := range p.IgnoredGoFiles {
			if !strings.HasSuffix(n, "_test.go") {
				lp.skipped = append(lp.skipped, n)
			}
		}
		imp := l.Importer
		if len(p.ImportMap) > 0 || lp.XTest {
			gc := importer.ForCompiler(l.Fset, "gc", lookup(p.ImportMap))
			imp = importerFunc(func(path string) (*types.Package, error) {
				// An external test imports the source-checked package under
				// test, so the objects a lint compares are the same.
				key := path
				if v, ok := p.ImportMap[path]; ok {
					key = v
				}
				if checked[key] != nil {
					return checked[key], nil
				}
				return gc.Import(path)
			})
		}
		lp.Info = &types.Info{
			Types:      map[ast.Expr]types.TypeAndValue{},
			Defs:       map[*ast.Ident]types.Object{},
			Uses:       map[*ast.Ident]types.Object{},
			Implicits:  map[ast.Node]types.Object{},
			Selections: map[*ast.SelectorExpr]*types.Selection{},
			Scopes:     map[ast.Node]*types.Scope{},
			Instances:  map[*ast.Ident]types.Instance{},
		}
		conf := types.Config{Importer: imp, Sizes: l.Sizes}
		if lp.Types, err = conf.Check(path, l.Fset, lp.Files, lp.Info); err != nil {
			return nil, fmt.Errorf("type-checking %s (%s/%s): %v", p.ImportPath, l.goos, l.goarch, err)
		}
		checked[p.ImportPath] = lp.Types
		l.Packages = append(l.Packages, lp)
	}
	return l, nil
}

// Skipped returns the base names of the files in the package's directory
// the build left out or go/types cannot see (ignored, cgo, assembly, syso
// and other non-Go sources), for a lint that refuses every one of them.
func (p *Package) Skipped() []string { return append([]string(nil), p.skipped...) }

// Check type-checks files as package path against the load's export data,
// for a lint's synthetic sources.
func (l *Loaded) Check(path string, files []*ast.File) (*types.Package, *types.Info, error) {
	return Check(l.Fset, l.Importer, l.Sizes, path, files)
}

// Check type-checks files as package path with imp, recording every Info
// map; any type error fails it.
func Check(fset *token.FileSet, imp types.Importer, sizes types.Sizes, path string, files []*ast.File) (*types.Package, *types.Info, error) {
	info := &types.Info{
		Types:      map[ast.Expr]types.TypeAndValue{},
		Defs:       map[*ast.Ident]types.Object{},
		Uses:       map[*ast.Ident]types.Object{},
		Implicits:  map[ast.Node]types.Object{},
		Selections: map[*ast.SelectorExpr]*types.Selection{},
		Scopes:     map[ast.Node]*types.Scope{},
		Instances:  map[*ast.Ident]types.Instance{},
	}
	pkg, err := (&types.Config{Importer: imp, Sizes: sizes}).Check(path, fset, files, info)
	if err != nil {
		return nil, nil, fmt.Errorf("type-checking %s: %v", path, err)
	}
	return pkg, info, nil
}

type importerFunc func(path string) (*types.Package, error)

func (f importerFunc) Import(path string) (*types.Package, error) { return f(path) }

// Unread returns, sorted, each file of the loaded packages' directories
// that a lint must not pass over: a non-Go source or a cgo file (C is out
// of go/types' sight), or a non-test Go file no load read that some build of a
// load's GOOS and GOARCH compiles under another tag set or cgo setting. A
// file only another platform compiles is not one, nor one whose package a
// partial load left out on its platform, nor a `//go:build ignore` file,
// which no build compiles.
func Unread(loads ...*Loaded) ([]string, error) {
	read, cgo := map[string]bool{}, map[string]bool{}
	type cand struct{ dir, name string }
	var cands []cand
	for _, l := range loads {
		for _, p := range l.Packages {
			for _, f := range p.Files {
				read[l.Fset.Position(f.Package).Filename] = true
			}
			for _, n := range p.skipped {
				cands = append(cands, cand{p.Dir, n})
			}
			for _, n := range p.cgo {
				cgo[filepath.Join(p.Dir, n)] = true
			}
		}
	}
	seen := map[string]bool{}
	var unread []string
	for _, c := range cands {
		full := filepath.Join(c.dir, c.name)
		if seen[full] {
			continue
		}
		seen[full] = true
		if !strings.HasSuffix(c.name, ".go") || cgo[full] {
			unread = append(unread, full)
			continue
		}
		if read[full] {
			continue
		}
		for _, l := range loads {
			if !l.has(c.dir) {
				continue // under a partial build the package does not compile for this platform, so no binary of it holds the file
			}
			ok, err := reachable(c.dir, c.name, l.goos, l.goarch)
			if err != nil {
				return nil, err
			}
			if ok {
				unread = append(unread, full)
				break
			}
		}
	}
	sort.Strings(unread)
	return unread, nil
}

func (l *Loaded) has(dir string) bool {
	for _, p := range l.Packages {
		if p.Dir == dir {
			return true
		}
	}
	return false
}

// platformTags are the GOOS and GOARCH names and the other tags a build
// sets from its platform rather than -tags; a file's other tags are free.
var platformTags = map[string]bool{
	"aix": true, "android": true, "darwin": true, "dragonfly": true, "freebsd": true, "hurd": true,
	"illumos": true, "ios": true, "js": true, "linux": true, "nacl": true, "netbsd": true,
	"openbsd": true, "plan9": true, "solaris": true, "wasip1": true, "windows": true, "zos": true,
	"386": true, "amd64": true, "arm": true, "arm64": true, "loong64": true, "mips": true,
	"mipsle": true, "mips64": true, "mips64le": true, "ppc64": true, "ppc64le": true,
	"riscv64": true, "s390x": true, "wasm": true, "unix": true, "gc": true, "gccgo": true,
	"ignore": true,
}

// reachable reports whether a build for goos/goarch with some set of the
// file's free tags, cgo among them, compiles dir/name.
func reachable(dir, name, goos, goarch string) (bool, error) {
	src, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		return false, err
	}
	free := map[string]bool{"cgo": true}
	for _, line := range strings.Split(string(src), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "//") && !constraint.IsGoBuild(line) {
			continue
		}
		if !constraint.IsGoBuild(line) {
			break // past the header: build lines must come before the package clause
		}
		x, err := constraint.Parse(line)
		if err != nil {
			return false, fmt.Errorf("%s: %v", filepath.Join(dir, name), err)
		}
		x.Eval(func(tag string) bool {
			if !platformTags[tag] && !strings.HasPrefix(tag, "go1.") {
				free[tag] = true
			}
			return false
		})
	}
	var tags []string
	for t := range free {
		tags = append(tags, t)
	}
	sort.Strings(tags)
	if len(tags) > 12 {
		return true, nil // too many to try: count it as reachable, so it fails closed
	}
	for set := 0; set < 1<<len(tags); set++ {
		ctx := build.Default
		ctx.GOOS, ctx.GOARCH, ctx.CgoEnabled, ctx.BuildTags = goos, goarch, false, nil
		for i, t := range tags {
			if set&(1<<i) == 0 {
				continue
			}
			if t == "cgo" {
				ctx.CgoEnabled = true
			} else {
				ctx.BuildTags = append(ctx.BuildTags, t)
			}
		}
		ok, err := ctx.MatchFile(dir, name)
		if err != nil {
			return false, err
		}
		if ok {
			return true, nil
		}
	}
	return false, nil
}

// overlay reads the -overlay file among flags, if any, as a map from each
// replaced path to the file holding its text.
func overlay(flags []string) (map[string]string, error) {
	for _, f := range flags {
		path, ok := strings.CutPrefix(f, "-overlay=")
		if !ok {
			continue
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		var ov struct{ Replace map[string]string }
		if err := json.Unmarshal(b, &ov); err != nil {
			return nil, err
		}
		return ov.Replace, nil
	}
	return nil, nil
}
