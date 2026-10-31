package hostdisk

import (
	"fmt"
	"go/ast"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// REQ: HW-8

// HW-8 forbids mounting, writing or repairing a host disk. The probe and
// its command can only read: their non-test source opens files read-only
// and has no call or import that writes, mounts, swaps or runs a program.
func TestSourceCannotWriteOrMount(t *testing.T) {
	// Both packages type-check as built, every file in them counts (a file
	// the build leaves out would go unchecked, so one fails), and the fence
	// reads what each name resolves to (#4256).
	var files int
	for _, p := range goList(t, ".", "../cmd/agentos-hostdisk") {
		if p.ignored != "" {
			t.Errorf("%s: files outside the build go unchecked: %s", p.path, p.ignored)
		}
		srcs := map[string]string{}
		for _, n := range strings.Fields(p.goFiles) {
			b, err := os.ReadFile(filepath.Join(p.dir, n))
			if err != nil {
				t.Fatal(err)
			}
			srcs[filepath.Join(p.dir, n)] = string(b)
			files++
		}
		for _, problem := range fenceProblems(t, p.path, srcs) {
			t.Error(problem)
		}
	}
	if files < 3 {
		t.Fatalf("only %d source files checked", files)
	}
}

// The fence refuses each way out it names, on synthetic sources: in
// particular every syscall name but the two open flags, under the plain
// import name or any other (#3950).
func TestFenceRefusesSyntheticSources(t *testing.T) {
	const head = "package hostdisk\n\nimport (\n\t\"os\"\n\t\"syscall\"\n)\n\n"
	ok := head + "func f(p string) (*os.File, error) {\n\treturn os.OpenFile(p, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)\n}\n"
	if problems := fenceFile(t, ok); len(problems) != 0 {
		t.Fatalf("the device open as written: %q, want none", problems)
	}
	for name, src := range map[string]string{
		"syscall.Pwrite":                   head + "func f() { syscall.Pwrite(0, nil, 0); _ = os.O_RDONLY }\n",
		"syscall.Open":                     head + "func f() { syscall.Open(\"x\", 0, 0); _ = os.O_RDONLY }\n",
		"syscall.Mmap as a value":          head + "var _ = syscall.Mmap\nvar _ = os.O_RDONLY\n",
		"syscall.O_RDWR":                   head + "var _ = syscall.O_RDWR\nvar _ = os.O_RDONLY\n",
		"syscall.Mount":                    head + "var _ = syscall.Mount\nvar _ = os.O_RDONLY\n",
		"a renamed syscall":                "package hostdisk\n\nimport s \"syscall\"\n\nvar _ = s.O_NOFOLLOW\n",
		"a dot import of syscall":          "package hostdisk\n\nimport . \"syscall\"\n\nvar _ = O_NOFOLLOW\n",
		"golang.org/x/sys/unix":            "package hostdisk\n\nimport \"golang.org/x/sys/unix\"\n\nvar _ = unix.O_NOFOLLOW\n",
		"an OpenFile flag beyond the pair": head + "func f(p string) { os.OpenFile(p, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|os.O_CREATE, 0) }\n",
		"an OpenFile flag variable":        head + "var fl = os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK\n\nfunc f(p string) { os.OpenFile(p, fl, 0) }\n",
		"os.WriteFile":                     "package hostdisk\n\nimport \"os\"\n\nvar _ = os.WriteFile\n",
		// #4256: names count by what they resolve to, not how they are
		// spelled. A local struct spelled syscall makes the flags
		// O_RDWR|O_CREAT; an os import under another name opens with
		// literal flags; a dot import of os writes with a bare name.
		"a local named syscall":        head + "var _ = syscall.O_NOFOLLOW\n\nfunc f(p string) {\n\tsyscall := struct{ O_NOFOLLOW, O_NONBLOCK int }{2, 64}\n\tos.OpenFile(p, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)\n}\n",
		"a parameter named syscall":    head + "var _ = syscall.O_NOFOLLOW\n\nvar g = func(p string, syscall struct{ O_NOFOLLOW, O_NONBLOCK int }) {\n\tos.OpenFile(p, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)\n}\n",
		"a local named os":             "package hostdisk\n\nimport o \"os\"\n\nfunc f(p string) {\n\tos := struct{ O_RDONLY int }{2}\n\to.OpenFile(p, os.O_RDONLY, 0)\n}\n",
		"os under another name":        "package hostdisk\n\nimport o \"os\"\n\nfunc f(p string) { o.OpenFile(p, 2|64, 0) }\n",
		"os under another name, flags": "package hostdisk\n\nimport o \"os\"\n\nfunc f(p string) { o.OpenFile(p, o.O_RDONLY|2, 0) }\n",
		"a dot import of os, open":     "package hostdisk\n\nimport . \"os\"\n\nfunc f(p string) { OpenFile(p, 2, 0) }\n",
		"a dot import of os, write":    "package hostdisk\n\nimport . \"os\"\n\nvar _ = WriteFile\n",
		"os.OpenFile as a value":       "package hostdisk\n\nimport \"os\"\n\nvar open = os.OpenFile\n\nfunc f(p string) { open(p, 2, 0) }\n",
		"literal flags":                "package hostdisk\n\nimport \"os\"\n\nfunc f(p string) { os.OpenFile(p, 0, 0) }\n",
	} {
		if problems := fenceFile(t, src); len(problems) == 0 {
			t.Errorf("%s: the fence passed it", name)
		}
	}
}

// fenceFile is the fence on one synthetic source, type-checked as package
// hostdisk; a source that does not type-check fails the test, so a refusal
// is the fence's own.
func fenceFile(t *testing.T, src string) []string {
	t.Helper()
	return fenceProblems(t, "x", map[string]string{"x.go": src})
}

// fenceProblems is the HW-8 fence on one package's source files. It
// type-checks them against export data (a type error fails the test) and
// judges each name by the object it resolves to (#4256).
func fenceProblems(t *testing.T, pkgPath string, srcs map[string]string) []string {
	t.Helper()
	forbiddenImports := map[string]bool{
		"os/exec": true, "golang.org/x/sys/unix": true,
		"net": true, "net/http": true, "unsafe": true,
	}
	forbiddenSel := map[string]bool{
		"O_RDWR": true, "O_WRONLY": true, "O_APPEND": true, "O_CREATE": true, "O_TRUNC": true,
		"Create": true, "WriteFile": true, "Mkdir": true, "MkdirAll": true, "Remove": true,
		"RemoveAll": true, "Rename": true, "Chmod": true, "Chown": true, "Truncate": true,
		"Symlink": true, "Link": true, "Mount": true, "Unmount": true, "Swapon": true,
		"WriteAt": true, "StartProcess": true, "O_EXCL": true, "Sync": true, "Fsync": true,
		"Ioctl": true, "Syscall": true, "RawSyscall": true, "Fd": true, "NewFile": true,
	}
	forbiddenText := []string{"sync_file_range", "BLKDISCARD", "discard", "ioctl"}
	var problems []string
	fail := func(format string, args ...any) { problems = append(problems, fmt.Sprintf(format, args...)) }
	fs := token.NewFileSet()
	var files []*ast.File
	names := make([]string, 0, len(srcs))
	for p := range srcs {
		names = append(names, p)
	}
	sort.Strings(names)
	for _, p := range names {
		f, err := parser.ParseFile(fs, p, srcs[p], 0)
		if err != nil {
			t.Fatal(err)
		}
		files = append(files, f)
	}
	info := &types.Info{Uses: map[*ast.Ident]types.Object{}}
	conf := types.Config{Importer: exportImporter(t, fs)}
	if _, err := conf.Check(pkgPath, fs, files, info); err != nil {
		t.Fatalf("type-checking %s: %v", pkgPath, err)
	}
	for _, f := range files {
		for _, im := range f.Imports {
			path, _ := strconv.Unquote(im.Path.Value)
			if forbiddenImports[path] {
				fail("%s imports %s", fs.Position(im.Pos()).Filename, path)
			}
			if path == "syscall" && im.Name != nil {
				fail("%s imports syscall under another name", fs.Position(im.Pos()).Filename)
			}
		}
		// The identifiers that are a direct call's os.OpenFile; any other
		// use of it (a value) fails, since its flags could not be read.
		opens := map[*ast.Ident]bool{}
		ast.Inspect(f, func(n ast.Node) bool {
			switch x := n.(type) {
			case *ast.BasicLit:
				for _, w := range forbiddenText {
					if strings.Contains(strings.ToLower(x.Value), w) {
						fail("%s: literal mentions %s", fs.Position(x.Pos()), w)
					}
				}
			case *ast.FuncDecl:
				// The open device never leaves the package: no exported
				// function or method returns a file or the device.
				if x.Name.IsExported() && x.Type.Results != nil {
					for _, r := range x.Type.Results.List {
						if s := typeString(r.Type); strings.Contains(s, "File") || strings.Contains(s, "device") || strings.Contains(s, "Reader") {
							fail("%s: exported %s returns %s", fs.Position(x.Pos()), x.Name.Name, s)
						}
					}
				}
			case *ast.SelectorExpr:
				// By spelling, on any receiver or package: a method such as
				// File.WriteAt or File.Fd counts as well.
				if forbiddenSel[x.Sel.Name] {
					fail("%s: uses %s", fs.Position(x.Pos()), x.Sel.Name)
				}
			case *ast.CallExpr:
				if id := callee(x.Fun); id != nil && isPkgObj(info.Uses[id], "os", "OpenFile") {
					opens[id] = true
					// OpenFile is allowed only with the read-only flag,
					// alone or with syscall.O_NOFOLLOW|syscall.O_NONBLOCK.
					if len(x.Args) < 2 || !isRDONLY(x.Args[1], info) {
						fail("%s: os.OpenFile without os.O_RDONLY alone or with O_NOFOLLOW and O_NONBLOCK", fs.Position(x.Pos()))
					}
				}
			case *ast.Ident:
				obj := info.Uses[x]
				if obj == nil || obj.Pkg() == nil {
					return true
				}
				if _, isPkg := obj.(*types.PkgName); isPkg {
					return true
				}
				// By resolution: a name from another package that a dot
				// import brings in bare counts as its selector would.
				if forbiddenSel[obj.Name()] && obj.Pkg().Path() != pkgPath {
					fail("%s: uses %s.%s", fs.Position(x.Pos()), obj.Pkg().Path(), obj.Name())
				}
				// syscall is imported only for the two open flags that keep a
				// device open from following a link or blocking (#3950); any
				// other name in it fails.
				if obj.Pkg().Path() == "syscall" && !syscallFlags[obj.Name()] {
					fail("%s: uses syscall.%s", fs.Position(x.Pos()), obj.Name())
				}
			}
			return true
		})
		ast.Inspect(f, func(n ast.Node) bool {
			if id, ok := n.(*ast.Ident); ok && !opens[id] && isPkgObj(info.Uses[id], "os", "OpenFile") {
				fail("%s: os.OpenFile used other than as a direct call", fs.Position(id.Pos()))
			}
			return true
		})
	}
	return problems
}

// callee is the identifier a call's function expression names.
func callee(e ast.Expr) *ast.Ident {
	switch x := e.(type) {
	case *ast.ParenExpr:
		return callee(x.X)
	case *ast.Ident:
		return x
	case *ast.SelectorExpr:
		return x.Sel
	}
	return nil
}

// isPkgObj reports whether obj is the package-level object name of the
// package at path: never a field, method, local or parameter so spelled.
func isPkgObj(obj types.Object, path, name string) bool {
	if obj == nil || obj.Pkg() == nil || obj.Pkg().Path() != path || obj.Name() != name || obj.Parent() != obj.Pkg().Scope() {
		return false
	}
	return true
}

type listed struct{ path, dir, goFiles, ignored, export string }

var (
	exportsOnce sync.Once
	exports     map[string]listed
	exportsErr  error
	firstPkgs   []listed
)

// goList lists pkgs and every package they or the fence's synthetic sources
// import, with export data; the first entries returned are pkgs, in order.
func goList(t *testing.T, pkgs ...string) []listed {
	t.Helper()
	exportsOnce.Do(func() {
		args := append([]string{"list", "-deps", "-export", "-f", "{{.ImportPath}}\t{{.Dir}}\t{{join .GoFiles \" \"}}\t{{join .IgnoredGoFiles \" \"}}\t{{.Export}}"}, pkgs...)
		args = append(args, "os", "syscall", "golang.org/x/sys/unix", "os/exec", "net/http")
		cmd := exec.Command("go", args...)
		cmd.Env = append(os.Environ(), "GOFLAGS=")
		out, err := cmd.Output()
		if err != nil {
			if ee, ok := err.(*exec.ExitError); ok {
				err = fmt.Errorf("%v\n%s", err, ee.Stderr)
			}
			exportsErr = fmt.Errorf("go list: %v", err)
			return
		}
		exports = map[string]listed{}
		for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
			f := strings.Split(line, "\t")
			if len(f) != 5 {
				exportsErr = fmt.Errorf("go list: unexpected line %q", line)
				return
			}
			exports[f[0]] = listed{f[0], f[1], f[2], f[3], f[4]}
		}
		for _, p := range pkgs {
			cmd := exec.Command("go", "list", "-f", "{{.ImportPath}}", p)
			cmd.Env = append(os.Environ(), "GOFLAGS=")
			out, err := cmd.Output()
			if err != nil {
				exportsErr = fmt.Errorf("go list %s: %v", p, err)
				return
			}
			firstPkgs = append(firstPkgs, exports[strings.TrimSpace(string(out))])
		}
	})
	if exportsErr != nil {
		t.Fatal(exportsErr)
	}
	return firstPkgs
}

// exportImporter imports a package from the export data go list found.
func exportImporter(t *testing.T, fs *token.FileSet) types.Importer {
	t.Helper()
	goList(t, ".", "../cmd/agentos-hostdisk")
	return importer.ForCompiler(fs, "gc", func(path string) (io.ReadCloser, error) {
		if exports[path].export == "" {
			return nil, fmt.Errorf("no export data for %s", path)
		}
		return os.Open(exports[path].export)
	})
}

// isBlock accepts only a block device node, as uid-independent unit
// cases: the real-node case below needs a node this uid can open.
func TestIsBlock(t *testing.T) {
	for m, want := range map[os.FileMode]bool{
		os.ModeDevice:                     true,
		os.ModeDevice | 0o660:             true,
		os.ModeDevice | os.ModeCharDevice: false,
		0o644:                             false,
		os.ModeDir:                        false,
		os.ModeSymlink:                    false,
		os.ModeNamedPipe:                  false,
		os.ModeSocket:                     false,
	} {
		if got := isBlock(m); got != want {
			t.Errorf("isBlock(%v) = %v, want %v", m, got, want)
		}
	}
}

func typeString(e ast.Expr) string {
	switch x := e.(type) {
	case *ast.Ident:
		return x.Name
	case *ast.StarExpr:
		return "*" + typeString(x.X)
	case *ast.SelectorExpr:
		return typeString(x.X) + "." + x.Sel.Name
	}
	return "?"
}

// syscallFlags are the only syscall names the package may use.
var syscallFlags = map[string]bool{"O_NOFOLLOW": true, "O_NONBLOCK": true}

// isRDONLY accepts os.O_RDONLY alone, or ORed with exactly
// syscall.O_NOFOLLOW and syscall.O_NONBLOCK: neither can write. Each operand
// must resolve to that package constant, however it is spelled; a local,
// field or parameter of the same name does not (#4256).
func isRDONLY(e ast.Expr, info *types.Info) bool {
	var names []string
	var walk func(e ast.Expr) bool
	walk = func(e ast.Expr) bool {
		var id *ast.Ident
		switch x := e.(type) {
		case *ast.BinaryExpr:
			return x.Op == token.OR && walk(x.X) && walk(x.Y)
		case *ast.SelectorExpr:
			id = x.Sel
		case *ast.Ident:
			id = x
		default:
			return false
		}
		c, ok := info.Uses[id].(*types.Const)
		if !ok || c.Pkg() == nil || !isPkgObj(c, c.Pkg().Path(), c.Name()) {
			return false
		}
		names = append(names, c.Pkg().Path()+"."+c.Name())
		return true
	}
	if !walk(e) {
		return false
	}
	sort.Strings(names)
	got := strings.Join(names, "|")
	return got == "os.O_RDONLY" || got == "os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK"
}

// The device opener asks for read-only access with close-on-exec
// (security H5 on HOST-1a), and the open file cannot write.
func TestOpenReadOnly(t *testing.T) {
	p := filepath.Join(t.TempDir(), "disk")
	if err := os.WriteFile(p, make([]byte, 4096), 0o644); err != nil {
		t.Fatal(err)
	}
	// A test cannot make a block node, so a regular file stands in for one
	// through the opener openReadOnly calls.
	f, err := openNode(p, os.FileMode.IsRegular)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := f.Write([]byte{1}); err == nil {
		t.Fatal("device opened writable")
	}
	info, err := os.ReadFile(fmt.Sprintf("/proc/self/fdinfo/%d", f.Fd()))
	if err != nil {
		t.Skip("no /proc fdinfo:", err)
	}
	for _, l := range strings.Split(string(info), "\n") {
		if v, ok := strings.CutPrefix(l, "flags:"); ok {
			flags, err := strconv.ParseUint(strings.TrimSpace(v), 8, 64)
			if err != nil {
				t.Fatal(err)
			}
			const accmode, cloexec, excl = 0o3, 0o2000000, 0o200
			if flags&accmode != 0 || flags&cloexec == 0 || flags&excl != 0 {
				t.Fatalf("flags %o: want O_RDONLY|O_CLOEXEC only", flags)
			}
			return
		}
	}
	t.Fatal("no flags line")
}

// The device opener follows no link, never waits on a FIFO and keeps only a
// block node (#3950): a link at the path is refused whatever it points at,
// as are a regular file, a character device, a directory and a FIFO.
func TestOpenReadOnlyRefusesALinkOrANonBlockNode(t *testing.T) {
	dir := t.TempDir()
	disk := filepath.Join(dir, "disk")
	if err := os.WriteFile(disk, make([]byte, 4096), 0o644); err != nil {
		t.Fatal(err)
	}
	fifo := filepath.Join(dir, "fifo")
	if err := mkfifo(fifo); err != nil {
		t.Fatal(err)
	}
	for name, target := range map[string]string{"sda": disk, "sdb": "/dev/null", "sdc": dir, "sdd": fifo} {
		if err := os.Symlink(target, filepath.Join(dir, name)); err != nil {
			t.Fatal(err)
		}
	}
	for _, p := range []string{"sda", "sdb", "sdc", "sdd", "disk", "fifo"} {
		p = filepath.Join(dir, p)
		done := make(chan error, 1)
		go func() {
			d, err := openReadOnly(p)
			if err == nil {
				d.Close()
			}
			done <- err
		}()
		select {
		case err := <-done:
			if err == nil {
				t.Errorf("openReadOnly(%s) opened a link or a file that is no block node", p)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("openReadOnly(%s) blocked", p)
		}
	}
	for _, p := range []string{"/dev/null", dir} {
		if d, err := openReadOnly(p); err == nil {
			d.Close()
			t.Errorf("openReadOnly(%s) opened a file that is no block node", p)
		}
	}
	// A link to a regular file is refused even where the mode would pass:
	// the refusal is the open's own.
	if f, err := openNode(filepath.Join(dir, "sda"), os.FileMode.IsRegular); err == nil {
		f.Close()
		t.Fatal("openNode followed a link")
	}
	// A real block node opens, where the test can read one.
	ents, _ := os.ReadDir("/sys/block")
	for _, e := range ents {
		p := filepath.Join("/dev", strings.ReplaceAll(e.Name(), "!", "/"))
		if f, err := os.Open(p); err == nil {
			f.Close()
			d, err := openReadOnly(p)
			if err != nil {
				t.Errorf("openReadOnly(%s), a block node this uid can open: %v", p, err)
			} else {
				d.Close()
			}
			break
		}
	}
}

// The fence admits syscall only for the two open flags, each operand
// resolved: the expression is type-checked in a file that imports os and
// syscall and declares a local flags.
func TestFenceAdmitsOnlyTheOpenFlags(t *testing.T) {
	for src, want := range map[string]bool{
		"os.O_RDONLY": true,
		"os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK":             true,
		"syscall.O_NONBLOCK|os.O_RDONLY|syscall.O_NOFOLLOW":             true,
		"os.O_RDONLY|syscall.O_NOFOLLOW":                                false,
		"os.O_RDWR|syscall.O_NOFOLLOW|syscall.O_NONBLOCK":               false,
		"os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|os.O_CREATE": false,
		"os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_DIRECT":               false,
		"os.O_RDONLY+syscall.O_NOFOLLOW+syscall.O_NONBLOCK":             false,
		"(os.O_RDONLY)": false,
		"flags":         false,
		"os.O_RDONLY|cfg.O_NOFOLLOW|syscall.O_NONBLOCK": false,
		"0": false,
	} {
		fs := token.NewFileSet()
		f, err := parser.ParseFile(fs, "x.go", "package x\n\nimport (\n\t\"os\"\n\t\"syscall\"\n)\n\nvar flags = 0\n\nvar cfg = struct{ O_NOFOLLOW int }{}\n\nvar _, _ = os.O_RDONLY, syscall.O_NOFOLLOW\n\nvar e = "+src+"\n", 0)
		if err != nil {
			t.Fatal(err)
		}
		info := &types.Info{Uses: map[*ast.Ident]types.Object{}}
		if _, err := (&types.Config{Importer: exportImporter(t, fs)}).Check("x", fs, []*ast.File{f}, info); err != nil {
			t.Fatalf("%s: %v", src, err)
		}
		e := f.Decls[len(f.Decls)-1].(*ast.GenDecl).Specs[0].(*ast.ValueSpec).Values[0]
		if got := isRDONLY(e, info); got != want {
			t.Errorf("isRDONLY(%s) = %v, want %v", src, got, want)
		}
	}
}

func mkfifo(p string) error { return syscall.Mkfifo(p, 0o644) }
