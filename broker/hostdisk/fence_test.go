package hostdisk

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// REQ: HW-8

// HW-8 forbids mounting, writing or repairing a host disk. The probe and
// its command can only read: their non-test source opens files read-only
// and has no call or import that writes, mounts, swaps or runs a program.
func TestSourceCannotWriteOrMount(t *testing.T) {
	dirs := []string{".", "../cmd/agentos-hostdisk"}
	forbiddenImports := map[string]bool{
		"os/exec": true, "syscall": true, "golang.org/x/sys/unix": true,
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
	var files int
	for _, dir := range dirs {
		paths, err := filepath.Glob(filepath.Join(dir, "*.go"))
		if err != nil {
			t.Fatal(err)
		}
		for _, p := range paths {
			if strings.HasSuffix(p, "_test.go") {
				continue
			}
			files++
			fs := token.NewFileSet()
			f, err := parser.ParseFile(fs, p, nil, 0)
			if err != nil {
				t.Fatal(err)
			}
			for _, im := range f.Imports {
				path, _ := strconv.Unquote(im.Path.Value)
				if forbiddenImports[path] {
					t.Errorf("%s imports %s", p, path)
				}
			}
			ast.Inspect(f, func(n ast.Node) bool {
				switch x := n.(type) {
				case *ast.BasicLit:
					for _, w := range forbiddenText {
						if strings.Contains(strings.ToLower(x.Value), w) {
							t.Errorf("%s: literal mentions %s", fs.Position(x.Pos()), w)
						}
					}
				case *ast.FuncDecl:
					// The open device never leaves the package: no exported
					// function or method returns a file or the device.
					if x.Name.IsExported() && x.Type.Results != nil {
						for _, r := range x.Type.Results.List {
							if s := types(r.Type); strings.Contains(s, "File") || strings.Contains(s, "device") || strings.Contains(s, "Reader") {
								t.Errorf("%s: exported %s returns %s", fs.Position(x.Pos()), x.Name.Name, s)
							}
						}
					}
				case *ast.SelectorExpr:
					if forbiddenSel[x.Sel.Name] {
						t.Errorf("%s: uses %s", fs.Position(x.Pos()), x.Sel.Name)
					}
				case *ast.CallExpr:
					if sel, ok := x.Fun.(*ast.SelectorExpr); ok {
						if id, ok := sel.X.(*ast.Ident); ok && id.Name == "os" && sel.Sel.Name == "OpenFile" {
							// OpenFile is allowed only with the read-only flag.
							if len(x.Args) < 2 || !isRDONLY(x.Args[1]) {
								t.Errorf("%s: os.OpenFile without os.O_RDONLY alone", fs.Position(x.Pos()))
							}
						}
					}
				}
				return true
			})
		}
	}
	if files < 3 {
		t.Fatalf("only %d source files checked", files)
	}
}

func types(e ast.Expr) string {
	switch x := e.(type) {
	case *ast.Ident:
		return x.Name
	case *ast.StarExpr:
		return "*" + types(x.X)
	case *ast.SelectorExpr:
		return types(x.X) + "." + x.Sel.Name
	}
	return "?"
}

func isRDONLY(e ast.Expr) bool {
	sel, ok := e.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	id, ok := sel.X.(*ast.Ident)
	return ok && id.Name == "os" && sel.Sel.Name == "O_RDONLY"
}

// The device opener asks for read-only access with close-on-exec
// (security H5 on HOST-1a), and the open file cannot write.
func TestOpenReadOnly(t *testing.T) {
	p := filepath.Join(t.TempDir(), "disk")
	if err := os.WriteFile(p, make([]byte, 4096), 0o644); err != nil {
		t.Fatal(err)
	}
	d, err := openReadOnly(p)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	f := d.(*os.File)
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
