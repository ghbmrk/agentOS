package hostdisk

import (
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
		"WriteAt": true, "StartProcess": true,
	}
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

func isRDONLY(e ast.Expr) bool {
	sel, ok := e.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	id, ok := sel.X.(*ast.Ident)
	return ok && id.Name == "os" && sel.Sel.Name == "O_RDONLY"
}

// The device opener asks for read-only access and nothing else.
func TestOpenReadOnly(t *testing.T) {
	p := filepath.Join(t.TempDir(), "disk")
	if err := os.WriteFile(p, make([]byte, 4096), 0o444); err != nil {
		t.Fatal(err)
	}
	d, err := OpenReadOnly(p)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	if f, ok := d.(*os.File); !ok {
		t.Fatalf("%T", d)
	} else if _, err := f.Write([]byte{1}); err == nil {
		t.Fatal("device opened writable")
	}
}
