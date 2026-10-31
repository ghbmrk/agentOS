package hostdisk

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// REQ: HW-8

// HW-8 forbids mounting, writing or repairing a host disk. The probe and
// its command can only read: their non-test source opens files read-only
// and has no call or import that writes, mounts, swaps or runs a program.
func TestSourceCannotWriteOrMount(t *testing.T) {
	dirs := []string{".", "../cmd/agentos-hostdisk"}
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
			syscallName := ""
			for _, im := range f.Imports {
				path, _ := strconv.Unquote(im.Path.Value)
				if forbiddenImports[path] {
					t.Errorf("%s imports %s", p, path)
				}
				if path == "syscall" {
					syscallName = "syscall"
					if im.Name != nil {
						t.Errorf("%s imports syscall under another name", p)
					}
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
					// syscall is imported only for the two open flags that
					// keep a device open from following a link or blocking
					// (#3950); any other name in it fails.
					if id, ok := x.X.(*ast.Ident); ok && syscallName != "" && id.Name == syscallName && !syscallFlags[x.Sel.Name] {
						t.Errorf("%s: uses syscall.%s", fs.Position(x.Pos()), x.Sel.Name)
					}
				case *ast.CallExpr:
					if sel, ok := x.Fun.(*ast.SelectorExpr); ok {
						if id, ok := sel.X.(*ast.Ident); ok && id.Name == "os" && sel.Sel.Name == "OpenFile" {
							// OpenFile is allowed only with the read-only flag,
							// alone or with syscall.O_NOFOLLOW|syscall.O_NONBLOCK.
							if len(x.Args) < 2 || !isRDONLY(x.Args[1]) {
								t.Errorf("%s: os.OpenFile without os.O_RDONLY alone or with O_NOFOLLOW and O_NONBLOCK", fs.Position(x.Pos()))
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

// syscallFlags are the only syscall names the package may use.
var syscallFlags = map[string]bool{"O_NOFOLLOW": true, "O_NONBLOCK": true}

// isRDONLY accepts os.O_RDONLY alone, or ORed with exactly
// syscall.O_NOFOLLOW and syscall.O_NONBLOCK: neither can write.
func isRDONLY(e ast.Expr) bool {
	var names []string
	var walk func(e ast.Expr) bool
	walk = func(e ast.Expr) bool {
		switch x := e.(type) {
		case *ast.BinaryExpr:
			return x.Op == token.OR && walk(x.X) && walk(x.Y)
		case *ast.SelectorExpr:
			id, ok := x.X.(*ast.Ident)
			if !ok {
				return false
			}
			names = append(names, id.Name+"."+x.Sel.Name)
			return true
		}
		return false
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

// The fence admits syscall only for the two open flags.
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
		"flags": false,
	} {
		e, err := parser.ParseExpr(src)
		if err != nil {
			t.Fatal(err)
		}
		if got := isRDONLY(e); got != want {
			t.Errorf("isRDONLY(%s) = %v, want %v", src, got, want)
		}
	}
}

func mkfifo(p string) error { return syscall.Mkfifo(p, 0o644) }
