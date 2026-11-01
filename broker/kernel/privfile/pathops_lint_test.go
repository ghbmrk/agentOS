package privfile

// REQ: KRN-2

// The root-side path lint (REV-CHK-links, #3900). A file operation a root
// process makes by path follows any link on that path, so a guest, clerk or
// other uid that can plant one in a directory on it redirects the write,
// removal or read (#3282, #3382, #3624). The root side is derived, not
// listed: every binary a shipped .service or .socket unit (#4330) starts
// with no User= or DynamicUser= (or on an Exec line with a + or ! prefix),
// every binary a file under image/ or broker/ makes root run (runKinds: a
// udev rule's RUN, PROGRAM or IMPORT{program}, #3950; a modprobe.d install
// or remove command, #4279; a sysctl.d usermode helper, or a tmpfiles.d
// write of one, #4320), each only a path root_programs.txt lists (#4257),
// and the module's packages those binaries link. A udev rule
// sets no property that makes systemd start a unit (#4276), and no file
// ships in a directory root runs whole. Each package is type-checked, and in
// those packages each identifier that resolves to a path-based os or
// io/ioutil function that follows links (pathOps, #4272) fails, whatever
// name spells it (#4256), unless it is os.OpenFile with the real O_NOFOLLOW,
// goes through privfile, or has an allow line in pathops_allow.txt naming
// the file, the function and the call, with a reason a review checks.
//
// Bound: an allow line's reason is held by review, as is a link planted
// through a path the reason deems safe (a parent directory another uid can
// write). Every call outside pathOps (among them os.Lstat, os.Symlink,
// os.Chtimes, os.Truncate, os.DirFS, os.CopyFS, filepath.EvalSymlinks, Glob
// and Walk, a unix socket's net.Listen, and syscall and unix path calls), a
// binary that a script rather than a unit or runKinds file starts (a listed
// program's reason included), the properties a listed IMPORT{program} or a
// udev builtin sets, a modprobe.d, sysctl.d or tmpfiles.d file kept outside
// a directory of that name and installed by a script, units and tmpfiles.d
// lines a package rather than image/ or broker/ ships, a binary built by a line
// binaryPackages does not parse, files only a build tag brings in (go list
// runs with no -tags; no root-side binary builds with tags today), and file
// operations of non-root host processes are outside the check.

import (
	"bufio"
	"bytes"
	"fmt"
	"go/ast"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	"io"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// pathOps are, by import path, the path-based calls that follow links: the
// os calls the brief names (briefs/REV-CHK.md) and the os forms of
// io/ioutil's ReadDir, TempFile and TempDir (#4329), and io/ioutil's path
// functions, each a wrapper of an os call that follows links the same way
// (#4272). A use and an allow line spell one as the package's last path
// element, a dot and the name: os.Remove, ioutil.WriteFile.
var pathOps = map[string]map[string]bool{
	"os": {
		"Open": true, "OpenFile": true, "Create": true, "ReadFile": true, "WriteFile": true,
		"Remove": true, "RemoveAll": true, "Rename": true, "Chmod": true, "Chown": true,
		"Mkdir": true, "MkdirAll": true, "Stat": true, "Link": true,
		"ReadDir": true, "CreateTemp": true, "MkdirTemp": true,
	},
	"io/ioutil": {"ReadFile": true, "WriteFile": true, "ReadDir": true, "TempFile": true, "TempDir": true},
}

// pathOpName is how a use spells a package-level function, and whether the
// function is in pathOps (a method, such as one of *os.File, never is).
func pathOpName(obj types.Object) (string, bool) {
	f, ok := obj.(*types.Func)
	if !ok || f.Pkg() == nil || f.Type().(*types.Signature).Recv() != nil || !pathOps[f.Pkg().Path()][f.Name()] {
		return "", false
	}
	return path.Base(f.Pkg().Path()) + "." + f.Name(), true
}

// isPathOpName reports whether an allow line's call names a pathOps entry.
func isPathOpName(name string) bool {
	q, fn, ok := strings.Cut(name, ".")
	for pkg, ops := range pathOps {
		if ok && path.Base(pkg) == q && ops[fn] {
			return true
		}
	}
	return false
}

const allowFile = "pathops_allow.txt"

func TestRootSidePathOpsGoThroughPrivfile(t *testing.T) {
	t.Run("refuses", func(t *testing.T) {
		problems := lintFiles(t, map[string]string{
			"broker/side/side.go": "package side\n\nimport (\n\t\"os\"\n\t\"path/filepath\"\n)\n\nfunc Drop(dir, name string) error { return os.Remove(filepath.Join(dir, name)) }\n",
		}, "")
		if len(problems) != 1 || !strings.Contains(problems[0], "broker/side/side.go") || !strings.Contains(problems[0], "Drop") || !strings.Contains(problems[0], "os.Remove") {
			t.Fatalf("a root-side os.Remove on a joined path: got %q, want one problem naming the file, Drop and os.Remove", problems)
		}
	})
	t.Run("refuses each call and form", func(t *testing.T) {
		// Each source compiles: the lint type-checks the package and a type
		// error fails it, so a refusal here is the use's own.
		args := map[string]string{
			"os.Open": `""`, "os.OpenFile": `"", os.O_RDONLY, 0`, "os.Create": `""`, "os.ReadFile": `""`, "os.WriteFile": `"", nil, 0`,
			"os.Remove": `""`, "os.RemoveAll": `""`, "os.Rename": `"", ""`, "os.Chmod": `"", 0`, "os.Chown": `"", 0, 0`,
			"os.Mkdir": `"", 0`, "os.MkdirAll": `"", 0`, "os.Stat": `""`, "os.Link": `"", ""`,
			"os.ReadDir": `""`, "os.CreateTemp": `"", ""`, "os.MkdirTemp": `"", ""`,
			"ioutil.ReadFile": `""`, "ioutil.WriteFile": `"", nil, 0`, "ioutil.ReadDir": `""`, "ioutil.TempFile": `"", ""`, "ioutil.TempDir": `"", ""`,
		}
		// The list above is the expected set, so a pathOps that drops one
		// (os.ReadDir, os.CreateTemp or os.MkdirTemp, #4329) fails here, not
		// only one that gains a call with no arguments.
		for name := range args {
			if !isPathOpName(name) {
				t.Errorf("%s is not in pathOps", name)
			}
		}
		for pkg, ops := range pathOps {
			q := path.Base(pkg)
			for op := range ops {
				name := q + "." + op
				a := args[name]
				if a == "" {
					t.Fatalf("no call arguments for %s", name)
				}
				// A value and a call take the same path (an identifier that
				// resolves to the function), so one value form is enough.
				for _, form := range []string{"call", "value", "alias call", "dot import"} {
					src := "package side\n\nimport \"" + pkg + "\"\n\nvar _ = " + name + "\n"
					switch form {
					case "call":
						src = "package side\n\nimport \"" + pkg + "\"\n\nfunc F() { " + name + "(" + a + ") }\n"
					case "alias call":
						src = "package side\n\nimport o \"" + pkg + "\"\n\nfunc F() { o." + op + "(" + strings.ReplaceAll(a, q+".", "o.") + ") }\n"
					case "dot import":
						src = "package side\n\nimport . \"" + pkg + "\"\n\nfunc F() { " + op + "(" + strings.ReplaceAll(a, q+".", "") + ") }\n"
					}
					problems := lintFiles(t, map[string]string{"broker/side/side.go": src}, "")
					if len(problems) != 1 || !strings.Contains(problems[0], " calls "+name+" ") {
						t.Errorf("%s as a %s: got %q, want one problem", name, form, problems)
					}
				}
			}
		}
	})
	t.Run("a method or a local of the same name is not os's", func(t *testing.T) {
		src := "package side\n\nimport \"os\"\n\nfunc F(f *os.File) { f.Chmod(0); f.Stat(); _ = (*os.File).Chown }\n\nfunc G() { os := struct{ Remove func(string) error }{}; _ = os.Remove }\n\nfunc Remove(string) error { return nil }\n\nvar _ = Remove\n"
		if problems := lintFiles(t, map[string]string{"broker/side/side.go": src}, ""); len(problems) != 0 {
			t.Fatalf("got %q, want none", problems)
		}
	})
	t.Run("O_NOFOLLOW opens pass, other flags fail", func(t *testing.T) {
		const decls = "\n\nconst O_NOFOLLOW = 0x20000\n\nvar cfg = struct{ O_NOFOLLOW int }{0x20000}\n\nfunc flags(x int) int { return x }\n"
		src := "package side\n\nimport (\n\t\"os\"\n\t\"syscall\"\n)\n\nfunc F(p string) { os.OpenFile(p, os.O_RDONLY|syscall.O_NOFOLLOW, 0) }" + decls
		for _, ok := range []string{
			src,
			"package side\n\nimport (\n\t\"os\"\n\tsc \"syscall\"\n)\n\nfunc F(p string) { os.OpenFile(p, os.O_RDONLY|sc.O_NOFOLLOW, 0) }\n",
			"package side\n\nimport (\n\t\"os\"\n\t. \"syscall\"\n)\n\nfunc F(p string) { os.OpenFile(p, os.O_RDONLY|O_NOFOLLOW, 0) }\n",
		} {
			if problems := lintFiles(t, map[string]string{"broker/side/side.go": ok}, ""); len(problems) != 0 {
				t.Fatalf("an O_NOFOLLOW open: got %q, want none for\n%s", problems, ok)
			}
		}
		for _, fl := range []string{"os.O_RDONLY|syscall.O_CLOEXEC", "os.O_RDWR&^syscall.O_NOFOLLOW", "flags(syscall.O_NOFOLLOW)", "os.O_RDONLY|(syscall.O_NOFOLLOW^syscall.O_NOFOLLOW)", "os.O_RDONLY+syscall.O_NOFOLLOW", "os.O_RDONLY|O_NOFOLLOW", "os.O_RDONLY|cfg.O_NOFOLLOW", "0x20000"} {
			src := strings.Replace(src, "os.O_RDONLY|syscall.O_NOFOLLOW", fl, 1)
			if !strings.Contains(src, "syscall.") {
				src = strings.Replace(src, "func F", "var _ = syscall.O_RDONLY\n\nfunc F", 1)
			}
			if problems := lintFiles(t, map[string]string{"broker/side/side.go": src}, ""); len(problems) != 1 {
				t.Errorf("an open with flags %s: got %q, want one problem", fl, problems)
			}
		}
	})
	t.Run("a shadowed flag package fails", func(t *testing.T) {
		for _, src := range []string{
			"package side\n\nimport (\n\t\"os\"\n\t\"syscall\"\n)\n\nvar _ = syscall.O_RDONLY\n\nfunc F(p string) { syscall := struct{ O_NOFOLLOW int }{}; os.OpenFile(p, os.O_RDWR|syscall.O_NOFOLLOW, 0) }\n",
			"package side\n\nimport (\n\t\"os\"\n\tunix \"syscall\"\n)\n\nvar _ = unix.O_RDONLY\n\nfunc F(p string) { unix := struct{ O_NOFOLLOW int }{}; os.OpenFile(p, os.O_RDWR|unix.O_NOFOLLOW, 0) }\n",
			"package side\n\nimport (\n\t\"os\"\n\t\"syscall\"\n)\n\nvar _ = syscall.O_RDONLY\n\nvar G = func(p string, syscall struct{ O_NOFOLLOW int }) { os.OpenFile(p, os.O_RDWR|syscall.O_NOFOLLOW, 0) }\n",
			// The #4256 failure path: a local struct spelled like syscall
			// makes the flags O_RDWR|O_CREAT.
			"package side\n\nimport (\n\t\"os\"\n\t\"syscall\"\n)\n\nvar _ = syscall.O_RDONLY\n\nfunc F(p string) { syscall := struct{ O_NOFOLLOW, O_NONBLOCK int }{2, 64}; os.OpenFile(p, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0) }\n",
			// A shadowing local in a nested scope, past the use's own block.
			"package side\n\nimport (\n\t\"os\"\n\t\"syscall\"\n)\n\nvar _ = syscall.O_RDONLY\n\nfunc F(p string) {\n\tfor _, syscall := range []struct{ O_NOFOLLOW int }{{2}} {\n\t\tif true {\n\t\t\tos.OpenFile(p, os.O_RDWR|syscall.O_NOFOLLOW, 0)\n\t\t}\n\t}\n}\n",
		} {
			if problems := lintFiles(t, map[string]string{"broker/side/side.go": src}, ""); len(problems) != 1 {
				t.Errorf("got %q, want one problem for\n%s", problems, src)
			}
		}
	})
	t.Run("an io/ioutil path call is its own, allowed by its own line", func(t *testing.T) {
		files := map[string]string{"broker/side/side.go": "package side\n\nimport \"io/ioutil\"\n\nfunc Save(p string) error { return ioutil.WriteFile(p, nil, 0o600) }\n\nfunc Read(p string) { ioutil.ReadAll(nil); ioutil.NopCloser(nil) }\n"}
		problems := lintFiles(t, files, "")
		if len(problems) != 1 || !strings.Contains(problems[0], "Save calls ioutil.WriteFile") {
			t.Fatalf("got %q, want only ioutil.WriteFile refused (ReadAll and NopCloser take no path)", problems)
		}
		if problems := lintFiles(t, files, "allow broker/side/side.go Save os.WriteFile reason\n"); len(problems) != 2 {
			t.Fatalf("an os.WriteFile line: got %q, want the use refused and the line stale", problems)
		}
		if problems := lintFiles(t, files, "allow broker/side/side.go Save ioutil.WriteFile reason\n"); len(problems) != 0 {
			t.Fatalf("allowed: got %q, want none", problems)
		}
	})
	t.Run("a dot import of os is resolved", func(t *testing.T) {
		src := "package side\n\nimport . \"os\"\n\nfunc F(p string) { Remove(p) }\n"
		problems := lintFiles(t, map[string]string{"broker/side/side.go": src}, "")
		if len(problems) != 1 || !strings.Contains(problems[0], "F calls os.Remove") {
			t.Fatalf("got %q, want the bare Remove refused as os.Remove", problems)
		}
		if problems := lintFiles(t, map[string]string{"broker/side/side.go": src}, "allow broker/side/side.go F os.Remove reason\n"); len(problems) != 0 {
			t.Fatalf("allowed: got %q, want none", problems)
		}
	})
	t.Run("a package that does not build fails the lint", func(t *testing.T) {
		// go list -export compiles each package, so it stops here first.
		bins := []string{"./cmd/agentos-side"}
		root := fakeRepo(t, map[string]string{
			"broker/side/side.go":             "package side\n\nimport \"os\"\n\nfunc F() { os.Remove() }\n",
			"broker/cmd/agentos-side/main.go": "package main\n\nimport _ \"example.test/broker/side\"\n\nfunc main() {}\n",
		})
		if _, err := rootSideUses(root, bins); err == nil || !strings.Contains(err.Error(), "go list (") {
			t.Fatalf("a package that does not build: got %v, want go list's error", err)
		}
	})
	t.Run("a type error fails the type check", func(t *testing.T) {
		// checkTypes reads again what go list compiled; a source the gc
		// compiler passes and go/types refuses would reach this branch the
		// same way (#4280 1).
		for src, bad := range map[string]bool{"package side\n\nvar X int = \"s\"\n": true, "package side\n\nvar X int = 1\n": false} {
			fset := token.NewFileSet()
			f, err := parser.ParseFile(fset, "side.go", src, 0)
			if err != nil {
				t.Fatal(err)
			}
			_, err = checkTypes(fset, nil, "example.test/broker/side", "amd64", []*ast.File{f})
			if bad != (err != nil) || bad && !strings.Contains(err.Error(), "type-checking example.test/broker/side (amd64)") {
				t.Errorf("%q: got %v, want an error %v", src, err, bad)
			}
		}
	})
	t.Run("through privfile passes", func(t *testing.T) {
		files := map[string]string{
			"broker/privfile/privfile.go": "package privfile\n\nfunc Remove(dir, name string) error { return nil }\n",
			"broker/side/side.go":         "package side\n\nimport \"example.test/broker/privfile\"\n\nfunc Drop(dir, name string) error { return privfile.Remove(dir, name) }\n",
		}
		if problems := lintFiles(t, files, ""); len(problems) != 0 {
			t.Fatalf("the same removal through privfile: got %q, want none", problems)
		}
	})
	t.Run("an allow line passes it, a blank reason does not", func(t *testing.T) {
		files := map[string]string{"broker/side/side.go": "package side\n\nimport \"os\"\n\nfunc Drop(p string) error { return os.Remove(p) }\n"}
		if problems := lintFiles(t, files, "allow broker/side/side.go Drop os.Remove the directory is root's own 0700\n"); len(problems) != 0 {
			t.Fatalf("allowed: got %q, want none", problems)
		}
		if problems := lintFiles(t, files, "allow broker/side/side.go Drop os.Remove\n"); len(problems) == 0 {
			t.Fatal("an allow line with no reason was accepted")
		}
	})
	t.Run("a pending package passes until it is clean", func(t *testing.T) {
		files := map[string]string{"broker/side/side.go": "package side\n\nimport \"os\"\n\nfunc Drop(p string) error { return os.Remove(p) }\n"}
		if problems := lintFiles(t, files, "pending broker/side #1 ported by its row\n"); len(problems) != 0 {
			t.Fatalf("pending: got %q, want none", problems)
		}
		files["broker/side/side.go"] = "package side\n"
		if problems := lintFiles(t, files, "pending broker/side #1 ported by its row\n"); len(problems) != 1 || !strings.Contains(problems[0], "stale") {
			t.Fatalf("a pending package with no finding: got %q, want one stale problem", problems)
		}
	})
	t.Run("test files are outside", func(t *testing.T) {
		files := map[string]string{
			"broker/side/side.go":      "package side\n",
			"broker/side/side_test.go": "package side\n\nimport \"os\"\n\nfunc drop(p string) error { return os.Remove(p) }\n",
		}
		if problems := lintFiles(t, files, ""); len(problems) != 0 {
			t.Fatalf("a test file: got %q, want none", problems)
		}
	})
	t.Run("main", func(t *testing.T) {
		allow, err := os.ReadFile(allowFile)
		if err != nil {
			t.Fatal(err)
		}
		if problems := lintRepo(t, repoRoot(t), string(allow)); len(problems) != 0 {
			t.Fatalf("%d root-side path operation(s) neither go through privfile nor have an allow line in broker/kernel/privfile/%s:\n%s",
				len(problems), allowFile, strings.Join(problems, "\n"))
		}
	})
}

func TestRootSideSetComesFromTheUnits(t *testing.T) {
	files := map[string]string{
		"broker/side/side.go":                   "package side\n\nimport \"os\"\n\nfunc Drop(p string) error { return os.Remove(p) }\n",
		"broker/cmd/agentos-side/main.go":       "package main\n\nimport \"example.test/broker/side\"\n\nfunc main() { side.Drop(\"\") }\n",
		"broker/other/main.go":                  "package main\n\nimport \"example.test/broker/side\"\n\nfunc main() { side.Drop(\"\") }\n",
		"image/build.sh":                        "cd broker && go build -o \"$STAGE/usr/lib/agentos/agentos-other\" ./other\n",
		"image/mkosi/agentos-side.service":      "[Service]\nUser=agentos-side\nExecStart=/usr/lib/agentos/agentos-side\n",
		"image/mkosi/agentos-other.service":     "[Service]\nUser=agentos-other\nExecStart=/usr/lib/agentos/agentos-other\n",
		"image/mkosi/agentos-.service.d/x.conf": "[Service]\nInaccessiblePaths=/x\n",
	}
	set := func(t *testing.T, files map[string]string) []string {
		t.Helper()
		bins, err := rootBinaries(fakeRepo(t, files))
		if err != nil {
			t.Fatal(err)
		}
		return bins
	}
	if bins := set(t, files); len(bins) != 0 {
		t.Fatalf("units that all set User=: got %q, want no root-side binary", bins)
	}
	for name, unit := range map[string]string{
		"a unit without User=":                "[Service]\nExecStart=/usr/lib/agentos/with-uids /usr/lib/agentos/agentos-side -x @uid:y\n",
		"a + line in a unit with User=":       "[Service]\nUser=agentos-side\nExecStartPre=+/usr/lib/agentos/agentos-side\n",
		"a unit whose User= is commented out": "[Service]\n# User=agentos-side\nExecStart=/usr/lib/agentos/agentos-side\n",
	} {
		t.Run(name, func(t *testing.T) {
			files := clone(files)
			files["image/mkosi/agentos-side.service"] = unit
			if bins := set(t, files); len(bins) != 1 || bins[0] != "./cmd/agentos-side" {
				t.Fatalf("got %q, want [./cmd/agentos-side]", bins)
			}
			if problems := lintFiles(t, files, ""); len(problems) != 1 || !strings.Contains(problems[0], "broker/side/side.go") {
				t.Fatalf("the binary's linked package: got %q, want its os.Remove refused", problems)
			}
		})
	}
	// A .socket's Exec lines run under its own User= like a .service's
	// (#4330); a socket with none runs them as root.
	for name, c := range map[string]struct{ path, text string }{
		"a .socket without User=":          {"image/mkosi/agentos-side.socket", "[Socket]\nListenStream=/run/x\nExecStartPre=/usr/lib/agentos/agentos-side\n"},
		"a + line in a .socket with User=": {"image/mkosi/agentos-side.socket", "[Socket]\nUser=agentos-side\nExecStopPost=+/usr/lib/agentos/agentos-side\n"},
		"a .socket drop-in with User=root": {"image/mkosi/agentos-side.socket.d/z.conf", "[Socket]\nUser=root\n"},
		"a socket.d drop-in with User=0":   {"image/mkosi/socket.d/z.conf", "[Socket]\nUser=0\n"},
		"a service.d drop-in with User=":   {"image/mkosi/service.d/z.conf", "[Service]\nUser=\n"},
	} {
		t.Run(name, func(t *testing.T) {
			files := clone(files)
			files["image/mkosi/agentos-side.socket"] = "[Socket]\nUser=agentos-side\nExecStartPost=/usr/lib/agentos/agentos-side\n"
			if bins := set(t, files); len(bins) != 0 {
				t.Fatalf("a .socket with User=: got %q, want none", bins)
			}
			files[c.path] = c.text
			// service.d reaches every service, agentos-other's too.
			if bins := set(t, files); len(bins) == 0 || bins[0] != "./cmd/agentos-side" {
				t.Fatalf("got %q, want ./cmd/agentos-side first", bins)
			}
			if problems := lintFiles(t, files, ""); len(problems) != 1 || !strings.Contains(problems[0], "broker/side/side.go") {
				t.Fatalf("the unit's binary's linked package: got %q, want its os.Remove refused", problems)
			}
		})
	}
	t.Run("a binary a build line names", func(t *testing.T) {
		files := clone(files)
		files["image/mkosi/agentos-other.service"] = "[Service]\nExecStart=/usr/lib/agentos/agentos-other\n"
		if bins := set(t, files); len(bins) != 1 || bins[0] != "./other" {
			t.Fatalf("got %q, want [./other]", bins)
		}
	})
	for name, dropin := range map[string]string{
		"an empty User=": "[Service]\nUser=\n",
		"User=root":      "[Service]\nUser=root\n",
		"User=0":         "[Service]\nUser=0\n",
		"DynamicUser=no": "[Service]\nDynamicUser=no\n",
	} {
		t.Run("a drop-in resetting the user: "+name, func(t *testing.T) {
			files := clone(files)
			files["image/mkosi/agentos-side.service.d/z.conf"] = dropin
			if bins := set(t, files); len(bins) != 1 || bins[0] != "./cmd/agentos-side" {
				t.Fatalf("got %q, want [./cmd/agentos-side]", bins)
			}
		})
	}
	t.Run("User= from a drop-in", func(t *testing.T) {
		files := clone(files)
		files["image/mkosi/agentos-side.service"] = "[Service]\nExecStart=/usr/lib/agentos/agentos-side\n"
		files["image/mkosi/agentos-side.service.d/user.conf"] = "[Service]\nUser=agentos-side\n"
		if bins := set(t, files); len(bins) != 0 {
			t.Fatalf("got %q, want none", bins)
		}
		delete(files, "image/mkosi/agentos-side.service.d/user.conf")
		files["image/mkosi/agentos-.service.d/user.conf"] = "[Service]\nDynamicUser=yes\n"
		if bins := set(t, files); len(bins) != 0 {
			t.Fatalf("a prefix drop-in: got %q, want none", bins)
		}
	})
}

// A udev rule runs its programs as root, so a broker binary a rule runs
// joins the root side (#3950); a rule may run only a listed absolute path,
// so no wrapper, bare name, substitution or escape can hide one (#4257).
func TestRootSideSetCountsUdevRulePrograms(t *testing.T) {
	const rule = "broker/side/udev/59-agentos-side.rules"
	files := map[string]string{
		"broker/side/side.go":              "package side\n\nimport \"os\"\n\nfunc Drop(p string) error { return os.Remove(p) }\n",
		"broker/cmd/agentos-side/main.go":  "package main\n\nimport \"example.test/broker/side\"\n\nfunc main() { side.Drop(\"\") }\n",
		"image/mkosi/agentos-side.service": "[Service]\nUser=agentos-side\nExecStart=/usr/lib/agentos/agentos-side\n",
		rule:                               "ACTION==\"remove\", GOTO=\"end\"\nENV{SYSTEMD_READY}=\"0\", ENV{SYSTEMD_WANTS}==\"x\", IMPORT{parent}=\"AGENTOS_DISK\", IMPORT{db}=\"ID_X\"\nRUN+=\"/usr/lib/agentos/host-disk-unlink %k\"\nENV{X}=\"agentos-side\"\nOWNER=\"agentos-side\", GROUP:=\"agentos-side\", MODE=\"0600\"\n# RUN+=\"/usr/lib/agentos/agentos-side\"\n  # RUN+=\"/bin/sh -c 'agentos-side'\"\nLABEL=\"end\"\n",
		"broker/side/udev/README":          "RUN+=\"/usr/lib/agentos/agentos-side\"\n",
		programsFile:                       "# synthetic\n/usr/lib/agentos/host-disk-unlink a script\n/usr/lib/agentos/agentos-side the binary under test\n",
	}
	set := func(t *testing.T, files map[string]string) ([]string, error) {
		t.Helper()
		return rootBinaries(fakeRepo(t, files))
	}
	// agentos-side is listed but run only by the cases below.
	base := clone(files)
	base[programsFile] = "/usr/lib/agentos/host-disk-unlink a script\n"
	if bins, err := set(t, base); err != nil || len(bins) != 0 {
		t.Fatalf("a rule running only another program, naming the binary in an ENV value, an account or a comment, setting SYSTEMD_READY, matching SYSTEMD_WANTS, importing plain names, and a file that is no .rules: got %q, %v, want none", bins, err)
	}
	for name, text := range map[string]string{
		"RUN+=":                    "ACTION==\"add\", RUN+=\"/usr/lib/agentos/agentos-side %k\"\n",
		"RUN{program}+=":           "RUN{program}+=\"/usr/lib/agentos/agentos-side\"\n",
		"IMPORT{program}=":         "ENV{DEVTYPE}==\"disk\", IMPORT{program}=\"/usr/lib/agentos/agentos-side classify %k\"\n",
		"PROGRAM==":                "PROGRAM==\"/usr/lib/agentos/agentos-side %k\", SYMLINK+=\"x\"\n",
		"PROGRAM!= with no spaces": "PROGRAM!=\"/usr/lib/agentos/agentos-side\",GOTO=\"end\"\n",
		"blanks around the op":     "\tRUN +=  \"/usr/lib/agentos/agentos-side\" ,\n",
		"a rule under image":       "RUN+=\"/usr/lib/agentos/agentos-side\"\n",
	} {
		t.Run(name, func(t *testing.T) {
			files := clone(files)
			path := rule
			if name == "a rule under image" {
				path = "image/mkosi/rules.d/60-x.rules"
			}
			files[path] = files[path] + text
			if bins, err := set(t, files); err != nil || len(bins) != 1 || bins[0] != "./cmd/agentos-side" {
				t.Fatalf("got %q, %v, want [./cmd/agentos-side]", bins, err)
			}
			if problems := lintFiles(t, files, ""); len(problems) != 1 || !strings.Contains(problems[0], "broker/side/side.go") {
				t.Fatalf("the rule's binary's linked package: got %q, want its os.Remove refused", problems)
			}
		})
	}
	for name, c := range map[string]struct{ text, want string }{
		"a wrapper's word":            {"RUN+=\"/usr/lib/agentos/with-uids /usr/lib/agentos/agentos-side\"\n", `with-uids", which`},
		"a bare name udev resolves":   {"RUN+=\"agentos-side %k\"\n", `absolute program path`},
		"a name an ENV value holds":   {"ENV{P}=\"/usr/lib/agentos/agentos-side\"\nRUN+=\"$env{P}\"\n", `absolute program path`},
		"a $ substitution in an arg":  {"RUN+=\"/usr/lib/agentos/agentos-side $env{P}\"\n", `may not hold`},
		"a %c in the program":         {"RUN+=\"/usr/lib/agentos/%c\"\n", `absolute program path`},
		"a continued line":            {"ACTION==\"add\", \\\n  RUN+=\"/usr/lib/agentos/agentos-side\"\n", `a backslash`},
		"a comment ending in \\":      {"# old rule \\\nRUN+=\"/usr/lib/agentos/agentos-side\"\n", `a backslash`},
		"sh -c":                       {"RUN+=\"/bin/sh -c true;/usr/lib/agentos/agentos-side\"\n", `may not hold`},
		"sh -c with quotes":           {"RUN+=\"/bin/sh -c 'agentos-side'\"\n", `may not hold`},
		"a quoted arg":                {"RUN+=\"/usr/lib/agentos/agentos-side 'a b'\"\n", `may not hold`},
		"a shell backslash escape":    {"RUN+=\"/usr/lib/agentos/host-disk-unlink agentos\\-side\"\n", `a backslash`},
		"udev \\x escapes":            {"RUN+=e\"/usr/lib/agentos/agentos\\x2dside\"\n", `a backslash`},
		"udev octal escapes":          {"RUN+=e\"/usr/lib/agentos/\\141gentos-side\"\n", `a backslash`},
		"an e\"...\" value":           {"RUN+=e\"/usr/lib/agentos/agentos-side\"\n", `is not KEY`},
		"an escaped quote":            {"RUN+=\"/usr/lib/agentos/host-disk-unlink \\\"x\"\n", `a backslash`},
		"a single-quoted value":       {"RUN+='/usr/lib/agentos/agentos-side'\n", `is not KEY`},
		"an unlisted path":            {"RUN+=\"/usr/lib/agentos/agentos-other\"\n", `agentos-other", which`},
		"a key udev(7) lacks":         {"RUNX+=\"/usr/lib/agentos/agentos-side\"\n", `is not one of udev(7)'s`},
		"a lower-case key":            {"run+=\"/usr/lib/agentos/agentos-side\"\n", `is not KEY`},
		"RUN{other}":                  {"RUN{prog}+=\"/usr/lib/agentos/agentos-side\"\n", `want RUN, RUN{program}`},
		"IMPORT{other}":               {"IMPORT{programs}=\"/usr/lib/agentos/agentos-side\"\n", `want program, builtin`},
		"PROGRAM{x}":                  {"PROGRAM{x}==\"/usr/lib/agentos/agentos-side\"\n", `PROGRAM takes no attribute`},
		"text after a value":          {"RUN+=\"/usr/lib/agentos/agentos-side\" x\n", `is not KEY`},
		"an unclosed value":           {"RUN+=\"/usr/lib/agentos/agentos-side\n", `is not KEY`},
		"a CR that udev splits at":    {"# old\rRUN+=\"/usr/lib/agentos/agentos-side\"\n", `byte 0xd`},
		"a NUL that udev splits at":   {"# old\x00RUN+=\"/usr/lib/agentos/agentos-side\"\n", `byte 0x0`},
		"a byte past ASCII":           {"RUN+=\"/usr/lib/agentos/agentos\u2010side\"\n", `byte 0xe2`},
		"a rule under image, refused": {"RUN+=\"/bin/sh -c x\"\n", `/bin/sh", which`},
		"a core_pattern sysctl":       {"SYSCTL{kernel.core_pattern}=\"|/usr/lib/agentos/agentos-side %p\"\n", `is not one of udev(7)'s`},
		"a modprobe sysctl":           {"SYSCTL{kernel.modprobe}=\"/usr/lib/agentos/agentos-side\"\n", `is not one of udev(7)'s`},
		"an ATTR path":                {"ATTR{../../kernel/uevent_helper}=\"/usr/lib/agentos/agentos-side\"\n", `an attribute name`},
		"an ATTR [subsystem/device]":  {"ATTR{[module/x]parameters}=\"y\"\n", `an attribute name`},
		"an ATTRS path":               {"ATTRS{device/x}==\"y\"\n", `an attribute name`},
		// #4276: a property systemd reads to start a unit.
		"ENV{SYSTEMD_WANTS}=":              {"ENV{SYSTEMD_WANTS}=\"agentos-x@%k.service\", TAG+=\"systemd\"\n", `sets no SYSTEMD_ property`},
		"ENV{SYSTEMD_USER_WANTS}+=":        {"ENV{SYSTEMD_USER_WANTS}+=\"x.service\"\n", `sets no SYSTEMD_ property`},
		"ENV{SYSTEMD_ALIAS}:=":             {"ENV{SYSTEMD_ALIAS}:=\"/dev/x\"\n", `sets no SYSTEMD_ property`},
		"IMPORT{file}":                     {"IMPORT{file}=\"/etc/agentos/x\"\n", `properties go unread`},
		"IMPORT{parent} of a glob":         {"IMPORT{parent}=\"SYSTEMD_*\"\n", `one plain property name`},
		"IMPORT{parent} of all":            {"IMPORT{parent}=\"*\"\n", `one plain property name`},
		"IMPORT{db} of SYSTEMD_WANTS":      {"IMPORT{db}=\"SYSTEMD_WANTS\"\n", `one plain property name`},
		"IMPORT{cmdline} of SYSTEMD_WANTS": {"IMPORT{cmdline}=\"SYSTEMD_WANTS\"\n", `one plain property name`},
	} {
		t.Run("refuses "+name, func(t *testing.T) {
			files := clone(files)
			path := rule
			if name == "a rule under image, refused" {
				path = "image/mkosi/rules.d/60-x.rules"
			}
			files[path] = files[path] + "RUN+=\"/usr/lib/agentos/agentos-side\"\n" + c.text
			// Each refusal's own text: a case another check catches first
			// does not reach the check it names (#4280 2).
			if bins, err := set(t, files); err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("got %q, %v, want the rule refused with %q", bins, err, c.want)
			}
		})
	}
	for name, list := range map[string]string{
		"a listed program no rule runs": files[programsFile] + "/usr/lib/agentos/agentos-gone gone\n",
		"a line with no reason":         files[programsFile] + "/usr/lib/agentos/agentos-x\n",
		"a relative path":               files[programsFile] + "agentos-x reason\n",
		"a doubled line":                files[programsFile] + "/usr/lib/agentos/agentos-side again\n",
	} {
		t.Run("refuses the list with "+name, func(t *testing.T) {
			files := clone(files)
			files[rule] += "RUN+=\"/usr/lib/agentos/agentos-side\"\n"
			files[programsFile] = list
			if bins, err := set(t, files); err == nil {
				t.Fatalf("got %q and no error, want the list refused", bins)
			}
		})
	}
	t.Run("the shipped rules", func(t *testing.T) {
		bins, err := rootBinaries(repoRoot(t))
		if err != nil {
			t.Fatal(err)
		}
		found := false
		for _, b := range bins {
			found = found || b == "./cmd/agentos-hostdisk"
		}
		if !found {
			t.Fatalf("root side %q lacks ./cmd/agentos-hostdisk, which 59-agentos-host-disks.rules runs", bins)
		}
	})
}

// A modprobe.d install or remove command and a sysctl.d usermode helper are
// run by root too, so they are read like a udev rule's programs (#4279); a
// file in a directory root runs whole, or a hwdb file that can set a unit's
// SYSTEMD_WANTS (#4276), is refused, being read by no reader.
func TestRootSideSetCountsModprobeAndSysctlPrograms(t *testing.T) {
	const (
		modprobe = "image/mkosi/mkosi.extra/usr/lib/modprobe.d/agentos-x.conf"
		sysctl   = "image/mkosi/mkosi.extra/usr/lib/sysctl.d/99-agentos-x.conf"
		tmpfiles = "image/mkosi/mkosi.extra/usr/lib/tmpfiles.d/agentos-x.conf"
		extra    = "image/mkosi/mkosi.extra/"
	)
	files := map[string]string{
		"broker/side/side.go":                     "package side\n\nimport \"os\"\n\nfunc Drop(p string) error { return os.Remove(p) }\n",
		"broker/cmd/agentos-side/main.go":         "package main\n\nimport \"example.test/broker/side\"\n\nfunc main() { side.Drop(\"\") }\n",
		"image/mkosi/agentos-side.service":        "[Service]\nUser=agentos-side\nExecStart=/usr/lib/agentos/agentos-side\n",
		modprobe:                                  "# agentos-side\nblacklist btusb\n\talias usb:v1 btusb\noptions btusb x=1\nsoftdep btusb pre: btmtk\nweakdep btusb btmtk\ninstall btusb /bin/false\n",
		sysctl:                                    "; agentos-side\n# kernel.modprobe=/usr/lib/agentos/agentos-side\nkernel.core_pattern = core.%p\nfs.suid_dumpable=0\n-kernel.hotplug\n-net.ipv4.ip_forward = 0\n",
		extra + "usr/lib/modprobe.d/README":       "install btusb /usr/lib/agentos/agentos-side\n",
		"image/mkosi/agentos-x.conf":              "install btusb /usr/lib/agentos/agentos-side\nkernel.modprobe=/usr/lib/agentos/agentos-side\n",
		extra + "usr/lib/udev/rules.d/60-x.rules": "KERNEL==\"x\", MODE=\"0600\"\n",
		tmpfiles:                            "# w /proc/sys/kernel/modprobe - - - - /usr/lib/agentos/agentos-side\nd /var/lib/agentos-x 0700 root root -\nz /sys/class/leds/x/brightness 0660 root root -\nw /proc/sys/kernel/core_pattern - - - - core.%p\nw- /proc/sys/vm/swappiness - - - - 10\nw /sys/class/leds/x/trigger - - - - none\nR /var/tmp/agentos-x\nd /var/tmp/agentos-y 1777 root root -\nd /run/agentos-y :0750 root root -\nz /run/agentos-y ~0755\n",
		extra + "usr/lib/tmpfiles.d/README": "w /proc/sys/kernel/modprobe - - - - /usr/lib/agentos/agentos-side\n",
		programsFile:                        "/bin/false exits 1\n/usr/lib/agentos/agentos-side the binary under test\n",
	}
	set := func(t *testing.T, files map[string]string) ([]string, error) {
		t.Helper()
		return rootBinaries(fakeRepo(t, files))
	}
	base := clone(files)
	base[programsFile] = "/bin/false exits 1\n"
	if bins, err := set(t, base); err != nil || len(bins) != 0 {
		t.Fatalf("files that run only /bin/false, name the binary in a comment, a non-helper key or a pipe-less core_pattern, write no helper, or sit outside a modprobe.d, sysctl.d or tmpfiles.d directory: got %q, %v, want none", bins, err)
	}
	for name, c := range map[string]struct{ path, text string }{
		"an install command":             {modprobe, "install btusb /usr/lib/agentos/agentos-side --quiet\n"},
		"a remove command":               {modprobe, "remove btusb /usr/lib/agentos/agentos-side\n"},
		"an indented install":            {modprobe, "  install\tbtusb /usr/lib/agentos/agentos-side\n"},
		"a modprobe.d under broker":      {"broker/side/modprobe.d/x.conf", "install btusb /usr/lib/agentos/agentos-side\n"},
		"a core_pattern pipe":            {sysctl, "kernel.core_pattern = |/usr/lib/agentos/agentos-side %p\n"},
		"a core_pattern pipe, no blanks": {sysctl, "kernel.core_pattern=| /usr/lib/agentos/agentos-side\n"},
		"kernel.modprobe":                {sysctl, "kernel.modprobe=/usr/lib/agentos/agentos-side\n"},
		"kernel.hotplug":                 {sysctl, "kernel.hotplug = /usr/lib/agentos/agentos-side\n"},
		"kernel.poweroff_cmd":            {sysctl, "kernel.poweroff_cmd=/usr/lib/agentos/agentos-side\n"},
		"a - prefixed helper":            {sysctl, "-kernel.modprobe=/usr/lib/agentos/agentos-side\n"},
		// #4320: systemd-tmpfiles writes a w line as root at boot.
		"a tmpfiles core_pattern pipe":  {tmpfiles, "w /proc/sys/kernel/core_pattern - - - - |/usr/lib/agentos/agentos-side %p\n"},
		"a tmpfiles w+ kernel.modprobe": {tmpfiles, "w+ /proc/sys/kernel/modprobe - - - - /usr/lib/agentos/agentos-side\n"},
		"a tmpfiles kernel.hotplug":     {tmpfiles, "w-! /proc/sys/kernel/hotplug - - - - /usr/lib/agentos/agentos-side\n"},
		"a tmpfiles uevent_helper":      {tmpfiles, "w /sys/kernel/uevent_helper - - - - /usr/lib/agentos/agentos-side\n"},
		"a tmpfiles poweroff_cmd":       {tmpfiles, "\tw /proc/sys/kernel/poweroff_cmd\t-\t-\t-\t-\t/usr/lib/agentos/agentos-side --now\n"},
		"a tmpfiles.d under broker":     {"broker/side/tmpfiles.d/x.conf", "w /proc/sys/kernel/modprobe - - - - /usr/lib/agentos/agentos-side\n"},
	} {
		t.Run(name, func(t *testing.T) {
			files := clone(files)
			files[c.path] += c.text
			if bins, err := set(t, files); err != nil || len(bins) != 1 || bins[0] != "./cmd/agentos-side" {
				t.Fatalf("got %q, %v, want [./cmd/agentos-side]", bins, err)
			}
			if problems := lintFiles(t, files, ""); len(problems) != 1 || !strings.Contains(problems[0], "broker/side/side.go") {
				t.Fatalf("the program's linked package: got %q, want its os.Remove refused", problems)
			}
		})
	}
	for name, c := range map[string]struct{ path, text, want string }{
		"a command modprobe.d(5) lacks": {modprobe, "include /etc/agentos\n", `not a modprobe.d(5) command`},
		"an install with no command":    {modprobe, "install btusb\n", `takes a module and a command`},
		"a second shell command":        {modprobe, "install btusb /bin/false; /usr/lib/agentos/agentos-side\n", `may not hold`},
		"$CMDLINE_OPTS":                 {modprobe, "install btusb /usr/lib/agentos/agentos-side $CMDLINE_OPTS\n", `may not hold`},
		"a quoted word":                 {modprobe, "remove btusb /bin/false 'x'\n", `may not hold`},
		"a bare name":                   {modprobe, "install btusb agentos-side\n", `absolute program path`},
		"a continued line":              {modprobe, "install btusb \\\n/usr/lib/agentos/agentos-side\n", `a backslash`},
		"a CR":                          {modprobe, "# x\rinstall btusb /usr/lib/agentos/agentos-side\n", `byte 0xd`},
		"an unlisted install":           {modprobe, "install btusb /usr/lib/agentos/agentos-other\n", `agentos-other", which`},
		"a glob key":                    {sysctl, "kernel.core_*=|/usr/lib/agentos/agentos-side\n", `plain dotted key`},
		"a slash key":                   {sysctl, "kernel/modprobe=/usr/lib/agentos/agentos-side\n", `plain dotted key`},
		"an empty component":            {sysctl, "kernel..modprobe=/usr/lib/agentos/agentos-side\n", `plain dotted key`},
		"a leading dot":                 {sysctl, ".kernel.modprobe=/usr/lib/agentos/agentos-side\n", `plain dotted key`},
		"a key with no value":           {sysctl, "kernel.modprobe\n", `plain dotted key`},
		"a binfmt_misc register":        {sysctl, "fs.binfmt_misc.register=:x:E::bin::/usr/lib/agentos/agentos-side:\n", `registers an interpreter`},
		"a helper with a $":             {sysctl, "kernel.modprobe=$X\n", `absolute program path`},
		"an unlisted core_pattern pipe": {sysctl, "kernel.core_pattern=|/usr/lib/agentos/agentos-other\n", `agentos-other", which`},
		"a generator":                   {extra + "usr/lib/systemd/system-generators/agentos-gen", "#!/bin/sh\n", `reads no such file`},
		"an environment generator":      {extra + "usr/lib/systemd/system-environment-generators/x", "", `reads no such file`},
		"a sleep hook":                  {extra + "usr/lib/systemd/system-sleep/x", "", `reads no such file`},
		"a shutdown hook":               {extra + "usr/lib/systemd/system-shutdown/x", "", `reads no such file`},
		"a binfmt.d file":               {extra + "usr/lib/binfmt.d/x.conf", "", `reads no such file`},
		"a program udev finds by name":  {extra + "usr/lib/udev/agentos-side", "", `reads no such file`},
		"a hwdb file":                   {extra + "etc/udev/hwdb.d/60-x.hwdb", "", `reads no such file`},
		"an init.d script":              {extra + "etc/init.d/agentos-x", "", `reads no such file`},
		"an rc.local":                   {extra + "etc/rc.local", "", `reads no such file`},
		"a build into a generator dir":  {"image/build.sh", "go build -o \"$STAGE/usr/lib/systemd/system-generators/agentos-gen\" ./cmd/agentos-side\n", `a directory root runs whole`},
		// #4320: request-key's programs run as root.
		"a request-key.conf":   {extra + "etc/request-key.conf", "create user * * /usr/lib/agentos/agentos-side %k\n", `reads no such file`},
		"a request-key.d file": {extra + "etc/request-key.d/x.conf", "", `reads no such file`},
		// #4342: a compiled hwdb sets properties as its sources do.
		"an /etc/udev hwdb.bin":           {extra + "etc/udev/hwdb.bin", "", `reads no such file`},
		"an /etc/systemd/hwdb hwdb.bin":   {extra + "etc/systemd/hwdb/hwdb.bin", "", `reads no such file`},
		"a /usr/lib/systemd hwdb.bin":     {extra + "usr/lib/systemd/hwdb/hwdb.bin", "", `reads no such file`},
		"a /usr/lib/udev hwdb.bin":        {extra + "usr/lib/udev/hwdb.bin", "", `reads no such file`},
		"a tmpfiles binfmt_misc register": {tmpfiles, "w /proc/sys/fs/binfmt_misc/register - - - - :x:E::bin::/usr/lib/agentos/agentos-side:\n", `registers an interpreter`},
		"a tmpfiles binfmt_misc mode":     {tmpfiles, "z /proc/sys/fs/binfmt_misc/status 0666\n", `registers an interpreter`},
		"a tmpfiles unlisted helper":      {tmpfiles, "w /proc/sys/kernel/modprobe - - - - /usr/lib/agentos/agentos-other\n", `agentos-other", which`},
		"a tmpfiles specifier program":    {tmpfiles, "w /proc/sys/kernel/modprobe - - - - %S/agentos-side\n", `absolute program path`},
		"a tmpfiles shell word":           {tmpfiles, "w /proc/sys/kernel/core_pattern - - - - |/bin/false;/usr/lib/agentos/agentos-side\n", `may not hold`},
		"a tmpfiles glob path":            {tmpfiles, "w /proc/sys/kernel/modprob? - - - - /usr/lib/agentos/agentos-side\n", `plain absolute path`},
		"a tmpfiles specifier path":       {tmpfiles, "w /proc/sys/kernel/%a - - - - /usr/lib/agentos/agentos-side\n", `plain absolute path`},
		"a tmpfiles unclean path":         {tmpfiles, "w /proc/sys/kernel/../kernel/modprobe - - - - /usr/lib/agentos/agentos-side\n", `plain absolute path`},
		"a tmpfiles type it lacks":        {tmpfiles, "ww /proc/sys/kernel/modprobe - - - - /usr/lib/agentos/agentos-side\n", `plain absolute path`},
		"a tmpfiles base64 argument":      {tmpfiles, "w~ /proc/sys/kernel/core_pattern - - - - fC91c3IvbGliL2FnZW50b3MvYWdlbnRvcy1zaWRlICVw\n", `no ~ or ^ modifier`},
		"a tmpfiles credential argument":  {tmpfiles, "w^ /proc/sys/kernel/modprobe - - - - agentos.helper\n", `no ~ or ^ modifier`},
		"a tmpfiles setuid mode":          {tmpfiles, "z /usr/lib/agentos/agentos-side 4755 root root -\n", `no setuid or setgid`},
		"a tmpfiles setgid mode":          {tmpfiles, "Z /usr/lib/agentos 2755 root root -\n", `no setuid or setgid`},
		"a tmpfiles masked setuid mode":   {tmpfiles, "d /var/lib/agentos-x ~6755 root root -\n", `no setuid or setgid`},
		"a tmpfiles magic link":           {tmpfiles, "w /proc/1/root/proc/sys/kernel/modprobe - - - - /usr/lib/agentos/agentos-side\n", `in /proc but not /proc/sys`},
		"a tmpfiles mode on a helper":     {tmpfiles, "z /proc/sys/kernel/core_pattern 0666\n", `a helper is only written`},
		"a tmpfiles w to a file":          {tmpfiles, "w /etc/modprobe.d/x.conf - - - - install btusb /usr/lib/agentos/agentos-side\n", `writes only under /proc/sys or /sys`},
		"a tmpfiles f":                    {tmpfiles, "f /etc/rc.local 0755 - - - /usr/lib/agentos/agentos-side\n", `type f writes`},
		"a tmpfiles L":                    {tmpfiles, "L+ /etc/systemd/system-generators/x - - - - /usr/lib/agentos/agentos-side\n", `type L+ writes`},
		"a tmpfiles C":                    {tmpfiles, "C /etc/udev/rules.d - - - - /usr/share/agentos/rules.d\n", `type C writes`},
		"a tmpfiles xattr":                {tmpfiles, "t /usr/lib/agentos/agentos-side - - - - security.capability=0sAQAAAg\n", `type t writes`},
	} {
		t.Run("refuses "+name, func(t *testing.T) {
			files := clone(files)
			files[c.path] += c.text
			if bins, err := set(t, files); err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("got %q, %v, want a refusal with %q", bins, err, c.want)
			}
		})
	}
	t.Run("the shipped files", func(t *testing.T) {
		// root_programs.txt lists /bin/false and /usr/bin/false only for
		// agentos-no-bluetooth.conf and 99-agentos-nodump.conf: were either
		// file unread, its line would be stale and this would fail.
		if _, err := rootBinaries(repoRoot(t)); err != nil {
			t.Fatal(err)
		}
	})
}

func TestStaleAllowEntryFails(t *testing.T) {
	files := map[string]string{"broker/side/side.go": "package side\n\nimport \"os\"\n\nfunc Drop(p string) error { return os.Remove(p) }\n"}
	for name, line := range map[string]string{
		"another function":     "allow broker/side/side.go Keep os.Remove reason\n",
		"another call":         "allow broker/side/side.go Drop os.Rename reason\n",
		"a missing file":       "allow broker/side/gone.go Drop os.Remove reason\n",
		"a non-root file":      "allow broker/elsewhere/x.go Drop os.Remove reason\n",
		"a doubled line":       "allow broker/side/side.go Drop os.Remove reason\nallow broker/side/side.go Drop os.Remove again\n",
		"a pending package":    "pending broker/elsewhere #1 reason\n",
		"a malformed line":     "allow broker/side/side.go Drop\n",
		"a call ioutil lacks":  "allow broker/side/side.go Drop ioutil.Remove reason\n",
		"a package not listed": "allow broker/side/side.go Drop syscall.Unlink reason\n",
	} {
		t.Run(name, func(t *testing.T) {
			if problems := lintFiles(t, files, "allow broker/side/side.go Drop os.Remove reason\n"+line); len(problems) == 0 {
				t.Fatalf("%q was accepted", line)
			}
		})
	}
	t.Run("the shipped file has none", func(t *testing.T) {
		// The main subtest of TestRootSidePathOpsGoThroughPrivfile reads
		// it; this names the rule that stale lines fail in its own test.
		allow, err := os.ReadFile(allowFile)
		if err != nil {
			t.Fatal(err)
		}
		for _, p := range lintRepo(t, repoRoot(t), string(allow)) {
			if strings.Contains(p, "stale") {
				t.Error(p)
			}
		}
	})
}

// lintFiles lints a fake repository holding files and, unless files names
// one, a unit that starts ./cmd/agentos-side as root and a main that links
// broker/side.
func lintFiles(t *testing.T, files map[string]string, allow string) []string {
	t.Helper()
	files = clone(files)
	if _, ok := files["broker/cmd/agentos-side/main.go"]; !ok {
		files["broker/cmd/agentos-side/main.go"] = "package main\n\nimport _ \"example.test/broker/side\"\n\nfunc main() {}\n"
	}
	if _, ok := files["image/mkosi/agentos-side.service"]; !ok {
		files["image/mkosi/agentos-side.service"] = "[Service]\nExecStart=/usr/lib/agentos/agentos-side\n"
	}
	return lintRepo(t, fakeRepo(t, files), allow)
}

func fakeRepo(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	files = clone(files)
	files["broker/go.mod"] = "module example.test/broker\n\ngo 1.22\n"
	for name, body := range files {
		p := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func clone(m map[string]string) map[string]string {
	c := make(map[string]string, len(m))
	for k, v := range m {
		c[k] = v
	}
	return c
}

func repoRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs("../../..")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, "image")); err != nil {
		t.Fatalf("repository root: %v", err)
	}
	return root
}

// lintRepo returns one line per problem: a root-side use with no allow or
// pending line, or an allow or pending line that matches nothing.
func lintRepo(t *testing.T, root, allowText string) []string {
	t.Helper()
	bins, err := rootBinaries(root)
	if err != nil {
		t.Fatal(err)
	}
	var problems []string
	allows, pending, bad := parseAllow(allowText)
	problems = append(problems, bad...)
	uses, err := rootSideUses(root, bins)
	if err != nil {
		t.Fatal(err)
	}
	usedAllow, usedPending := map[string]bool{}, map[string]bool{}
	for _, u := range uses {
		key := u.file + " " + u.fn + " " + u.op
		if _, ok := allows[key]; ok {
			usedAllow[key] = true
			continue
		}
		if _, ok := pending[filepath.ToSlash(filepath.Dir(u.file))]; ok {
			usedPending[filepath.ToSlash(filepath.Dir(u.file))] = true
			continue
		}
		problems = append(problems, fmt.Sprintf("%s:%d: %s calls %s by path; use privfile, os.OpenFile with O_NOFOLLOW, or add \"allow %s <reason>\"", u.file, u.line, u.fn, u.op, key))
	}
	for key := range allows {
		if !usedAllow[key] {
			problems = append(problems, fmt.Sprintf("stale allow line %q: no root-side use matches it", key))
		}
	}
	for dir := range pending {
		if !usedPending[dir] {
			problems = append(problems, fmt.Sprintf("stale pending line for %s: not root-side, or every use there is clean or allowed", dir))
		}
	}
	sort.Strings(problems)
	return problems
}

func parseAllow(text string) (allows, pending map[string]string, bad []string) {
	allows, pending = map[string]string{}, map[string]string{}
	for i, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		f := strings.Fields(line)
		switch {
		case f[0] == "allow" && len(f) >= 5 && isPathOpName(f[3]):
			key := strings.Join(f[1:4], " ")
			if _, dup := allows[key]; dup {
				bad = append(bad, fmt.Sprintf("%s line %d: a second allow line for %q", allowFile, i+1, key))
			}
			allows[key] = strings.Join(f[4:], " ")
		case f[0] == "pending" && len(f) >= 4 && strings.HasPrefix(f[2], "#"):
			if _, dup := pending[f[1]]; dup {
				bad = append(bad, fmt.Sprintf("%s line %d: a second pending line for %s", allowFile, i+1, f[1]))
			}
			pending[f[1]] = strings.Join(f[2:], " ")
		default:
			bad = append(bad, fmt.Sprintf("%s line %d: want \"allow <file> <func> <pkg>.<Call> <reason>\" or \"pending <dir> #<issue> <reason>\", got %q", allowFile, i+1, line))
		}
	}
	return allows, pending, bad
}

// execUnits are the unit types whose Exec lines a process manager runs:
// a .service's, and a .socket's ExecStartPre, ExecStartPost, ExecStopPre and
// ExecStopPost, under the same User= and DynamicUser= (#4330). The other
// types have no Exec line.
var execUnits = map[string]bool{".service": true, ".socket": true}

// isDropinDir reports whether dir names a drop-in directory of an
// execUnits type: a unit's or prefix's (x.service.d, agentos-.socket.d) or
// the type's own (service.d).
func isDropinDir(dir string) bool {
	t, ok := strings.CutSuffix(dir, ".d")
	return ok && (execUnits[path.Ext(t)] || execUnits["."+t])
}

// rootBinaries returns the broker packages (as ./path, relative to broker/)
// of the binaries a unit under image/ starts as root or a runKinds file
// names.
func rootBinaries(root string) ([]string, error) {
	units := map[string]string{}     // unit file path -> name
	dropins := map[string][]string{} // drop-in directory name -> its .conf paths
	err := filepath.WalkDir(filepath.Join(root, "image"), func(p string, d os.DirEntry, err error) error {
		dir := filepath.Base(filepath.Dir(p))
		switch {
		case err != nil:
			return err
		case d.IsDir():
			return nil
		case execUnits[filepath.Ext(p)]:
			units[p] = d.Name()
		case strings.HasSuffix(p, ".conf") && isDropinDir(dir):
			dropins[dir] = append(dropins[dir], p)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	pkgs, err := binaryPackages(root)
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	for p, name := range units {
		paths := []string{p}
		for _, dir := range dropinDirs(name) {
			paths = append(paths, dropins[dir]...)
		}
		// A later User= or DynamicUser= replaces an earlier one, and drop-ins
		// sort across directories, so any assignment that runs as root (an
		// empty, root or 0 User=, a false DynamicUser=) counts as root
		// wherever it sits: an over-approximation that never drops a root
		// binary (#3951 L3 3).
		asUser, asRoot := false, false
		var lines []string
		for _, f := range paths {
			b, err := os.ReadFile(f)
			if err != nil {
				return nil, err
			}
			for _, line := range strings.Split(string(b), "\n") {
				line = strings.TrimSpace(line)
				k, v, ok := strings.Cut(line, "=")
				if !ok || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
					continue
				}
				k, v = strings.TrimSpace(k), strings.TrimSpace(v)
				switch {
				case k == "User" && (v == "" || v == "root" || v == "0"):
					asRoot = true
				case k == "User":
					asUser = true
				case k == "DynamicUser" && (v == "yes" || v == "true" || v == "1" || v == "on"):
					asUser = true
				case k == "DynamicUser":
					asRoot = true
				case strings.HasPrefix(k, "Exec"):
					lines = append(lines, v)
				}
			}
		}
		for _, v := range lines {
			prefix := v[:len(v)-len(strings.TrimLeft(v, "@-:+!|"))]
			if asUser && !asRoot && !strings.ContainsAny(prefix, "+!") {
				continue
			}
			for _, word := range strings.Fields(v[len(prefix):]) {
				if pkg, ok := pkgs[filepath.Base(word)]; ok && strings.HasPrefix(word, "/") {
					seen[pkg] = true
				}
			}
		}
	}
	if err := runBinaries(root, pkgs, seen); err != nil {
		return nil, err
	}
	var out []string
	for pkg := range seen {
		out = append(out, pkg)
	}
	sort.Strings(out)
	return out, nil
}

// programsFile lists, relative to the repository root, the only programs a
// runKinds file may make root run (#4257, #4276, #4279).
const programsFile = "broker/kernel/privfile/root_programs.txt"

// ruleKeys are the keys udev(7) defines, less SYSCTL: a sysctl write such as
// kernel.core_pattern="|/path" or kernel.modprobe makes the kernel run a
// program as root, so it is refused rather than read. A rule using any other
// key fails.
var ruleKeys = map[string]bool{
	"ACTION": true, "DEVPATH": true, "KERNEL": true, "KERNELS": true, "NAME": true, "SYMLINK": true,
	"SUBSYSTEM": true, "SUBSYSTEMS": true, "DRIVER": true, "DRIVERS": true, "ATTR": true, "ATTRS": true,
	"ENV": true, "CONST": true, "TAG": true, "TAGS": true, "TEST": true, "PROGRAM": true,
	"RESULT": true, "IMPORT": true, "OPTIONS": true, "OWNER": true, "GROUP": true, "MODE": true,
	"SECLABEL": true, "RUN": true, "LABEL": true, "GOTO": true,
}

// ruleToken is one KEY[{attr}] OP "value" of a rule line, with what follows
// it: blanks and at most one comma.
var ruleToken = regexp.MustCompile(`^([A-Z]+)(\{([^{}"\\ \t]*)\})?[ \t]*(==|!=|\+=|-=|:=|=)[ \t]*"([^"\\]*)"[ \t]*(?:,[ \t]*)?`)

// ruleAttr is a plain name: an ATTR or ATTRS name, or a property an IMPORT
// copies in.
var ruleAttr = regexp.MustCompile(`^[A-Za-z0-9_]+$`)

// ruleArg is a word a listed program may take after its path: no shell or
// udev quoting, escape or $ substitution.
var ruleArg = regexp.MustCompile(`^[A-Za-z0-9_./:=%+@,-]+$`)

// runKind is a kind of file under image/ or broker/ that makes root run a
// program: which paths are of it, and the reader that returns each program
// one names. A kind with no reader is refused outright.
type runKind struct {
	what  string
	match func(rel string) bool
	read  func(text string) ([]ruleProgram, error)
}

// runKinds are the files that make root run a program, the channels
// image/mkosi/mkosi.finalize's exec.allow holds: a udev rules file (#3950);
// a modprobe.d file, whose install and remove commands root's /bin/sh runs
// when a module loads or unloads, through udev's kmod builtin, modprobe or
// the kernel's request_module (#4279); a sysctl.d file, whose usermode
// helper keys name a program the kernel runs as root; a tmpfiles.d file,
// whose w lines systemd-tmpfiles writes as root, to those helpers among
// other paths (#4320); and any file in a directory whose every file root
// runs (system and environment generators, system-sleep and system-shutdown
// hooks, udev's own directory, where a rule finds a bare name, init.d and
// rc.local, which systemd's sysv and rc-local generators make root units
// of, should either come back, and request-key.d and request-key.conf, whose
// programs /sbin/request-key runs as root, #4320), registers as an
// interpreter (binfmt.d) or reads for device properties (udev's hwdb.d, and
// a prebuilt hwdb.bin wherever the hwdb loader might read one, either of
// which can set SYSTEMD_WANTS, #4276, #4342).
// The lint reads none of the last, so none may ship.
var runKinds = []runKind{
	{"udev rules file", func(rel string) bool { return strings.HasSuffix(rel, ".rules") }, rulePrograms},
	{"modprobe.d file", confIn("modprobe.d"), modprobePrograms},
	{"sysctl.d file", confIn("sysctl.d"), sysctlPrograms},
	{"tmpfiles.d file", confIn("tmpfiles.d"), tmpfilesPrograms},
	{"file in a directory root runs whole or reads for properties", inRunDir, nil},
}

// runDirs are the directories, as path suffixes, of runKinds' last kind.
var runDirs = []string{
	"systemd/system-generators", "systemd/system-environment-generators", "systemd/system-sleep",
	"systemd/system-shutdown", "binfmt.d", "lib/udev", "udev/hwdb.d", "init.d", "request-key.d",
}

// runNames are the file names of runKinds' last kind wherever they sit:
// rc.local, request-key.conf and udev's compiled hwdb.bin, which systemd
// and udev look for in several directories (/etc/udev, /etc/systemd/hwdb,
// /usr/lib/systemd/hwdb, /usr/lib/udev).
var runNames = map[string]bool{"rc.local": true, "request-key.conf": true, "hwdb.bin": true}

// confIn matches a .conf file directly in a directory named dir, the only
// files kmod and systemd-sysctl read there.
func confIn(dir string) func(string) bool {
	return func(rel string) bool { return strings.HasSuffix(rel, ".conf") && path.Base(path.Dir(rel)) == dir }
}

// inRunDir matches a file directly in one of runDirs, or one of runNames;
// rel is slash-separated.
func inRunDir(rel string) bool {
	if runNames[path.Base(rel)] {
		return true
	}
	dir := "/" + path.Dir(rel)
	for _, d := range runDirs {
		if strings.HasSuffix(dir, "/"+d) {
			return true
		}
	}
	return false
}

// runBinaries reads every runKinds file under image/ and broker/ as its
// consumer does and adds the package of each broker binary one runs. A
// program's name could hide behind a shell (sh -c 'a;agentos-x'), a bare
// name udev resolves in /usr/lib/udev, an $env{X} substitution, or a udev
// or shell escape (agentos\x2dx, agentos\-x). Rather than decode each form,
// the readers refuse them (#4257): a file may hold only printable ASCII, no
// backslash anywhere (so no escape and no continuation), only its format's
// keys or commands, and each program must be an absolute path programsFile
// lists, then words of ruleArg. A listed path that no file runs fails too,
// so the list only holds what ships. Bound: what a listed program itself
// starts (host-disk-unlink is a script) is held by review of the list's
// reason.
func runBinaries(root string, pkgs map[string]string, seen map[string]bool) error {
	// A repository with no list lets a file run nothing.
	b, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(programsFile)))
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	listed := map[string]bool{} // listed path -> a file runs it
	for i, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		f := strings.Fields(line)
		if _, dup := listed[f[0]]; len(f) < 2 || !strings.HasPrefix(f[0], "/") || dup {
			return fmt.Errorf("%s line %d: want one \"<absolute path> <reason>\" line per program, got %q", programsFile, i+1, line)
		}
		listed[f[0]] = false
	}
	for _, dir := range []string{"image", "broker"} {
		err := filepath.WalkDir(filepath.Join(root, dir), func(p string, d os.DirEntry, err error) error {
			switch {
			case err != nil && os.IsNotExist(err):
				return filepath.SkipDir
			case err != nil:
				return err
			case d.IsDir():
				return nil
			}
			rel, _ := filepath.Rel(root, p)
			rel = filepath.ToSlash(rel)
			var kind *runKind
			for i := range runKinds {
				if runKinds[i].match(rel) {
					kind = &runKinds[i]
					break
				}
			}
			switch {
			case kind == nil:
				return nil
			case kind.read == nil:
				return fmt.Errorf("%s: a %s; the lint reads no such file, so none may ship", rel, kind.what)
			}
			b, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			progs, err := kind.read(string(b))
			if err != nil {
				return fmt.Errorf("%s:%v", rel, err)
			}
			for _, prog := range progs {
				if _, ok := listed[prog.path]; !ok {
					return fmt.Errorf("%s:%d: runs %q, which %s does not list; a %s may run only a listed absolute path", rel, prog.line, prog.path, programsFile, kind.what)
				}
				listed[prog.path] = true
				if pkg, ok := pkgs[filepath.Base(prog.path)]; ok {
					seen[pkg] = true
				}
			}
			return nil
		})
		if err != nil {
			return err
		}
	}
	for path, used := range listed {
		if !used {
			return fmt.Errorf("%s lists %s, which no file runs", programsFile, path)
		}
	}
	return nil
}

type ruleProgram struct {
	path string
	line int
}

// eachLine calls fn with each line of text that is neither blank nor, after
// leading blanks, a comment (a line starting with a byte of comments). Every
// consumer here ends a line at \n (udev and systemd-sysctl also at \r and
// NUL) and kmod joins a line ending in a backslash; refusing every byte but
// printable ASCII and tab, and any backslash, makes each split this one.
func eachLine(text, comments string, fn func(n int, line string) error) error {
	for i, line := range strings.Split(text, "\n") {
		n := i + 1
		for _, c := range []byte(line) {
			if c != '\t' && (c < 0x20 || c > 0x7e) {
				return fmt.Errorf("%d: byte %#x; the file holds only printable ASCII and tabs", n, c)
			}
		}
		if strings.Contains(line, "\\") {
			return fmt.Errorf("%d: a backslash; no escape or continuation is read, so none may be written", n)
		}
		rest := strings.TrimLeft(line, " \t")
		if rest == "" || strings.ContainsRune(comments, rune(rest[0])) {
			continue
		}
		if err := fn(n, rest); err != nil {
			return err
		}
	}
	return nil
}

// programOf is the program a command's words run: an absolute path with no
// % substitution, then words of ruleArg.
func programOf(n int, what string, words []string) (ruleProgram, error) {
	if len(words) == 0 || !strings.HasPrefix(words[0], "/") || strings.Contains(words[0], "%") {
		return ruleProgram{}, fmt.Errorf("%d: %s %q does not start with an absolute program path", n, what, strings.Join(words, " "))
	}
	for _, w := range words {
		if !ruleArg.MatchString(w) {
			return ruleProgram{}, fmt.Errorf("%d: %s %q: word %q has a character a program value may not hold", n, what, strings.Join(words, " "), w)
		}
	}
	return ruleProgram{path: words[0], line: n}, nil
}

// systemdProp reports whether a device property is one systemd reads to act
// on: SYSTEMD_WANTS and SYSTEMD_USER_WANTS start the units they name when a
// device tagged systemd appears, as root unless the unit says otherwise, and
// the unit may come from a package rather than image/ (#4276). Only
// SYSTEMD_READY, which only stops units, is not.
func systemdProp(name string) bool {
	return strings.HasPrefix(name, "SYSTEMD_") && name != "SYSTEMD_READY"
}

// rulePrograms parses one rules file and returns the program each RUN,
// RUN{program}, PROGRAM and IMPORT{program} value runs, or an error naming
// the first line it refuses.
func rulePrograms(text string) ([]ruleProgram, error) {
	var progs []ruleProgram
	err := eachLine(text, "#", func(n int, rest string) error {
		for rest != "" {
			m := ruleToken.FindStringSubmatch(rest)
			if m == nil {
				return fmt.Errorf("%d: %q is not KEY[{attr}]OP\"value\" with a plain value", n, rest)
			}
			rest = rest[len(m[0]):]
			key, hasAttr, attr, op, value := m[1], m[2] != "", m[3], m[4], m[5]
			if !ruleKeys[key] {
				return fmt.Errorf("%d: key %s is not one of udev(7)'s, or is SYSCTL", n, key)
			}
			// An ATTR name is a path under the device's sysfs directory, so
			// a / or [subsystem/device] form could reach another file (the
			// kernel's uevent_helper among them); only a plain name is read.
			if (key == "ATTR" || key == "ATTRS") && !ruleAttr.MatchString(attr) {
				return fmt.Errorf("%d: %s{%s}; an attribute name is letters, digits and _ only", n, key, attr)
			}
			if key == "ENV" && op != "==" && op != "!=" && systemdProp(attr) {
				return fmt.Errorf("%d: ENV{%s}%s; a rule sets no SYSTEMD_ property but SYSTEMD_READY", n, attr, op)
			}
			program := false
			switch key {
			case "RUN":
				switch {
				case !hasAttr || attr == "program":
					program = true
				case attr != "builtin":
					return fmt.Errorf("%d: RUN{%s}; want RUN, RUN{program} or RUN{builtin}", n, attr)
				}
			case "PROGRAM":
				if hasAttr {
					return fmt.Errorf("%d: PROGRAM takes no attribute", n)
				}
				program = true
			case "IMPORT":
				switch attr {
				case "program":
					program = true
				case "builtin":
				case "db", "cmdline", "parent":
					// These copy properties in by name or glob; a plain
					// name keeps a SYSTEMD_ property out.
					if !ruleAttr.MatchString(value) || systemdProp(value) {
						return fmt.Errorf("%d: IMPORT{%s}=%q; want one plain property name, not a glob or a SYSTEMD_ property but SYSTEMD_READY", n, attr, value)
					}
				case "file":
					return fmt.Errorf("%d: IMPORT{file}; the file's properties go unread, so it may set a SYSTEMD_ property", n)
				default:
					return fmt.Errorf("%d: IMPORT{%s}; want program, builtin, db, cmdline or parent", n, attr)
				}
			}
			if !program {
				continue
			}
			p, err := programOf(n, key+"=", strings.Fields(value))
			if err != nil {
				return err
			}
			progs = append(progs, p)
		}
		return nil
	})
	return progs, err
}

// modprobeCmds are the commands of modprobe.d(5), as kmod 34 reads them.
var modprobeCmds = map[string]bool{"alias": true, "blacklist": true, "install": true, "remove": true, "options": true, "softdep": true, "weakdep": true}

// modprobePrograms parses one modprobe.d file and returns the program each
// install and remove command runs (kmod hands the command to /bin/sh -c, so
// plain words keep a second command and $CMDLINE_OPTS out), or an error
// naming the first line it refuses.
func modprobePrograms(text string) ([]ruleProgram, error) {
	var progs []ruleProgram
	err := eachLine(text, "#", func(n int, line string) error {
		f := strings.Fields(line)
		switch {
		case !modprobeCmds[f[0]]:
			return fmt.Errorf("%d: %q is not a modprobe.d(5) command", n, f[0])
		case f[0] != "install" && f[0] != "remove":
			return nil
		case len(f) < 3:
			return fmt.Errorf("%d: %s takes a module and a command", n, f[0])
		}
		p, err := programOf(n, f[0]+" "+f[1], f[2:])
		if err != nil {
			return err
		}
		progs = append(progs, p)
		return nil
	})
	return progs, err
}

// sysctlKey is a dotted sysctl name: systemd-sysctl also takes / separators,
// empty components and globs, which the reader refuses rather than resolves.
var sysctlKey = regexp.MustCompile(`^-?[A-Za-z0-9_-]+(\.[A-Za-z0-9_-]+)*$`)

// sysctlHelpers are the sysctls that name a program the kernel runs as root:
// kernel.core_pattern when it starts with |, and the modprobe, uevent and
// poweroff usermode helpers.
var sysctlHelpers = map[string]bool{"kernel.core_pattern": true, "kernel.modprobe": true, "kernel.hotplug": true, "kernel.poweroff_cmd": true}

// sysctlPrograms parses one sysctl.d file as systemd-sysctl does and returns
// the program each helper sysctl names, or an error naming the first line it
// refuses: a key that is not plain dotted, or one under fs.binfmt_misc,
// whose register file adds an interpreter.
func sysctlPrograms(text string) ([]ruleProgram, error) {
	var progs []ruleProgram
	err := eachLine(text, "#;", func(n int, line string) error {
		k, v, ok := strings.Cut(line, "=")
		k, v = strings.TrimSpace(k), strings.TrimSpace(v)
		switch {
		case !sysctlKey.MatchString(k) || !ok && !strings.HasPrefix(k, "-"):
			return fmt.Errorf("%d: %q is not a plain dotted key = value", n, line)
		case strings.HasPrefix(strings.TrimPrefix(k, "-"), "fs.binfmt_misc."):
			return fmt.Errorf("%d: %s registers an interpreter", n, k)
		}
		if !ok {
			return nil
		}
		p, run, err := helperProgram(n, strings.TrimPrefix(k, "-"), v)
		if run {
			progs = append(progs, p)
		}
		return err
	})
	return progs, err
}

// helperProgram is the program a value v written to sysctl k makes the
// kernel run as root, if k is one of sysctlHelpers: core_pattern's only
// when v starts with |.
func helperProgram(n int, k, v string) (ruleProgram, bool, error) {
	if !sysctlHelpers[k] || k == "kernel.core_pattern" && !strings.HasPrefix(v, "|") {
		return ruleProgram{}, false, nil
	}
	p, err := programOf(n, k+"=", strings.Fields(strings.TrimPrefix(v, "|")))
	return p, err == nil, err
}

// tmpfilesType is a tmpfiles.d(5) type: a letter, an optional +, then
// modifiers. The ~ (base64) and ^ (credential) modifiers make the argument
// something other than the text the reader sees, so neither is taken.
var tmpfilesType = regexp.MustCompile(`^([A-Za-z])(\+?)([-!=$?]*)$`)

// tmpfilesMode is a tmpfiles.d(5) mode the reader takes: - or octal, with
// its optional ~ or : prefix, and no setuid or setgid bit, which would
// make a file run as its owner, root among them, for any user (#4381).
var tmpfilesMode = regexp.MustCompile(`^(-|[~:]?[0-7]{3}|[~:]?[0-1][0-7]{3})$`)

// tmpfilesPlain are the tmpfiles.d(5) types that only make a directory or
// subvolume, set a mode or owner, or ignore or remove what is at a path.
// The rest write content (f, w), copy (C), link (L), make a device node or
// fifo (c, b, p) or set an ACL, attribute or xattr (a, h, t, a file
// capability among them); only w is read, and only to /proc/sys or /sys.
var tmpfilesPlain = map[string]bool{"d": true, "D": true, "e": true, "v": true, "q": true, "Q": true, "z": true, "Z": true, "x": true, "X": true, "r": true, "R": true}

// tmpfilesPath is a path the reader resolves itself: absolute and clean,
// with no % specifier, glob or blank.
var tmpfilesPath = regexp.MustCompile(`^/[A-Za-z0-9_./@:+-]*$`)

// tmpfilesPrograms parses one tmpfiles.d file and returns the program each
// w line to a usermode helper writes (kernel.core_pattern's pipe,
// kernel.modprobe, kernel.hotplug or its sysfs name /sys/kernel/uevent_helper,
// kernel.poweroff_cmd), or an error naming the first line it refuses: a path
// that is not plain, a type that is not plain or w, a w outside /proc/sys
// and /sys, any line on a helper but such a w, and any line under
// /proc/sys/fs/binfmt_misc, whose register file adds an interpreter.
func tmpfilesPrograms(text string) ([]ruleProgram, error) {
	var progs []ruleProgram
	err := eachLine(text, "#", func(n int, line string) error {
		f := strings.Fields(line)
		if len(f) < 2 || !tmpfilesType.MatchString(f[0]) || !tmpfilesPath.MatchString(f[1]) || path.Clean(f[1]) != f[1] {
			return fmt.Errorf("%d: %q is not a tmpfiles.d type and a plain absolute path; no ~ or ^ modifier is read", n, line)
		}
		if len(f) > 2 && !tmpfilesMode.MatchString(f[2]) {
			return fmt.Errorf("%d: mode %q; want - or an octal mode with no setuid or setgid bit", n, f[2])
		}
		m := tmpfilesType.FindStringSubmatch(f[0])
		typ, p := m[1]+m[2], f[1]
		key := ""
		switch {
		case p == "/sys/kernel/uevent_helper":
			key = "kernel.hotplug"
		case strings.HasPrefix(p, "/proc/sys/"):
			key = strings.ReplaceAll(strings.TrimPrefix(p, "/proc/sys/"), "/", ".")
		}
		switch {
		case key == "fs.binfmt_misc" || strings.HasPrefix(key, "fs.binfmt_misc."):
			return fmt.Errorf("%d: %s is under /proc/sys/fs/binfmt_misc, which registers an interpreter", n, p)
		case strings.HasPrefix(p, "/proc/") && key == "":
			return fmt.Errorf("%d: %s is in /proc but not /proc/sys", n, p)
		case typ != "w" && typ != "w+" && sysctlHelpers[key]:
			return fmt.Errorf("%d: %s on %s; a helper is only written, with w", n, f[0], p)
		case typ == "w" || typ == "w+":
			if key == "" && !strings.HasPrefix(p, "/sys/") {
				return fmt.Errorf("%d: w to %s; a w line writes only under /proc/sys or /sys", n, p)
			}
		case !tmpfilesPlain[typ]:
			return fmt.Errorf("%d: type %s writes, copies, links, makes a node or labels a file, which the lint does not read", n, f[0])
		}
		if len(f) < 7 {
			return nil
		}
		prog, run, err := helperProgram(n, key, strings.Join(f[6:], " "))
		if run {
			progs = append(progs, prog)
		}
		return err
	})
	return progs, err
}

// dropinDirs are the drop-in directories systemd reads for a unit:
// name.d, its type's (service.d, socket.d), each dash-truncated prefix
// ("agentos-x-y.service" reads "agentos-x-.service.d" and
// "agentos-.service.d") and, for an instance, its template's.
func dropinDirs(name string) []string {
	ext := path.Ext(name)
	base := strings.TrimSuffix(name, ext)
	dirs := []string{name + ".d", ext[1:] + ".d"}
	if at := strings.Index(base, "@"); at >= 0 && at < len(base)-1 {
		dirs = append(dirs, base[:at+1]+ext+".d")
	}
	for i := len(base) - 1; i > 0; i-- {
		if base[i] == '-' {
			dirs = append(dirs, base[:i+1]+ext+".d")
		}
	}
	return dirs
}

var buildOut = regexp.MustCompile(`-o\s+"?([^"\s]*)/([A-Za-z0-9._-]+)"?\s+"?(\./[A-Za-z0-9_./-]+)"?`)

// binaryPackages maps an installed binary's name to its broker package:
// broker/cmd/<name>, and each "go build ... -o <dir>/<name> ./<pkg>" line in
// image/ and .github/workflows/.
func binaryPackages(root string) (map[string]string, error) {
	pkgs := map[string]string{}
	cmds, err := os.ReadDir(filepath.Join(root, "broker", "cmd"))
	if err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	for _, d := range cmds {
		if d.IsDir() {
			pkgs[d.Name()] = "./cmd/" + d.Name()
		}
	}
	for _, dir := range []string{"image", ".github/workflows"} {
		err := filepath.WalkDir(filepath.Join(root, dir), func(p string, d os.DirEntry, err error) error {
			if err != nil {
				if os.IsNotExist(err) {
					return filepath.SkipDir
				}
				return err
			}
			if d.IsDir() || !(strings.HasSuffix(p, ".sh") || strings.HasSuffix(p, ".yml") || strings.HasSuffix(p, ".yaml")) {
				return nil
			}
			b, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			for _, m := range buildOut.FindAllStringSubmatch(string(b), -1) {
				if inRunDir(m[1] + "/" + m[2]) {
					return fmt.Errorf("%s builds %s into %s, a directory root runs whole or reads for properties", p, m[3], m[1])
				}
				if !strings.Contains(m[3], "$") {
					if _, err := os.Stat(filepath.Join(root, "broker", m[3])); err == nil {
						pkgs[m[2]] = filepath.ToSlash(filepath.Clean(m[3]))
						if !strings.HasPrefix(pkgs[m[2]], ".") {
							pkgs[m[2]] = "./" + pkgs[m[2]]
						}
					}
				}
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	return pkgs, nil
}

type use struct {
	file, fn, op string // file is relative to the repository root; op as pathOpName spells it
	line         int
}

// rootSideUses lists the pathOps uses in the non-test files the module's
// packages linked into bins hold, on each architecture the image builds.
// Each package is type-checked against its dependencies' export data, so a
// use is an identifier that resolves to the os function, whatever name or
// import form spells it, and a type error fails the lint (#4256).
func rootSideUses(root string, bins []string) ([]use, error) {
	if len(bins) == 0 {
		return nil, nil
	}
	seen := map[use]bool{}
	var uses []use
	for _, arch := range []string{"amd64", "arm64"} {
		cmd := exec.Command("go", append([]string{"list", "-deps", "-export", "-f", "{{.ImportPath}}\t{{.Export}}\t{{with .Module}}{{if .Main}}{{$.Dir}}\t{{join $.GoFiles \" \"}}{{end}}{{end}}"}, bins...)...)
		cmd.Dir = filepath.Join(root, "broker")
		cmd.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS=linux", "GOARCH="+arch, "GOFLAGS=")
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		out, err := cmd.Output()
		if err != nil {
			return nil, fmt.Errorf("go list (%s): %v\n%s", arch, err, stderr.String())
		}
		exports := map[string]string{}
		type pkg struct{ path, dir, names string }
		var main []pkg
		sc := bufio.NewScanner(bytes.NewReader(out))
		for sc.Scan() {
			f := strings.Split(sc.Text(), "\t")
			if len(f) < 2 {
				return nil, fmt.Errorf("go list (%s): unexpected line %q", arch, sc.Text())
			}
			exports[f[0]] = f[1]
			if len(f) == 4 {
				main = append(main, pkg{f[0], f[2], f[3]})
			}
		}
		fset := token.NewFileSet()
		imp := importer.ForCompiler(fset, "gc", func(path string) (io.ReadCloser, error) {
			if exports[path] == "" {
				return nil, fmt.Errorf("no export data for %s", path)
			}
			return os.Open(exports[path])
		})
		for _, p := range main {
			var files []*ast.File
			for _, n := range strings.Fields(p.names) {
				f, err := parser.ParseFile(fset, filepath.Join(p.dir, n), nil, 0)
				if err != nil {
					return nil, err
				}
				files = append(files, f)
			}
			info, err := checkTypes(fset, imp, p.path, arch, files)
			if err != nil {
				return nil, err
			}
			for _, f := range files {
				rel, err := filepath.Rel(root, fset.Position(f.Pos()).Filename)
				if err != nil {
					return nil, err
				}
				for _, u := range fileUses(fset, f, info, filepath.ToSlash(rel)) {
					if !seen[u] {
						seen[u] = true
						uses = append(uses, u)
					}
				}
			}
		}
	}
	return uses, nil
}

// checkTypes type-checks one package's files for arch, recording what each
// identifier resolves to; any type error fails it.
func checkTypes(fset *token.FileSet, imp types.Importer, pkgPath, arch string, files []*ast.File) (*types.Info, error) {
	info := &types.Info{Uses: map[*ast.Ident]types.Object{}}
	conf := types.Config{Importer: imp, Sizes: types.SizesFor("gc", arch)}
	if _, err := conf.Check(pkgPath, fset, files, info); err != nil {
		return nil, fmt.Errorf("type-checking %s (%s): %v", pkgPath, arch, err)
	}
	return info, nil
}

// fileUses finds each identifier in the file that resolves to a pathOps
// function, called or not (a selector on any import name, a
// dot import's bare name, a value), with the top-level function (Type.Method
// for a method, the first name for a package-level var) it sits in. A
// method of *os.File is not one: it works on an open file, not a path. An
// os.OpenFile call whose flag argument has the real O_NOFOLLOW as an OR
// operand is not a use.
func fileUses(fset *token.FileSet, f *ast.File, info *types.Info, rel string) []use {
	var uses []use
	for _, decl := range f.Decls {
		fn := declName(decl)
		safe := map[*ast.Ident]bool{}
		ast.Inspect(decl, func(n ast.Node) bool {
			switch n := n.(type) {
			case *ast.CallExpr:
				if id := calleeIdent(n.Fun); id != nil && isFunc(info.Uses[id], "os", "OpenFile") && len(n.Args) == 3 && namesNoFollow(n.Args[1], info) {
					safe[id] = true
				}
			case *ast.Ident:
				if op, ok := pathOpName(info.Uses[n]); ok && !safe[n] {
					uses = append(uses, use{file: rel, fn: fn, op: op, line: fset.Position(n.Pos()).Line})
				}
			}
			return true
		})
	}
	return uses
}

// calleeIdent is the identifier a call's function expression names: x in
// x(...) or (x)(...), Sel in a.Sel(...).
func calleeIdent(e ast.Expr) *ast.Ident {
	switch e := e.(type) {
	case *ast.ParenExpr:
		return calleeIdent(e.X)
	case *ast.Ident:
		return e
	case *ast.SelectorExpr:
		return e.Sel
	}
	return nil
}

// isFunc reports whether obj is the package-level function name of the
// package at path (never a method, a variable or a local of that name).
func isFunc(obj types.Object, path, name string) bool {
	f, ok := obj.(*types.Func)
	return ok && f.Pkg() != nil && f.Pkg().Path() == path && f.Name() == name && f.Type().(*types.Signature).Recv() == nil
}

// flagObject is the object an OR operand resolves to: an identifier, or the
// selected name of a selector.
func flagObject(e ast.Expr, info *types.Info) types.Object {
	switch e := e.(type) {
	case *ast.Ident:
		return info.Uses[e]
	case *ast.SelectorExpr:
		return info.Uses[e.Sel]
	}
	return nil
}

// namesNoFollow reports whether a flag argument is an OR of named flags
// (parentheses allowed) with one operand resolving to the O_NOFOLLOW
// constant of syscall or golang.org/x/sys/unix; any other shape, such as one
// that clears it with &^, is not (#3951 L3 1), nor is a local, field or
// parameter of that name, however it is spelled (#4256).
func namesNoFollow(e ast.Expr, info *types.Info) bool {
	switch e := e.(type) {
	case *ast.ParenExpr:
		return namesNoFollow(e.X, info)
	case *ast.BinaryExpr:
		return e.Op == token.OR && orOfFlags(e.X) && orOfFlags(e.Y) && (namesNoFollow(e.X, info) || namesNoFollow(e.Y, info))
	case *ast.SelectorExpr, *ast.Ident:
		c, ok := flagObject(e, info).(*types.Const)
		return ok && c.Name() == "O_NOFOLLOW" && c.Pkg() != nil && (c.Pkg().Path() == "syscall" || c.Pkg().Path() == "golang.org/x/sys/unix")
	}
	return false
}

func orOfFlags(e ast.Expr) bool {
	switch e := e.(type) {
	case *ast.ParenExpr:
		return orOfFlags(e.X)
	case *ast.BinaryExpr:
		return e.Op == token.OR && orOfFlags(e.X) && orOfFlags(e.Y)
	case *ast.SelectorExpr, *ast.Ident:
		return true
	}
	return false
}

func declName(d ast.Decl) string {
	switch d := d.(type) {
	case *ast.FuncDecl:
		if d.Recv != nil && len(d.Recv.List) == 1 {
			t := d.Recv.List[0].Type
			if s, ok := t.(*ast.StarExpr); ok {
				t = s.X
			}
			if ix, ok := t.(*ast.IndexExpr); ok {
				t = ix.X
			}
			if ix, ok := t.(*ast.IndexListExpr); ok {
				t = ix.X
			}
			if id, ok := t.(*ast.Ident); ok {
				return id.Name + "." + d.Name.Name
			}
		}
		return d.Name.Name
	case *ast.GenDecl:
		for _, s := range d.Specs {
			if v, ok := s.(*ast.ValueSpec); ok && len(v.Names) > 0 {
				return v.Names[0].Name
			}
		}
	}
	return "-"
}
