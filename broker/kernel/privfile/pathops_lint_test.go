package privfile

// REQ: KRN-2

// The root-side path lint (REV-CHK-links, #3900). A file operation a root
// process makes by path follows any link on that path, so a guest, clerk or
// other uid that can plant one in a directory on it redirects the write,
// removal or read (#3282, #3382, #3624). The root side is derived, not
// listed: every binary a shipped .service or .socket unit (#4330) starts
// as root, each Exec program a plain absolute path, read across continued
// lines, sections, quotes and ;, with no substitution in what a wrapper
// runs (#4390, #4494). A root unit is closed (D-271): a unit is root as
// main classes it (a true DynamicUser= with no User= runs as the unit
// name's prefix, root.service included), or when it has a + or ! line or a
// true PermissionsStartOnly=, a .socket handing its socket to one is root,
// and no unit sets PAMName= and no pam.d file ships; root_commands.txt
// pins each of its commands whole and each of its pinnedKeys settings, an
// inertKeys key needs no pin and any other key fails, a root script's $$
// names only what systemd sets and no setting of its unit may set, no
// manager file sets an environment, every broker binary a root-run pin
// names, bare or absolute, counts, and no pinned path is reached through a
// link a mkosi.extra or overlay tree ships (#4493); every broker binary
// named as a mount, umount, fsck or mkfs helper, a .mount unit, mount
// drop-in or fstab line naming only a plain type and no helper option
// (#4380), and over a tree root reads or runs no bind, move or loop, a
// source only a device under /dev outside openDevs, with no .. step or %
// specifier, options of only letters, digits and =,_-./, and a tmpfs only
// with a mode no other uid writes (#4516);
// every binary a file under image/ or broker/ makes root run (runKinds: a
// udev rule's RUN, PROGRAM or IMPORT{program}, #3950; a modprobe.d install
// or remove command, #4279; a sysctl.d usermode helper, or a tmpfiles.d
// write of one, #4320), each only a path root_programs.txt lists (#4257),
// no modprobe.d options value naming a program and no tmpfiles.d line
// letting another uid write in or above a tree or program root reads or
// runs (#4423),
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
// operations of non-root host processes are outside the check, as are a
// listed program's reason (that it runs nothing its arguments name, and
// starts only the +<path> broker binaries its line names) and a pin's (that
// it runs no program but those its reason names, such as one a pinned shell
// script names, and no broker binary but its whole-word paths), the
// binaries of a root unit's commands that run under its non-root User= (a
// line with no + prefix: pinned whole, not counted), a mount drop-in read
// alone for a packaged unit, whose type the lint does not see, and a link
// the build makes rather than a mkosi.extra or overlay tree ships (#4589).

import (
	"fmt"
	"go/ast"
	"go/token"
	"go/types"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/ghbmrk/agentos/broker/internal/lintload"
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
	t.Run("a file no build reads fails the lint", func(t *testing.T) {
		bins := []string{"./cmd/agentos-side"}
		for name, c := range map[string]struct {
			file, src string
			bad       bool
		}{
			"another tag":     {"tagged.go", "//go:build agentos_x\n\npackage side\n", true},
			"assembly":        {"side_amd64.s", "", true},
			"cgo":             {"cgo.go", "package side\n\nimport \"C\"\n", true},
			"another GOOS":    {"side_darwin.go", "package side\n", false},
			"go:build ignore": {"gen.go", "//go:build ignore\n\npackage main\n", false},
		} {
			t.Run(name, func(t *testing.T) {
				root := fakeRepo(t, map[string]string{
					"broker/side/side.go":             "package side\n",
					"broker/side/" + c.file:           c.src,
					"broker/cmd/agentos-side/main.go": "package main\n\nimport _ \"example.test/broker/side\"\n\nfunc main() {}\n",
				})
				_, err := rootSideUses(root, bins)
				if c.bad != (err != nil) || c.bad && !strings.Contains(err.Error(), "broker/side/"+c.file) {
					t.Fatalf("got %v, want an error naming the file %v", err, c.bad)
				}
			})
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
	for name, c := range map[string]struct{ unit, pins string }{
		"a unit without User=":                {"[Service]\nExecStart=/usr/lib/agentos/with-uids /usr/lib/agentos/agentos-side -x @uid:y\n", pins("agentos-side.service " + "/usr/lib/agentos/with-uids /usr/lib/agentos/agentos-side -x @uid:y")},
		"a + line in a unit with User=":       {"[Service]\nUser=agentos-side\nExecStartPre=+/usr/lib/agentos/agentos-side\n", pins("agentos-side.service /usr/lib/agentos/agentos-side", "agentos-side.service User=agentos-side")},
		"a unit whose User= is commented out": {"[Service]\n# User=agentos-side\nExecStart=/usr/lib/agentos/agentos-side\n", pins("agentos-side.service /usr/lib/agentos/agentos-side")},
		// #4390: what systemd joins, splits or unquotes is read as it does.
		"a wrapper's continued line":       {"[Service]\nExecStart=/usr/lib/agentos/with-uids \\\n# a comment inside the run\n\t/usr/lib/agentos/agentos-side -x\n", pins("agentos-side.service " + "/usr/lib/agentos/with-uids\n\t/usr/lib/agentos/agentos-side '-x'")},
		"a second command after ;":         {"[Service]\nExecStartPre=/bin/true ; /usr/lib/agentos/agentos-side\n", pins("agentos-side.service /bin/true", "agentos-side.service /usr/lib/agentos/agentos-side")},
		"a path in a shell script":         {"[Service]\nExecStart=/bin/sh -c 'exec /usr/lib/agentos/agentos-side'\n", pins("agentos-side.service /bin/sh -c 'exec /usr/lib/agentos/agentos-side'")},
		"a path after = in an argument":    {"[Service]\nExecStart=/usr/lib/agentos/launch -run=/usr/lib/agentos/agentos-side\n", pins("agentos-side.service /usr/lib/agentos/launch -run=/usr/lib/agentos/agentos-side")},
		"a shell's own $( in a script":     {"[Service]\nExecStart=/bin/sh -c 'exec /usr/lib/agentos/agentos-side $(cat /x)'\n", pins("agentos-side.service /bin/sh -c 'exec /usr/lib/agentos/agentos-side $(cat /x)'")},
		"a quoted program":                 {"[Service]\nExecStart=\"/usr/lib/agentos/agentos-side\"\n", pins("agentos-side.service /usr/lib/agentos/agentos-side")},
		"an empty reset, then a root line": {"[Service]\nExecStart=\nExecStart=-/usr/lib/agentos/agentos-side\n", pins("agentos-side.service /usr/lib/agentos/agentos-side")},
		// #4494 Security 1: only an unescaped last backslash continues.
		"a line ending in an escaped backslash": {"[Service]\nEnvironment=A=x\\\\\nExecStart=/usr/lib/agentos/agentos-side\n", pins("agentos-side.service /usr/lib/agentos/agentos-side", "agentos-side.service Environment=A=x\\\\")},
		"a blank after a backslash":             {"[Service]\nSyslogIdentifier=x \\ \nExecStart=/usr/lib/agentos/agentos-side\n", pins("agentos-side.service /usr/lib/agentos/agentos-side")},
		"a User= outside [Service]":             {"[Unit]\nUser=agentos-side\n[Service]\nExecStart=/usr/lib/agentos/agentos-side\n", pins("agentos-side.service /usr/lib/agentos/agentos-side", "agentos-side.service User=agentos-side")},
		"a [Socket] User= in a .service":        {"[Socket]\nUser=agentos-side\n[Service]\nExecStart=/usr/lib/agentos/agentos-side\n", pins("agentos-side.service /usr/lib/agentos/agentos-side", "agentos-side.service User=agentos-side")},
		"a template User=%i":                    {"[Service]\nUser=%i\nExecStart=/usr/lib/agentos/agentos-side\n", pins("agentos-side.service /usr/lib/agentos/agentos-side", "agentos-side.service User=%i")},
		"a template User=r%i":                   {"[Service]\nUser=r%i\nExecStart=/usr/lib/agentos/agentos-side\n", pins("agentos-side.service /usr/lib/agentos/agentos-side", "agentos-side.service User=r%i")},
		"a template User=0%i":                   {"[Service]\nUser=0%i\nExecStart=/usr/lib/agentos/agentos-side\n", pins("agentos-side.service /usr/lib/agentos/agentos-side", "agentos-side.service User=0%i")},
		"literal $$ and %%":                     {"[Service]\nExecStart=/usr/lib/agentos/agentos-side -x $$EXIT_CODE 100%%\n", pins("agentos-side.service /usr/lib/agentos/agentos-side -x $$EXIT_CODE 100%%")},
		// D-271: a pinned command counts each whole word naming a broker
		// binary (agentos-unlock's -exec), and a listed script the binaries
		// its line says it starts.
		"a pinned command's -exec program": {"[Service]\nExecStart=/usr/lib/agentos/with-uids /usr/lib/agentos/agentos-other -exec /usr/lib/agentos/agentos-side --\n", pins("agentos-side.service " + "/usr/lib/agentos/with-uids /usr/lib/agentos/agentos-other -exec /usr/lib/agentos/agentos-side --")},
		"a pinned shell":                   {"[Service]\nExecStart=/bin/sh -c 'exec /usr/lib/agentos/agentos-side' /usr/lib/agentos/agentos-side\n", pins("agentos-side.service " + "/bin/sh -c 'exec /usr/lib/agentos/agentos-side' /usr/lib/agentos/agentos-side")},
		"a listed script's started binary": {"[Service]\nExecStart=/usr/lib/agentos/health\n", "# a script that runs agentos-side\n# +/usr/lib/agentos/agentos-side\nagentos-side.service /usr/lib/agentos/health\n"},
	} {
		t.Run(name, func(t *testing.T) {
			files := clone(files)
			files["image/mkosi/agentos-side.service"] = c.unit
			files[commandsFile] = c.pins
			bins := set(t, files)
			if want := "./cmd/agentos-side"; !slices.Contains(bins, want) || len(bins) > 2 {
				t.Fatalf("got %q, want %s", bins, want)
			}
			if problems := lintFiles(t, files, ""); len(problems) != 1 || !strings.Contains(problems[0], "broker/side/side.go") {
				t.Fatalf("the binary's linked package: got %q, want its os.Remove refused", problems)
			}
		})
	}
	// A .socket's Exec lines run under its own User= like a .service's
	// (#4330); a socket with none runs them as root.
	socketPin := pins("agentos-side.socket /usr/lib/agentos/agentos-side", "agentos-side.socket User=agentos-side")
	for name, c := range map[string]struct{ path, text, pins string }{
		"a .socket without User=":          {"image/mkosi/agentos-side.socket", "[Socket]\nListenStream=/run/x\nExecStartPre=/usr/lib/agentos/agentos-side\n", pins("agentos-side.socket /usr/lib/agentos/agentos-side", "agentos-side.socket ListenStream=/run/x")},
		"a + line in a .socket with User=": {"image/mkosi/agentos-side.socket", "[Socket]\nUser=agentos-side\nExecStopPost=+/usr/lib/agentos/agentos-side\n", socketPin},
		"a .socket drop-in with User=root": {"image/mkosi/agentos-side.socket.d/z.conf", "[Socket]\nUser=root\n", socketPin + pins("agentos-side.socket User=root")},
		"a socket.d drop-in with User=0":   {"image/mkosi/socket.d/z.conf", "[Socket]\nUser=0\n", socketPin + pins("agentos-side.socket User=0")},
		// service.d reaches every service, agentos-other's too.
		"a service.d drop-in with User=": {"image/mkosi/service.d/z.conf", "[Service]\nUser=\n",
			pins("agentos-side.service /usr/lib/agentos/agentos-side", "agentos-other.service /usr/lib/agentos/agentos-other",
				"agentos-side.service User=agentos-side", "agentos-side.service User=", "agentos-other.service User=agentos-other", "agentos-other.service User=",
				// The socket hands its socket to the now root service.
				"agentos-side.socket /usr/lib/agentos/agentos-side", "agentos-side.socket User=agentos-side")},
	} {
		t.Run(name, func(t *testing.T) {
			files := clone(files)
			files["image/mkosi/agentos-side.socket"] = "[Socket]\nUser=agentos-side\nExecStartPost=/usr/lib/agentos/agentos-side\n"
			if bins := set(t, files); len(bins) != 0 {
				t.Fatalf("a .socket with User=: got %q, want none", bins)
			}
			files[c.path] = c.text
			files[commandsFile] = c.pins
			if bins := set(t, files); len(bins) == 0 || bins[0] != "./cmd/agentos-side" {
				t.Fatalf("got %q, want ./cmd/agentos-side first", bins)
			}
			if problems := lintFiles(t, files, ""); len(problems) != 1 || !strings.Contains(problems[0], "broker/side/side.go") {
				t.Fatalf("the unit's binary's linked package: got %q, want its os.Remove refused", problems)
			}
		})
	}
	// #4390: a program systemd resolves through its search path, a shell
	// line or a substitution goes unread, so each is refused, on a .socket
	// as on a .service and under User= too.
	for name, c := range map[string]struct{ path, text, want string }{
		"a bare program":                {"image/mkosi/agentos-side.service", "[Service]\nExecStart=agentos-side\n", `plain absolute path`},
		"a bare program after a prefix": {"image/mkosi/agentos-side.service", "[Service]\nUser=agentos-side\nExecStartPre=+agentos-side\n", `plain absolute path`},
		"a bare program on a .socket":   {"image/mkosi/agentos-side.socket", "[Socket]\nExecStartPre=-agentos-side\n", `plain absolute path`},
		"a bare second command":         {"image/mkosi/agentos-side.service", "[Service]\nExecStartPre=/bin/true ; agentos-side\n", `plain absolute path`},
		"a quoted bare program":         {"image/mkosi/agentos-side.service", "[Service]\nExecStart='agentos-side' -x\n", `plain absolute path`},
		"a bare program in a drop-in":   {"image/mkosi/agentos-.service.d/z.conf", "[Service]\nExecStartPost=agentos-side\n", `plain absolute path`},
		"a shell line":                  {"image/mkosi/agentos-side.service", "[Service]\nExecStart=|/bin/true\n", `no | prefix`},
		"a specifier program":           {"image/mkosi/agentos-side.service", "[Service]\nExecStart=%h/agentos-side\n", `plain absolute path`},
		"a variable program":            {"image/mkosi/agentos-side.service", "[Service]\nExecStart=/usr/lib/agentos/$X\n", `plain absolute path`},
		"an unclean program":            {"image/mkosi/agentos-side.service", "[Service]\nExecStart=/usr/lib/../lib/agentos/agentos-side\n", `plain absolute path`},
		"an escape":                     {"image/mkosi/agentos-side.service", "[Service]\nExecStart=/usr/lib/agentos/agentos\\x2dside\n", `a backslash`},
		"an unclosed quote":             {"image/mkosi/agentos-side.service", "[Service]\nExecStart=/bin/sh -c 'exec x\n", `an unclosed '`},
		// #4494 Security 2 and 3: a substitution hides what a wrapper runs.
		"a specifier in a program":   {"image/mkosi/agentos-x@.service", "[Service]\nExecStart=/usr/lib/agentos/agentos-%i\n", `% specifier`},
		"a specifier in an argument": {"image/mkosi/agentos-x@.service", "[Service]\nExecStart=/usr/lib/agentos/with-uids /usr/lib/agentos/agentos-%i\n", `% specifier`},
		"a variable a wrapper runs":  {"image/mkosi/agentos-side.service", "[Service]\nEnvironment=P=/usr/lib/agentos/agentos-side\nExecStart=/usr/lib/agentos/with-uids ${P}\n", `holds a $ substitution`},
		"a bare $ variable":          {"image/mkosi/agentos-side.service", "[Service]\nExecStart=/usr/lib/agentos/with-uids $P\n", `holds a $ substitution`},
		"a CR":                       {"image/mkosi/agentos-side.service", "[Service]\nUser=agentos-side\rExecStart=/usr/lib/agentos/agentos-side\n", `byte 0xd`},
		// #4494 Security delta 1 and 2.
		"a byte-order mark":               {"image/mkosi/agentos-side.service", "\xef\xbb\xbf[Service]\nExecStart=/usr/lib/agentos/agentos-side\n", `byte 0xef`},
		"a variable a shell script runs":  {"image/mkosi/agentos-side.service", "[Service]\nEnvironment=P=/usr/lib/agentos/agentos-side\nExecStart=/bin/sh -c 'exec ${P}'\n", `holds a $ substitution`},
		"a variable not in unitVars":      {"image/mkosi/agentos-side.service", "[Service]\nExecStart=/usr/lib/agentos/with-uids /usr/lib/agentos/agentos-side -owner ${X}\n", `holds a $ substitution`},
		"a listed variable inside a word": {"image/mkosi/agentos-side.service", "[Service]\nExecStart=/usr/lib/agentos/with-uids /usr/bin/env x${AGENTOS_OWNER}\n", `holds a $ substitution`},
		"an unclosed listed variable":     {"image/mkosi/agentos-side.service", "[Service]\nExecStart=/usr/lib/agentos/with-uids /usr/lib/agentos/agentos-side ${AGENTOS_OWNER\n", `holds a $ substitution`},
		// #4494 Security delta 2 (57e6fae): sections by unit type, pinned variables.
		"a listed variable a wrapper runs":     {"image/mkosi/agentosd.service", "[Service]\nExecStart=/usr/lib/agentos/with-uids ${AGENTOS_OWNER}\n", `holds a $ substitution`},
		"a listed variable a shell runs":       {"image/mkosi/agentosd.service", "[Service]\nExecStart=/bin/sh -c ${AGENTOS_OWNER}\n", `holds a $ substitution`},
		"a listed variable the unit sets":      {"image/mkosi/agentosd.service", "[Service]\nEnvironment=AGENTOS_OWNER=/usr/lib/agentos/agentos-side\nExecStart=/usr/lib/agentos/with-uids /usr/lib/agentos/agentosd -owner ${AGENTOS_OWNER}\n", `holds a $ substitution`},
		"a listed variable in another unit":    {"image/mkosi/agentos-side.service", "[Service]\nExecStart=/usr/lib/agentos/with-uids /usr/lib/agentos/agentosd -owner ${AGENTOS_OWNER}\n", `holds a $ substitution`},
		"a listed variable after another flag": {"image/mkosi/agentosd.service", "[Service]\nExecStart=/usr/lib/agentos/with-uids /usr/lib/agentos/agentosd -run ${AGENTOS_OWNER}\n", `holds a $ substitution`},
		"a listed variable in another command": {"image/mkosi/agentosd.service", "[Service]\nExecStart=/usr/lib/agentos/with-uids /usr/lib/agentos/other -owner ${AGENTOS_OWNER}\n", `holds a $ substitution`},
		// #4494 Security delta 3 R-1, R-2.
		"an unclosed pinned variable":                   {"image/mkosi/agentosd.service", "[Service]\nExecStart=/usr/lib/agentos/with-uids /usr/lib/agentos/agentosd -owner ${AGENTOS_OWNER\n", `holds a $ substitution`},
		"a pinned variable with an unread Environment=": {"image/mkosi/agentosd.service", "[Service]\nEnvironment='A=1\nExecStart=/usr/lib/agentos/with-uids /usr/lib/agentos/agentosd -owner ${AGENTOS_OWNER}\n", `holds a $ substitution`},
		// #4533: the manager's environment may fill a pinned variable the
		// unit does not clear.
		"a pinned variable the unit does not clear": {"image/mkosi/agentosd.service", "[Service]\nExecStart=/usr/lib/agentos/with-uids /usr/lib/agentos/agentosd -owner ${AGENTOS_OWNER}\n", `holds a $ substitution`},
		"a pinned variable a reset unclears":        {"image/mkosi/agentosd.service", "[Service]\nEnvironment=AGENTOS_OWNER=\nEnvironment=\nExecStart=/usr/lib/agentos/with-uids /usr/lib/agentos/agentosd -owner ${AGENTOS_OWNER}\n", `holds a $ substitution`},
		"a pinned variable PassEnvironment= names":  {"image/mkosi/agentosd.service", "[Service]\nEnvironment=AGENTOS_OWNER=\nPassEnvironment=X AGENTOS_OWNER\nExecStart=/usr/lib/agentos/with-uids /usr/lib/agentos/agentosd -owner ${AGENTOS_OWNER}\n", `holds a $ substitution`},
	} {
		t.Run("refuses "+name, func(t *testing.T) {
			files := clone(files)
			files[c.path] = c.text
			files[commandsFile] = pins("agentos-side.service /bin/true")
			if bins, err := rootBinaries(fakeRepo(t, files)); err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("got %q, %v, want a refusal with %q", bins, err, c.want)
			}
		})
	}
	// #4494 L3 2: ExecPaths= and ExecSearchPath= are paths, not commands.
	t.Run("a root unit whose paths name a binary it does not run", func(t *testing.T) {
		files := clone(files)
		files["image/mkosi/agentos-side.service"] = "[Service]\nExecStart=/bin/true\nExecPaths=/usr/lib/agentos/agentos-side\nExecSearchPath=/usr/lib/agentos/agentos-side\n"
		files[commandsFile] = pins("agentos-side.service /bin/true", "agentos-side.service ExecPaths=/usr/lib/agentos/agentos-side", "agentos-side.service ExecSearchPath=/usr/lib/agentos/agentos-side")
		if bins := set(t, files); len(bins) != 0 {
			t.Fatalf("got %q, want none", bins)
		}
	})
	t.Run("a [Service] User= in a .socket", func(t *testing.T) {
		files := clone(files)
		files["image/mkosi/agentos-side.socket"] = "[Service]\nUser=agentos-side\n[Socket]\nExecStartPre=/usr/lib/agentos/agentos-side\n"
		files[commandsFile] = socketPin // a [Service] line is a setting of the .socket too
		if bins := set(t, files); len(bins) != 1 || bins[0] != "./cmd/agentos-side" {
			t.Fatalf("got %q, want [./cmd/agentos-side]", bins)
		}
	})
	t.Run("refuses a pinned variable another env file may fill", func(t *testing.T) {
		files := clone(files)
		files["image/mkosi/agentosd.service"] = "[Service]\nEnvironment=AGENTOS_OWNER=\nEnvironmentFile=-/etc/agentos/agentosd.env\nExecStart=/usr/lib/agentos/with-uids /usr/lib/agentos/agentosd -owner ${AGENTOS_OWNER}\n"
		files[commandsFile] = agentosdPinned + pins("agentosd.service Environment=AGENTOS_OWNER=", "agentosd.service EnvironmentFile=-/etc/agentos/agentosd.env")
		if _, err := rootBinaries(fakeRepo(t, files)); err != nil {
			t.Fatalf("the pinned env file alone: %v", err)
		}
		files["image/mkosi/agentosd.service.d/z.conf"] = "[Service]\nEnvironmentFile=/var/tmp/x.env\n"
		files[commandsFile] += pins("agentosd.service EnvironmentFile=/var/tmp/x.env")
		if _, err := rootBinaries(fakeRepo(t, files)); err == nil || !strings.Contains(err.Error(), "holds a $ substitution") {
			t.Fatalf("got %v, want a refusal", err)
		}
	})
	// #4533: a drop-in may reset Environment= only if it clears the
	// pinned variable again after.
	t.Run("refuses a drop-in that unclears a pinned variable", func(t *testing.T) {
		files := clone(files)
		files["image/mkosi/agentosd.service"] = "[Service]\nEnvironment=AGENTOS_OWNER=\nExecStart=/usr/lib/agentos/with-uids /usr/lib/agentos/agentosd -owner ${AGENTOS_OWNER}\n"
		for dropin, ok := range map[string]bool{
			"[Service]\nEnvironment=\nEnvironment=AGENTOS_OWNER= A=1\n":              true,
			"[Service]\nEnvironment=A=1\n":                                           true,
			"[Service]\nEnvironment=\n":                                              false,
			"[Service]\nEnvironment=AGENTOS_OWNER=\nEnvironment=\n":                  false,
			"[Service]\nEnvironment=\nPassEnvironment=AGENTOS_OWNER\n":               false,
			"[Service]\nEnvironment=AGENTOS_OWNER=\nPassEnvironment=AGENTOS_OWNER\n": false,
		} {
			files["image/mkosi/agentosd.service.d/z.conf"] = dropin
			files[commandsFile] = agentosdPinned + pins("agentosd.service Environment=AGENTOS_OWNER=")
			for _, l := range strings.Split(strings.TrimPrefix(dropin, "[Service]\n"), "\n") {
				if l != "" && l != "Environment=AGENTOS_OWNER=" {
					files[commandsFile] += pins("agentosd.service " + l)
				}
			}
			if _, err := rootBinaries(fakeRepo(t, files)); (err == nil) != ok || err != nil && !strings.Contains(err.Error(), "holds a $ substitution") {
				t.Errorf("drop-in %q: got %v, want accepted %v", dropin, err, ok)
			}
		}
	})
	t.Run("a pinned variable where unitVars pins it", func(t *testing.T) {
		files := clone(files)
		files["image/mkosi/agentosd.service"] = "[Service]\nEnvironment=OTHER=1 AGENTOS_OWNER=\nExecStart=/usr/lib/agentos/with-uids /usr/lib/agentos/agentosd -owner ${AGENTOS_OWNER}\n"
		files[commandsFile] = agentosdPinned + pins("agentosd.service Environment=OTHER=1 AGENTOS_OWNER=")
		if _, err := rootBinaries(fakeRepo(t, files)); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("a binary a build line names", func(t *testing.T) {
		files := clone(files)
		files["image/mkosi/agentos-other.service"] = "[Service]\nExecStart=/usr/lib/agentos/agentos-other\n"
		files[commandsFile] = pins("agentos-other.service /usr/lib/agentos/agentos-other")
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
			k, v, _ := strings.Cut(strings.TrimSpace(strings.TrimPrefix(dropin, "[Service]\n")), "=")
			files[commandsFile] = pins("agentos-side.service /usr/lib/agentos/agentos-side", "agentos-side.service User=agentos-side", "agentos-side.service "+k+"="+v)
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
		files["image/mkosi/agentos-.service.d/user.conf"] = "[Service]\nUser=agentos-side\n"
		if bins := set(t, files); len(bins) != 0 {
			t.Fatalf("a prefix drop-in: got %q, want none", bins)
		}
		files["image/mkosi/agentos-.service.d/user.conf"] = "[Service]\nDynamicUser=yes\n"
		if bins := set(t, files); len(bins) != 0 {
			t.Fatalf("a prefix drop-in with DynamicUser=yes: got %q, want none", bins)
		}
	})
}

// mount(8) runs a helper as root for a type or option that names one, so a
// mount names only a plain type and no helper option, and a broker binary
// named as a mount, umount, fsck or mkfs helper is root-side (#4380).
func TestRootSideSetCountsMountHelpers(t *testing.T) {
	const unit = "image/camnode/overlay/etc/systemd/system/var-lib-x.mount"
	files := map[string]string{
		"broker/side/side.go":               "package side\n\nimport \"os\"\n\nfunc Drop(p string) error { return os.Remove(p) }\n",
		"broker/cmd/agentos-side/main.go":   "package main\n\nimport \"example.test/broker/side\"\n\nfunc main() { side.Drop(\"\") }\n",
		"image/mkosi/agentos-side.service":  "[Service]\nUser=agentos-side\nExecStart=/usr/lib/agentos/agentos-side\n",
		unit:                                "[Mount]\nWhat=/dev/x\nWhere=/var/lib/x\nType=ext4\nOptions=nosuid,nodev,noexec\n",
		"image/mkosi/tmp.mount.d/50-x.conf": "[Mount]\nOptions=mode=1777,nosuid,nodev,noexec,size=50%%\n",
		"image/mkosi/mkosi.extra/etc/fstab": "# x\ntmpfs /run tmpfs mode=0755,nosuid,nodev,noexec 0 0\ndevtmpfs /dev devtmpfs nosuid\ntmpfs /var/tmp/x tmpfs mode=0777,x-a=\"b,c\"\n",
		"image/x/run-camboot.mount":         "[Mount]\nType=vfat\nOptions=uid=990,gid=990,umask=0077\n",
	}
	if bins, err := rootBinaries(fakeRepo(t, files)); err != nil || len(bins) != 0 {
		t.Fatalf("plain mounts: got %q, %v, want none", bins, err)
	}
	for name, c := range map[string]struct{ path, text, want string }{
		"a helper type":                       {unit, "[Mount]\nWhat=x:/y\nType=nfs\n", `Type=nfs`},
		"a FUSE type":                         {unit, "[Mount]\nWhat=agentos-side\nType=fuse\n", `Type=fuse`},
		"a FUSE subtype":                      {unit, "[Mount]\nWhat=x\nType=fuse.agentos\n", `Type=fuse.agentos`},
		"no type":                             {unit, "[Mount]\nWhat=/dev/x\nWhere=/var/lib/x\n", `no Type=`},
		"a type reset in a drop-in":           {"image/x/var-lib-x.mount.d/z.conf", "[Mount]\nType=\n", `Type=;`},
		"a helper option":                     {unit, "[Mount]\nType=ext4\nOptions=nosuid,helper=agentos\n", `option helper=agentos`},
		"a umount helper in a drop-in":        {"image/mkosi/tmp.mount.d/60-x.conf", "[Mount]\nOptions=uhelper=agentos\n", `option uhelper=agentos`},
		"a type in a packaged unit's drop-in": {"image/mkosi/tmp.mount.d/60-x.conf", "[Mount]\nType=fuse.agentos\n", `Type=fuse.agentos`},
		"a type in mount.d":                   {"image/mkosi/mount.d/x.conf", "[Mount]\nType=cifs\n", `Type=cifs`},
		"a helper type in fstab":              {"image/mkosi/mkosi.extra/etc/fstab", "x:/y /mnt nfs defaults 0 0\n", `plain file system type`},
		"a probed type in fstab":              {"image/mkosi/mkosi.extra/etc/fstab", "/dev/x /mnt auto defaults 0 0\n", `plain file system type`},
		"a short fstab line":                  {"image/mkosi/mkosi.extra/etc/fstab", "/dev/x /mnt\n", `plain file system type`},
		"a helper option in fstab":            {"image/mkosi/mkosi.extra/etc/fstab", "/dev/x /mnt ext4 ro,uhelper=agentos 0 0\n", `option uhelper=agentos`},
		"a continued Type=":                   {unit, "[Mount]\nType=ext4\\\n.x\n", `Type=ext4 .x`},
		// #4494 Security 1 and release R1.
		"a type after an escaped backslash":      {unit, "[Mount]\nType=ext4\nOptions=nosuid,x-a=b\\\\\nType=fuse\n", `Type=fuse`},
		"a type only under [Unit]":               {unit, "[Unit]\nType=ext4\n[Mount]\nWhat=/dev/x\n", `no Type=`},
		"a writable tmpfs over a rules dir":      {"image/mkosi/mkosi.extra/etc/fstab", "tmpfs /etc/udev/rules.d tmpfs mode=0777 0 0\n", `option mode=0777`},
		"an owned tmpfs above /run/systemd":      {"image/mkosi/mkosi.extra/etc/fstab", "tmpfs /run/ tmpfs uid=1000 0 0\n", `option uid=1000`},
		"an overlay in fstab over /usr":          {"image/mkosi/mkosi.extra/etc/fstab", "overlay /usr overlay lowerdir=/usr 0 0\n", `no overlay over`},
		"an overlay unit over /usr":              {"image/x/usr-lib-agentos.mount", "[Mount]\nType=overlay\nOptions=lowerdir=/usr/lib/agentos,upperdir=/var/tmp/u\n", `no overlay over`},
		"an upper dir in the unit's drop-in":     {"image/x/usr-lib-agentos.mount.d/z.conf", "[Mount]\nOptions=upperdir=/var/tmp/u\n", `option upperdir=/var/tmp/u`},
		"an owner option in a type drop-in":      {"image/mkosi/mount.d/x.conf", "[Mount]\nOptions=uid=1000\n", `option uid=1000`},
		"an owner option on the root mount":      {"image/x/-.mount", "[Mount]\nType=ext4\nOptions=gid=100\n", `option gid=100`},
		"an X-mount.mode over a rules dir":       {"image/mkosi/mkosi.extra/etc/fstab", "/dev/x /etc/udev/rules.d ext4 X-mount.mode=0777 0 0\n", `option X-mount.mode=0777`},
		"an X-mount.owner over /usr":             {"image/mkosi/mkosi.extra/etc/fstab", "/dev/x /usr/lib/agentos ext4 X-mount.owner=1000 0 0\n", `option X-mount.owner=1000`},
		"an X-mount.group over /usr":             {"image/mkosi/mkosi.extra/etc/fstab", "/dev/x /usr/lib/agentos ext4 X-mount.group=100 0 0\n", `option X-mount.group=100`},
		"an X-mount.idmap over /etc":             {"image/mkosi/mkosi.extra/etc/fstab", "/dev/x /etc ext4 X-mount.idmap=/proc/1/ns/user 0 0\n", `option X-mount.idmap`},
		"a writable tmpfs over /var/run/systemd": {"image/mkosi/mkosi.extra/etc/fstab", "tmpfs /var/run/systemd/system tmpfs mode=0777 0 0\n", `option mode=0777`},
		"an owner option on a var-run unit":      {"image/x/var-run-udev.mount", "[Mount]\nType=tmpfs\nOptions=uid=1\n", `option uid=1`},
		"an owner option on an escaped name":     {"image/x/run-modules\\x2dload.d.mount", "[Mount]\nType=tmpfs\nOptions=uid=1\n", `option uid=1`},
		// #4516: a tmpfs defaults to 1777; a bind, move or loop puts another
		// tree over a root tree.
		"a default tmpfs over a rules dir":  {"image/mkosi/mkosi.extra/etc/fstab", "tmpfs /etc/udev/rules.d tmpfs defaults 0 0\n", `with no mode=`},
		"a ramfs over /usr":                 {"image/mkosi/mkosi.extra/etc/fstab", "ramfs /usr/lib/agentos ramfs nosuid 0 0\n", `with no mode=`},
		"a tmpfs with no options over /run": {"image/mkosi/mkosi.extra/etc/fstab", "tmpfs /run tmpfs\n", `with no mode=`},
		"a group-writable tmpfs mode":       {"image/mkosi/mkosi.extra/etc/fstab", "tmpfs /etc/x tmpfs mode=0775 0 0\n", `option mode=0775`},
		"an other-writable tmpfs mode":      {"image/mkosi/mkosi.extra/etc/fstab", "tmpfs /etc/x tmpfs mode=0757 0 0\n", `option mode=0757`},
		"an image in /dev/shm in fstab":     {"image/mkosi/mkosi.extra/etc/fstab", "/dev/shm/x.img /usr/lib/agentos squashfs ro 0 0\n", `source /dev/shm/x.img`},
		"a file in /dev/mqueue in fstab":    {"image/mkosi/mkosi.extra/etc/fstab", "/dev/mqueue/x /etc ext4 ro 0 0\n", `source /dev/mqueue/x`},
		"an image in /dev/shm in a unit":    {"image/x/usr-lib-agentos.mount", "[Mount]\nWhat=/dev/shm/x.img\nType=squashfs\n", `What=/dev/shm/x.img`},
		"an unclean /dev/shm source":        {"image/mkosi/mkosi.extra/etc/fstab", "/dev/./shm/x.img /usr squashfs ro 0 0\n", `source /dev/./shm/x.img`},
		"an image in /run/shm":              {"image/mkosi/mkosi.extra/etc/fstab", "/run/shm/x.img /usr squashfs ro 0 0\n", `source /run/shm/x.img`},
		"a /dev/fd source":                  {"image/mkosi/mkosi.extra/etc/fstab", "/dev/fd/3 /etc ext4 ro 0 0\n", `source /dev/fd/3`},
		"a /dev/stdin source in a unit":     {"image/x/usr-lib-agentos.mount", "[Mount]\nWhat=/dev/stdin\nType=squashfs\n", `What=/dev/stdin`},
		"a /dev/stdout source":              {"image/mkosi/mkosi.extra/etc/fstab", "/dev/stdout /etc ext4 ro 0 0\n", `source /dev/stdout`},
		"a /dev/stderr source":              {"image/mkosi/mkosi.extra/etc/fstab", "/dev/stderr /etc ext4 ro 0 0\n", `source /dev/stderr`},
		"a /proc source in a unit":          {"image/x/usr-lib-agentos.mount", "[Mount]\nWhat=/proc/self/fd/3\nType=squashfs\n", `What=/proc/self/fd/3`},
		"a .. after /dev/fd in fstab":       {"image/mkosi/mkosi.extra/etc/fstab", "/dev/fd/../root/tmp/x.img /usr/lib/agentos squashfs ro 0 0\n", `source /dev/fd/../root/tmp/x.img`},
		"a .. after /dev/fd in a unit":      {"image/x/usr-lib-agentos.mount", "[Mount]\nWhat=/dev/fd/../root/tmp/x.img\nType=squashfs\n", `What=/dev/fd/../root/tmp/x.img`},
		"a specifier source":                {"image/x/usr-lib-agentos.mount", "[Mount]\nWhat=%V\nType=squashfs\n", `What=%V`},
		"a symbolic mode":                   {"image/mkosi/mkosi.extra/etc/fstab", "tmpfs /etc/x tmpfs mode=u-w 0 0\n", `option mode=u-w`},
		"a mode past 7777":                  {"image/mkosi/mkosi.extra/etc/fstab", "tmpfs /etc/x tmpfs mode=10755 0 0\n", `option mode=10755`},
		"a bind in fstab":                   {"image/mkosi/mkosi.extra/etc/fstab", "/dev/x /usr/lib/agentos ext4 bind 0 0\n", `option bind`},
		"a move in fstab":                   {"image/mkosi/mkosi.extra/etc/fstab", "/dev/x /etc ext4 nosuid,move 0 0\n", `option move`},
		"a loop in fstab":                   {"image/mkosi/mkosi.extra/etc/fstab", "/dev/x /usr squashfs loop=/dev/loop0 0 0\n", `option loop=/dev/loop0`},
		"a directory source in fstab":       {"image/mkosi/mkosi.extra/etc/fstab", "/var/tmp/u /usr/lib/agentos ext4 defaults 0 0\n", `source /var/tmp/u`},
		"an unclean source in fstab":        {"image/mkosi/mkosi.extra/etc/fstab", "/dev/../var/tmp/u /etc ext4 defaults 0 0\n", `source /dev/../var/tmp/u`},
		"a default tmpfs over /var/run":     {"image/mkosi/mkosi.extra/etc/fstab", "tmpfs /var/run/udev tmpfs nosuid 0 0\n", `with no mode=`},
		"an rbind unit":                     {"image/x/usr-lib-agentos.mount", "[Mount]\nWhat=/dev/x\nType=ext4\nOptions=rbind\n", `option rbind`},
		"a loop in a type drop-in":          {"image/mkosi/mount.d/x.conf", "[Mount]\nOptions=loop\n", `option loop`},
		"an image file source":              {"image/x/usr-lib-agentos.mount", "[Mount]\nWhat=/var/tmp/x.img\nType=squashfs\n", `What=/var/tmp/x.img`},
		"a default tmpfs unit over /etc":    {"image/x/etc-udev-rules.d.mount", "[Mount]\nWhat=tmpfs\nType=tmpfs\nOptions=nosuid\n", `sets no mode=`},
		"a tmpfs unit with no Options=":     {"image/x/etc-udev-rules.d.mount", "[Mount]\nWhat=tmpfs\nType=tmpfs\n", `with no Options=`},
		"a tmpfs in a drop-in over /etc":    {"image/x/etc-udev-rules.d.mount.d/z.conf", "[Mount]\nType=ramfs\n", `with no Options=`},
		// #4559 Security 1: libmount keeps a quoted value whole.
		"a quoted mode in fstab":  {"image/mkosi/mkosi.extra/etc/fstab", "tmpfs /etc/udev/rules.d tmpfs x-a=\",mode=0755,\",nosuid 0 0\n", `hold a byte other than`},
		"a quoted mode in a unit": {"image/x/etc-udev-rules.d.mount", "[Mount]\nWhat=tmpfs\nType=tmpfs\nOptions=x-a=\",mode=0755,\",nosuid\n", `hold a byte other than`},
		// #4559 Security delta 1: libmount keeps a \-escaped comma too.
		"an escaped comma in a unit":    {"image/x/etc-udev-rules.d.mount", "[Mount]\nWhat=tmpfs\nType=tmpfs\nOptions=x-a=a\\,mode=0755,nosuid\n", `hold a byte other than`},
		"an escaped comma in a drop-in": {"image/x/etc-udev-rules.d.mount.d/z.conf", "[Mount]\nType=tmpfs\nOptions=x-a=a\\,mode=0755\n", `hold a byte other than`},
		"a single quote in a unit":      {"image/x/etc-udev-rules.d.mount", "[Mount]\nWhat=tmpfs\nType=tmpfs\nOptions=mode=0755,x-a='b'\n", `hold a byte other than`},
	} {
		t.Run("refuses "+name, func(t *testing.T) {
			files := clone(files)
			files[c.path] = c.text
			if bins, err := rootBinaries(fakeRepo(t, files)); err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("got %q, %v, want a refusal with %q", bins, err, c.want)
			}
		})
	}
	t.Run("a tmpfs over a root tree whose every Options= holds a mode", func(t *testing.T) {
		files := clone(files)
		files["image/mkosi/mkosi.extra/etc/fstab"] += "tmpfs /run/systemd/x tmpfs mode=1755,nosuid 0 0\nramfs /etc/y ramfs mode=700 0 0\n"
		files["image/x/etc-x.mount"] = "[Mount]\nWhat=tmpfs\nType=tmpfs\nOptions=mode=0755,nosuid\n"
		if _, err := rootBinaries(fakeRepo(t, files)); err != nil {
			t.Fatal(err)
		}
		// Options= in a drop-in replaces the unit's.
		files["image/x/etc-x.mount.d/z.conf"] = "[Mount]\nOptions=nosuid\n"
		if _, err := rootBinaries(fakeRepo(t, files)); err == nil || !strings.Contains(err.Error(), "sets no mode=") {
			t.Fatalf("a drop-in without the mode: got %v, want a refusal", err)
		}
		// Drop-ins sort across directories, so which one is last is not
		// read: a mode only in the drop-in is refused too.
		files["image/x/etc-x.mount"] = "[Mount]\nWhat=tmpfs\nType=tmpfs\nOptions=nosuid\n"
		files["image/x/etc-x.mount.d/z.conf"] = "[Mount]\nOptions=mode=0755\n"
		if _, err := rootBinaries(fakeRepo(t, files)); err == nil || !strings.Contains(err.Error(), "sets no mode=") {
			t.Fatalf("a unit without the mode: got %v, want a refusal", err)
		}
	})
	for _, helper := range []string{"mount.agentos", "umount.agentos", "fsck.ext4", "mkfs.ext4"} {
		t.Run("a broker binary named "+helper, func(t *testing.T) {
			files := clone(files)
			files["image/build.sh"] = "cd broker && go build -o \"$STAGE/usr/sbin/" + helper + "\" ./cmd/agentos-side\n"
			if bins, err := rootBinaries(fakeRepo(t, files)); err != nil || len(bins) != 1 || bins[0] != "./cmd/agentos-side" {
				t.Fatalf("got %q, %v, want [./cmd/agentos-side]", bins, err)
			}
		})
	}
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
		"image/mkosi/agentos-side.service":        "[Service]\nUser=agentos-side\nExecStart=/usr/lib/agentos/agentos-side\nExecStartPre=+/opt/x/agentos-x\nExecStartPre=+/run/agentos-v/x\n",
		modprobe:                                  "# agentos-side\nblacklist btusb\n\talias usb:v1 btusb\noptions btusb x=1\nsoftdep btusb pre: btmtk\nweakdep btusb btmtk\ninstall btusb /bin/false\n",
		sysctl:                                    "; agentos-side\n# kernel.modprobe=/usr/lib/agentos/agentos-side\nkernel.core_pattern = core.%p\nfs.suid_dumpable=0\n-kernel.hotplug\n-net.ipv4.ip_forward = 0\n",
		extra + "usr/lib/modprobe.d/README":       "install btusb /usr/lib/agentos/agentos-side\n",
		"image/mkosi/agentos-x.conf":              "install btusb /usr/lib/agentos/agentos-side\nkernel.modprobe=/usr/lib/agentos/agentos-side\n",
		extra + "usr/lib/udev/rules.d/60-x.rules": "KERNEL==\"x\", MODE=\"0600\"\n",
		tmpfiles:                            "# w /proc/sys/kernel/modprobe - - - - /usr/lib/agentos/agentos-side\nd /var/lib/agentos-x 0700 agentos-x agentos-x -\nd /var/lib/agentos-y 0770 - agentos-y\nz /etc/agentos 0755 root agentos-x\nz /sys/class/leds/x/brightness 0660 root root -\nw /proc/sys/kernel/core_pattern - - - - core.%p\nw- /proc/sys/vm/swappiness - - - - 10\nR /var/tmp/agentos-x\nd /var/tmp/agentos-y 1777 root root -\nd /run/agentos-y :0750 root root -\nz /run/agentos-y ~0755\n",
		extra + "usr/lib/tmpfiles.d/README": "w /proc/sys/kernel/modprobe - - - - /usr/lib/agentos/agentos-side\n",
		programsFile:                        "/bin/false exits 1\n/usr/lib/agentos/agentos-side the binary under test\n",
		commandsFile:                        pins("agentos-side.service /opt/x/agentos-x", "agentos-side.service /run/agentos-v/x", "agentos-side.service /usr/lib/agentos/agentos-side", "agentos-side.service User=agentos-side"),
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
		// #4423: a module parameter may name a helper the kernel runs.
		"an options helper path":        {modprobe, "options drbd usermode_helper=/usr/lib/agentos/agentos-side\n", `may name no program`},
		"an options relative path":      {modprobe, "options nfsd x=1 y=sbin/agentos-side\n", `may name no program`},
		"an options helper name":        {modprobe, "options drbd usermode_helper=agentos-side\n", `may name no program`},
		"an options prog name":          {modprobe, "options nfsd cltrack_prog=x\n", `may name no program`},
		"an options with no module":     {modprobe, "options\n", `options takes a module`},
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
		"an /etc/udev hwdb.bin":              {extra + "etc/udev/hwdb.bin", "", `reads no such file`},
		"an /etc/systemd/hwdb hwdb.bin":      {extra + "etc/systemd/hwdb/hwdb.bin", "", `reads no such file`},
		"a /usr/lib/systemd hwdb.bin":        {extra + "usr/lib/systemd/hwdb/hwdb.bin", "", `reads no such file`},
		"a /usr/lib/udev hwdb.bin":           {extra + "usr/lib/udev/hwdb.bin", "", `reads no such file`},
		"a tmpfiles binfmt_misc register":    {tmpfiles, "w /proc/sys/fs/binfmt_misc/register - - - - :x:E::bin::/usr/lib/agentos/agentos-side:\n", `registers an interpreter`},
		"a tmpfiles binfmt_misc mode":        {tmpfiles, "z /proc/sys/fs/binfmt_misc/status 0666\n", `registers an interpreter`},
		"a tmpfiles unlisted helper":         {tmpfiles, "w /proc/sys/kernel/modprobe - - - - /usr/lib/agentos/agentos-other\n", `agentos-other", which`},
		"a tmpfiles specifier program":       {tmpfiles, "w /proc/sys/kernel/modprobe - - - - %S/agentos-side\n", `absolute program path`},
		"a tmpfiles shell word":              {tmpfiles, "w /proc/sys/kernel/core_pattern - - - - |/bin/false;/usr/lib/agentos/agentos-side\n", `may not hold`},
		"a tmpfiles glob path":               {tmpfiles, "w /proc/sys/kernel/modprob? - - - - /usr/lib/agentos/agentos-side\n", `plain absolute path`},
		"a tmpfiles specifier path":          {tmpfiles, "w /proc/sys/kernel/%a - - - - /usr/lib/agentos/agentos-side\n", `plain absolute path`},
		"a tmpfiles unclean path":            {tmpfiles, "w /proc/sys/kernel/../kernel/modprobe - - - - /usr/lib/agentos/agentos-side\n", `plain absolute path`},
		"a tmpfiles type it lacks":           {tmpfiles, "ww /proc/sys/kernel/modprobe - - - - /usr/lib/agentos/agentos-side\n", `plain absolute path`},
		"a tmpfiles base64 argument":         {tmpfiles, "w~ /proc/sys/kernel/core_pattern - - - - fC91c3IvbGliL2FnZW50b3MvYWdlbnRvcy1zaWRlICVw\n", `no ~ or ^ modifier`},
		"a tmpfiles credential argument":     {tmpfiles, "w^ /proc/sys/kernel/modprobe - - - - agentos.helper\n", `no ~ or ^ modifier`},
		"a tmpfiles setuid mode":             {tmpfiles, "z /usr/lib/agentos/agentos-side 4755 root root -\n", `no setuid or setgid`},
		"a tmpfiles setgid mode":             {tmpfiles, "Z /usr/lib/agentos 2755 root root -\n", `no setuid or setgid`},
		"a tmpfiles Z above a helper":        {tmpfiles, "Z /sys/kernel 0666 - -\n", `a directory above /sys/kernel/uevent_helper`},
		"a tmpfiles z on /":                  {tmpfiles, "z / 0755\n", `a directory above`},
		"a tmpfiles release_agent":           {tmpfiles, "w /sys/fs/cgroup/x/release_agent - - - - /usr/lib/agentos/agentos-side\n", `release_agent`},
		"a tmpfiles masked setuid mode":      {tmpfiles, "d /var/lib/agentos-x ~6755 root root -\n", `no setuid or setgid`},
		"a tmpfiles magic link":              {tmpfiles, "w /proc/1/root/proc/sys/kernel/modprobe - - - - /usr/lib/agentos/agentos-side\n", `in /proc but not /proc/sys`},
		"a tmpfiles mode on a helper":        {tmpfiles, "z /proc/sys/kernel/core_pattern 0666\n", `a helper is only written`},
		"a tmpfiles w to a file":             {tmpfiles, "w /etc/modprobe.d/x.conf - - - - install btusb /usr/lib/agentos/agentos-side\n", `writes only under /proc/sys`},
		"a tmpfiles uevent_helper":           {tmpfiles, "w /sys/kernel/uevent_helper - - - - /usr/lib/agentos/agentos-side\n", `the only line in /sys`},
		"a tmpfiles mode on uevent_helper":   {tmpfiles, "z /sys/kernel/uevent_helper 0666 nobody -\n", `the only line in /sys`},
		"a tmpfiles mode on a module helper": {tmpfiles, "z /sys/module/drbd/parameters/usermode_helper 0666\n", `the only line in /sys`},
		"a tmpfiles w to a device":           {tmpfiles, "w /sys/class/leds/x/trigger - - - - none\n", `the only line in /sys`},
		"a tmpfiles link to a module":        {tmpfiles, "z /sys/class/net/eth0/driver/module/parameters/usermode_helper 0666\n", `the only line in /sys`},
		"a tmpfiles devices path":            {tmpfiles, "z /sys/devices/platform/x/brightness 0666\n", `the only line in /sys`},
		"a tmpfiles Z on a device":           {tmpfiles, "Z /sys/class/leds/x/brightness 0660\n", `the only line in /sys`},
		"a tmpfiles cgroup file":             {tmpfiles, "z /sys/fs/cgroup/x/cgroup.procs 0666\n", `the only line in /sys`},
		"a tmpfiles module helper":           {tmpfiles, "w /sys/module/drbd/parameters/usermode_helper - - - - /usr/lib/agentos/agentos-side\n", `the only line in /sys`},
		"a tmpfiles f":                       {tmpfiles, "f /etc/rc.local 0755 - - - /usr/lib/agentos/agentos-side\n", `type f writes`},
		"a tmpfiles L":                       {tmpfiles, "L+ /etc/systemd/system-generators/x - - - - /usr/lib/agentos/agentos-side\n", `type L+ writes`},
		"a tmpfiles C":                       {tmpfiles, "C /etc/udev/rules.d - - - - /usr/share/agentos/rules.d\n", `type C writes`},
		"a tmpfiles xattr":                   {tmpfiles, "t /usr/lib/agentos/agentos-side - - - - security.capability=0sAQAAAg\n", `type t writes`},
		// #4423: no other uid may write where root reads or runs.
		"a tmpfiles writable program":          {tmpfiles, "z /usr/lib/agentos/agentos-hostdisk 0777\n", `in or above /usr`},
		"a tmpfiles group-writable rules dir":  {tmpfiles, "d /etc/udev/rules.d 0775 root agentos-side -\n", `in or above /etc`},
		"a tmpfiles sticky rules dir":          {tmpfiles, "d /etc/udev/rules.d 1777\n", `mode 1777 /etc/udev/rules.d`},
		"a tmpfiles other-writable unit dir":   {tmpfiles, "d /run/systemd/system 0757\n", `in or above /run/systemd`},
		"a tmpfiles non-root owner":            {tmpfiles, "d /etc/modprobe.d 0755 nobody\n", `owner nobody`},
		"a tmpfiles create-only owner":         {tmpfiles, "d /usr/lib/agentos 0755 :agentos-side\n", `owner :agentos-side`},
		"a tmpfiles writable /run":             {tmpfiles, "d /run 0777\n", `in or above /run/systemd`},
		"a tmpfiles writable listed program":   {tmpfiles, "z /bin/false 0757\n", `in or above /bin`},
		"a tmpfiles writable runtime sysctl.d": {tmpfiles, "d /run/sysctl.d 0700 agentos-side\n", `in or above /run/sysctl.d`},
		"a tmpfiles owned unit program":        {tmpfiles, "z /opt/x/agentos-x 0755 agentos-side\n", `in or above /opt/x/agentos-x`},
		"a tmpfiles writable initramfs":        {tmpfiles, "d /run/initramfs 0777 root root -\n", `in or above /run/initramfs`},
		"a tmpfiles owned extensions dir":      {tmpfiles, "d /var/lib/extensions 0755 agentos-side\n", `in or above /var/lib/extensions`},
		// #4494 L3 1: /var/run is /run.
		"a tmpfiles writable /var/run unit dir":  {tmpfiles, "d /var/run/systemd/system 0777\n", `in or above /run/systemd`},
		"a tmpfiles writable /var/run rules dir": {tmpfiles, "d /var/run/udev/rules.d 0777\n", `in or above /run/udev`},
		"a tmpfiles owned /var/run modprobe.d":   {tmpfiles, "d /var/run/modprobe.d 0755 nobody\n", `in or above /run/modprobe.d`},
		"a tmpfiles writable /var/run":           {tmpfiles, "z /var/run 0777\n", `in or above /run/systemd`},
		"a tmpfiles owned /var/run unit program": {tmpfiles, "z /var/run/agentos-v/x 0755 agentos-side\n", `in or above /run/agentos-v/x`},
	} {
		t.Run("refuses "+name, func(t *testing.T) {
			files := clone(files)
			files[c.path] += c.text
			if bins, err := set(t, files); err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("got %q, %v, want a refusal with %q", bins, err, c.want)
			}
		})
	}
	t.Run("refuses a tmpfiles line handing a listed program outside rootTrees to another uid", func(t *testing.T) {
		files := clone(files)
		files[programsFile] = "/bin/false exits 1\n/opt/y/helper a synthetic helper\n"
		files[modprobe] += "install btmtk /opt/y/helper\n"
		if _, err := set(t, files); err != nil {
			t.Fatalf("the listed helper alone: %v", err)
		}
		files[tmpfiles] += "z /opt/y/helper 0775\n"
		if bins, err := set(t, files); err == nil || !strings.Contains(err.Error(), "in or above /opt/y/helper") {
			t.Fatalf("got %q, %v, want a refusal naming /opt/y/helper", bins, err)
		}
	})
	// #4516 (#4494 Security delta R-1): /var/lock is /run/lock, /run/shm is
	// /dev/shm, and /var/run/shm is both.
	t.Run("refuses a grant on a root program spelled through an alias", func(t *testing.T) {
		for prog, grant := range map[string]string{
			"/run/lock/agentos-v/x":    "/var/lock/agentos-v/x",
			"/var/lock/agentos-w/x":    "/run/lock/agentos-w/x",
			"/dev/shm/agentos-v/x":     "/run/shm/agentos-v/x", // #4559 L3 1: /run/shm is /dev/shm
			"/var/run/shm/agentos-w/x": "/dev/shm/agentos-w/x", // and the aliases chain
		} {
			files := clone(files)
			files[programsFile] = "/bin/false exits 1\n"
			files["image/mkosi/agentos-side.service"] += "ExecStartPre=+" + prog + "\n"
			files[commandsFile] += pins("agentos-side.service " + prog)
			// D-271 item 8: a pin spelled through an alias fails alone.
			if _, err := set(t, files); unalias(prog) != prog && (err == nil || !strings.Contains(err.Error(), "by a link every image has")) || unalias(prog) == prog && err != nil {
				t.Fatalf("%s alone: %v", prog, err)
			}
			if unalias(prog) != prog {
				continue
			}
			files[tmpfiles] += "z " + grant + " 0755 nobody\n"
			if bins, err := set(t, files); err == nil || !strings.Contains(err.Error(), "which root reads or runs") {
				t.Errorf("%s with a grant on %s: got %q, %v, want a refusal", prog, grant, bins, err)
			}
		}
	})
	t.Run("the shipped files", func(t *testing.T) {
		// root_programs.txt lists /bin/false and /usr/bin/false only for
		// agentos-no-bluetooth.conf and 99-agentos-nodump.conf: were either
		// file unread, its line would be stale and this would fail.
		if _, err := rootBinaries(repoRoot(t)); err != nil {
			t.Fatal(err)
		}
	})
}

// D-271: every command a unit runs as root is pinned whole, word for word,
// in its unit, on top of the checks above. A shell, wrapper or other runner
// that no pin admits runs nothing as root, whichever spelling hides what it
// runs (#4493; #4559 Security delta 3 1 and 2).
func TestRootCommandsArePinned(t *testing.T) {
	const (
		unit     = "image/mkosi/agentos-v.service"
		tmpfiles = "image/mkosi/mkosi.extra/usr/lib/tmpfiles.d/agentos-x.conf"
		extra    = "image/mkosi/mkosi.extra"
		overlay  = "image/camnode/external/board/qemu/overlay"
		pinned   = "/usr/lib/agentos/with-uids /usr/lib/agentos/agentos-other -exec /usr/lib/agentos/agentos-side --"
	)
	files := map[string]string{
		"broker/side/side.go":              "package side\n\nimport \"os\"\n\nfunc Drop(p string) error { return os.Remove(p) }\n",
		"broker/cmd/agentos-side/main.go":  "package main\n\nimport \"example.test/broker/side\"\n\nfunc main() { side.Drop(\"\") }\n",
		"broker/cmd/agentos-other/main.go": "package main\n\nfunc main() {}\n",
		unit:                               "[Service]\nExecStart=" + pinned + "\nExecStartPost=/usr/bin/rm -f /run/x\n",
		commandsFile: "# a header\n\n# with-uids execs agentos-other, which execs its -exec program\nagentos-v.service " + pinned + "\n\n" +
			"# rm runs no program\nagentos-v.service /usr/bin/rm -f /run/x\n",
	}
	set := func(t *testing.T, files map[string]string, links map[string]string) ([]string, error) {
		t.Helper()
		root := fakeRepo(t, files)
		for name, target := range links {
			p := filepath.Join(root, filepath.FromSlash(name))
			if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(target, p); err != nil {
				t.Fatal(err)
			}
		}
		return rootBinaries(root)
	}
	if bins, err := set(t, files, nil); err != nil || !slices.Equal(bins, []string{"./cmd/agentos-other", "./cmd/agentos-side"}) {
		t.Fatalf("two pinned commands: got %q, %v, want both binaries the pin names", bins, err)
	}
	type change struct {
		files map[string]string // path -> text it gets, or "+" text appended
		links map[string]string
		want  string
	}
	add := func(path, text string) map[string]string { return map[string]string{path: "+" + text} }
	cmd := func(c string) map[string]string { return add(unit, "ExecStartPre="+c+"\n") }
	// script pins a script whose reason says it starts agentos-side.
	script := func(prog string) string {
		return "\n# a script that runs agentos-side\n# +" + prog + "\nagentos-v.service /usr/lib/agentos/s\n"
	}
	const unpinned = "pins no such command of this unit"
	for name, c := range map[string]change{
		// #4559 Security delta 3 2: a program that changes its directory or
		// root before it runs a relative name is no pin, whatever option
		// spells the change.
		"nsenter's --root":            {files: cmd("/usr/bin/nsenter -t 1 --root=tmp /helper"), want: unpinned},
		"unshare -R":                  {files: cmd("/usr/bin/unshare -R tmp /helper"), want: unpinned},
		"unshare --root":              {files: cmd("/usr/bin/unshare --root=tmp /helper"), want: unpinned},
		"start-stop-daemon -d":        {files: cmd("/usr/sbin/start-stop-daemon --start -d tmp --exec /bin/sh -- x"), want: unpinned},
		"make -C":                     {files: cmd("/usr/bin/make -C tmp"), want: unpinned},
		"find -execdir":               {files: cmd("/usr/bin/find tmp -name x -execdir sh x"), want: unpinned},
		"capsh --chroot":              {files: cmd("/usr/sbin/capsh --chroot=tmp -- -c x"), want: unpinned},
		"systemd-nspawn -D":           {files: cmd("/usr/bin/systemd-nspawn -D tmp /helper"), want: unpinned},
		"a shell's bare name":         {files: cmd("/bin/sh -c 'exec agentos-camnode'"), want: unpinned},
		"a shell's quote-joined name": {files: cmd("/bin/sh -c 'exec agentos-\"si\"de'"), want: unpinned},
		"a shell's cd":                {files: cmd("/usr/bin/sh -c 'cd /tmp && ./x'"), want: unpinned},
		"env":                         {files: cmd("/usr/bin/env agentos-side"), want: unpinned},
		"flock -c":                    {files: cmd("/usr/bin/flock /run/x -c agentos-side"), want: unpinned},
		"systemd-run":                 {files: cmd("/usr/bin/systemd-run agentos-side"), want: unpinned},
		"nft -f a world file":         {files: cmd("/usr/sbin/nft -f /tmp/rules.nft"), want: unpinned},
		"rm in a world tree":          {files: cmd("/usr/bin/rm -rf /tmp/d/x"), want: unpinned},
		// #4493: with-uids runs only what a pin names.
		"with-uids unpinned":                {files: cmd("/usr/lib/agentos/with-uids /usr/lib/agentos/r/tmp/agentos-side"), want: unpinned},
		"a pinned command with a word more": {files: cmd(pinned + " -runsc /tmp/x"), want: unpinned},
		"a pinned command with a word less": {files: cmd("/usr/lib/agentos/with-uids /usr/lib/agentos/agentos-other -exec /usr/lib/agentos/agentos-side"), want: unpinned},
		"a pinned command in another unit":  {files: map[string]string{"image/mkosi/agentos-w.service": "[Service]\nExecStart=" + pinned + "\n"}, want: unpinned},
		"a pinned command on a + line":      {files: map[string]string{"image/mkosi/agentos-w.service": "[Service]\nUser=agentos-w\nExecStopPost=+/usr/bin/rm -f /run/x\n"}, want: unpinned},
		"a drop-in on a packaged unit":      {files: map[string]string{"image/mkosi/mkosi.extra/usr/lib/systemd/system/systemd-x.service.d/z.conf": "[Service]\nExecStart=\nExecStart=/usr/bin/rm -f /run/x\n"}, want: unpinned},
		// Pin lines.
		"a pin with no reason":         {files: add(commandsFile, "\nagentos-v.service /usr/bin/rm -x\n"), want: "want the entry's reason"},
		"a stray continuation":         {files: add(commandsFile, "\n\t-x\n"), want: "a continuation with no entry"},
		"two commands in one pin":      {files: add(commandsFile, "\n# r\nagentos-v.service /usr/bin/rm ; /usr/bin/rm\n"), want: "want \"<unit> <one command"},
		"a relative pinned program":    {files: add(commandsFile, "\n# r\nagentos-v.service rm -f\n"), want: "want \"<unit> <one command"},
		"an unclean pinned program":    {files: add(commandsFile, "\n# r\nagentos-v.service /usr/../bin/rm\n"), want: "want \"<unit> <one command"},
		"a pin with no unit type":      {files: add(commandsFile, "\n# r\nagentos-v /usr/bin/rm\n"), want: "want \"<unit> <one command"},
		"a pin with an unclosed quote": {files: add(commandsFile, "\n# r\nagentos-v.service /usr/bin/rm 'x\n"), want: "an unclosed '"},
		"a doubled pin":                {files: add(commandsFile, "\n# again\nagentos-v.service "+pinned+"\n"), want: "the command line 4 pins"},
		"a pin no unit runs":           {files: add(commandsFile, "\n# r\nagentos-v.service /usr/bin/true -x\n"), want: "runs nowhere as root"},
		"a pin of a non-root command":  {files: map[string]string{unit: "[Service]\nUser=agentos-v\nExecStart=" + pinned + "\n"}, want: "runs nowhere as root"},
		"a relative started program":   {files: add(commandsFile, script("agentos-side")), want: "+<plain absolute path>"},
		// #4559 Security delta 3 1: a pinned path reached through a link the
		// image ships, or through /var/run, names another program than the
		// pin reads.
		"a pinned program that is a link": {files: map[string]string{commandsFile: "+\n# r\nagentos-v.service /usr/lib/agentos/helper\n", unit: "+ExecStartPre=/usr/lib/agentos/helper\n"},
			links: map[string]string{extra + "/usr/lib/agentos/helper": "agentos-side"}, want: "image/mkosi/mkosi.extra/usr/lib/agentos/helper is a link"},
		"a pinned program under a linked directory": {files: map[string]string{commandsFile: "+\n# r\nagentos-v.service /usr/lib/agentos/r/tmp/x\n", unit: "+ExecStartPre=/usr/lib/agentos/r/tmp/x\n"},
			links: map[string]string{extra + "/usr/lib/agentos/r": "/var"}, want: "mkosi.extra/usr/lib/agentos/r is a link"},
		"a relative link with a .. step": {files: map[string]string{commandsFile: "+\n# r\nagentos-v.service /usr/lib/agentos/r/agentos-side\n", unit: "+ExecStartPre=/usr/lib/agentos/r/agentos-side\n"},
			links: map[string]string{extra + "/usr/lib/agentos/r": "../../../var/lock/../shm"}, want: "mkosi.extra/usr/lib/agentos/r is a link"},
		"an overlay link": {files: map[string]string{commandsFile: "+\n# r\nagentos-v.service /usr/lib/agentos/helper\n", unit: "+ExecStartPre=/usr/lib/agentos/helper\n"},
			links: map[string]string{overlay + "/usr/lib/agentos/helper": "agentos-side"}, want: "overlay/usr/lib/agentos/helper is a link"},
		"a linked started program": {files: map[string]string{commandsFile: "+" + script("/usr/lib/agentos/helper"), unit: "+ExecStartPre=/usr/lib/agentos/s\n"},
			links: map[string]string{extra + "/usr/lib/agentos/helper": "agentos-side"}, want: "helper is a link"},
		"a linked pinned word": {links: map[string]string{extra + "/usr/lib/agentos/agentos-side": "/var/tmp/x"}, want: "agentos-side is a link"},
		"a pinned /var/run word": {files: map[string]string{commandsFile: "+\n# r\nagentos-v.service /var/run/agentos-v/x\n", unit: "+ExecStartPre=/var/run/agentos-v/x\n"},
			want: "is /run/agentos-v/x by a link every image has"},
		// D-271 Security 3: a setting outside the pin changes what a pinned
		// command runs or reads.
		"a $$ name a drop-in's Environment= sets": {files: map[string]string{
			unit:                                     "+ExecStartPre=/usr/bin/sh -c 'exec /usr/lib/agentos/with-uids $$P'\n",
			commandsFile:                             "+\n# r\nagentos-v.service /usr/bin/sh -c 'exec /usr/lib/agentos/with-uids $$P'\n\n# r\nagentos-v.service Environment=P=/usr/lib/agentos/agentos-side\n",
			"image/mkosi/agentos-v.service.d/z.conf": "[Service]\nEnvironment=P=/usr/lib/agentos/agentos-side\n"}, want: "reads $P"},
		"a $${} name the unit sets": {files: map[string]string{
			unit:         "+Environment=P=/usr/lib/agentos/agentos-side\nExecStartPre=/usr/bin/sh -c 'exec $${P}'\n",
			commandsFile: "+\n# r\nagentos-v.service /usr/bin/sh -c 'exec $${P}'\n\n# r\nagentos-v.service Environment=P=/usr/lib/agentos/agentos-side\n"}, want: "reads $P"},
		"a $$ name with an env file": {files: map[string]string{
			unit:         "+EnvironmentFile=-/var/tmp/x.env\nExecStartPre=/usr/bin/sh -c 'exec /usr/sbin/nft -f $$F'\n",
			commandsFile: "+\n# r\nagentos-v.service /usr/bin/sh -c 'exec /usr/sbin/nft -f $$F'\n\n# r\nagentos-v.service EnvironmentFile=-/var/tmp/x.env\n"}, want: "reads $F"},
		"a $$ name the manager passes": {files: map[string]string{
			unit:         "+PassEnvironment=F\nExecStartPre=/usr/bin/sh -c 'exec /usr/sbin/nft -f $$F'\n",
			commandsFile: "+\n# r\nagentos-v.service /usr/bin/sh -c 'exec /usr/sbin/nft -f $$F'\n\n# r\nagentos-v.service PassEnvironment=F\n"}, want: "reads $F"},
		"an unpinned setting":                             {files: add(unit, "Environment=X=1\n"), want: "pins no such setting"},
		"a changed setting":                               {files: map[string]string{unit: "+Environment=X=2\n", commandsFile: "+\n# r\nagentos-v.service Environment=X=1\n"}, want: "pins no such setting"},
		"a doubled setting":                               {files: map[string]string{unit: "+Environment=X=1\n", commandsFile: "+\n# r\nagentos-v.service Environment=X=1\n\n# again\nagentos-v.service Environment=X=1\n"}, want: "the setting line 10 pins"},
		"a pinned setting of a unit with no root command": {files: map[string]string{"image/mkosi/agentos-w.service": "[Service]\nUser=w\nEnvironment=X=1\nExecStart=/usr/bin/rm -f /run/x\n", commandsFile: "+\n# r\nagentos-w.service Environment=X=1\n"}, want: "runs nowhere as root"},
		// #4617 Security R-b: a . or .. step in a pinned path word.
		"a .. step in a pinned word": {files: map[string]string{unit: "+ExecStartPre=/usr/bin/rm -f /run/../tmp/x\n", commandsFile: "+\n# r\nagentos-v.service /usr/bin/rm -f /run/../tmp/x\n"}, want: "holds a .. step"},
		"a . step in a pinned word":  {files: map[string]string{unit: "+ExecStartPre=/usr/bin/rm -f ./x\n", commandsFile: "+\n# r\nagentos-v.service /usr/bin/rm -f ./x\n"}, want: "holds a . step"},
		// #4423 extended: no other uid writes a program a pin says it starts.
		"a writable started program outside rootTrees": {files: map[string]string{commandsFile: "+" + script("/opt/y/agentos-side"), unit: "+ExecStartPre=/usr/lib/agentos/s\n", tmpfiles: "z /opt/y/agentos-side 0775\n"},
			want: "in or above /opt/y/agentos-side"},
	} {
		t.Run("refuses "+name, func(t *testing.T) {
			files := clone(files)
			for p, text := range c.files {
				if more, ok := strings.CutPrefix(text, "+"); ok {
					text = files[p] + more
				}
				files[p] = text
			}
			if bins, err := set(t, files, c.links); err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("got %q, %v, want a refusal with %q", bins, err, c.want)
			}
		})
	}
	for key := range pinnedKeys {
		t.Run("refuses an unpinned "+key+" drop-in on a root unit", func(t *testing.T) {
			files := clone(files)
			val := "/var/tmp/r:/etc/agentos"
			if key == "User" {
				val = "root" // a non-root User= would end the unit's root commands
			}
			files["image/mkosi/agentos-v.service.d/z.conf"] = "[Service]\n" + key + "=" + val + "\n"
			if _, err := set(t, files, nil); err == nil || !strings.Contains(err.Error(), "pins no such setting") {
				t.Fatalf("got %v, want the setting refused", err)
			}
			files[commandsFile] += "\n# r\nagentos-v.service " + key + "=" + val + "\n"
			if _, err := set(t, files, nil); err != nil {
				t.Fatalf("pinned: %v", err)
			}
		})
	}
	// D-271 item 2: every key of a root unit is on one closed list.
	t.Run("an inert key needs no pin, an unknown key fails", func(t *testing.T) {
		files := clone(files)
		files[unit] += "ProtectSystem=strict\nPrivateTmp=yes\nInaccessiblePaths=/x\n"
		if _, err := set(t, files, nil); err != nil {
			t.Fatalf("inert keys: %v", err)
		}
		for _, line := range []string{"[Service]\nFrobnicate=1\n", "[Unit]\nFrobnicate=1\n", "[Install]\nFrobnicate=1\n"} {
			files["image/mkosi/agentos-v.service.d/z.conf"] = line
			if _, err := set(t, files, nil); err == nil || !strings.Contains(err.Error(), "on neither pinnedKeys nor inertKeys") {
				t.Fatalf("%q: got %v, want the key refused", line, err)
			}
		}
	})
	t.Run("a key on both lists", func(t *testing.T) {
		for k := range inertKeys {
			if pinnedKeys[k] || commandKeys[k] {
				t.Errorf("%s is on two lists", k)
			}
		}
	})
	t.Run("a unit with no root command needs no setting pinned", func(t *testing.T) {
		files := clone(files)
		files["image/mkosi/agentos-w.service"] = "[Service]\nUser=w\nFrobnicate=1\nEnvironment=X=1\nExecStart=/usr/bin/rm -f /run/x\n"
		if _, err := set(t, files, nil); err != nil {
			t.Fatal(err)
		}
	})
	// D-271 item 1: a .socket handing its socket to a root unit is root;
	// a true DynamicUser= ends a templated User='s root.
	t.Run("a socket handing to a root service", func(t *testing.T) {
		files := clone(files)
		files["image/mkosi/agentos-v.socket"] = "[Socket]\nUser=w\nExecStartPre=/usr/bin/rm -f /run/y\n"
		if _, err := set(t, files, nil); err == nil || !strings.Contains(err.Error(), "agentos-v.socket: ExecStartPre=") {
			t.Fatalf("got %v, want the socket's command refused", err)
		}
		files[commandsFile] += "\n# r\nagentos-v.socket /usr/bin/rm -f /run/y\nagentos-v.socket User=w\n"
		if _, err := set(t, files, nil); err != nil {
			t.Fatal(err)
		}
		files["image/mkosi/agentos-v.service.d/user.conf"] = "[Service]\nUser=v\n"
		if _, err := set(t, files, nil); err == nil || !strings.Contains(err.Error(), "runs nowhere as root") {
			t.Fatalf("a non-root service: got %v, want the socket's pins stale", err)
		}
	})
	for name, c := range map[string]struct {
		user string
		root bool
	}{
		"User=%i":                        {"User=%i\n", true},
		"User=x-$X":                      {"User=x-$X\n", true},
		"User=x-%i, DynamicUser=yes":     {"User=x-%i\nDynamicUser=yes\n", false},
		"User=r%i, DynamicUser=yes":      {"User=r%i\nDynamicUser=yes\n", true},
		"DynamicUser=yes":                {"DynamicUser=yes\n", false},
		"User=, DynamicUser=yes":         {"User=\nDynamicUser=yes\n", false},
		"User=w, User=, DynamicUser=yes": {"User=w\nUser=\nDynamicUser=yes\n", false},
		"User=":                          {"User=\n", true},
		"User=w, DynamicUser=yes":        {"User=w\nDynamicUser=yes\n", false},
		"PermissionsStartOnly=yes":       {"User=w\nPermissionsStartOnly=yes\n", true},
		"PermissionsStartOnly=no":        {"User=w\nPermissionsStartOnly=no\n", false},
		"User=root, DynamicUser=yes":     {"User=root\nDynamicUser=yes\n", true},
		"DynamicUser=yes, then no":       {"DynamicUser=yes\nDynamicUser=no\n", true},
		"User=w":                         {"User=w\n", false},
		"User=w, then User=%i":           {"User=w\nUser=%i\n", true},
		"User=w, DynamicUser=false":      {"User=w\nDynamicUser=false\n", true},
	} {
		t.Run("a unit with "+name, func(t *testing.T) {
			files := clone(files)
			files["image/mkosi/agentos-w@.service"] = "[Service]\n" + c.user + "ExecStart=/usr/bin/rm -f /run/x\n"
			_, err := set(t, files, nil)
			if root := err != nil && strings.Contains(err.Error(), "agentos-w@.service: ExecStart="); root != c.root {
				t.Fatalf("got %v, want root %v", err, c.root)
			}
		})
	}
	// D-271 item 1: DynamicUser= with no User= runs as the unit name's
	// prefix, a reused static user, root included.
	for _, unit := range []string{"root.service", "root@.service", "0@.service"} {
		t.Run("a DynamicUser= unit named "+unit, func(t *testing.T) {
			files := clone(files)
			files["image/mkosi/"+unit] = "[Service]\nDynamicUser=yes\nUser=\nExecStart=/usr/bin/rm -f /run/x\n"
			if _, err := set(t, files, nil); err == nil || !strings.Contains(err.Error(), unit+": ExecStart=") {
				t.Fatalf("got %v, want the unit's command refused", err)
			}
			files["image/mkosi/"+unit] = "[Service]\nDynamicUser=yes\nExecStart=/usr/bin/rm -f /run/x\n"
			if _, err := set(t, files, nil); err == nil || !strings.Contains(err.Error(), unit+": ExecStart=") {
				t.Fatalf("no User=: got %v, want the unit's command refused", err)
			}
			// A later empty User= resets an earlier literal one.
			files["image/mkosi/"+unit] = "[Service]\nUser=w\nDynamicUser=yes\nExecStart=/usr/bin/rm -f /run/x\n"
			files["image/mkosi/"+unit+".d/z.conf"] = "[Service]\nUser=\n"
			if _, err := set(t, files, nil); err == nil || !strings.Contains(err.Error(), unit+": ExecStart=") {
				t.Fatalf("a reset User=: got %v, want the unit's command refused", err)
			}
		})
	}
	t.Run("refuses a pam.d file", func(t *testing.T) {
		files := clone(files)
		files["image/mkosi/mkosi.extra/etc/pam.d/agentos"] = "auth required pam_permit.so\n"
		if _, err := set(t, files, nil); err == nil || !strings.Contains(err.Error(), "a pam.d file runs its stack as root") {
			t.Fatalf("got %v, want the pam.d file refused", err)
		}
	})
	for name, unit := range map[string]string{
		"a root unit":     "[Service]\nPAMName=login\nExecStart=/usr/bin/rm -f /run/x\n",
		"a non-root unit": "[Service]\nUser=w\nPAMName=login\nExecStart=/usr/bin/rm -f /run/x\n",
	} {
		t.Run("refuses PAMName= on "+name, func(t *testing.T) {
			files := clone(files)
			files["image/mkosi/agentos-w.service"] = unit
			if _, err := set(t, files, nil); err == nil || !strings.Contains(err.Error(), "PAMName=login: PAM runs") {
				t.Fatalf("got %v, want PAMName= refused", err)
			}
		})
	}
	// D-271 item 5: $$ names only what systemd sets after the manager,
	// and only when no setting of the unit may set it.
	for name, setting := range map[string]string{
		"Environment=":         "Environment=\"A=1 SERVICE_RESULT=success\"\n",
		"PassEnvironment=":     "PassEnvironment=SERVICE_RESULT\n",
		"any EnvironmentFile=": "EnvironmentFile=-/etc/agentos/x.env\n",
	} {
		t.Run("refuses $$SERVICE_RESULT with "+name, func(t *testing.T) {
			files := clone(files)
			const script = "/usr/bin/sh -c 'echo $$SERVICE_RESULT'"
			files[unit] += "ExecStopPost=" + script + "\n" + setting
			k, v, _ := strings.Cut(strings.TrimSpace(setting), "=")
			files[commandsFile] += "\n# r\nagentos-v.service " + script + "\nagentos-v.service " + k + "=" + v + "\n"
			if _, err := set(t, files, nil); err == nil || !strings.Contains(err.Error(), "may set") {
				t.Fatalf("got %v, want the $$ name refused", err)
			}
		})
	}
	for _, w := range []string{"$$HOME", "$${PATH}", "x$$IFS", "$${SERVICE_RESULTX}"} {
		t.Run("refuses a root script reading "+w, func(t *testing.T) {
			files := clone(files)
			script := "/usr/bin/sh -c 'echo " + w + "'"
			files[unit] += "ExecStopPost=" + script + "\n"
			files[commandsFile] += "\n# r\nagentos-v.service " + script + "\n"
			if _, err := set(t, files, nil); err == nil || !strings.Contains(err.Error(), "reads only $SERVICE_RESULT") {
				t.Fatalf("got %v, want the $$ name refused", err)
			}
		})
	}
	t.Run("the names systemd sets", func(t *testing.T) {
		files := clone(files)
		const script = "/usr/bin/sh -c 'echo $$EXIT_CODE $${EXIT_STATUS} $${SERVICE_RESULT}'"
		files[unit] += "ExecStopPost=" + script + "\n"
		files[commandsFile] += "\n# r\nagentos-v.service " + script + "\n"
		if _, err := set(t, files, nil); err != nil {
			t.Fatal(err)
		}
	})
	// D-271 item 6: no manager-wide environment.
	for name, c := range map[string]struct{ path, text string }{
		"DefaultEnvironment":              {"image/mkosi/mkosi.extra/etc/systemd/system.conf", "[Manager]\nDefaultEnvironment=PATH=/tmp\n"},
		"ManagerEnvironment in a drop-in": {"image/mkosi/mkosi.extra/usr/lib/systemd/system.conf.d/z.conf", "[Manager]\nManagerEnvironment=X=1\n"},
		"a backslash-joined key":          {"image/mkosi/mkosi.extra/etc/systemd/system.conf", "[Manager]\nDefault\\\nEnvironment=X=1\n"},
		"systemd.setenv=":                 {"image/mkosi/mkosi.conf", "[Content]\nKernelCommandLine=quiet systemd.setenv=PATH=/tmp\n"},
		"systemd.setenv= continued":       {"image/mkosi/mkosi.conf.d/z.conf", "[Content]\nKernelCommandLine=quiet\n    systemd.setenv=PATH=/tmp\n"},
	} {
		t.Run("refuses "+name, func(t *testing.T) {
			files := clone(files)
			files[c.path] = c.text
			if _, err := set(t, files, nil); err == nil || !strings.Contains(err.Error(), "sets every unit's environment") {
				t.Fatalf("got %v, want the manager environment refused", err)
			}
		})
	}
	t.Run("a manager file with no environment", func(t *testing.T) {
		files := clone(files)
		files["image/mkosi/mkosi.extra/etc/systemd/system.conf"] = "[Manager]\n#DefaultEnvironment=X=1\nDefaultTimeoutStopSec=10s\n"
		files["image/mkosi/mkosi.conf"] = "[Content]\nKernelCommandLine=quiet systemd.log_level=info\n"
		if _, err := set(t, files, nil); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("a $$ name nothing sets, and $$$$", func(t *testing.T) {
		files := clone(files)
		const script = "/usr/bin/sh -c 'if [ \"$$SERVICE_RESULT\" != success ]; then echo $$$$; fi'"
		files[unit] += "ExecStopPost=" + script + "\n"
		files[commandsFile] += "\n# r\nagentos-v.service " + script + "\n"
		if _, err := set(t, files, nil); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("a bare name in a pinned script counts, an account name does not", func(t *testing.T) {
		files := clone(files)
		files[unit] = "[Service]\nExecStart=/usr/bin/sh -c 'exec agentos-side'\nExecStartPost=/usr/bin/install -o @uid:agentos-other -d /run/x\n"
		files[commandsFile] = "# r\nagentos-v.service /usr/bin/sh -c 'exec agentos-side'\n\n# r\nagentos-v.service /usr/bin/install -o @uid:agentos-other -d /run/x\n"
		if bins, err := set(t, files, nil); err != nil || !slices.Equal(bins, []string{"./cmd/agentos-side"}) {
			t.Fatalf("got %q, %v, want [./cmd/agentos-side]", bins, err)
		}
	})
	t.Run("a pinned script counts what its reason says it starts", func(t *testing.T) {
		files := clone(files)
		files[commandsFile] = script("/usr/lib/agentos/agentos-side")
		files[unit] = "[Service]\nExecStart=/usr/lib/agentos/s\n"
		if bins, err := set(t, files, nil); err != nil || !slices.Equal(bins, []string{"./cmd/agentos-side"}) {
			t.Fatalf("got %q, %v, want [./cmd/agentos-side]", bins, err)
		}
	})
	t.Run("a drop-in on a packaged unit is root", func(t *testing.T) {
		files := clone(files)
		files["image/mkosi/mkosi.extra/usr/lib/systemd/system/systemd-x.service.d/z.conf"] = "[Service]\nExecStart=\nExecStart=/usr/lib/agentos/agentos-side\n"
		files[commandsFile] += "\n# r\nsystemd-x.service /usr/lib/agentos/agentos-side\n"
		if bins, err := set(t, files, nil); err != nil || !slices.Equal(bins, []string{"./cmd/agentos-other", "./cmd/agentos-side"}) {
			t.Fatalf("got %q, %v", bins, err)
		}
		files["image/mkosi/mkosi.extra/usr/lib/systemd/system/systemd-x.service.d/user.conf"] = "[Service]\nUser=x\n"
		if _, err := set(t, files, nil); err == nil || !strings.Contains(err.Error(), "runs nowhere as root") {
			t.Fatalf("a drop-in that sets User=: got %v, want its pin stale", err)
		}
	})
	t.Run("a unit under broker", func(t *testing.T) {
		files := clone(files)
		files["broker/cmd/agentos-side/agentos-side.service"] = "[Service]\nExecStart=/usr/lib/agentos/agentos-side -x\n"
		if _, err := set(t, files, nil); err == nil || !strings.Contains(err.Error(), "broker/cmd/agentos-side/agentos-side.service: ExecStart=") {
			t.Fatalf("got %v, want the broker unit's command refused", err)
		}
	})
	t.Run("the shipped units", func(t *testing.T) {
		bins, err := rootBinaries(repoRoot(t))
		if err != nil {
			t.Fatal(err)
		}
		// agentos-keeper-kernel.service's pin names agentos-unlock's -exec
		// program, and agentos-localui.service under broker/ runs a + line.
		for _, want := range []string{"./cmd/agentos-unlock", "./cmd/agentos-kernel", "./cmd/agentosd", "./cmd/agentos-link", "./cmd/agentos-localui"} {
			if !slices.Contains(bins, want) {
				t.Errorf("root side %q lacks %s", bins, want)
			}
		}
	})
}

func TestUnitVarsAreUsed(t *testing.T) {
	used := map[string]bool{}
	for _, tree := range []string{"image", "broker"} {
		err := filepath.WalkDir(filepath.Join(repoRoot(t), tree), func(p string, d os.DirEntry, err error) error {
			if err != nil || d.IsDir() || !unitTypes[filepath.Ext(p)] && !strings.HasSuffix(p, ".conf") {
				return err
			}
			b, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			for name := range unitVars {
				if strings.Contains(string(b), "${"+name+"}") {
					used[name] = true
				}
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	for name := range unitVars {
		if !used[name] {
			t.Errorf("unitVars lists %s, which no unit under image/ or broker/ passes", name)
		}
	}
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
// one, a unit that starts ./cmd/agentos-side as root, with its pin, and a
// main that links broker/side.
func lintFiles(t *testing.T, files map[string]string, allow string) []string {
	t.Helper()
	files = clone(files)
	if _, ok := files["broker/cmd/agentos-side/main.go"]; !ok {
		files["broker/cmd/agentos-side/main.go"] = "package main\n\nimport _ \"example.test/broker/side\"\n\nfunc main() {}\n"
	}
	if _, ok := files["image/mkosi/agentos-side.service"]; !ok {
		files["image/mkosi/agentos-side.service"] = "[Service]\nExecStart=/usr/lib/agentos/agentos-side\n"
		files[commandsFile] += pins("agentos-side.service /usr/lib/agentos/agentos-side")
	}
	return lintRepo(t, fakeRepo(t, files), allow)
}

// pins is a commandsFile pinning each "<unit> <command>" entry.
func pins(entries ...string) string {
	var b strings.Builder
	for _, e := range entries {
		b.WriteString("# synthetic\n" + e + "\n\n")
	}
	return b.String()
}

// agentosdPinned pins agentosd.service's synthetic root command.
const agentosdPinned = "# with-uids execs agentosd\nagentosd.service /usr/lib/agentos/with-uids /usr/lib/agentos/agentosd -owner ${AGENTOS_OWNER}\n"

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
// ExecStopPost, under the same User= and DynamicUser= (#4330). A .mount has
// no Exec line but makes mount(8) run a helper (mountUnits, #4380); the other
// types run no program (a .swap's swapon runs no helper).
var execUnits = map[string]bool{".service": true, ".socket": true}

// unitTypes are the unit types the scan reads.
var unitTypes = map[string]bool{".service": true, ".socket": true, ".mount": true}

// isDropinDir reports whether dir names a drop-in directory of a unitTypes
// type: a unit's or prefix's (x.service.d, agentos-.socket.d) or the
// type's own (service.d).
func isDropinDir(dir string) bool {
	t, ok := strings.CutSuffix(dir, ".d")
	return ok && (unitTypes[path.Ext(t)] || unitTypes["."+t])
}

// unitLine is one assignment of a unit file and the section it sits in.
type unitLine struct{ section, key, value string }

// unitLines returns a unit file's assignments as systemd reads them
// (systemd.syntax(7), conf-parser.c): a comment line is skipped, inside a
// continued run too; a line whose last byte is a backslash that no
// backslash escapes goes on with the next (a blank after it, or \\, ends
// the line); and a key outside a [section] is ignored. Any byte but
// printable ASCII, tab and LF fails: a CR or NUL would end a line where this
// reader does not, and systemd drops a leading byte-order mark this reader
// would keep.
func unitLines(text string) ([]unitLine, error) {
	for _, c := range []byte(text) {
		if c != '\t' && c != '\n' && (c < 0x20 || c > 0x7e) {
			return nil, fmt.Errorf("byte %#x; a unit file holds only printable ASCII, tabs and LF", c)
		}
	}
	var out []unitLine
	section, cur := "", ""
	flush := func() {
		line := strings.TrimSpace(cur)
		cur = ""
		switch {
		case strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]"):
			section = line[1 : len(line)-1]
		case section != "":
			if k, v, ok := strings.Cut(line, "="); ok {
				out = append(out, unitLine{section, strings.TrimSpace(k), strings.TrimSpace(v)})
			}
		}
	}
	for _, line := range strings.Split(text, "\n") {
		if l := strings.TrimLeft(line, " \t"); strings.HasPrefix(l, "#") || strings.HasPrefix(l, ";") {
			continue
		}
		escaped := false
		for i := 0; i < len(line); i++ {
			escaped = !escaped && line[i] == '\\'
		}
		if escaped {
			cur += line[:len(line)-1] + " "
			continue
		}
		cur += line
		flush()
	}
	flush()
	return out, nil
}

// execWords splits an Exec value into systemd's commands (a lone ; word
// separates two) of words, each with its quotes removed. A backslash is
// refused, so no escape needs decoding.
func execWords(v string) ([][]string, error) {
	if strings.Contains(v, "\\") {
		return nil, fmt.Errorf("a backslash; no escape is read, so none may be written")
	}
	var cmds [][]string
	var cmd []string
	for v = strings.TrimLeft(v, " \t"); v != ""; v = strings.TrimLeft(v, " \t") {
		word, quoted := "", false
		for v != "" && v[0] != ' ' && v[0] != '\t' {
			if q := v[0]; q == '"' || q == '\'' {
				end := strings.IndexByte(v[1:], q)
				if end < 0 {
					return nil, fmt.Errorf("an unclosed %c", q)
				}
				word, quoted, v = word+v[1:1+end], true, v[2+end:]
				continue
			}
			word, v = word+v[:1], v[1:]
		}
		if word == ";" && !quoted {
			cmds, cmd = append(cmds, cmd), nil
			continue
		}
		cmd = append(cmd, word)
	}
	return append(cmds, cmd), nil
}

// mayBeRoot reports whether a User= value with a % specifier can expand to
// root or 0: its literal text before the first % begins one of them
// (User=%i, User=r%i), as camdec-%i cannot.
func mayBeRoot(v string) bool {
	pre, _, ok := strings.Cut(v, "%")
	return ok && (strings.HasPrefix("root", pre) || strings.HasPrefix("0", pre))
}

// unitVars are the variables a root command may pass, each as a whole
// word, with what holds its value to data no wrapper runs. A name no
// shipped Exec line passes fails (TestUnitVarsAreUsed).
var unitVars = map[string]unitVar{
	"AGENTOS_OWNER": {"agentosd.service", []string{"/usr/lib/agentos/with-uids", "/usr/lib/agentos/agentosd"}, "-owner", "-/etc/agentos/agentosd.env",
		"agentosd's -owner value: the unit's AGENTOS_OWNER= overrides the manager's environment, and only /etc/agentos/agentosd.env (0600 in root's 0700 /etc/agentos, written by onboarding, image ASSUMPTIONS I6) fills it; with-uids runs agentosd, its first argument, and passes this one on as data", true},
	"AGENTOS_PAGE_IFACE": {"agentos-localui.service", []string{"/usr/lib/agentos/agentos-localui"}, "-iface", "",
		"agentos-localui's -iface value, port 1's interface name: no Environment=, PassEnvironment= or EnvironmentFile= of the unit names it, so only the manager's environment could fill it, which D-271 item 6 keeps empty on the image (a test harness's own drop-in sets it); agentos-localui only names an interface with it", false},
}

// unitVar pins where a unitVars variable may appear: only in unit, in a
// command that starts with cmd, right after the word flag, and only when
// every EnvironmentFile= is envFile (#4494 Security delta 2 and 3) and the
// unit clears it with NAME= that no Environment= reset undoes and no
// PassEnvironment= names (#4533). systemd lays Environment= over the
// manager's environment (DefaultEnvironment=, systemd.setenv=) and
// PassEnvironment=, and EnvironmentFile= over all three, so the value is
// the env file's or empty.
type unitVar struct {
	unit    string
	cmd     []string
	flag    string
	envFile string
	reason  string
	clear   bool // the unit must clear it (NAME=) against the manager's environment
}

// envLine is one Environment=, EnvironmentFile= or PassEnvironment= of a
// unit, in the order systemd reads its files and lines.
type envLine struct{ file, key, value string }

// allowedVar reports whether word i of a command of unit is a whole-word
// ${NAME} that unitVars pins there and only its envFile may fill.
func allowedVar(unit string, words []string, i int, env []envLine) bool {
	name, ok := strings.CutPrefix(words[i], "${")
	name, whole := strings.CutSuffix(name, "}")
	v, listed := unitVars[name]
	if !ok || !whole || !listed || unit != v.unit || i < len(v.cmd) || words[i-1] != v.flag {
		return false
	}
	for j, w := range v.cmd {
		if words[j] != w {
			return false
		}
	}
	// Drop-ins sort by name across directories, so the order of files is
	// not read: a file with a reset (an empty Environment=) must clear the
	// variable again after its last one, which holds whichever file sorts
	// last.
	cleared := false
	open := map[string]bool{} // file -> a reset not yet followed by NAME=
	for _, e := range env {
		switch e.key {
		case "EnvironmentFile":
			if e.value != v.envFile {
				return false
			}
		case "PassEnvironment":
			if strings.Contains(e.value, name) {
				return false
			}
		case "Environment":
			if e.value == "" {
				open[e.file] = true
				continue
			}
			cmds, err := execWords(e.value)
			if err != nil {
				return false
			}
			for _, cmd := range cmds {
				for _, a := range cmd {
					switch {
					case a == name+"=":
						cleared, open[e.file] = true, false
					case strings.HasPrefix(a, name+"="):
						// The unit may only clear it (agentosd.service's
						// AGENTOS_OWNER=, so an absent env file runs setup
						// mode).
						return false
					}
				}
			}
		}
	}
	for _, o := range open {
		if o {
			return false
		}
	}
	return cleared || !v.clear
}

// substitutes reports whether w holds a substitution systemd makes: a %
// specifier, or with c '$' a $NAME or ${NAME} ($$ is a literal $, and a $
// before anything else, such as a shell's $(, is passed on as it is).
func substitutes(w string, c byte) bool {
	for i := 0; i < len(w); i++ {
		switch {
		case w[i] != c:
		case i+1 < len(w) && w[i+1] == c:
			i++
		case c == '%' || i+1 < len(w) && (w[i+1] == '{' || w[i+1] == '_' || isAlnum(w[i+1])):
			return true
		}
	}
	return false
}

func isAlnum(b byte) bool {
	return 'a' <= b && b <= 'z' || 'A' <= b && b <= 'Z' || '0' <= b && b <= '9'
}

// rootTrees are the trees root reads configuration and programs from: the
// image's own, and the /run directories systemd, udev and the runKinds
// readers take runtime files from. tmpfilesPrograms lets no other uid write
// in, or above, one of them or a program root runs (#4423).
var rootTrees = []string{
	"/etc", "/usr", "/boot", "/efi", "/bin", "/sbin", "/lib", "/lib64",
	"/run/systemd", "/run/udev", "/run/modprobe.d", "/run/sysctl.d", "/run/tmpfiles.d", "/run/binfmt.d", "/run/modules-load.d",
	// systemd-shutdown runs /run/initramfs/shutdown; systemd-sysext and
	// -confext merge images from these over /usr and /etc; sysusers.d makes
	// users; root's home.
	"/run/initramfs", "/run/extensions", "/var/lib/extensions", "/run/confexts", "/var/lib/confexts", "/run/sysusers.d", "/root",
}

// pathAliases are the links every image has between trees: /var/run is
// /run (systemd-tmpfiles also rewrites a /var/run/ path to /run/) and
// /var/lock is /run/lock (BOX_LINKS, legacy.conf) and /run/shm is /dev/shm
// (Debian's link, #4559 Security delta 1), so a path is compared as
// the tree it lands in (#4494 L3 1, #4516).
var pathAliases = map[string]string{"/var/run": "/run", "/var/lock": "/run/lock", "/run/shm": "/dev/shm"}

// openDevs are the paths under /dev that hold no device: any uid may make a
// file in /dev/shm and /dev/mqueue, and /dev/fd and /dev/std* link to
// another process's files, so heldSource refuses a mount source in one like
// any other path (#4516, #4559 Security delta 1). What a root command names
// there is #4493's.
var openDevs = []string{"/dev/shm", "/dev/mqueue", "/dev/fd", "/dev/stdin", "/dev/stdout", "/dev/stderr"}

// unalias is p with a leading pathAliases link resolved.
func unalias(p string) string {
	// Aliases chain (/var/run/shm is /run/shm is /dev/shm), so resolve until
	// none applies; each step moves to another tree, so this ends.
	for again := true; again; {
		again = false
		for from, to := range pathAliases {
			if p == from || strings.HasPrefix(p, from+"/") {
				p, again = to+p[len(from):], true
				break
			}
		}
	}
	return p
}

// inTree reports whether the absolute path p is one of trees or under one.
func inTree(p string, trees []string) (string, bool) {
	p = unalias(p)
	for _, t := range trees {
		if p == t || strings.HasPrefix(p, t+"/") {
			return t, true
		}
	}
	return "", false
}

// inOrAbove reports whether the absolute path p is one of paths, under one,
// or a directory above one.
func inOrAbove(p string, paths []string) (string, bool) {
	p = unalias(p)
	for _, t := range paths {
		if t := unalias(t); p == t || p == "/" || strings.HasPrefix(p, t+"/") || strings.HasPrefix(t, p+"/") {
			return t, true
		}
	}
	return "", false
}

// dotdot reports whether a slash path has a .. component, which the kernel
// resolves after following the link before it (/var/lock/../shm is
// /run/shm), while path.Clean folds it as text (#4559 L3 delta 2 1).
func dotdot(p string) bool {
	for _, c := range strings.Split(p, "/") {
		if c == ".." {
			return true
		}
	}
	return false
}

// accountWord is a with-uids account reference: @uid:NAME or @gid:NAME.
var accountWord = regexp.MustCompile(`@[ug]id:[A-Za-z0-9_.-]+`)

// nameToken is a run of the bytes of a word that can belong to a program's name;
// any other ends a token (a quote, =, :, ;, $, a parenthesis or blank).
var nameToken = regexp.MustCompile(`[A-Za-z0-9_./@+-]+`)

// commandKeys are the Exec keys whose values are commands.
var commandKeys = map[string]bool{
	"ExecCondition": true, "ExecStartPre": true, "ExecStart": true, "ExecStartPost": true, "ExecReload": true,
	"ExecStop": true, "ExecStopPost": true, "ExecStopPre": true,
}

// pinnedKeys decide what a root unit's command runs, reads, receives or is
// named by, or which other units run with it: each line of one is pinned,
// key and value, in commandsFile (D-271 item 2). When in doubt a key is
// pinned.
var pinnedKeys = map[string]bool{
	// The other Exec keys, and the environment.
	"ExecPaths": true, "ExecSearchPath": true,
	"Environment": true, "EnvironmentFile": true, "PassEnvironment": true, "UnsetEnvironment": true,
	// Who it runs as, and what it may do beyond a plain uid.
	"User": true, "Group": true, "DynamicUser": true, "SupplementaryGroups": true, "AmbientCapabilities": true,
	"Delegate": true, "Slice": true, "UMask": true,
	// The paths it sees.
	"BindPaths": true, "BindReadOnlyPaths": true, "RootDirectory": true, "RootImage": true, "RootImageOptions": true,
	"MountImages": true, "ExtensionImages": true, "ExtensionDirectories": true, "TemporaryFileSystem": true,
	"WorkingDirectory": true, "ReadWritePaths": true, "DeviceAllow": true, "IPAddressAllow": true,
	// Its input and output, and what the manager opens or makes for it.
	"StandardInput": true, "StandardOutput": true, "StandardError": true, "TTYPath": true, "OpenFile": true,
	"LoadCredential": true, "LoadCredentialEncrypted": true, "SetCredential": true, "SetCredentialEncrypted": true,
	"ImportCredential": true,
	"StateDirectory":   true, "RuntimeDirectory": true, "CacheDirectory": true, "LogsDirectory": true, "ConfigurationDirectory": true,
	"StateDirectoryMode": true, "RuntimeDirectoryMode": true, "CacheDirectoryMode": true, "LogsDirectoryMode": true,
	"ConfigurationDirectoryMode": true, "RuntimeDirectoryPreserve": true, "JoinsNamespaceOf": true,
	"NetworkNamespacePath": true, "IPCNamespacePath": true, "BPFProgram": true, "IPIngressFilterPath": true,
	"IPEgressFilterPath": true, "LogNamespace": true,
	// Keys that set a variable for its commands, or run its pre and post
	// commands as root (which makes the unit root, D-271 item 1).
	"Type": true, "WatchdogSec": true, "MemoryPressureWatch": true, "PermissionsStartOnly": true,
	// The units that run with it, and its names.
	"Requires": true, "Requisite": true, "Wants": true, "BindsTo": true, "PartOf": true, "Upholds": true,
	"Conflicts": true, "OnFailure": true, "OnSuccess": true, "DefaultDependencies": true,
	"WantedBy": true, "RequiredBy": true, "UpheldBy": true, "Alias": true, "DefaultInstance": true, "Also": true,
	// A .path or .timer unit's unit, and a .path unit's paths.
	"Unit": true, "PathExists": true, "PathExistsGlob": true, "PathChanged": true, "PathModified": true,
	"DirectoryNotEmpty": true, "MakeDirectory": true,
	// A handed socket's.
	"Service": true, "Accept": true, "ListenStream": true, "ListenDatagram": true, "ListenSequentialPacket": true,
	"ListenFIFO": true, "ListenSpecial": true, "ListenNetlink": true, "ListenMessageQueue": true,
	"ListenUSBFunction": true, "SocketUser": true, "SocketGroup": true, "SocketMode": true, "DirectoryMode": true,
	"Symlinks": true, "FileDescriptorName": true,
}

// inertKeys can only narrow: for every value, a root unit's pinned command
// runs, reads, writes and receives nothing a non-root uid or a file outside
// the pin controls that it could not with the key absent. Each sets no
// environment variable, opens no file as the manager, runs nothing and
// changes no unit name or drop-in set (D-271 item 2).
var inertKeys = map[string]string{
	"Description": "text", "Documentation": "text", "SyslogIdentifier": "the journal's tag for the unit's lines",
	"After": "ordering only", "Before": "ordering only",
	"ConditionPathExists": "the manager only tests a path, and a false one only stops the start",
	"RemainAfterExit":     "how the manager tracks the start",
	"Restart":             "runs the same pinned commands again", "RestartSec": "timing", "RestartSteps": "timing",
	"RestartMaxDelaySec": "timing", "TimeoutStartSec": "timing", "StartLimitIntervalSec": "timing", "StartLimitBurst": "timing",
	"MemoryMax": "a resource limit", "MemoryHigh": "a resource limit",
	"LimitCORE":   "a resource limit; a core goes to kernel.core_pattern's pipe, /usr/bin/false (99-agentos-nodump.conf)",
	"NoExecPaths": "removes exec access", "InaccessiblePaths": "removes access (D-154; mkosi.finalize requires it)",
	"PrivateTmp": "a fresh /tmp and /var/tmp only this unit sees; JoinsNamespaceOf is pinned (D-154)",
	"PrivateIPC": "removes access", "PrivateDevices": "removes access", "PrivateNetwork": "removes access",
	"ProtectSystem": "removes write access", "ProtectHome": "removes access", "ProtectProc": "removes access",
	"ProtectKernelTunables": "removes access", "ProtectKernelModules": "removes access", "ProtectKernelLogs": "removes access",
	"ProtectHostname": "removes access", "ProtectControlGroups": "removes access", "ProtectClock": "removes access",
	"NoNewPrivileges": "removes privilege", "CapabilityBoundingSet": "removes capabilities",
	"RestrictAddressFamilies": "removes access", "RestrictNamespaces": "removes access", "RestrictRealtime": "removes access",
	"RestrictSUIDSGID": "removes privilege", "LockPersonality": "removes access", "MemoryDenyWriteExecute": "removes access",
	"SystemCallFilter": "removes system calls", "SystemCallArchitectures": "removes system calls",
	"SystemCallErrorNumber": "how a removed call fails", "DevicePolicy": "removes device access; DeviceAllow is pinned",
	"IPAddressDeny": "removes network access; IPAddressAllow is pinned", "RemoveIPC": "removes IPC objects at stop",
	"PrivatePIDs": "removes access", "TasksMax": "a resource limit", "CollectMode": "when the manager forgets a stopped unit",
	"MaxConnections": "a socket's connection limit", "NoDelay": "a socket's TCP option",
}

// systemdVars are the names systemd sets for a command after the manager
// environment, so no unit or manager setting fills them (D-271 item 5).
var systemdVars = map[string]bool{"SERVICE_RESULT": true, "EXIT_CODE": true, "EXIT_STATUS": true}

// mergedUnit is one unit with its drop-ins, as rootBinaries reads it.
type mergedUnit struct {
	name           string
	execs          []execLine // its type section's command lines
	settings       []execLine // every other line, any section
	env, envFiles  []string   // its Environment= and EnvironmentFile= values
	asUser, asRoot bool       // some User= runs it as a user, as root
	pass           []string   // its PassEnvironment= values
	envLines       []envLine  // its Environment=, EnvironmentFile= and PassEnvironment= lines, in order
	plus           bool       // some command line has a + or ! prefix
	service        string     // a .socket's Service=
	accept         bool       // a .socket's Accept=yes
	root           bool
}

type execLine struct{ file, key, value string }

// readMerged reads unit name from paths, the unit file first, then its
// drop-ins.
func readMerged(root, name string, paths []string) (*mergedUnit, error) {
	m := &mergedUnit{name: name}
	// A later User= replaces an earlier one, and drop-ins sort across
	// directories, so any assignment that may run as root (a root or 0
	// User=, one holding $ or a % that may expand to root, a false
	// DynamicUser=) counts as root wherever it sits: an over-approximation
	// that never drops a root unit (#3951 L3 3). PermissionsStartOnly=
	// runs every command but ExecStart as root (D-271 item 1).
	section := map[string]string{".service": "Service", ".socket": "Socket"}[filepath.Ext(name)]
	var emptyUser, dynamic bool
	for _, f := range paths {
		b, err := os.ReadFile(f)
		if err != nil {
			return nil, err
		}
		rel, _ := filepath.Rel(root, f)
		ul, err := unitLines(string(b))
		if err != nil {
			return nil, fmt.Errorf("%s: %v", filepath.ToSlash(rel), err)
		}
		for _, line := range ul {
			k, v := line.key, line.value
			if line.section == section && commandKeys[k] {
				m.execs = append(m.execs, execLine{f, k, v})
				if p := strings.TrimLeft(v, " \t"); strings.HasPrefix(strings.TrimLeft(p, "@-:"), "+") || strings.HasPrefix(strings.TrimLeft(p, "@-:"), "!") {
					m.plus = true
				}
				continue
			}
			m.settings = append(m.settings, execLine{f, k, v})
			if line.section != section {
				// systemd reads a unit's User= and Exec lines only in its
				// type's own section.
				continue
			}
			switch {
			case k == "Environment" || k == "EnvironmentFile" || k == "PassEnvironment":
				m.envLines = append(m.envLines, envLine{f, k, v})
			}
			switch {
			case k == "Environment":
				m.env = append(m.env, v)
			case k == "EnvironmentFile":
				m.envFiles = append(m.envFiles, v)
			case k == "PassEnvironment":
				m.pass = append(m.pass, v)
			case k == "User" && v == "":
				emptyUser = true
			case k == "User" && (v == "root" || v == "0" || strings.Contains(v, "$") || mayBeRoot(v)):
				m.asRoot = true
			case k == "User":
				m.asUser = true
			case k == "DynamicUser" && (v == "yes" || v == "true" || v == "1" || v == "on"):
				dynamic = true
			case k == "DynamicUser":
				m.asRoot = true // as on main
			case k == "PermissionsStartOnly" && v != "no" && v != "false" && v != "0" && v != "off":
				m.asRoot = true
			case k == "Service":
				m.service = v
			case k == "Accept":
				m.accept = v == "yes" || v == "true" || v == "1" || v == "on"
			}
		}
	}
	// A true DynamicUser= with no User= (or an empty one) runs as the
	// unit name's prefix, which systemd reuses as a static user, root
	// included (user_from_unit_name; D-271 item 1). An empty User=
	// without it runs as root.
	prefix, _, _ := strings.Cut(strings.TrimSuffix(name, filepath.Ext(name)), "@")
	switch byName := dynamic && (emptyUser || !m.asUser && !m.asRoot); {
	case byName && (prefix == "root" || prefix == "0"):
		m.asRoot = true
	case byName:
		m.asUser = true
	case emptyUser:
		m.asRoot = true
	}
	return m, nil
}

// envSource names a setting of m that may fill name before its commands
// run, or "": an Environment= or PassEnvironment= naming it anywhere in
// its value, or any EnvironmentFile= (D-271 item 5).
func (m *mergedUnit) envSource(name string) string {
	for _, v := range m.env {
		if strings.Contains(v, name+"=") {
			return "Environment=" + v
		}
	}
	for _, v := range m.pass {
		if strings.Contains(v, name) {
			return "PassEnvironment=" + v
		}
	}
	if len(m.envFiles) > 0 {
		return "EnvironmentFile=" + m.envFiles[0]
	}
	return ""
}

// handed is the service a .socket hands its socket to, or "".
func (m *mergedUnit) handed() string {
	base, ok := strings.CutSuffix(m.name, ".socket")
	switch {
	case !ok:
		return ""
	case m.service != "":
		return m.service
	case m.accept:
		return base + "@.service"
	}
	return base + ".service"
}

// managerEnv fails a shipped system.conf or system.conf.d drop-in that sets
// DefaultEnvironment or ManagerEnvironment, and a KernelCommandLine= word
// systemd.setenv=, any of which fills a name every unit's commands read
// (D-271 item 6).
func managerEnv(root string) error {
	return filepath.WalkDir(filepath.Join(root, "image"), func(p string, d os.DirEntry, err error) error {
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
		// PAM runs a pam.d stack as root for a unit's PAMName= or a
		// login, outside any pin (D-271 item 1).
		if slices.Contains(strings.Split(filepath.ToSlash(rel), "/"), "pam.d") {
			return fmt.Errorf("%s: a pam.d file runs its stack as root, outside any pin (D-271)", rel)
		}
		conf := d.Name() == "system.conf" || strings.HasSuffix(p, ".conf") && filepath.Base(filepath.Dir(p)) == "system.conf.d"
		mkosi := d.Name() == "mkosi.conf" || strings.HasSuffix(p, ".conf") && filepath.Base(filepath.Dir(p)) == "mkosi.conf.d"
		if !conf && !mkosi {
			return nil
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		// Read wider than systemd and mkosi do, so a backslash-joined
		// key or an indented continuation of KernelCommandLine= is caught
		// too: any uncommented Environment in a manager file, and any
		// systemd.setenv= word in an mkosi file.
		for i, line := range strings.Split(string(b), "\n") {
			if t := strings.TrimSpace(line); conf && strings.Contains(t, "Environment") && !strings.HasPrefix(t, "#") && !strings.HasPrefix(t, ";") {
				return fmt.Errorf("%s:%d: %q sets every unit's environment, which root units' commands read (D-271)", rel, i+1, t)
			}
			for _, w := range strings.Fields(line) {
				if mkosi && strings.Contains(w, "systemd.setenv=") {
					return fmt.Errorf("%s:%d: %s sets every unit's environment, which root units' commands read (D-271)", rel, i+1, w)
				}
			}
		}
		return nil
	})
}

// shellVars returns the names w reads as $$NAME or $${NAME}: what a shell
// expands once systemd turns $$ into $. $$$$ (the shell's own $$) and a
// $$ before anything else name no variable.
func shellVars(w string) []string {
	var out []string
	for i := strings.Index(w, "$$"); i >= 0; i = strings.Index(w, "$$") {
		w = w[i+2:]
		if strings.HasPrefix(w, "$$") {
			w = w[2:]
			continue
		}
		name := strings.TrimPrefix(w, "{")
		n := 0
		for n < len(name) && (name[n] == '_' || isAlnum(name[n])) {
			n++
		}
		if n > 0 && !('0' <= name[0] && name[0] <= '9') {
			out = append(out, name[:n])
		}
	}
	return out
}

// packaged marks, in rootBinaries' units, a unit no tree here ships that a
// drop-in here extends.
const packaged = "packaged:"

// rootBinaries returns the broker packages (as ./path, relative to broker/)
// of the binaries a unit under image/ starts as root or a runKinds file
// names.
func rootBinaries(root string) ([]string, error) {
	units := map[string]string{}     // unit file path -> name
	dropins := map[string][]string{} // drop-in directory name -> its .conf paths
	var fstabs []string
	// image/build.sh installs units from broker/ too (agentos-localui's,
	// #4559 Security R4 on D-271), so both trees are read.
	for _, tree := range []string{"image", "broker"} {
		err := filepath.WalkDir(filepath.Join(root, tree), func(p string, d os.DirEntry, err error) error {
			dir := filepath.Base(filepath.Dir(p))
			switch {
			case err != nil && os.IsNotExist(err) && p == filepath.Join(root, tree):
				return filepath.SkipDir
			case err != nil:
				return err
			case d.IsDir():
				return nil
			case unitTypes[filepath.Ext(p)]:
				units[p] = d.Name()
			case strings.HasSuffix(p, ".conf") && isDropinDir(dir):
				dropins[dir] = append(dropins[dir], p)
			case d.Name() == "fstab":
				fstabs = append(fstabs, p)
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	pkgs, err := binaryPackages(root)
	if err != nil {
		return nil, err
	}
	lists, err := readLists(root)
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	var progs []string // the programs a unit runs as root
	// mount(8), umount(8), systemd-fsck and systemd-makefs run
	// /sbin/<tool>.<type> as root for a file system of that type, whatever
	// unit, fstab line or package mounts it, so a broker binary of such a
	// name is root-side wherever it is installed (#4380).
	for name, pkg := range pkgs {
		for _, tool := range []string{"mount.", "umount.", "fsck.", "mkfs."} {
			if strings.HasPrefix(name, tool) {
				seen[pkg] = true
			}
		}
	}
	// A mount drop-in may also extend a unit a package ships (tmp.mount), so
	// every one is read, not only those of image/'s own units.
	for dir, confs := range dropins {
		if !strings.HasSuffix(dir, ".mount.d") && dir != "mount.d" {
			continue
		}
		for _, f := range confs {
			if _, err := mountLines(root, []string{f}, false); err != nil {
				return nil, err
			}
		}
	}
	for _, f := range fstabs {
		if err := fstabLines(root, f); err != nil {
			return nil, err
		}
	}
	// A drop-in may add Exec lines to a unit a package ships (systemd-
	// networkd-wait-online.service's ExecStart=), which run as root unless
	// the drop-in sets a user, so each such unit is read from its drop-ins
	// alone (D-271 Security 3). The packaged unit's own lines are a
	// package's, outside the check.
	shipped := map[string]bool{}
	for _, name := range units {
		shipped[name] = true
	}
	for dir := range dropins {
		name := strings.TrimSuffix(dir, ".d")
		base := strings.TrimSuffix(name, path.Ext(name))
		if (path.Ext(name) == ".service" || path.Ext(name) == ".socket") && base != "" && !strings.HasSuffix(base, "-") && !shipped[name] {
			units[packaged+name] = name
		}
	}
	// Each unit is read merged, its drop-ins with it, and placed: a root
	// unit (D-271 item 1) is one with no literal non-root User= and no true
	// DynamicUser=, or with a + or ! line, or a .socket handing its socket
	// to one.
	var ms []*mergedUnit
	byName := map[string][]*mergedUnit{}
	for p, name := range units {
		paths := []string{p}
		if strings.HasPrefix(p, packaged) {
			paths = nil
		}
		for _, dir := range dropinDirs(name) {
			paths = append(paths, dropins[dir]...)
		}
		if filepath.Ext(name) == ".mount" {
			if _, err := mountLines(root, paths, true); err != nil {
				return nil, err
			}
			continue
		}
		m, err := readMerged(root, name, paths)
		if err != nil {
			return nil, err
		}
		// PAM runs as root before the uid changes, and its stack is
		// outside any pin, so no unit sets PAMName= (D-271 item 1).
		for _, st := range m.settings {
			if st.key == "PAMName" {
				rel, _ := filepath.Rel(root, st.file)
				return nil, fmt.Errorf("%s: PAMName=%s: PAM runs its stack as root, outside any pin; no unit sets it (D-271)", filepath.ToSlash(rel), st.value)
			}
		}
		ms = append(ms, m)
		byName[name] = append(byName[name], m)
	}
	for _, m := range ms {
		// A .socket's own commands run as root unless it sets a user; one
		// with none is root only for the service it hands its socket to.
		m.root = m.plus || (m.asRoot || !m.asUser) && (len(m.execs) > 0 || filepath.Ext(m.name) != ".socket")
	}
	for _, m := range ms {
		if h := m.handed(); h != "" {
			for _, s := range byName[h] {
				m.root = m.root || s.root
			}
		}
	}
	sort.Slice(ms, func(i, j int) bool { return ms[i].name < ms[j].name })
	for _, m := range ms {
		name := m.name
		for _, l := range m.execs {
			rel, _ := filepath.Rel(root, l.file)
			cmds, err := execWords(l.value)
			if err != nil {
				return nil, fmt.Errorf("%s: %s=%s: %v", filepath.ToSlash(rel), l.key, l.value, err)
			}
			for _, words := range cmds {
				if len(words) == 0 {
					continue // an empty ExecStart= resets the list
				}
				prefix := words[0][:len(words[0])-len(strings.TrimLeft(words[0], "@-:+!|"))]
				prog := words[0][len(prefix):]
				// systemd resolves a bare program through its own search path
				// (v239), | hands the line to a shell, and % and $ substitute;
				// none is read, so a program is a plain absolute path (#4390).
				// A wrapper (with-uids) runs its first argument, so that holds
				// no $ substitution either, and no word holds a % specifier
				// (agentos-%i in a template); $$ and %% are literal.
				if strings.Contains(prefix, "|") || !strings.HasPrefix(prog, "/") || substitutes(prog, '$') || path.Clean(prog) != prog {
					return nil, fmt.Errorf("%s: %s=%s: want a program that is a plain absolute path, with no | prefix, %% or $", filepath.ToSlash(rel), l.key, l.value)
				}
				for _, w := range words {
					if substitutes(w, '%') {
						return nil, fmt.Errorf("%s: %s=%s: word %q holds a %% specifier, whose value the reader cannot see", filepath.ToSlash(rel), l.key, l.value, w)
					}
				}
				asRoot := !m.asUser || m.asRoot || strings.ContainsAny(prefix, "+!")
				if !asRoot && !m.root {
					continue
				}
				// systemd fills in $X and ${X} before a wrapper or shell runs
				// the result, so a root command holds none but a whole-word
				// ${X} of unitVars (#4494).
				cmd := append([]string{prog}, words[1:]...)
				for i, w := range cmd[1:] {
					if !allowedVar(name, cmd, i+1, m.envLines) && substitutes(w, '$') {
						return nil, fmt.Errorf("%s: %s=%s: word %q holds a $ substitution, whose value a wrapper or shell may run; only a whole-word ${X} of unitVars is read", filepath.ToSlash(rel), l.key, l.value, w)
					}
				}
				// systemd passes $$NAME on as $NAME, which a shell expands
				// from the unit's environment, so a command reads only a name
				// systemd sets after the manager environment (D-271 item 5).
				for _, w := range cmd[1:] {
					for _, v := range shellVars(w) {
						if !systemdVars[v] {
							return nil, fmt.Errorf("%s: %s=%s: word %q reads $%s; a root unit's command reads only $SERVICE_RESULT, $EXIT_CODE or $EXIT_STATUS", filepath.ToSlash(rel), l.key, l.value, w, v)
						}
						if src := m.envSource(v); src != "" {
							return nil, fmt.Errorf("%s: %s=%s: word %q reads $%s, which %s may set; a root unit's command reads a systemd-set name only from systemd", filepath.ToSlash(rel), l.key, l.value, w, v, src)
						}
					}
				}
				pin, err := lists.rootCommand(name, cmd)
				if err != nil {
					return nil, fmt.Errorf("%s: %s=%s: %v", filepath.ToSlash(rel), l.key, l.value, err)
				}
				if !asRoot {
					continue // pinned, but it runs as the unit's user
				}
				// The program and those its pin says it starts are what
				// root runs. On top of the pin, a program's arguments may
				// name another a wrapper (with-uids execs "$@") or shell
				// runs, so every absolute token naming a broker binary
				// counts, in a quoted shell script, after = or inside $(
				// too: a data path of the same name only adds packages.
				ran := append([]string{cmd[0]}, pin.starts...)
				progs = append(progs, ran...)
				for _, w := range append(ran, cmd[1:]...) {
					// with-uids turns @uid:NAME and @gid:NAME into ids, so
					// an account name there runs nothing.
					for _, tok := range nameToken.FindAllString(accountWord.ReplaceAllString(w, ""), -1) {
						// A bare name counts too: a shell resolves it
						// through PATH (D-271 item 7).
						if pkg, ok := pkgs[path.Base(tok)]; ok && (strings.HasPrefix(tok, "/") || !strings.Contains(tok, "/")) {
							seen[pkg] = true
						}
					}
				}
			}
		}
		if !m.root {
			continue
		}
		// Every other key of a root unit is pinned or inert (D-271 item 2).
		for _, st := range m.settings {
			rel, _ := filepath.Rel(root, st.file)
			switch {
			case inertKeys[st.key] != "":
			case pinnedKeys[st.key]:
				if err := lists.rootSetting(name, st.key, st.value); err != nil {
					return nil, fmt.Errorf("%s: %s=%s: %v", filepath.ToSlash(rel), st.key, st.value, err)
				}
			default:
				return nil, fmt.Errorf("%s: %s=%s: the key is on neither pinnedKeys nor inertKeys, so a root unit may not set it (D-271)", filepath.ToSlash(rel), st.key, st.value)
			}
		}
	}
	if err := managerEnv(root); err != nil {
		return nil, err
	}
	if err := runBinaries(root, pkgs, seen, progs, lists); err != nil {
		return nil, err
	}

	var out []string
	for pkg := range seen {
		out = append(out, pkg)
	}
	sort.Strings(out)
	return out, nil
}

// plainFS are the file system types a mount may name: in-kernel types
// mount(8) mounts with no program of its own. Any other type may have a
// helper (nfs's mount.nfs starts rpc.statd), a FUSE type runs the program
// its source names as root, and a missing type is probed, so each is
// refused (#4380).
var plainFS = map[string]bool{
	"ext2": true, "ext3": true, "ext4": true, "xfs": true, "btrfs": true, "vfat": true, "msdos": true,
	"exfat": true, "iso9660": true, "udf": true, "squashfs": true, "erofs": true, "overlay": true,
	"tmpfs": true, "ramfs": true, "devtmpfs": true, "proc": true, "sysfs": true,
}

// ownerOptions are the mount options that set who may write the mounted
// tree, or (overlay's) where its writes land; a mode= is read instead.
var ownerOptions = map[string]bool{
	"uid": true, "gid": true, "umask": true, "fmask": true, "dmask": true, "upperdir": true, "workdir": true, "lowerdir": true,
	"X-mount.mode": true, "X-mount.owner": true, "X-mount.group": true, "X-mount.idmap": true,
}

// linkOptions are the mount options that put another tree over the mount
// point: a bind, a move, or a loop device on an image file (#4516).
var linkOptions = map[string]bool{"bind": true, "rbind": true, "move": true, "loop": true}

// mountOptions refuses an option list naming a helper: helper= and
// uhelper= make mount(8) or umount(8) run /sbin/umount.<name> as root.
// On a mount point in or above rootTrees (held), it also refuses an option
// of ownerOptions or linkOptions, and a mode= with a group or other write
// bit, any of which could hand that tree to another uid (#4494, #4516). A
// held list is read only if every byte is in heldOptionBytes: libmount
// keeps a quoted or \-escaped comma inside one value, so a mode= in
// x-a=",mode=0755," or x-a=a\,mode=0755 would be counted here and never
// reach the kernel (#4559 Security 1, delta 1). It reports whether the list
// holds a mode= it read.
func mountOptions(opts string, held bool) (bool, error) {
	if held && !heldOptionBytes.MatchString(opts) {
		return false, fmt.Errorf("options %s on a mount in or above a tree root reads or runs hold a byte other than a letter, digit or one of =,_-./, which mount(8) may split unlike this lint", opts)
	}
	moded := false
	for _, o := range strings.Split(opts, ",") {
		k, v, _ := strings.Cut(strings.TrimSpace(o), "=")
		switch {
		case k == "helper" || k == "uhelper":
			return false, fmt.Errorf("option %s names a program umount(8) runs as root", o)
		case held && k == "mode":
			if m, err := strconv.ParseUint(v, 8, 32); err != nil || m > 0o7777 || m&0o022 != 0 {
				return false, fmt.Errorf("option %s on a mount in or above a tree root reads or runs; want an octal mode with no group or other write bit", o)
			}
			moded = true
		case held && (ownerOptions[k] || linkOptions[k]):
			return false, fmt.Errorf("option %s on a mount in or above a tree root reads or runs", o)
		}
	}
	return moded, nil
}

// heldOptionBytes are the bytes a held mount's option list may hold.
var heldOptionBytes = regexp.MustCompile(`^[A-Za-z0-9=,_./-]*$`)

// heldSource reports whether a mount's source may sit over a tree root
// reads or runs: a name with no slash (tmpfs, UUID=x, LABEL=x) or a device
// under /dev, outside openDevs. A path elsewhere, /run/shm among them, or in
// openDevs names a directory or image file, which
// mount(8) binds or loop-mounts (#4516, #4559 L3 1, Security delta 1).
func heldSource(what string) bool {
	if strings.Contains(what, "%") {
		return false // a specifier the lint does not expand
	}
	if !strings.Contains(what, "/") {
		return true
	}
	if dotdot(what) {
		return false
	}
	what = path.Clean(what)
	_, open := inTree(what, openDevs)
	return strings.HasPrefix(what, "/dev/") && !open
}

// tmpfsTypes default their root directory to 1777 unless a mode= says
// otherwise.
var tmpfsTypes = map[string]bool{"tmpfs": true, "ramfs": true}

// unitEscape is systemd-escape's form of a byte in a unit name.
var unitEscape = regexp.MustCompile(`\\x[0-9a-fA-F]{2}`)

// mountWhere is the mount point a mount unit or drop-in directory name
// stands for (var-lib-x.mount is /var/lib/x, a \xNN escape is that byte),
// and whether it is held: in or above rootTrees, or a type drop-in such as
// mount.d, which reaches every mount.
func mountWhere(name string) bool {
	base, ok := strings.CutSuffix(strings.TrimSuffix(name, ".d"), ".mount")
	if !ok {
		return true
	}
	where := unitEscape.ReplaceAllStringFunc(strings.ReplaceAll(base, "-", "/"), func(e string) string {
		b, _ := strconv.ParseUint(e[2:], 16, 8)
		return string(rune(b))
	})
	where = "/" + strings.Trim(where, "/")
	_, held := inOrAbove(where, rootTrees)
	return held
}

// mountLines reads a .mount unit's files (the unit, then its drop-ins):
// every Type= must be plainFS and every Options= free of helpers; with
// unit, one of them must set Type=. Over a tree root reads or runs, What=
// must be heldSource, and a tmpfs or ramfs needs a mode= in every Options=
// (a later one replaces an earlier one, and drop-ins sort across
// directories), and at least one Options=.
func mountLines(root string, paths []string, unit bool) (bool, error) {
	typed, tmpfs, optioned, moded := false, false, false, true
	var where string
	for _, f := range paths {
		rel, _ := filepath.Rel(root, f)
		rel = filepath.ToSlash(rel)
		b, err := os.ReadFile(f)
		if err != nil {
			return false, err
		}
		ul, err := unitLines(string(b))
		if err != nil {
			return false, fmt.Errorf("%s: %v", rel, err)
		}
		// A drop-in applies to the unit it is read for, or alone to what its
		// directory names.
		name := filepath.Base(filepath.Dir(f))
		if unit {
			name = filepath.Base(paths[0])
		}
		held := mountWhere(name)
		if held {
			where = rel
		}
		for _, line := range ul {
			k, v := line.key, line.value
			switch {
			case line.section != "Mount":
				// systemd reads no Type= or Options= elsewhere.
			case k == "Type" && (!plainFS[v] || v == "overlay" && held):
				return false, fmt.Errorf("%s: Type=%s; want one of the plain file system types, whose mount runs no helper (and no overlay over a tree root reads or runs)", rel, v)
			case k == "Type":
				typed, tmpfs = true, tmpfs || held && tmpfsTypes[v]
			case k == "Options":
				m, err := mountOptions(v, held)
				if err != nil {
					return false, fmt.Errorf("%s: Options=%s: %v", rel, v, err)
				}
				optioned, moded = true, moded && m
			case k == "What" && held && !heldSource(v):
				return false, fmt.Errorf("%s: What=%s; over a tree root reads or runs, a mount's source is a device node under /dev, not a directory or image file (nor anything in /dev/shm, /dev/mqueue or a /dev/fd link)", rel, v)
			}
		}
	}
	if unit && !typed {
		return false, fmt.Errorf("%s: no Type=; mount(8) would probe the type and run its helper", filepath.ToSlash(paths[0]))
	}
	switch {
	case tmpfs && !optioned:
		return false, fmt.Errorf("%s: a tmpfs or ramfs over a tree root reads or runs, with no Options=; its root directory would be 1777, so set Options=mode=0755", where)
	case tmpfs && !moded:
		return false, fmt.Errorf("%s: a tmpfs or ramfs over a tree root reads or runs, with an Options= that sets no mode=; its root directory would be 1777, so give every Options= mode=0755", where)
	}
	return typed, nil
}

// fstabLines reads an fstab file as systemd-fstab-generator does, holding
// each line's type and options to mountLines' rules.
func fstabLines(root, f string) error {
	rel, _ := filepath.Rel(root, f)
	rel = filepath.ToSlash(rel)
	b, err := os.ReadFile(f)
	if err != nil {
		return err
	}
	return eachLine(string(b), "#", func(n int, line string) error {
		w := strings.Fields(line)
		var held bool
		if len(w) > 1 {
			_, held = inOrAbove(path.Clean(w[1]), rootTrees)
		}
		moded := false
		switch {
		case len(w) < 3 || !plainFS[w[2]] || w[2] == "overlay" && held:
			return fmt.Errorf("%s:%d: %q; want a plain file system type, whose mount runs no helper (and no overlay over a tree root reads or runs)", rel, n, line)
		case held && !heldSource(w[0]):
			return fmt.Errorf("%s:%d: source %s; over a tree root reads or runs, a mount's source is a device node under /dev, not a directory or image file (nor anything in /dev/shm, /dev/mqueue or a /dev/fd link)", rel, n, w[0])
		case len(w) > 3:
			m, err := mountOptions(w[3], held)
			if err != nil {
				return fmt.Errorf("%s:%d: %v", rel, n, err)
			}
			moded = m
		}
		if held && tmpfsTypes[w[2]] && !moded {
			return fmt.Errorf("%s:%d: %s on %s with no mode=; its root directory would be 1777 over a tree root reads or runs (systemd's own /run is mode=0755)", rel, n, w[2], w[1])
		}
		return nil
	})
}

// programsFile lists, relative to the repository root, the only programs a
// runKinds file may make root run (#4257, #4276, #4279).
const programsFile = "broker/kernel/privfile/root_programs.txt"

// commandsFile pins, relative to the repository root, every command a unit
// runs as root, whole (#4493, D-271).
const commandsFile = "broker/kernel/privfile/root_commands.txt"

// rootLists are the two allow-lists root is checked against: programs, from
// programsFile, the paths a runKinds file may make root run; and pins, from
// commandsFile, each one whole root command of one unit (D-271). The lint
// reads no argument of a root command for a program: a root command is
// pinned word for word in its unit, or it fails, so a new spelling, wrapper
// or argument is a command no pin admits.
type rootLists struct {
	programs map[string]bool // listed path -> a file runs it
	pins     []pin
	used     []bool // pins[i] is a shipped root command
}

// pin is one commandsFile entry: the unit whose root command it is, the
// command's words as execWords splits them, with no Exec prefix, the broker
// binaries its reason says it starts (a script's), and why.
type pin struct {
	line   int
	unit   string
	key    string // a setting's key, with value its value; empty for a command
	value  string
	cmd    []string
	starts []string
	reason string
}

// readLists reads programsFile and commandsFile. A repository with neither
// lets root run nothing. No absolute word of a pin, and no program its
// reason says it starts, is reached through a link a tree under image/
// ships (a mkosi.extra or overlay tree) or a pathAliases alias, so each path
// is counted as the program it names (#4559 Security delta 3 1).
func readLists(root string) (*rootLists, error) {
	l := &rootLists{programs: map[string]bool{}}
	b, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(programsFile)))
	if err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	for i, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		f := strings.Fields(line)
		if _, dup := l.programs[f[0]]; len(f) < 2 || !strings.HasPrefix(f[0], "/") || dup {
			return nil, fmt.Errorf("%s line %d: want one \"<absolute path> <reason>\" line per program, got %q", programsFile, i+1, line)
		}
		l.programs[f[0]] = false
	}
	if l.pins, err = readPins(root); err != nil {
		return nil, err
	}
	l.used = make([]bool, len(l.pins))
	var paths []string
	for _, p := range l.pins {
		paths = append(paths, p.starts...)
		for _, w := range p.cmd {
			if strings.HasPrefix(w, "/") {
				paths = append(paths, w)
			}
		}
	}
	for _, p := range paths {
		if unalias(p) != p {
			return nil, fmt.Errorf("%s pins %s, which is %s by a link every image has; pin the path it lands on", commandsFile, p, unalias(p))
		}
	}
	return l, shippedLinks(root, paths)
}

// readPins parses commandsFile. An entry is a line "<unit> <command>", the
// command written as an Exec value is, with no Exec prefix; a line that
// starts with a blank or tab continues it. Its reason is the comment block
// right above it, which a blank line ends; a comment line of +<path> words
// names the broker binaries the command's program starts (a script's).
func readPins(root string) ([]pin, error) {
	b, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(commandsFile)))
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []pin
	var reason, starts []string
	cur := -1 // the entry a continuation line extends
	text := map[int]string{}
	for i, line := range strings.Split(string(b), "\n") {
		switch {
		case strings.TrimSpace(line) == "":
			reason, starts, cur = nil, nil, -1
		case strings.HasPrefix(line, "#"):
			if cur >= 0 {
				reason = nil // a comment after an entry opens a new block
			}
			cur = -1
			c := strings.TrimSpace(strings.TrimPrefix(line, "#"))
			if !strings.HasPrefix(c, "+") {
				reason = append(reason, c)
				continue
			}
			for _, w := range strings.Fields(c) {
				p, ok := strings.CutPrefix(w, "+")
				if !ok || !strings.HasPrefix(p, "/") || path.Clean(p) != p {
					return nil, fmt.Errorf("%s line %d: %q: a program a pinned script starts is +<plain absolute path>", commandsFile, i+1, w)
				}
				starts = append(starts, p)
			}
		case line[0] == ' ' || line[0] == '\t':
			if cur < 0 {
				return nil, fmt.Errorf("%s line %d: a continuation with no entry above it", commandsFile, i+1)
			}
			text[cur] += " " + strings.TrimSpace(line)
		default:
			unit, cmd, _ := strings.Cut(line, " ")
			if len(reason) == 0 {
				return nil, fmt.Errorf("%s line %d: want the entry's reason in the comment block right above it", commandsFile, i+1)
			}
			// One block's reason covers each entry below it up to a
			// blank line or the next comment; its +<path> words, the
			// first entry only.
			out = append(out, pin{line: i + 1, unit: unit, starts: starts, reason: strings.Join(reason, " ")})
			cur, starts = len(out)-1, nil
			text[cur] = cmd
		}
	}
	for i := range out {
		if k, v, ok := strings.Cut(text[i], "="); ok && pinnedKeys[k] {
			out[i].key, out[i].value = k, v
			for j := range out[:i] {
				if out[j].unit == out[i].unit && out[j].key == k && out[j].value == v {
					return nil, fmt.Errorf("%s line %d: the setting line %d pins", commandsFile, out[i].line, out[j].line)
				}
			}
			continue
		}
		cmds, err := execWords(text[i])
		if err != nil {
			return nil, fmt.Errorf("%s line %d: %v", commandsFile, out[i].line, err)
		}
		c := cmds[0]
		if len(cmds) != 1 || len(c) == 0 || !strings.HasPrefix(c[0], "/") || path.Clean(c[0]) != c[0] || !unitTypes[path.Ext(out[i].unit)] {
			return nil, fmt.Errorf("%s line %d: want \"<unit> <one command, its program a plain absolute path>\"", commandsFile, out[i].line)
		}
		for j := range out[:i] {
			if out[j].unit == out[i].unit && slices.Equal(out[j].cmd, c) {
				return nil, fmt.Errorf("%s line %d: the command line %d pins", commandsFile, out[i].line, out[j].line)
			}
		}
		// A . or .. step names a path other than it reads (#4617
		// Security R-b).
		for _, w := range c {
			for _, tok := range nameToken.FindAllString(w, -1) {
				for _, part := range strings.Split(tok, "/") {
					if strings.Contains(tok, "/") && (part == "." || part == "..") {
						return nil, fmt.Errorf("%s line %d: word %q holds a %s step", commandsFile, out[i].line, w, part)
					}
				}
			}
		}
		out[i].cmd = c
	}
	return out, nil
}

// rootCommand returns the pin that admits one root command of unit, its
// words with no Exec prefix.
func (l *rootLists) rootCommand(unit string, cmd []string) (pin, error) {
	for i, p := range l.pins {
		if p.unit == unit && p.key == "" && slices.Equal(p.cmd, cmd) {
			l.used[i] = true
			return p, nil
		}
	}
	return pin{}, fmt.Errorf("%s pins no such command of this unit; root runs only a command pinned whole (D-271)", commandsFile)
}

// rootSetting fails a pinnedKeys setting of a unit with a root command
// unless a pin holds it, key and value.
func (l *rootLists) rootSetting(unit, key, value string) error {
	for i, p := range l.pins {
		if p.unit == unit && p.key == key && p.value == value {
			l.used[i] = true
			return nil
		}
	}
	return fmt.Errorf("the unit runs a root command, and %s pins no such setting of it; a setting that changes what a root command names or reads is pinned whole (D-271)", commandsFile)
}

// stale fails a list line no shipped file uses.
func (l *rootLists) stale() error {
	for p, used := range l.programs {
		if !used {
			return fmt.Errorf("%s lists %s, which no file runs", programsFile, p)
		}
	}
	for i, p := range l.pins {
		if !l.used[i] {
			return fmt.Errorf("%s line %d pins a command %s runs nowhere as root", commandsFile, p.line, p.unit)
		}
	}
	return nil
}

// shippedLinks fails a path whose own name, or a directory on the way to
// it, is a link in a tree under image/ that the image copies in as it is:
// a mkosi.extra tree or a buildroot overlay.
func shippedLinks(root string, paths []string) error {
	var trees []string
	err := filepath.WalkDir(filepath.Join(root, "image"), func(p string, d os.DirEntry, err error) error {
		switch {
		case err != nil && os.IsNotExist(err):
			return filepath.SkipDir
		case err != nil:
			return err
		case d.IsDir() && (d.Name() == "mkosi.extra" || d.Name() == "overlay"):
			trees = append(trees, p)
		}
		return nil
	})
	if err != nil {
		return err
	}
	for _, p := range paths {
		for _, t := range trees {
			for q := p; q != "/"; q = path.Dir(q) {
				if fi, err := os.Lstat(filepath.Join(t, filepath.FromSlash(q))); err == nil && fi.Mode()&os.ModeSymlink != 0 {
					rel, _ := filepath.Rel(root, filepath.Join(t, filepath.FromSlash(q)))
					return fmt.Errorf("%s is a link, so %s may name another program than it reads; a listed or pinned path is reached through no shipped link", filepath.ToSlash(rel), p)
				}
			}
		}
	}
	return nil
}

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
//
// A tmpfiles.d line that lets another uid write a path (a group or other
// write bit, sticky or not, since a sticky directory still takes a new
// file; or an owner other than root) fails on a path in or above rootTrees,
// progs (the programs units run as root) or a listed program (#4423).
func runBinaries(root string, pkgs map[string]string, seen map[string]bool, progs []string, lists *rootLists) error {
	listed := lists.programs
	var grants []grant
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
			read, err := kind.read(string(b))
			if err != nil {
				return fmt.Errorf("%s:%v", rel, err)
			}
			for _, prog := range read {
				if prog.grant != "" {
					grants = append(grants, grant{rel, prog})
					continue
				}
				if _, ok := listed[prog.path]; !ok {
					return fmt.Errorf("%s:%d: runs %q, which %s does not list; a %s may run only a listed absolute path", rel, prog.line, prog.path, programsFile, kind.what)
				}
				listed[prog.path] = true
				if pkg, ok := pkgs[path.Base(prog.path)]; ok {
					seen[pkg] = true
				}
			}
			return nil
		})
		if err != nil {
			return err
		}
	}
	held := append(append([]string{}, rootTrees...), progs...)
	for p := range listed {
		held = append(held, p)
	}
	for _, g := range grants {
		if h, ok := inOrAbove(g.prog.path, held); ok {
			return fmt.Errorf("%s:%d: %s %s, in or above %s, which root reads or runs; no other uid may write there", g.rel, g.prog.line, g.prog.grant, g.prog.path, h)
		}
	}
	return lists.stale()
}

// ruleProgram is a program a runKinds file makes root run, or, with grant
// set to how, a path a tmpfiles.d line lets another uid write.
type ruleProgram struct {
	path  string
	line  int
	grant string
}

type grant struct {
	rel  string
	prog ruleProgram
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

// helperParam matches a module parameter named like a program to run.
var helperParam = regexp.MustCompile(`(?i)helper|prog|cmd|exec`)

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
		case f[0] == "options" && len(f) < 2:
			return fmt.Errorf("%d: options takes a module", n)
		case f[0] == "options":
			// A module parameter can name a program the kernel runs as root
			// (drbd's usermode_helper, nfsd's cltrack_prog), resolved from /
			// if relative, so no value holds a / and no parameter is named
			// like a helper (#4423).
			for _, o := range f[2:] {
				k, v, _ := strings.Cut(o, "=")
				if strings.Contains(v, "/") || helperParam.MatchString(k) {
					return fmt.Errorf("%d: options %s %s; a parameter may name no program (no / in a value, no helper, prog, cmd or exec name)", n, f[1], o)
				}
			}
			return nil
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

// tmpfilesGrant says how a tmpfiles.d line's fields let a uid other than
// root write its path: a mode with the group or other write bit, or a
// user that is not root (:user too). "" if neither.
func tmpfilesGrant(f []string) string {
	if len(f) > 2 && f[2] != "-" {
		if d := f[2][len(f[2])-2:]; (d[0]-'0')&2 != 0 || (d[1]-'0')&2 != 0 {
			return "mode " + f[2]
		}
	}
	if len(f) > 3 {
		if u := strings.TrimPrefix(f[3], ":"); u != "-" && u != "root" && u != "0" {
			return "owner " + f[3]
		}
	}
	return ""
}

// tmpfilesPlain are the tmpfiles.d(5) types that only make a directory or
// subvolume, set a mode or owner, or ignore or remove what is at a path.
// The rest write content (f, w), copy (C), link (L), make a device node or
// fifo (c, b, p) or set an ACL, attribute or xattr (a, h, t, a file
// capability among them); only w is read, and only to /proc/sys.
var tmpfilesPlain = map[string]bool{"d": true, "D": true, "e": true, "v": true, "q": true, "Q": true, "z": true, "Z": true, "x": true, "X": true, "r": true, "R": true}

// tmpfilesHeld are the helper paths and binfmt_misc: a line other than w
// on a directory above one (a recursive Z among them) is refused (#4381).
var tmpfilesHeld = []string{
	"/proc/sys/kernel/core_pattern", "/proc/sys/kernel/modprobe", "/proc/sys/kernel/hotplug",
	"/proc/sys/kernel/poweroff_cmd", "/sys/kernel/uevent_helper", "/proc/sys/fs/binfmt_misc",
}

// tmpfilesPath is a path the reader resolves itself: absolute and clean,
// with no % specifier, glob or blank.
var tmpfilesPath = regexp.MustCompile(`^/[A-Za-z0-9_./@:+-]*$`)

// tmpfilesPrograms parses one tmpfiles.d file and returns the program each
// w line to a usermode helper writes (kernel.core_pattern's pipe,
// kernel.modprobe, kernel.hotplug, kernel.poweroff_cmd), or an error naming
// the first line it refuses: a path that is not plain, a type that is not
// plain or w, a w outside /proc/sys, any line on a helper but such a w or on
// a directory above one, a release_agent, and any line under
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
		if g := tmpfilesGrant(f); g != "" {
			progs = append(progs, ruleProgram{path: p, line: n, grant: g})
		}
		key := ""
		switch {
		case strings.HasPrefix(p, "/proc/sys/"):
			key = strings.ReplaceAll(strings.TrimPrefix(p, "/proc/sys/"), "/", ".")
		}
		above := ""
		for _, h := range tmpfilesHeld {
			if typ != "w" && typ != "w+" && (p == "/" || strings.HasPrefix(h, p+"/")) {
				above = h
			}
		}
		switch {
		case above != "":
			return fmt.Errorf("%d: %s on %s, a directory above %s, whose mode decides who sets a program root runs", n, f[0], p, above)
		case path.Base(p) == "release_agent":
			return fmt.Errorf("%d: %s names a cgroup v1 release_agent, a program the kernel runs as root", n, p)
		case key == "fs.binfmt_misc" || strings.HasPrefix(key, "fs.binfmt_misc."):
			return fmt.Errorf("%d: %s is under /proc/sys/fs/binfmt_misc, which registers an interpreter", n, p)
		case strings.HasPrefix(p, "/proc/") && key == "":
			return fmt.Errorf("%d: %s is in /proc but not /proc/sys", n, p)
		// sysfs holds root helpers the reader does not know (uevent_helper,
		// module parameters such as drbd's usermode_helper, cgroup v1
		// release_agent), and its links (a device's driver/module,
		// iommu_group) lead from a device to them, and systemd-tmpfiles
		// follows links on the path. So the only sysfs line read is a z on
		// /sys/class/<class>/<device>/<attribute>: the one link is the
		// device's own, into /sys/devices, and the attribute is its file
		// (#4381).
		case (p == "/sys" || strings.HasPrefix(p, "/sys/")) && (typ != "z" || !strings.HasPrefix(p, "/sys/class/") || strings.Count(p, "/") != 5):
			return fmt.Errorf("%d: %s %s; the only line in /sys is a z on /sys/class/<class>/<device>/<attribute>", n, f[0], p)
		case typ != "w" && typ != "w+" && sysctlHelpers[key]:
			return fmt.Errorf("%d: %s on %s; a helper is only written, with w", n, f[0], p)
		case typ == "w" || typ == "w+":
			// sysfs holds root helpers the reader does not know (module
			// parameters such as drbd's usermode_helper, uevent_helper), so
			// a w goes only to /proc/sys, read as sysctl.d is (#4381).
			if key == "" {
				return fmt.Errorf("%d: w to %s; a w line writes only under /proc/sys (a sysctl belongs in sysctl.d)", n, p)
			}
		case !tmpfilesPlain[typ]:
			return fmt.Errorf("%d: type %s writes, copies, links, makes a node or labels a file, which the lint does not read; ship the file itself under image/ instead", n, f[0])
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
// The shared lint loader type-checks each package against its
// dependencies' export data, so a use is an identifier that resolves to the
// os function, whatever name or import form spells it, and a type error
// fails the lint (#4256); a file of those packages no build here reads, but
// one of these platforms could compile, fails it too (#4273).
func rootSideUses(root string, bins []string) ([]use, error) {
	if len(bins) == 0 {
		return nil, nil
	}
	seen := map[use]bool{}
	var uses []use
	var loads []*lintload.Loaded
	for _, arch := range []string{"amd64", "arm64"} {
		l, err := lintload.Load(filepath.Join(root, "broker"), lintload.Build{
			Env:    []string{"CGO_ENABLED=0", "GOOS=linux", "GOARCH=" + arch},
			Module: true,
		}, bins...)
		if err != nil {
			return nil, fmt.Errorf("go list (%s): %v", arch, err)
		}
		loads = append(loads, l)
		for _, p := range l.Packages {
			for _, f := range p.Files {
				rel, err := filepath.Rel(root, l.Fset.File(f.Pos()).Name())
				if err != nil {
					return nil, err
				}
				for _, u := range fileUses(l.Fset, f, p.Info, filepath.ToSlash(rel)) {
					if !seen[u] {
						seen[u] = true
						uses = append(uses, u)
					}
				}
			}
		}
	}
	unread, err := lintload.Unread(loads...)
	if err != nil {
		return nil, err
	}
	if len(unread) > 0 {
		return nil, fmt.Errorf("root-side files the lint does not read (another tag, cgo, assembly or syso): %s", strings.Join(unread, " "))
	}
	return uses, nil
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
					uses = append(uses, use{file: rel, fn: fn, op: op, line: fset.PositionFor(n.Pos(), false).Line})
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
