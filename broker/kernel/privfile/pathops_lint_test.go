package privfile

// REQ: KRN-2

// The root-side path lint (REV-CHK-links, #3900). A file operation a root
// process makes by path follows any link on that path, so a guest, clerk or
// other uid that can plant one in a directory on it redirects the write,
// removal or read (#3282, #3382, #3624). The root side is derived, not
// listed: every binary a shipped .service or .socket unit (#4330) starts
// with no User= or DynamicUser= (or on an Exec line with a + or ! prefix),
// each Exec program a plain absolute path, read across continued lines,
// sections, quotes and ;, with no substitution in what a wrapper runs
// (#4390, #4494); every broker binary named as a mount, umount, fsck or
// mkfs helper, a .mount unit, mount drop-in or fstab line naming only a
// plain type and no helper option (#4380), and over a tree root reads or
// runs no bind, move or loop, a source only a device under /dev outside
// openDevs, with no .. step or % specifier, options of only letters,
// digits and =,_-./, and a tmpfs only with a mode no other uid writes
// (#4516);
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
// operations of non-root host processes are outside the check, as is what
// a wrapper or shell in a root command runs beyond the absolute broker paths
// it names (a bare name on PATH, a relative path, a shell's own expansion,
// a change of directory, a program in a tree another uid writes: #4493,
// which replaces this with an allow-list of root programs), and a mount
// drop-in read alone for a packaged unit, whose type the lint does not see,
// and what a rootOwned EnvironmentFile= holds.
// A root unit's own namespace, search, stream and credential settings are
// read (rootPathKeys, #4589), and its Environment= sets only rootEnv names;
// rootOwned means in rootTrees, so a root unit's WorkingDirectory=
// /var/lib/agentos is refused. builtUnits holds the units of the image's
// built root file system to the same rules, each with the files its own
// systemd applies (image/unit_rules.py), a packaged unit's User= and
// drop-ins and generated units included (#4677). The initrd's and the
// camera node's units are outside that check (#4718).

import (
	"encoding/json"
	"errors"
	"fmt"
	"go/ast"
	"go/token"
	"go/types"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
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
	for name, unit := range map[string]string{
		"a unit without User=":                "[Service]\nExecStart=/usr/lib/agentos/with-uids /usr/lib/agentos/agentos-side -x @uid:y\n",
		"a + line in a unit with User=":       "[Service]\nUser=agentos-side\nExecStartPre=+/usr/lib/agentos/agentos-side\n",
		"a unit whose User= is commented out": "[Service]\n# User=agentos-side\nExecStart=/usr/lib/agentos/agentos-side\n",
		// #4390: what systemd joins, splits or unquotes is read as it does.
		"a wrapper's continued line":       "[Service]\nExecStart=/usr/lib/agentos/with-uids \\\n# a comment inside the run\n\t/usr/lib/agentos/agentos-side -x\n",
		"a second command after ;":         "[Service]\nExecStartPre=/bin/true ; /usr/lib/agentos/agentos-side\n",
		"a quoted program":                 "[Service]\nExecStart=\"/usr/lib/agentos/agentos-side\"\n",
		"a path in a shell script":         "[Service]\nExecStart=/bin/sh -c 'exec /usr/lib/agentos/agentos-side'\n",
		"a path after = in an argument":    "[Service]\nExecStart=/usr/lib/agentos/launch -run=/usr/lib/agentos/agentos-side\n",
		"an empty reset, then a root line": "[Service]\nExecStart=\nExecStart=-/usr/lib/agentos/agentos-side\n",
		// #4494 Security 1: only an unescaped last backslash continues.
		"a line ending in an escaped backslash": "[Service]\nSyslogIdentifier=x\\\\\nExecStart=/usr/lib/agentos/agentos-side\n",
		"a blank after a backslash":             "[Service]\nSyslogIdentifier=x \\ \nExecStart=/usr/lib/agentos/agentos-side\n",
		"a User= outside [Service]":             "[Unit]\nUser=agentos-side\n[Service]\nExecStart=/usr/lib/agentos/agentos-side\n",
		"a [Socket] User= in a .service":        "[Socket]\nUser=agentos-side\n[Service]\nExecStart=/usr/lib/agentos/agentos-side\n",
		"a template User=%i":                    "[Service]\nUser=%i\nExecStart=/usr/lib/agentos/agentos-side\n",
		"a template User=r%i":                   "[Service]\nUser=r%i\nExecStart=/usr/lib/agentos/agentos-side\n",
		"a template User=0%i":                   "[Service]\nUser=0%i\nExecStart=/usr/lib/agentos/agentos-side\n",
		"literal $$ and %%":                     "[Service]\nExecStart=/usr/lib/agentos/agentos-side -x $$HOME 100%%\n",
		"a shell's own $( in a script":          "[Service]\nExecStart=/bin/sh -c 'exec /usr/lib/agentos/agentos-side $(cat /x)'\n",
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
		"a .socket without User=":          {"image/mkosi/agentos-side.socket", "[Socket]\nListenStream=/run/agentos-side/s\nExecStartPre=/usr/lib/agentos/agentos-side\n"},
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
		// #4626 R-3: pam_env lays its variables over the unit's.
		"a pinned variable under PAMName=":         {"image/mkosi/agentosd.service", "[Service]\nEnvironment=AGENTOS_OWNER=\nPAMName=login\nExecStart=/usr/lib/agentos/with-uids /usr/lib/agentos/agentosd -owner ${AGENTOS_OWNER}\n", `holds a $ substitution`},
		"a pinned variable PassEnvironment= names": {"image/mkosi/agentosd.service", "[Service]\nEnvironment=AGENTOS_OWNER=\nPassEnvironment=X AGENTOS_OWNER\nExecStart=/usr/lib/agentos/with-uids /usr/lib/agentos/agentosd -owner ${AGENTOS_OWNER}\n", `holds a $ substitution`},
	} {
		t.Run("refuses "+name, func(t *testing.T) {
			files := clone(files)
			files[c.path] = c.text
			if bins, err := rootBinaries(fakeRepo(t, files)); err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("got %q, %v, want a refusal with %q", bins, err, c.want)
			}
		})
	}
	// #4494 L3 2: ExecPaths= and ExecSearchPath= are paths, not commands.
	t.Run("a root unit whose paths name a binary it does not run", func(t *testing.T) {
		files := clone(files)
		files["image/mkosi/agentos-side.service"] = "[Service]\nExecStart=/bin/true\nExecPaths=/usr/lib/agentos/agentos-side\nExecSearchPath=/usr/lib/agentos/agentos-side\n"
		if bins := set(t, files); len(bins) != 0 {
			t.Fatalf("got %q, want none", bins)
		}
	})
	t.Run("a [Service] User= in a .socket", func(t *testing.T) {
		files := clone(files)
		files["image/mkosi/agentos-side.socket"] = "[Service]\nUser=agentos-side\n[Socket]\nExecStartPre=/usr/lib/agentos/agentos-side\n"
		if bins := set(t, files); len(bins) != 1 || bins[0] != "./cmd/agentos-side" {
			t.Fatalf("got %q, want [./cmd/agentos-side]", bins)
		}
	})
	t.Run("refuses a pinned variable another env file may fill", func(t *testing.T) {
		files := clone(files)
		files["image/mkosi/agentosd.service"] = "[Service]\nEnvironment=AGENTOS_OWNER=\nEnvironmentFile=-/etc/agentos/agentosd.env\nExecStart=/usr/lib/agentos/with-uids /usr/lib/agentos/agentosd -owner ${AGENTOS_OWNER}\n"
		if _, err := rootBinaries(fakeRepo(t, files)); err != nil {
			t.Fatalf("the pinned env file alone: %v", err)
		}
		files["image/mkosi/agentosd.service.d/z.conf"] = "[Service]\nEnvironmentFile=/var/tmp/x.env\n"
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
			"[Service]\nEnvironment=\nEnvironment=AGENTOS_OWNER= GOMEMLIMIT=1\n":     true,
			"[Service]\nEnvironment=GOMEMLIMIT=1\n":                                  true,
			"[Service]\nEnvironment=\n":                                              false,
			"[Service]\nEnvironment=AGENTOS_OWNER=\nEnvironment=\n":                  false,
			"[Service]\nEnvironment=\nPassEnvironment=AGENTOS_OWNER\n":               false,
			"[Service]\nEnvironment=AGENTOS_OWNER=\nPassEnvironment=AGENTOS_OWNER\n": false,
			"[Service]\nPAMName=login\n":                                             false,
		} {
			files["image/mkosi/agentosd.service.d/z.conf"] = dropin
			if _, err := rootBinaries(fakeRepo(t, files)); (err == nil) != ok || err != nil && !strings.Contains(err.Error(), "holds a $ substitution") {
				t.Errorf("drop-in %q: got %v, want accepted %v", dropin, err, ok)
			}
		}
	})
	t.Run("a pinned variable where unitVars pins it", func(t *testing.T) {
		files := clone(files)
		files["image/mkosi/agentosd.service"] = "[Service]\nEnvironment=GOMEMLIMIT=1 AGENTOS_OWNER=\nExecStart=/usr/lib/agentos/with-uids /usr/lib/agentos/agentosd -owner ${AGENTOS_OWNER}\n"
		if _, err := rootBinaries(fakeRepo(t, files)); err != nil {
			t.Fatal(err)
		}
	})
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

// A root unit's namespace and search settings decide what its commands
// read, run and search, so each path they name lies in a tree root owns
// (#4589); the directories a unit makes for its user are grants, held out of
// what root runs like a tmpfiles.d grant (#4584).
func TestRootSideUnitPathsAndGrants(t *testing.T) {
	const unit = "image/mkosi/agentos-root.service"
	files := map[string]string{
		"broker/cmd/agentos-side/main.go": "package main\n\nfunc main() {}\n",
		// The shapes shipped units use.
		unit: "[Service]\nExecStart=/usr/lib/agentos/agentos-side\nTemporaryFileSystem=/:ro,noexec /run/agentos-setup:ro /etc/agentos/t\nBindReadOnlyPaths=/usr/lib/agentos/agentos-side\n" +
			"Environment=GOMEMLIMIT=1 PATH=/usr/bin:/usr/sbin\nEnvironmentFile=-/etc/agentos/x.env\nWorkingDirectory=-/etc/agentos\nExecSearchPath=/usr/bin\nStateDirectory=agentos/modem\nRuntimeDirectory=agentos-root\n",
		// No root command: what it binds and searches is its user's.
		"image/mkosi/agentos-user.service": "[Service]\nUser=agentos-user\nExecStart=/usr/lib/agentos/agentos-side\nBindPaths=/var/lib/agentos-user:/usr/lib/agentos\nWorkingDirectory=/tmp\nEnvironment=PATH=/tmp\n" +
			"RuntimeDirectory=agentos-user\nStateDirectory=agentos-user:agentos-u\nConfigurationDirectory=agentos-user\n",
	}
	if _, err := rootBinaries(fakeRepo(t, files)); err != nil {
		t.Fatalf("shipped shapes: %v", err)
	}
	t.Run("shipped shapes under systemd", func(t *testing.T) {
		if err := underSystemd(t, imageUnits(files), nil); err != nil {
			t.Fatalf("shipped shapes in a tree: %v", err)
		}
	})
	for name, c := range map[string]struct{ path, text, want string }{
		// #4589.
		"a root directory in /tmp":         {unit, "[Service]\nExecStart=/bin/true\nRootDirectory=/tmp/r\n", `path "/tmp/r"`},
		"a root image in /var/tmp":         {unit, "[Service]\nExecStart=/bin/true\nRootImage=/var/tmp/x.img\n", `path "/var/tmp/x.img"`},
		"a mount image in /tmp":            {unit, "[Service]\nExecStart=/bin/true\nMountImages=-/tmp/x.img:/usr/lib/agentos:ro\n", `path "/tmp/x.img"`},
		"a writable bind over /usr":        {unit, "[Service]\nExecStart=/bin/true\nBindPaths=/var/lib/agentos-x:/usr/lib/agentos\n", `path "/var/lib/agentos-x"`},
		"a second bind source":             {unit, "[Service]\nExecStart=/bin/true\nBindReadOnlyPaths=/usr/lib/x -/run/x:/etc/x\n", `path "/run/x"`},
		"a .. in a bind source":            {unit, "[Service]\nExecStart=/bin/true\nBindReadOnlyPaths=/usr/../tmp/x:/usr/lib/agentos\n", `path "/usr/../tmp/x"`},
		"an alias out of a root tree":      {unit, "[Service]\nExecStart=/bin/true\nBindReadOnlyPaths=/var/run/x:/usr/lib/agentos\n", `path "/var/run/x"`},
		"a 1777 tmpfs over /usr":           {unit, "[Service]\nExecStart=/bin/true\nTemporaryFileSystem=/usr/lib/agentos:mode=1777\n", `option mode=1777`},
		"an owned tmpfs over /etc":         {unit, "[Service]\nExecStart=/bin/true\nTemporaryFileSystem=/etc/x:uid=1000\n", `option uid=1000`},
		"a .. in a tmpfs":                  {unit, "[Service]\nExecStart=/bin/true\nTemporaryFileSystem=/run/x/../systemd\n", `with no ..`},
		"a relative tmpfs":                 {unit, "[Service]\nExecStart=/bin/true\nTemporaryFileSystem=usr\n", `TemporaryFileSystem= path "usr"; want an absolute path with no ..`},
		"an extension directory":           {unit, "[Service]\nExecStart=/bin/true\nExtensionDirectories=/var/tmp/ext\n", `path "/var/tmp/ext"`},
		"an extension image":               {unit, "[Service]\nExecStart=/bin/true\nExtensionImages=-/tmp/e.raw:ro\n", `path "/tmp/e.raw"`},
		"a working directory in /tmp":      {unit, "[Service]\nExecStart=/bin/sh -c x\nWorkingDirectory=-/var/tmp\n", `path "/var/tmp"`},
		"a home working directory":         {unit, "[Service]\nExecStart=/bin/true\nWorkingDirectory=~\n", `byte "~", a byte other than`},
		"a specifier path":                 {unit, "[Service]\nExecStart=/bin/true\nRootDirectory=%t/r\n", `a byte other than`},
		"a quoted path":                    {unit, "[Service]\nExecStart=/bin/true\nBindPaths=\"/tmp/x\"\n", `a byte other than`},
		"a specifier in PATH":              {"image/mkosi/agentos-t@.service", "[Service]\nExecStart=/usr/bin/env helper\nEnvironment=PATH=/usr/%I\n", `holds a % specifier`},
		"a specifier in another variable":  {unit, "[Service]\nExecStart=/usr/bin/env helper\nEnvironment=A=%h\n", `holds a % specifier`},
		"a PATH in /tmp":                   {unit, "[Service]\nExecStart=/usr/bin/env helper\nEnvironment=PATH=/tmp\n", `path "/tmp"`},
		"a PATH with an empty entry":       {unit, "[Service]\nExecStart=/usr/bin/env helper\nEnvironment=GOMEMLIMIT=1 PATH=/usr/bin:\n", `path ""`},
		"a later PATH entry":               {unit, "[Service]\nExecStart=/usr/bin/env helper\nEnvironment=PATH=/usr/bin:/var/tmp GOMEMLIMIT=2\n", `path "/var/tmp"`},
		"an escaped Environment=":          {unit, "[Service]\nExecStart=/usr/bin/env helper\nEnvironment=P\\x41TH=/tmp\n", `a backslash`},
		"a search path in /tmp":            {unit, "[Service]\nExecStart=/usr/bin/env helper\nExecSearchPath=/usr/bin:/tmp\n", `path "/tmp"`},
		"an env file in /var/tmp":          {unit, "[Service]\nExecStart=/bin/true\nEnvironmentFile=-/var/tmp/x.env\n", `path "/var/tmp/x.env"`},
		"a bind in a drop-in":              {"image/mkosi/agentos-.service.d/z.conf", "[Service]\nBindPaths=/var/lib/agentos-x:/usr/lib/agentos\n", `path "/var/lib/agentos-x"`},
		"a working directory for a + line": {"image/mkosi/agentos-user.service", "[Service]\nUser=agentos-user\nExecStartPre=+/bin/sh -c x\nWorkingDirectory=/tmp\n", `path "/tmp"`},
		// #4584.
		"a runtime directory over a root program": {unit, "[Service]\nUser=agentos-x\nRuntimeDirectory=agentos-x\nExecStartPre=+/run/agentos-x/helper\n", `the unit's user owns /run/agentos-x`},
		"a state directory over another unit's":   {"image/mkosi/agentos-x.service", "[Service]\nUser=agentos-x\nExecStart=/bin/true\nStateDirectory=agentos-x\n", `/var/lib/agentos-x, in or above /var/lib/agentos-x/h`},
		"a template user's directory":             {"image/mkosi/agentos-x@.service", "[Service]\nUser=%i\nExecStart=/bin/true\nStateDirectory=agentos-x\n", `the unit's user owns /var/lib/agentos-x, in or above`},
		"a dynamic user's private directory":      {"image/mkosi/agentos-x.service", "[Service]\nDynamicUser=yes\nExecStart=/bin/true\nCacheDirectory=agentos-x\n", `/var/cache/private/agentos-x, in or above`},
		"a linked logs directory":                 {"image/mkosi/agentos-x.service", "[Service]\nUser=agentos-x\nExecStart=/bin/true\nLogsDirectory=agentos-l:agentos-x\n", `/var/log/agentos-x, in or above`},
		"a user set in a drop-in":                 {"image/mkosi/agentos-x.service.d/z.conf", "[Service]\nUser=agentos-x\n", `/var/lib/agentos-x, in or above`},
		"a parent directory":                      {"image/mkosi/agentos-x.service", "[Service]\nUser=agentos-x\nExecStart=/bin/true\nRuntimeDirectory=systemd\n", `the unit's user owns /run/systemd, in or above /run/systemd`},
		"an open mode on a root unit":             {"image/mkosi/agentos-x.service", "[Service]\nExecStart=/bin/true\nStateDirectory=agentos-x\nStateDirectoryMode=0777\n", `mode 0777 /var/lib/agentos-x`},
		"a group-writable mode":                   {"image/mkosi/agentos-x.service", "[Service]\nGroup=agentos-x\nExecStart=/bin/true\nStateDirectory=agentos-x\nStateDirectoryMode=0775\n", `mode 0775 /var/lib/agentos-x`},
		"an unread mode":                          {"image/mkosi/agentos-x.service", "[Service]\nExecStart=/bin/true\nStateDirectory=agentos-x\nStateDirectoryMode=u=rwx\n", `mode u=rwx`},
		"an open configuration directory":         {"image/mkosi/agentos-x.service", "[Service]\nUser=agentos-x\nExecStart=/bin/true\nConfigurationDirectory=agentos-x\nConfigurationDirectoryMode=0770\n", `mode 0770 /etc/agentos-x, in or above /etc`},
		"a .. directory":                          {"image/mkosi/agentos-x.service", "[Service]\nExecStart=/bin/true\nRuntimeDirectory=x/../systemd\n", `want a plain relative path`},
		"an absolute directory":                   {"image/mkosi/agentos-x.service", "[Service]\nExecStart=/bin/true\nRuntimeDirectory=/etc/x\n", `want a plain relative path`},
		// #4677 Security R-2: what else a root unit loads or reads.
		"a preload":                   {unit, "[Service]\nExecStart=/bin/true\nEnvironment=LD_PRELOAD=/tmp/x.so\n", `variable "LD_PRELOAD"`},
		"a shell's env file":          {unit, "[Service]\nExecStart=/bin/sh -c x\nEnvironment=GOMEMLIMIT=1 BASH_ENV=/tmp/x\n", `variable "BASH_ENV"`},
		"a bare variable name":        {unit, "[Service]\nExecStart=/bin/true\nEnvironment=LD_LIBRARY_PATH\n", `variable "LD_LIBRARY_PATH"`},
		"an input file":               {unit, "[Service]\nExecStart=/bin/true\nStandardInput=file:/tmp/x\n", `path "/tmp/x"`},
		"an appended output":          {unit, "[Service]\nExecStart=/bin/true\nStandardOutput=append:/var/tmp/log\n", `path "/var/tmp/log"`},
		"a truncated error":           {unit, "[Service]\nExecStart=/bin/true\nStandardError=truncate:/run/x\n", `path "/run/x"`},
		"a credential in /tmp":        {unit, "[Service]\nExecStart=/bin/true\nLoadCredential=a:/tmp/x\n", `path "/tmp/x"`},
		"a searched credential":       {unit, "[Service]\nExecStart=/bin/true\nLoadCredential=a\n", `path ""`},
		"a relative credential":       {unit, "[Service]\nExecStart=/bin/true\nLoadCredentialEncrypted=a:a.cred\n", `path "a.cred"`},
		"a root hash file":            {unit, "[Service]\nExecStart=/bin/true\nRootHash=/tmp/h\n", `path "/tmp/h"`},
		"a root hash signature file":  {unit, "[Service]\nExecStart=/bin/true\nRootHashSignature=/tmp/s\n", `path "/tmp/s"`},
		"a verity file":               {unit, "[Service]\nExecStart=/bin/true\nRootVerity=/tmp/v\n", `path "/tmp/v"`},
		"a terminal in /tmp":          {unit, "[Service]\nExecStart=/bin/true\nTTYPath=/tmp/tty\n", `path "/tmp/tty"`},
		"an opened file":              {unit, "[Service]\nExecStart=/bin/true\nOpenFile=/var/lib/agentos-x/f:fd\n", `path "/var/lib/agentos-x/f"`},
		"an opened file with a blank": {unit, "[Service]\nExecStart=/bin/true\nOpenFile=/usr /etc:fd\n", `path "/usr /etc"`},
		"an imported credential":      {unit, "[Service]\nExecStart=/bin/true\nImportCredential=*\n", `ImportCredential= searches`},
		"a named import":              {unit, "[Service]\nExecStart=/bin/true\nImportCredential=a\n", `ImportCredential= searches`},
		"a BPF program":               {unit, "[Service]\nExecStart=/bin/true\nBPFProgram=egress:/tmp/p\n", `path "/tmp/p"`},
		"an ingress filter":           {unit, "[Service]\nExecStart=/bin/true\nIPIngressFilterPath=/tmp/f\n", `path "/tmp/f"`},
		"an egress filter":            {unit, "[Service]\nExecStart=/bin/true\nIPEgressFilterPath=/usr:/tmp\n", `path "/usr:/tmp"`},
		"a network namespace":         {unit, "[Service]\nExecStart=/bin/true\nNetworkNamespacePath=/run/x/net\n", `path "/run/x/net"`},
		"an IPC namespace":            {unit, "[Service]\nExecStart=/bin/true\nIPCNamespacePath=/tmp/ipc\n", `path "/tmp/ipc"`},
		// #4677 Security R-3: a single path is read whole.
		"a working directory with a colon": {unit, "[Service]\nExecStart=/bin/true\nWorkingDirectory=/usr:/tmp\n", `path "/usr:/tmp"`},
		"a working directory with a blank": {unit, "[Service]\nExecStart=/bin/true\nWorkingDirectory=-/usr /etc\n", `path "/usr /etc"`},
		"a root directory with a colon":    {unit, "[Service]\nExecStart=/bin/true\nRootDirectory=/usr:/tmp\n", `path "/usr:/tmp"`},
		"a root image with a colon":        {unit, "[Service]\nExecStart=/bin/true\nRootImage=/usr:/tmp\n", `path "/usr:/tmp"`},
		"an env file with a colon":         {unit, "[Service]\nExecStart=/bin/true\nEnvironmentFile=-/usr:/tmp\n", `path "/usr:/tmp"`},
		"a verity file with a colon":       {unit, "[Service]\nExecStart=/bin/true\nRootVerity=/usr:/tmp\n", `path "/usr:/tmp"`},
		"a terminal with a colon":          {unit, "[Service]\nExecStart=/bin/true\nTTYPath=/usr:/tmp\n", `path "/usr:/tmp"`},
		"a network namespace with a colon": {unit, "[Service]\nExecStart=/bin/true\nNetworkNamespacePath=/usr:/tmp\n", `path "/usr:/tmp"`},
		"an IPC namespace with a colon":    {unit, "[Service]\nExecStart=/bin/true\nIPCNamespacePath=/etc:/tmp\n", `path "/etc:/tmp"`},
		"an extension directory w/ colon":  {unit, "[Service]\nExecStart=/bin/true\nExtensionDirectories=-/usr/x /usr:/tmp\n", `path "/usr:/tmp"`},
		// #4677 Security R-5 and L3-R2.
		"a dot directory":                    {"image/mkosi/agentos-x.service", "[Service]\nExecStart=/bin/true\nRuntimeDirectory=.\n", `want a plain relative path below the base`},
		"a dot directory on a user unit":     {"image/mkosi/agentos-x.service", "[Service]\nUser=agentos-x\nExecStart=/bin/true\nRuntimeDirectory=systemd .\n", `"."`},
		"a specifier in a granted directory": {"image/mkosi/agentos-x@.service", "[Service]\nUser=agentos-x\nExecStart=/bin/true\nRuntimeDirectory=agentos-%i\n", `holds a % specifier`},
		"a specifier in an open directory":   {"image/mkosi/agentos-x@.service", "[Service]\nExecStart=/bin/true\nRuntimeDirectory=agentos-%i\nRuntimeDirectoryMode=0777\n", `holds a % specifier`},
	} {
		t.Run("refuses "+name, func(t *testing.T) {
			files := clone(files)
			// A root program in each tree a grant case names.
			files["image/mkosi/agentos-h.service"] = "[Service]\nExecStart=/var/lib/agentos-x/h\nExecStartPre=/var/cache/private/agentos-x/h\nExecStartPost=/var/log/agentos-x/h\n"
			files["image/mkosi/agentos-x.service"] = "[Service]\nExecStart=/bin/true\nStateDirectory=agentos-x\n"
			files[c.path] = c.text
			if bins, err := rootBinaries(fakeRepo(t, files)); err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("got %q, %v, want a refusal with %q", bins, err, c.want)
			}
			if err := underSystemd(t, imageUnits(files), nil); err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("under systemd: got %v, want a refusal with %q", err, c.want)
			}
		})
	}
	t.Run("a grant root runs nothing in", func(t *testing.T) {
		files := clone(files)
		files["image/mkosi/agentos-x.service"] = "[Service]\nUser=agentos-x\nExecStart=/bin/true\nRuntimeDirectory=agentos-x\nStateDirectory=agentos-x\nStateDirectoryMode=0700\n"
		files["image/mkosi/agentos-h.service"] = "[Service]\nExecStart=/var/lib/agentos-y/h\nRuntimeDirectory=agentos-r\nRuntimeDirectoryMode=0755\n"
		if _, err := rootBinaries(fakeRepo(t, files)); err != nil {
			t.Fatal(err)
		}
	})
	// #4677: a root unit's streams, credentials and hashes that name no
	// path or a rootOwned one; a packaged unit's drop-in as shipped; a %
	// directory that grants nothing.
	t.Run("root settings that load from root trees", func(t *testing.T) {
		files := clone(files)
		files["image/mkosi/agentos-x@.service"] = "[Service]\nExecStart=/bin/true\nStandardInput=socket\nStandardOutput=journal+console\nStandardError=file:/run/systemd/x\nOpenFile=/etc/agentos/f:f:read-only\nBPFProgram=egress:/usr/lib/x\nImportCredential=\n" +
			"LoadCredential=a:/etc/credstore/a\nRootHash=0fa1\nRootHashSignature=base64:AAA=\nRootVerity=/usr/lib/x.verity\nExtensionDirectories=-/usr/lib/x /etc/y\n" +
			"WorkingDirectory=\nRuntimeDirectory=agentos-%i\n"
		files["image/mkosi/systemd-networkd-wait-online.service.d/agentos-unplugged.conf"] = "[Service]\nExecStart=\nExecStart=-/usr/lib/systemd/systemd-networkd-wait-online --any --timeout=5\n"
		files["image/mkosi/systemd-networkd.service.d/agentos-inbound.conf"] = "[Unit]\nRequires=agentos-inbound.service\n"
		if _, err := rootBinaries(fakeRepo(t, files)); err != nil {
			t.Fatal(err)
		}
		if err := underSystemd(t, imageUnits(files), nil); err != nil {
			t.Fatal(err)
		}
	})
}

// The unit-rule fixtures run through what CI runs on each built tree:
// image/unit_rules.py, the runner's own systemd in test mode deciding each
// unit's files, masks and order, then builtUnits (#4677, Mark's option A on
// #4698). They need root and systemd, so they run in the image workflow
// (AGENTOS_REQUIRE_SYSTEMD=1 there turns the skip into a failure). ours
// says which files are ours: any other regular file counts as a package's.
func TestUnitRulesUnderSystemd(t *testing.T) {
	const (
		lib = "/usr/lib/systemd/system/"
		etc = "/etc/systemd/system/"
	)
	pkg := func(string) bool { return false }
	ourDropins := func(p string) bool { return strings.Contains(p, ".d/") || p == "/etc/fstab" }
	ourEtc := func(p string) bool { return strings.HasPrefix(p, "/etc/") }
	root := "[Service]\nExecStart=/usr/lib/systemd/systemd-udevd\n"
	user := "[Service]\nUser=systemd-x\nExecStart=/usr/lib/systemd/systemd-x\n"
	bad := "[Service]\nEnvironment=LD_PRELOAD=/tmp/x.so\n"
	badRoot := "[Service]\nExecStart=/bin/true\nEnvironment=LD_PRELOAD=/tmp/x.so\n"
	udevSocket := "[Socket]\nService=systemd-udevd.service\nListenSequentialPacket=/run/udev/control\nSocketMode=0600\n"
	udev := map[string]string{lib + "systemd-udevd.service": root, lib + "systemd-udevd-control.socket": udevSocket}
	devlog := map[string]string{lib + "systemd-journald-dev-log.socket": "[Socket]\nService=systemd-journald.service\nListenDatagram=/run/systemd/journal/dev-log\nSymlinks=/dev/log\nSocketMode=0666\n", lib + "systemd-journald.service": root}
	dbus := map[string]string{lib + "dbus.socket": "[Socket]\nListenStream=/run/dbus/system_bus_socket\n", lib + "dbus.service": "[Service]\nUser=messagebus\nExecStart=/usr/bin/dbus-daemon --system\n"}
	foo := map[string]string{lib + "foo.socket": "[Socket]\nListenStream=2222\nIPAddressDeny=any\nPrivateNetwork=yes\n", lib + "foo.service": root}
	inst := map[string]string{lib + "foo.socket": "[Socket]\nListenStream=2222\nService=bar@x.service\n"}
	ssh := map[string]string{lib + "ssh.socket": "[Socket]\nListenStream=2222\nAccept=yes\n", lib + "ssh@.service": "[Service]\nExecStart=-/usr/sbin/sshd -i\nStandardInput=socket\n"}
	with := func(base map[string]string, more ...string) map[string]string {
		out := map[string]string{}
		for k, v := range base {
			out[k] = v
		}
		for i := 0; i+1 < len(more); i += 2 {
			out[more[i]] = more[i+1]
		}
		return out
	}
	ourX := "[Service]\nUser=agentos-x\nExecStart=/usr/lib/agentos/x\n"
	for name, c := range map[string]struct {
		files map[string]string
		ours  func(string) bool
		want  string
	}{
		"a bind in a packaged root unit's drop-in":               {map[string]string{lib + "systemd-udevd.service": root, etc + "systemd-udevd.service.d/z.conf": "[Service]\nBindPaths=/var/lib/agentos-x:/usr/lib/agentos\n"}, ourDropins, `path "/var/lib/agentos-x"`},
		"a preload in a packaged root unit's drop-in":            {map[string]string{lib + "systemd-udevd.service": root, lib + "systemd-udevd.service.d/z.conf": "[Service]\nEnvironment=LD_PRELOAD=/var/lib/agentos-x/x.so\n"}, ourDropins, `variable "LD_PRELOAD"`},
		"a bare program in a packaged drop-in":                   {map[string]string{lib + "systemd-udevd.service": root, etc + "systemd-udevd.service.d/z.conf": "[Service]\nExecStartPre=agentos-side\n"}, ourDropins, `plain absolute path`},
		"an opened file in a drop-in":                            {map[string]string{lib + "systemd-udevd.service": root, etc + "systemd-udevd.service.d/z.conf": "[Service]\nOpenFile=/tmp/x:in\n"}, ourDropins, `path "/tmp/x"`},
		"a packaged import":                                      {map[string]string{lib + "systemd-sysctl.service": "[Service]\nExecStart=/usr/lib/systemd/systemd-sysctl\n", etc + "systemd-sysctl.service.d/z.conf": "[Service]\nImportCredential=sysctl.*\n"}, ourDropins, `ImportCredential= searches`},
		"a prefix drop-in":                                       {map[string]string{lib + "systemd-udevd.service": root, etc + "systemd-.service.d/z.conf": "[Service]\nWorkingDirectory=/tmp\n"}, ourDropins, `path "/tmp"`},
		"a prefix drop-in no unit reads":                         {map[string]string{etc + "agentos-.service.d/z.conf": "[Service]\nWorkingDirectory=/tmp\n"}, ourDropins, `path "/tmp"`},
		"a type-wide drop-in":                                    {map[string]string{etc + "service.d/z.conf": "[Service]\nStandardOutput=file:/tmp/o\n"}, ourDropins, `path "/tmp/o"`},
		"a socket's drop-in":                                     {map[string]string{etc + "agentos-x.service": user, etc + "agentos-x.socket": "[Socket]\nListenStream=/run/agentos-x\n", etc + "agentos-x.socket.d/z.conf": "[Socket]\nExecStartPre=/bin/sh -c ${X}\n"}, ourEtc, `holds a $ substitution`},
		"a drop-in for a unit not in the tree":                   {map[string]string{etc + "agentos-gone.service.d/z.conf": bad}, ourDropins, `variable "LD_PRELOAD"`},
		"a root command a drop-in adds to a user unit":           {map[string]string{lib + "systemd-x.service": user, etc + "systemd-x.service.d/z.conf": "[Service]\nExecStartPre=+/bin/true\nEnvironment=LD_PRELOAD=/tmp/x.so\n"}, ourDropins, `variable "LD_PRELOAD"`},
		"a packaged user unit's directory, granted":              {map[string]string{lib + "systemd-x.service": user, etc + "systemd-x.service.d/z.conf": "[Service]\nRuntimeDirectory=systemd\n"}, ourDropins, `the unit's user owns /run/systemd, in or above /run/systemd`},
		"a drop-in that makes a user unit's directory another's": {map[string]string{lib + "systemd-x.service": "[Service]\nExecStart=/usr/lib/systemd/systemd-x\nRuntimeDirectory=systemd\n", etc + "systemd-x.service.d/z.conf": "[Service]\nUser=systemd-x\n"}, ourDropins, `the unit's user owns /run/systemd`},
		// A higher unit file masks a lower one: the root one in /etc runs.
		"a drop-in on the unit /etc masks": {map[string]string{lib + "x.service": user, etc + "x.service": root, lib + "x.service.d/z.conf": bad}, nil, `variable "LD_PRELOAD"`},
		// Links are read in the tree, not on the host.
		"an absolute link":                                 {map[string]string{lib + "x.service": root, etc + "x.service": "-> " + lib + "x.service", etc + "x.service.d/z.conf": "[Service]\nTTYPath=/tmp/t\n"}, nil, `path "/tmp/t"`},
		"a linked drop-in directory":                       {map[string]string{lib + "x.service": root, "/usr/share/x/z.conf": "[Service]\nTTYPath=/tmp/t\n", etc + "x.service.d": "-> /usr/share/x"}, nil, `path "/tmp/t"`},
		"a linked unit directory":                          {map[string]string{"/usr/share/x/x.service": root, "/usr/share/x/x.service.d/z.conf": "[Service]\nTTYPath=/tmp/t\n", "/etc/systemd": "-> /usr/share/y", "/usr/share/y/system": "-> ../x"}, nil, `path "/tmp/t"`},
		"a root command and a path in an alias's drop-ins": {map[string]string{lib + "x.service": user, etc + "y.service": "-> " + lib + "x.service", etc + "x.service.d/a.conf": "[Service]\nExecStartPre=+/bin/true\n", etc + "y.service.d/b.conf": "[Service]\nTTYPath=/tmp/t\n"}, ourDropins, `path "/tmp/t"`},
		"an alias's drop-in":                               {map[string]string{lib + "x.service": root, etc + "y.service": "-> " + lib + "x.service", etc + "y.service.d/z.conf": "[Service]\nTTYPath=/tmp/t\n"}, ourDropins, `path "/tmp/t"`},
		"an instance's drop-in":                            {map[string]string{lib + "x@.service": root, etc + "x@a.service.d/z.conf": "[Service]\nTTYPath=/tmp/t\n"}, ourDropins, `path "/tmp/t"`},
		"a template's drop-in":                             {map[string]string{lib + "x@.service": root, etc + "x@.service.d/z.conf": "[Service]\nTTYPath=/tmp/t\n"}, ourDropins, `path "/tmp/t"`},
		"a unit of ours":                                   {map[string]string{etc + "getty@.service": "[Service]\nExecStart=-/sbin/agetty - $TERM\nTTYPath=/dev/%I\n"}, nil, `holds a $ substitution`},
		"a type in a mount drop-in":                        {map[string]string{lib + "tmp.mount": "[Mount]\nWhat=tmpfs\nWhere=/tmp\nType=tmpfs\n", etc + "tmp.mount.d/z.conf": "[Mount]\nType=fuse.agentos\n"}, ourDropins, `Type=fuse.agentos`},
		"a helper in fstab":                                {map[string]string{"/etc/fstab": "x /x fuse.agentos defaults 0 0\n"}, ourDropins, `fuse.agentos`},
		// #4737 L3 release 2: an fstab that is a link of ours to a
		// package's file is ours.
		"an fstab linked to a package's": {map[string]string{"/etc/fstab": "-> /usr/share/p/fstab", "/usr/share/p/fstab": "x /x fuse.agentos defaults 0 0\n"}, pkg, `fuse.agentos`},
		// #4737 L3 1, Security 1: a .conf masks one of its name in any of
		// the unit's later drop-in directories.
		"a type-wide drop-in a unit's own masks":         {map[string]string{lib + "x.service": badRoot, lib + "service.d/50-u.conf": "[Service]\nUser=nobody\n", etc + "x.service.d/50-u.conf": "[Service]\n"}, nil, `variable "LD_PRELOAD"`},
		"a prefix drop-in a unit's own masks":            {map[string]string{lib + "x-y.service": badRoot, lib + "x-.service.d/50-u.conf": "[Service]\nUser=nobody\n", etc + "x-y.service.d/50-u.conf": "[Service]\n"}, nil, `variable "LD_PRELOAD"`},
		"a packaged prefix drop-in a packaged one masks": {map[string]string{lib + "x-root.service": root, lib + "x-.service.d/50-u.conf": "[Service]\nUser=systemd-x\n", lib + "x-root.service.d/50-u.conf": "[Service]\nNice=5\n", etc + "x-root.service.d/60-p.conf": "[Service]\nEnvironment=LD_PRELOAD=/var/lib/agentos-x/x.so\n"}, ourEtc, `variable "LD_PRELOAD"`},
		// #4737 Security 6588498486 1: a higher path's type-wide drop-in
		// does not mask a unit's own in a lower path.
		"a unit's own drop-in a higher type-wide one names":  {map[string]string{lib + "x.service": "[Service]\nExecStart=/bin/true\n", lib + "x.service.d/50-p.conf": bad, etc + "service.d/50-p.conf": "[Service]\n"}, nil, `variable "LD_PRELOAD"`},
		"a unit's own drop-in a higher type-wide mask names": {map[string]string{lib + "x.service": "[Service]\nExecStart=/bin/true\n", lib + "x.service.d/50-p.conf": bad, etc + "service.d/50-p.conf": "-> /dev/null"}, nil, `variable "LD_PRELOAD"`},
		"a packaged User= a higher type-wide one names":      {map[string]string{lib + "x.service": root, lib + "x.service.d/50-u.conf": "[Service]\nUser=root\n", etc + "service.d/50-u.conf": "[Service]\nUser=nobody\n", etc + "x.service.d/z.conf": bad}, ourEtc, `variable "LD_PRELOAD"`},
		// #4737 L3 2, Security 2: a link of ours to a package's file is ours.
		"a drop-in linked to a package's file":      {map[string]string{lib + "systemd-udevd.service": root, "/usr/share/p/z.conf": bad, etc + "systemd-udevd.service.d/z.conf": "-> /usr/share/p/z.conf"}, ourEtc, `variable "LD_PRELOAD"`},
		"a drop-in directory linked to a package's": {map[string]string{lib + "systemd-udevd.service": root, "/usr/share/p/z.conf": bad, etc + "systemd-udevd.service.d": "-> /usr/share/p"}, ourEtc, `variable "LD_PRELOAD"`},
		"a unit linked to a package's file":         {map[string]string{"/usr/share/doc/p/ex.service": badRoot, etc + "agentos-ex.service": "-> /usr/share/doc/p/ex.service"}, ourEtc, `variable "LD_PRELOAD"`},
		// #4737 Security 3 and L3 6588613477 1: a link out of the search
		// path is a linked unit of its own name, however its target links on.
		"a linked unit a packaged one of its target's name": {map[string]string{etc + "x.service": "-> /usr/share/p/y.service", "/usr/share/p/y.service": "[Service]\nExecStart=/bin/true\n", lib + "y.service": user, etc + "x.service.d/z.conf": bad}, ourDropins, `variable "LD_PRELOAD"`},
		"a linked unit whose target links back":             {map[string]string{etc + "x.service": "-> /usr/share/p/y.service", "/usr/share/p/y.service": "-> " + lib + "y.service", lib + "y.service": root, lib + "y.service.d/50-u.conf": "[Service]\nUser=systemd-x\n", etc + "x.service.d/z.conf": bad}, ourEtc, `variable "LD_PRELOAD"`},
		"a linked mount":                                    {map[string]string{etc + "etc-x.mount": "-> /usr/share/m/foo.mount", "/usr/share/m/foo.mount": "[Mount]\nWhat=tmpfs\nWhere=/etc/x\nType=tmpfs\n"}, nil, `no Options=`},
		// #4737 Security 4: a grant and a root program, one ours.
		"a root program of ours in a package's grant":   {map[string]string{etc + "agentos-r.service": "[Service]\nExecStart=/var/lib/foo/run\n", lib + "foo.service": "[Service]\nUser=foo\nExecStart=/usr/bin/foo\nStateDirectory=foo\n"}, ourEtc, `in or above /var/lib/foo/run`},
		"a grant of ours over a package's root program": {map[string]string{etc + "agentos-y.service": "[Service]\nUser=agentos-y\nExecStart=/bin/true\nStateDirectory=pkg\n", lib + "pkg.service": "[Service]\nExecStart=/var/lib/pkg/bin/x\n"}, ourEtc, `in or above /var/lib/pkg/bin/x`},
		"a link loop":                             {map[string]string{etc + "x.service": "-> y.service", etc + "y.service": "-> x.service"}, nil, `more than 40 links`},
		"a drop-in through a link of ours":        {map[string]string{lib + "x.service": root, lib + "x.service.d/z.conf": "-> /etc/agentos/z.conf", "/etc/agentos/z.conf": "-> /usr/share/p/z.conf", "/usr/share/p/z.conf": bad}, pkg, `variable "LD_PRELOAD"`},
		"a drop-in we name in a linked directory": {map[string]string{lib + "x.service": root, etc + "x.service.d": "-> /usr/share/p", "/usr/share/p/z.conf": bad}, pkg, `variable "LD_PRELOAD"`},
		// #4779 Security 1: a value that forges systemd's dump lines reaches
		// no reply, and a name systemctl could not carry is refused.
		"a unit whose value forges dump lines": {map[string]string{lib + "systemd-udevd.service": root, etc + "systemd-udevd.service.d/z.conf": bad, etc + "aaa.service": "[Service]\nUser=nobody\nExecStart=/bin/true\nEnvironment=\"X=a\\n\\t\\tAlias: systemd-udevd.service\\n\\t-> Unit agentos-unit-lint.target:\\n\\t\\tUnit Load State: loaded\\n-> By jobs:\"\n"}, ourEtc, `variable "LD_PRELOAD"`},
		"a drop-in name with a newline":        {map[string]string{lib + "systemd-udevd.service": root, etc + "systemd-udevd.service.d/z\n.conf": "[Service]\n"}, ourEtc, `a name with a byte outside`},
		// #4779 Security 3: no name decides that a unit was generated.
		"a unit named like systemd's temporary directory": {map[string]string{etc + "systemd-temporary-ev.service": badRoot}, nil, `variable "LD_PRELOAD"`},
		// #4779 L3 1: an alias is decided from its target resolved in the
		// tree, not folded by spelling.
		"a link whose .. leaves the search path through a link": {map[string]string{etc + "x.service": "-> /usr/share/l/../../lib/systemd/system/y.service", "/usr/share/l": "-> /usr/share/doc/p/ex/sub", "/usr/share/doc/p/ex/sub/.keep": "", "/usr/share/doc/p/lib/systemd/system/y.service": badRoot, lib + "y.service": root}, ourEtc, `variable "LD_PRELOAD"`},
		// #4779 L3 2: a template drop-in directory no loaded instance reads.
		"a template drop-in with no template": {map[string]string{etc + "systemd-cryptsetup@.service.d/z.conf": bad}, ourDropins, `variable "LD_PRELOAD"`},
		// #4779 L3 round 2: a masked instance applies no drop-in, but any other instance would
		"a template drop-in beside a masked instance":      {map[string]string{etc + "systemd-cryptsetup@.service.d/z.conf": bad, etc + "systemd-cryptsetup@foo.service": "-> /dev/null"}, ourEtc, `variable "LD_PRELOAD"`},
		"a template drop-in with its lint instance masked": {map[string]string{lib + "getty@.service": "[Service]\nExecStart=/bin/true\n", etc + "getty@.service.d/z.conf": bad, etc + "getty@agentos-unit-lint.service": "-> /dev/null"}, ourEtc, `lint's own instance`}, // round 3: refused by its name
		// #4779 round 3: no instance but the lint's own, loaded, stands for its template's drop-ins
		"a template drop-in beside a bad-setting lint instance": {map[string]string{lib + "x@.service": "[Service]\nExecStart=%I\n", etc + "x@.service.d/z.conf": bad}, ourEtc, `variable "LD_PRELOAD"`},
		"a template drop-in beside a bad-setting template":      {map[string]string{lib + "x@.service": "[Service]\nExecStart=/bin/true\nUser=a:b\n", etc + "x@.service.d/z.conf": bad}, ourEtc, `variable "LD_PRELOAD"`},
		// #4821 Security R1: a lint instance systemd cannot load (a line
		// over its 1 MiB limit) hides which drop-ins its instances read and
		// what a package's lines run, so the run fails.
		"a template drop-in beside an error lint instance":     {map[string]string{lib + "x@.service": "[Service]\nExecStart=/bin/true\nDescription=" + strings.Repeat("a", 1100*1024) + "\n", etc + "x@.service.d/z.conf": bad}, ourEtc, `x@agentos-unit-lint.service: load state error`},
		"a template drop-in beside an instance's own drop-in":  {map[string]string{lib + "getty@.service": "[Service]\nExecStart=/usr/lib/systemd/systemd-udevd\n", etc + "getty@.service.d/z.conf": bad, etc + "getty@tty1.service.d/u.conf": "[Service]\nUser=nobody\n"}, ourEtc, `variable "LD_PRELOAD"`},
		"a template drop-in beside an instance's own fragment": {map[string]string{lib + "getty@.service": "[Service]\nExecStart=/usr/lib/systemd/systemd-udevd\n", etc + "getty@.service.d/z.conf": bad, etc + "getty@tty1.service": "[Service]\nUser=nobody\nExecStart=/bin/true\n"}, ourEtc, `variable "LD_PRELOAD"`},
		"a template drop-in beside a non-root instance":        {map[string]string{etc + "systemd-cryptsetup@.service.d/z.conf": bad, etc + "systemd-cryptsetup@foo.service": "[Service]\nUser=nobody\nExecStart=/bin/true\n"}, ourEtc, `variable "LD_PRELOAD"`},
		"a file of the lint's own instance":                    {map[string]string{lib + "getty@.service": "[Service]\nExecStart=/bin/true\n", etc + "getty@agentos-unit-lint.service.d/u.conf": "[Service]\nUser=nobody\n"}, ourEtc, `lint's own instance`},
		// #4779 re-plan (L3 6592951044 P1): a template's drop-in directory is
		// read by the instances of every template whose name it prefixes, so a
		// shared directory's drop-ins of ours are read alone whatever loaded.
		"a prefix template's drop-in a longer template reads": {map[string]string{lib + "x-@.service": "[Service]\nUser=nobody\nExecStart=/bin/true\n", lib + "x-y@.service": "[Service]\nExecStart=%I\n", etc + "x-@.service.d/z.conf": bad}, ourEtc, `variable "LD_PRELOAD"`},
		"a prefix instance's drop-in a longer template reads": {map[string]string{lib + "x-@.service": "[Service]\nUser=nobody\nExecStart=/bin/true\n", lib + "x-y@.service": root, etc + "x-@tty1.service.d/z.conf": bad}, ourEtc, `variable "LD_PRELOAD"`},
		"a prefix drop-in a unit of its own name loads":       {map[string]string{lib + "x-.service": "[Service]\nUser=nobody\nExecStart=/bin/true\n", etc + "x-.service.d/z.conf": bad}, ourEtc, `variable "LD_PRELOAD"`},
		// Every template loads as each instance name the tree holds, so a
		// package's prefix-instance drop-in is read with our template.
		"a template of ours a package's prefix-instance drop-in makes root": {map[string]string{etc + "x-y@.service": "[Service]\nUser=nobody\nExecStart=/bin/true\nEnvironment=LD_PRELOAD=/tmp/x.so\n", lib + "x-@tty1.service.d/p.conf": "[Service]\nUser=root\n"}, ourEtc, `variable "LD_PRELOAD"`},
		// Alone is the worst context only with no line that changes how
		// unseen lines read.
		"a user line in a shared drop-in":      {map[string]string{etc + "agentos-.service.d/u.conf": "[Service]\nUser=nobody\n"}, ourEtc, `may not set a directory's owner`},
		"a directory mode in a shared drop-in": {map[string]string{etc + "service.d/m.conf": "[Service]\nStateDirectoryMode=0777\n"}, ourEtc, `may not set a directory's owner or mode`},
		// A unit that did not finish loading may have stopped before its
		// drop-ins: each file of ours is read alone too.
		"a fragment of ours in a bad-setting template": {map[string]string{etc + "x@.service": "[Service]\nUser=nobody\nExecStart=/bin/true\nWorkingDirectory=%I\nEnvironment=LD_PRELOAD=/tmp/x.so\n", lib + "service.d/p.conf": "[Service]\nUser=root\n"}, ourEtc, `may not set a directory's owner`},
		// #4821 Security 1: Group= sets the directories' gid as User= sets their uid.
		"a group of ours on a package's directory":     {map[string]string{lib + "foo.service": "[Service]\nUser=foo\nExecStart=/usr/bin/foo\nStateDirectory=foo\nStateDirectoryMode=0770\n", lib + "bar.service": "[Service]\nExecStart=/var/lib/foo/run\n", etc + "foo.service.d/g.conf": "[Service]\nGroup=agentos-x\n"}, ourEtc, `in or above /var/lib/foo/run`},
		"a group line in a shared drop-in":             {map[string]string{lib + "foo.service": "[Service]\nUser=foo\nExecStart=/usr/bin/foo\nStateDirectory=foo\nStateDirectoryMode=0770\n", lib + "bar.service": "[Service]\nExecStart=/var/lib/foo/run\n", etc + "service.d/g.conf": "[Service]\nGroup=agentos-x\n"}, ourEtc, `may not set a directory's owner`},
		"a mode of ours on a package's 0770 directory": {map[string]string{lib + "foo.service": "[Service]\nUser=foo\nExecStart=/usr/bin/foo\nStateDirectory=foo\nStateDirectoryMode=0770\n", lib + "bar.service": "[Service]\nExecStart=/var/lib/foo/run\n", etc + "foo.service.d/g.conf": "[Service]\nStateDirectoryMode=0777\n"}, ourEtc, `in or above /var/lib/foo/run`},
		"a mode of ours on a package's directory":      {map[string]string{lib + "x.service": "[Service]\nExecStart=/bin/true\nStateDirectory=x\n", etc + "x.service.d/z.conf": "[Service]\nStateDirectoryMode=0777\n", lib + "y.service": "[Service]\nExecStart=/var/lib/x/bin\n"}, ourEtc, `mode 0777 /var/lib/x, in or above /var/lib/x/bin`},
		// #4821 Security R4, L3 R3: who may connect to a package's socket.
		"a socket mode of ours on a package's socket":  {map[string]string{lib + "systemd-udevd.service": root, lib + "systemd-udevd-control.socket": udevSocket, etc + "systemd-udevd-control.socket.d/z.conf": "[Socket]\nSocketMode=0666\n"}, ourEtc, `may not set any [Socket] setting`},
		"a socket group of ours on a package's socket": {map[string]string{lib + "systemd-udevd.service": root, lib + "systemd-udevd-control.socket": udevSocket, etc + "systemd-udevd-control.socket.d/z.conf": "[Socket]\nSocketGroup=agentos-x\nSocketMode=0660\n"}, ourEtc, `SocketGroup=agentos-x: a line of ours on a package's socket`},
		"a socket owner in a shared drop-in":           {map[string]string{etc + "socket.d/z.conf": "[Socket]\nSocketUser=agentos-x\n"}, ourEtc, `may not set any [Socket] setting`},
		// #5072 Security 1: a package's socket by its name or its service.
		"a fragment of ours hiding a package's socket":     {map[string]string{lib + "systemd-udevd.service": root, lib + "systemd-udevd-control.socket": udevSocket, etc + "systemd-udevd-control.socket": "[Socket]\nService=systemd-udevd.service\nListenSequentialPacket=/run/udev/control\nSocketMode=0666\n"}, ourEtc, `a line of ours on a package's socket`},
		"a socket of ours feeding a package's service":     {map[string]string{lib + "systemd-udevd.service": root, etc + "agentos-x.socket": "[Socket]\nService=systemd-udevd.service\nListenStream=/run/agentos-x\nSocketMode=0666\n"}, ourEtc, `a line of ours on a package's socket`},
		"a socket of ours a package's service takes":       {map[string]string{lib + "systemd-udevd.service": root, etc + "systemd-udevd.service.d/s.conf": "[Service]\nSockets=agentos-x.socket\n", etc + "agentos-x.socket": "[Socket]\nListenStream=/run/agentos-x\n"}, ourEtc, `ListenStream=/run/agentos-x: a line of ours on a package's socket`},
		"a socket of ours activating a package's template": {map[string]string{lib + "systemd-x@.service": root, etc + "systemd-x.socket": "[Socket]\nListenStream=/run/agentos-x\nAccept=yes\n"}, ourEtc, `a line of ours on a package's socket`},
		// #5072 Security 2: where a package's socket listens.
		"a listen line of ours on a package's socket": {map[string]string{lib + "systemd-udevd.service": root, lib + "systemd-udevd-control.socket": udevSocket, etc + "systemd-udevd-control.socket.d/z.conf": "[Socket]\nListenStream=0.0.0.0:7777\n"}, ourEtc, `ListenStream=0.0.0.0:7777: a line of ours`},
		"a listen line in a shared drop-in":           {map[string]string{etc + "socket.d/z.conf": "[Socket]\nListenStream=0.0.0.0:7777\n"}, ourEtc, `ListenStream=0.0.0.0:7777: a line of ours`},
		// #5072 L3 round 2: each criterion and key refused on its own.
		"a package's socket by its name alone":         {map[string]string{lib + "systemd-udevd.service": root, lib + "systemd-udevd-control.socket": udevSocket, etc + "agentos-x.service": user, etc + "systemd-udevd-control.socket": "[Socket]\nService=agentos-x.service\nListenSequentialPacket=/run/udev/control\nSocketMode=0666\n"}, ourEtc, `a line of ours on a package's socket`},
		"a service line of ours on a package's socket": {map[string]string{lib + "systemd-udevd.service": root, lib + "systemd-udevd-control.socket": udevSocket, etc + "agentos-x.service": user, etc + "systemd-udevd-control.socket.d/z.conf": "[Socket]\nService=agentos-x.service\n"}, ourEtc, `Service=agentos-x.service: a line of ours`},
		"a symlink of ours on a package's socket":      {map[string]string{lib + "systemd-udevd.service": root, lib + "systemd-udevd-control.socket": udevSocket, etc + "systemd-udevd-control.socket.d/z.conf": "[Socket]\nSymlinks=/run/open/control\n"}, ourEtc, `Symlinks=/run/open/control: a line of ours`},
		// #5072 Security round 2: Accept= hands each connection to a
		// template of ours; a fd name tells a daemon's endpoints apart; a
		// service of ours with Sockets= takes the package's listening fd.
		"an accept line of ours on a package's socket": {map[string]string{lib + "dbus.socket": "[Socket]\nListenStream=/run/dbus/system_bus_socket\n", lib + "dbus.service": "[Service]\nExecStart=/usr/bin/dbus-daemon --system\n", etc + "dbus.socket.d/z.conf": "[Socket]\nAccept=yes\n", etc + "dbus@.service": "[Service]\nUser=agentos-x\nExecStart=/usr/lib/agentos/x\nStandardInput=socket\n"}, ourEtc, `Accept=yes: a line of ours`},
		"a fd name of ours on a package's socket":      {map[string]string{lib + "systemd-udevd.service": root, lib + "systemd-udevd-control.socket": udevSocket, etc + "systemd-udevd-control.socket.d/z.conf": "[Socket]\nFileDescriptorName=varlink\n"}, ourEtc, `FileDescriptorName=varlink: a line of ours`},
		"a service of ours taking a package's socket":  {map[string]string{lib + "systemd-udevd.service": root, lib + "systemd-udevd-control.socket": udevSocket, etc + "agentos-x.service": "[Service]\nUser=agentos-x\nSockets=systemd-udevd-control.socket\nExecStart=/usr/lib/agentos/x\n"}, ourEtc, `a line of ours on a service a package's socket feeds`},
		"a sockets line in a shared drop-in":           {map[string]string{etc + "service.d/z.conf": "[Service]\nSockets=systemd-udevd-control.socket\n"}, ourEtc, `may not make a service take a socket`},
		"a device bind of ours on a package's socket":  {map[string]string{lib + "systemd-udevd.service": root, lib + "systemd-udevd-control.socket": udevSocket, etc + "systemd-udevd-control.socket.d/z.conf": "[Socket]\nBindToDevice=eth0\n"}, ourEtc, `BindToDevice=eth0: a line of ours`},
		// #5620 R-c, R-i: a link the tree holds, read from the records
		// (a link in the tree's /run is not there at boot: /run is a tmpfs).
		"a package's path through a link in the tree":        {with(udev, "/var/pkglink", "-> ../run/agentos-x", lib+"pkg.socket", "[Socket]\nListenStream=/var/pkglink/s\n", lib+"pkg.service", root, etc+"agentos-x.service", user, etc+"agentos-x.socket", "[Socket]\nListenStream=/run/agentos-x/s\n"), ourEtc, `on a package socket's path, /var/pkglink/s`},
		"a package's path through a link in the tree's /usr": {with(udev, "/usr/pkglink", "-> /run/agentos-x", lib+"pkg.socket", "[Socket]\nListenStream=/usr/pkglink/s\n", lib+"pkg.service", root, etc+"agentos-x.service", user, etc+"agentos-x.socket", "[Socket]\nListenStream=/run/agentos-x/s\n"), ourEtc, `on a package socket's path, /usr/pkglink/s`},
		"a package's path through two links in the tree":     {with(udev, "/var/a", "-> /var/b", "/var/b", "-> /run", lib+"pkg.socket", "[Socket]\nListenStream=/var/a/agentos-x/s\n", lib+"pkg.service", root, etc+"agentos-x.service", user, etc+"agentos-x.socket", "[Socket]\nListenStream=/run/agentos-x/t\n"), ourEtc, `on a package socket's path, /var/a/agentos-x/s`},
		// #5620 R-a, R-b.
		"an open directory mode of ours":  {map[string]string{etc + "agentos-x.service": user, etc + "agentos-x.socket": "[Socket]\nListenStream=/run/agentos-x/s\nDirectoryMode=0777\n"}, ourEtc, `DirectoryMode=0777: a directory mode of ours`},
		"a port of ours":                  {with(foo, etc+"agentos-x.service", user, etc+"agentos-x.socket", "[Socket]\nListenStream=2222\nReusePort=yes\n"), ourEtc, `ListenStream=2222: a listen path of ours names no path`},
		"a socket directory mode of ours": {map[string]string{lib + "systemd-udevd.service": root, lib + "systemd-udevd-control.socket": udevSocket, etc + "systemd-udevd-control.socket.d/z.conf": "[Socket]\nDirectoryMode=0777\n"}, ourEtc, `DirectoryMode=0777: a line of ours`},
		// #5072 Security round 3, 3: every [Socket] line of ours on a
		// package's socket, not a key list.
		"a reuse-port line of ours on a package's socket":  {with(foo, etc+"foo.socket.d/z.conf", "[Socket]\nReusePort=yes\n", etc+"agentos-x.service", user, etc+"agentos-x.socket", "[Socket]\nListenStream=0.0.0.0:2222\nReusePort=yes\n"), ourEtc, `ReusePort=yes: a line of ours on a package's socket`},
		"an address reset of ours on a package's socket":   {with(foo, etc+"foo.socket.d/z.conf", "[Socket]\nIPAddressDeny=\n"), ourEtc, `IPAddressDeny=: a line of ours on a package's socket`},
		"a network line of ours on a package's socket":     {with(foo, etc+"foo.socket.d/z.conf", "[Socket]\nPrivateNetwork=no\n"), ourEtc, `PrivateNetwork=no: a line of ours on a package's socket`},
		"a netns line of ours on a package's socket":       {with(foo, etc+"foo.socket.d/z.conf", "[Socket]\nNetworkNamespacePath=/run/netns/x\n"), ourEtc, `NetworkNamespacePath=/run/netns/x: a line of ours`},
		"a free bind of ours on a package's socket":        {with(foo, etc+"foo.socket.d/z.conf", "[Socket]\nFreeBind=yes\nBindIPv6Only=both\n"), ourEtc, `FreeBind=yes: a line of ours on a package's socket`},
		"a command of ours on a package's socket":          {with(udev, etc+"systemd-udevd-control.socket.d/z.conf", "[Socket]\nExecStartPost=/usr/bin/chmod 0666 /run/udev/control\n"), ourEtc, `ExecStartPost=/usr/bin/chmod 0666 /run/udev/control: a line of ours on a package's socket`},
		"a remove line of ours on a package's socket":      {with(udev, etc+"systemd-udevd-control.socket.d/z.conf", "[Socket]\nRemoveOnStop=yes\n"), ourEtc, `RemoveOnStop=yes: a line of ours`},
		"a credentials line of ours on a package's socket": {with(udev, etc+"systemd-udevd-control.socket.d/z.conf", "[Socket]\nPassCredentials=no\nPassSecurity=no\n"), ourEtc, `PassCredentials=no: a line of ours`},
		"a mark of ours on a package's socket":             {with(foo, etc+"foo.socket.d/z.conf", "[Socket]\nMark=7\n"), ourEtc, `Mark=7: a line of ours on a package's socket`},
		"a reuse-port line in a shared drop-in":            {map[string]string{etc + "socket.d/z.conf": "[Socket]\nReusePort=yes\n"}, ourEtc, `ReusePort=yes: a line of ours`},
		// #5072 Security round 3, 1: a service a package's socket feeds,
		// read from the socket's side (Service=, implicit name, Accept=
		// template), since the lint's manager forgets its TriggeredBy.
		"a fragment of ours on a service a package's socket names":  {with(udev, etc+"systemd-udevd.service", ourX), ourEtc, `User=agentos-x: a line of ours on a service a package's socket feeds`},
		"a fragment of ours on a package socket's implicit service": {with(dbus, etc+"dbus.service", ourX), ourEtc, `User=agentos-x: a line of ours on a service a package's socket feeds`},
		"a fragment of ours hiding a package's accept template":     {with(ssh, etc+"ssh@.service", ourX+"StandardInput=socket\n"), ourEtc, `User=agentos-x: a line of ours on a service a package's socket feeds`},
		"a template of ours for a package's accept socket":          {map[string]string{lib + "foo.socket": "[Socket]\nListenStream=2222\nAccept=yes\n", etc + "foo@.service": ourX + "StandardInput=socket\n"}, ourEtc, `User=agentos-x: a line of ours on a service a package's socket feeds`},
		// #5072 Security round 3, 2: every [Service] line of ours on a fed
		// service, in a drop-in as well as a fragment.
		"a command and user of ours on a fed package service": {with(udev, etc+"systemd-udevd.service.d/z.conf", "[Service]\nUser=agentos-x\nExecStart=\nExecStart=/usr/lib/agentos/x\n"), ourEtc, `User=agentos-x: a line of ours on a service a package's socket feeds`},
		"a root command of ours on a fed package service":     {with(udev, etc+"systemd-udevd.service.d/z.conf", "[Service]\nExecStart=\nExecStart=/usr/lib/agentos/x\n"), ourEtc, `ExecStart=: a line of ours on a service a package's socket feeds`},
		"a user of ours on a fed package service":             {with(udev, etc+"systemd-udevd.service.d/z.conf", "[Service]\nUser=agentos-x\n"), ourEtc, `User=agentos-x: a line of ours on a service a package's socket feeds`},
		"a preload of ours on a fed user service":             {with(dbus, etc+"dbus.service.d/z.conf", "[Service]\nEnvironment=LD_PRELOAD=/usr/lib/agentos/x.so\n"), ourEtc, `Environment=LD_PRELOAD=/usr/lib/agentos/x.so: a line of ours on a service a package's socket feeds`},
		"a bind of ours on a fed user service":                {with(dbus, etc+"dbus.service.d/z.conf", "[Service]\nBindReadOnlyPaths=/usr/lib/agentos/x:/usr/bin/dbus-daemon\n"), ourEtc, `BindReadOnlyPaths=/usr/lib/agentos/x:/usr/bin/dbus-daemon: a line of ours on a service`},
		"a command of ours on a fed implicit service":         {with(dbus, etc+"dbus.service.d/z.conf", "[Service]\nExecStart=\nExecStart=/usr/lib/agentos/x\n"), ourEtc, `ExecStart=: a line of ours on a service a package's socket feeds`},
		"a user of ours on a package's accept template":       {with(ssh, etc+"ssh@.service.d/z.conf", "[Service]\nUser=agentos-x\n"), ourEtc, `User=agentos-x: a line of ours on a service a package's socket feeds`},
		// #5072 round 4: a package's socket naming an instance feeds its
		// template, whose files reach the lint's instance; a [Unit] line
		// of ours but an ordering one; a file of ours hiding a package's
		// drop-in of the same name.
		"a template of ours for an instance a package's socket names": {with(inst, etc+"bar@.service", ourX+"StandardInput=socket\n"), ourEtc, `User=agentos-x: a line of ours on a service a package's socket feeds`},
		"a drop-in of ours on that template":                          {with(inst, lib+"bar@.service", root, etc+"bar@.service.d/z.conf", "[Service]\nExecStart=\nExecStart=/usr/lib/agentos/x\n"), ourEtc, `ExecStart=: a line of ours on a service a package's socket feeds`},
		"a type-wide drop-in of ours reaching that template":          {with(inst, lib+"bar@.service", root, etc+"service.d/z.conf", "[Service]\nBindReadOnlyPaths=/usr/lib/agentos/x:/usr/bin/bar\n"), ourEtc, `BindReadOnlyPaths=/usr/lib/agentos/x:/usr/bin/bar: a line of ours on a service`},
		"a namespace line of ours on a fed service":                   {with(udev, etc+"systemd-udevd.service.d/z.conf", "[Unit]\nJoinsNamespaceOf=agentos-x.service\n"), ourEtc, `JoinsNamespaceOf=agentos-x.service: a [Unit] line of ours`},
		"a binds line of ours on a fed template":                      {with(ssh, etc+"ssh@.service.d/z.conf", "[Unit]\nBindsTo=agentos-x.service\n"), ourEtc, `BindsTo=agentos-x.service: a [Unit] line of ours`},
		"a condition of ours on a package's socket":                   {with(udev, etc+"systemd-udevd-control.socket.d/z.conf", "[Unit]\nConditionPathExists=/run/agentos-x\n"), ourEtc, `ConditionPathExists=/run/agentos-x: a [Unit] line of ours`},
		"a conflicts line of ours on a fed implicit service":          {with(dbus, etc+"dbus.service.d/z.conf", "[Unit]\nConflicts=agentos-x.service\n"), ourEtc, `Conflicts=agentos-x.service: a [Unit] line of ours`},
		"a mask of ours on a package socket's drop-in":                {with(udev, lib+"systemd-udevd-control.socket.d/p.conf", "[Socket]\nSocketMode=0600\n", etc+"systemd-udevd-control.socket.d/p.conf", "-> /dev/null"), ourEtc, `hides a package's drop-in, /usr/lib/systemd/system/systemd-udevd-control.socket.d/p.conf`},
		"an empty file of ours on a fed service's drop-in":            {with(udev, lib+"systemd-udevd.service.d/p.conf", "[Service]\nUser=systemd-x\n", etc+"systemd-udevd.service.d/p.conf", ""), ourEtc, `hides a package's drop-in, /usr/lib/systemd/system/systemd-udevd.service.d/p.conf`},
		// #5075 R1: on a service no package's socket feeds, a /dev/null link
		// or an empty file of ours named as a package's User= drop-in makes
		// the package's unit run as root.
		"a mask of ours on a package's owner drop-in":        {map[string]string{lib + "pkgd.service": "[Service]\nExecStart=/usr/bin/pkgd\n", lib + "pkgd.service.d/user.conf": "[Service]\nUser=pkgd\n", etc + "pkgd.service.d/user.conf": "-> /dev/null"}, ourEtc, `hides a package's drop-in, /usr/lib/systemd/system/pkgd.service.d/user.conf`},
		"an empty file of ours on a package's owner drop-in": {map[string]string{lib + "pkgd.service": "[Service]\nExecStart=/usr/bin/pkgd\n", lib + "pkgd.service.d/user.conf": "[Service]\nUser=pkgd\n", etc + "pkgd.service.d/user.conf": ""}, ourEtc, `hides a package's drop-in, /usr/lib/systemd/system/pkgd.service.d/user.conf`},
		// #5075 R3: a socket of ours, name and service ours, on a package
		// socket's path: systemd unlinks and binds again, and our daemon
		// takes the package's endpoint.
		"a socket of ours on a package socket's path":             {with(udev, etc+"agentos-x.service", user, etc+"agentos-x.socket", "[Socket]\nListenSequentialPacket=/run/udev/control\nSocketMode=0666\n"), ourEtc, `ListenSequentialPacket=/run/udev/control: a listen path of ours on a package socket's path`},
		"a socket of ours in a package socket's directory":        {with(udev, etc+"agentos-x.service", user, etc+"agentos-x.socket", "[Socket]\nListenStream=/run/udev/x\n"), ourEtc, `ListenStream=/run/udev/x: a listen path of ours on a package socket's path`},
		"a socket of ours on a package socket's path by /var/run": {with(udev, "/var/run", "-> /run", etc+"agentos-x.service", user, etc+"agentos-x.socket", "[Socket]\nListenStream=/var/run/udev/control\n"), ourEtc, `a listen path of ours on a package socket's path, /run/udev/control`},
		"a socket of ours on a package socket's path by %t":       {with(udev, etc+"agentos-x.service", user, etc+"agentos-x.socket", "[Socket]\nListenStream=%t/udev/control\n"), ourEtc, `a listen path of ours on a package socket's path`},
		"a socket of ours on a journal namespace's path":          {map[string]string{lib + "systemd-journald@.socket": "[Socket]\nService=systemd-journald@%i.service\nListenStream=/run/systemd/journal.%i/stdout\n", lib + "systemd-journald@.service": root, etc + "agentos-x.service": user, etc + "agentos-x.socket": "[Socket]\nListenStream=/run/systemd/journal.ns/stdout\nSocketMode=0666\n"}, ourEtc, `ListenStream=/run/systemd/journal.ns/stdout: a listen path of ours on a package socket's path, /run/systemd/journal.%i/stdout`},
		// #5614 L3 1: Symlinks= paths are endpoints too, on both sides.
		"a socket of ours on a package socket's link": {with(devlog, etc+"agentos-x.service", user, etc+"agentos-x.socket", "[Socket]\nListenDatagram=/dev/log\n"), ourEtc, `ListenDatagram=/dev/log: a listen path of ours on a package socket's path, /dev/log`},
		"a link of ours on a package socket's link":   {with(devlog, etc+"agentos-x.service", user, etc+"agentos-x.socket", "[Socket]\nListenStream=/run/agentos-x/s\nSymlinks=/run/agentos-x/l /dev/log\n"), ourEtc, `Symlinks=/run/agentos-x/l /dev/log: a listen path of ours on a package socket's path, /dev/log`},
		"a link of ours on a package socket's path":   {with(devlog, etc+"agentos-x.service", user, etc+"agentos-x.socket", "[Socket]\nListenStream=/run/agentos-x/s\nSymlinks=/run/systemd/journal/dev-log\n"), ourEtc, `on a package socket's path, /run/systemd/journal/dev-log`},
		// #5614 Security round 2: systemd unquotes and unescapes Symlinks=.
		"a quoted link of ours on a package socket's link":   {with(devlog, etc+"agentos-x.service", user, etc+"agentos-x.socket", "[Socket]\nListenStream=/run/agentos-x/s\nSymlinks=\"/dev/log\"\n"), ourEtc, `Symlinks="/dev/log": a listen path of ours is quoted or escaped`},
		"an escaped link of ours on a package socket's link": {with(devlog, etc+"agentos-x.service", user, etc+"agentos-x.socket", "[Socket]\nListenStream=/run/agentos-x/s\nSymlinks=/dev/\\log\n"), ourEtc, `a listen path of ours is quoted or escaped`},
		"a socket of ours on a package's quoted link":        {map[string]string{lib + "systemd-journald-dev-log.socket": "[Socket]\nService=systemd-journald.service\nListenDatagram=/run/systemd/journal/dev-log\nSymlinks=\"/dev/log\"\n", lib + "systemd-journald.service": root, etc + "agentos-x.service": user, etc + "agentos-x.socket": "[Socket]\nListenDatagram=/dev/log\n"}, ourEtc, `on a package socket's path, /dev/log`},
		"a socket of ours beside a package's escaped link":   {map[string]string{lib + "systemd-journald-dev-log.socket": "[Socket]\nService=systemd-journald.service\nListenDatagram=/run/systemd/journal/dev-log\nSymlinks=/dev/\\log\n", lib + "systemd-journald.service": root, etc + "agentos-x.service": user, etc + "agentos-x.socket": "[Socket]\nListenDatagram=/run/agentos-x/log\n"}, ourEtc, `on a package socket's path, /dev/\log`},
		"a socket of ours through /var/lock/..":              {with(udev, etc+"agentos-x.service", user, etc+"agentos-x.socket", "[Socket]\nListenSequentialPacket=/var/lock/../udev/control\nSocketMode=0666\n"), ourEtc, `ListenSequentialPacket=/var/lock/../udev/control: a listen path of ours is not canonical`},
		"a socket of ours whose path holds a specifier":      {with(udev, etc+"agentos-x@.service", user, etc+"agentos-x@.socket", "[Socket]\nListenStream=/run/%I\n", etc+"sockets.target.wants/agentos-x@udev-control.socket", "-> ../agentos-x@.socket"), ourEtc, `ListenStream=/run/%I: a listen path of ours holds a specifier`},
		// #5072 Security round 5 point 2: systemd adds the edge on both
		// units, so a unit of ours naming one is the drop-in's route.
		"a unit of ours joining a fed service's namespace":      {with(dbus, etc+"agentos-x.service", "[Unit]\nJoinsNamespaceOf=dbus.service\n[Service]\nUser=agentos-x\nPrivateTmp=yes\nExecStart=/usr/lib/agentos/x\n"), ourEtc, `JoinsNamespaceOf=dbus.service: a [Unit] line of ours naming a package's socket`},
		"a unit of ours conflicting with a package's socket":    {with(udev, etc+"agentos-x.service", "[Unit]\nConflicts=systemd-udevd-control.socket\n"+ourX), ourEtc, `Conflicts=systemd-udevd-control.socket: a [Unit] line of ours naming`},
		"a unit of ours propagating stop to a fed service":      {with(udev, etc+"agentos-x.service", "[Unit]\nPropagatesStopTo=systemd-udevd.service\n"+ourX), ourEtc, `PropagatesStopTo=systemd-udevd.service: a [Unit] line of ours naming`},
		"a unit of ours propagating reload to a fed service":    {with(udev, etc+"agentos-x.service", "[Unit]\nPropagatesReloadTo=systemd-udevd.service\n"+ourX), ourEtc, `PropagatesReloadTo=systemd-udevd.service: a [Unit] line of ours naming`},
		"a unit of ours naming a fed template's other instance": {with(inst, lib+"bar@.service", user, etc+"agentos-x.service", "[Unit]\nConflicts=bar@y.service\n"+ourX), ourEtc, `Conflicts=bar@y.service: a [Unit] line of ours naming`},
		"a unit of ours naming a unit by a specifier":           {with(udev, etc+"agentos-x.service", "[Unit]\nConflicts=%p.socket\n"+ourX), ourEtc, `Conflicts=%p.socket: a [Unit] line of ours naming`},
		"a unit of ours naming a unit by a bare specifier":      {with(udev, etc+"agentos-x@.service", "[Unit]\nConflicts=%i\n"+ourX, etc+"multi-user.target.wants/agentos-x@systemd-udevd-control.socket.service", "-> ../agentos-x@.service"), ourEtc, `Conflicts=%i: a [Unit] line of ours naming`},
	} {
		t.Run("refuses "+name, func(t *testing.T) {
			if err := underSystemd(t, c.files, c.ours); err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("got %v, want a refusal with %q", err, c.want)
			}
		})
	}
	for name, c := range map[string]struct {
		files map[string]string
		ours  func(string) bool
	}{
		// A package's own lines are not held, though a drop-in of ours is.
		"a packaged unit as shipped":           {map[string]string{etc + "getty@.service": "[Service]\nExecStart=-/sbin/agetty - $TERM\nTTYPath=/dev/%I\n", "/etc/fstab": "proc /proc proc defaults 0 0\ndevpts /dev/pts devpts gid=5 0 0\n"}, pkg},
		"a drop-in of ours in a packaged unit": {map[string]string{lib + "getty@.service": "[Service]\nExecStart=-/sbin/agetty - $TERM\nTTYPath=/dev/%I\n", lib + "getty@.service.d/p.conf": "[Service]\nExecStart=\nExecStart=-/sbin/agetty -o %I - $TERM\n", etc + "getty@.service.d/z.conf": "[Service]\nEnvironment=GOMEMLIMIT=1\n"}, ourEtc},
		"a user unit's own drop-in":            {map[string]string{lib + "systemd-x.service": user, etc + "systemd-x.service.d/z.conf": "[Service]\nWorkingDirectory=/tmp\n" + "Environment=LD_PRELOAD=/tmp/x.so\n"}, ourDropins},
		// A higher unit file masks a lower one: the user one in /etc runs.
		"a drop-in on a unit /etc makes a user's": {map[string]string{lib + "x.service": root, etc + "x.service": user, lib + "x.service.d/z.conf": bad}, nil},
		"a masked unit":                  {map[string]string{lib + "x.service": root, etc + "x.service": "-> /dev/null", lib + "x.service.d/z.conf": bad}, nil},
		"an empty unit file":             {map[string]string{lib + "x.service": root, etc + "x.service": "", lib + "x.service.d/z.conf": "[Service]\nExecStartPre=/bin/true\nEnvironment=LD_PRELOAD=/tmp/x.so\n"}, nil},
		"a masked drop-in":               {map[string]string{lib + "x.service": root, lib + "x.service.d/z.conf": bad, etc + "x.service.d/z.conf": "-> /dev/null"}, nil},
		"a drop-in a higher one masks":   {map[string]string{lib + "x.service": root, lib + "x.service.d/z.conf": bad, etc + "x.service.d/z.conf": "[Service]\n"}, nil},
		"an instance of a user template": {map[string]string{lib + "x@.service": user, etc + "x@a.service.d/z.conf": "[Service]\nWorkingDirectory=/tmp\n"}, ourDropins},
		"a dangling unit link":           {map[string]string{etc + "x.service": "-> /usr/share/gone/x.service"}, nil},
		// #4737 L3 3: a package's own grant, with a drop-in of ours.
		"a packaged networkd with our drop-in": {map[string]string{lib + "systemd-networkd.service": "[Service]\nExecStart=!!/usr/lib/systemd/systemd-networkd\nUser=systemd-network\nRuntimeDirectory=systemd/netif\n", lib + "systemd-networkd.service.d/agentos-inbound.conf": "[Unit]\nRequires=agentos-inbound.service\n"}, ourDropins},
		"a package's type-wide drop-in":        {map[string]string{lib + "service.d/z.conf": "[Service]\nWorkingDirectory=/tmp\n"}, ourEtc},
		// A mount none of ours touches is not held (unitCheck.unit's mount
		// branch reads no trusted).
		"a packaged mount as shipped": {map[string]string{lib + "etc-x.mount": "[Mount]\nWhat=tmpfs\nWhere=/etc/x\nType=tmpfs\n"}, pkg},
		// #4737 Security 6588498486 R1: a package's own grant the reader
		// cannot read, on a unit none of ours touches.
		"a package's specifier directory": {map[string]string{lib + "foo@.service": "[Service]\nExecStart=/usr/bin/foo\nDynamicUser=yes\nStateDirectory=foo/%i\n"}, pkg},
		// A socket all of whose files are ours sets its own owner and mode.
		// #5075 R3: a socket of ours beside a package's in a shared tree.
		"a socket of ours beside a package's in /run": {map[string]string{lib + "pkgs.socket": "[Socket]\nListenStream=/run/pkgs.sock\n", lib + "pkgs.service": user, etc + "agentos-x.service": user, etc + "agentos-x.socket": "[Socket]\nListenStream=%t/agentos-x.sock\nListenStream=/run/agentos-x/100%%\n"}, ourEtc},
		"a socket of ours with its owner":             {map[string]string{etc + "agentos-x.service": user, etc + "agentos-x.socket": "[Socket]\nListenStream=/run/agentos-x/s\nSocketUser=root\nSocketGroup=agentos-x\nSocketMode=0660\nDirectoryMode=0755\nReusePort=yes\nFreeBind=yes\n"}, ourEtc},
		// A package's socket feeding a package's service, with the package's
		// own [Service] drop-in and [Unit]-only drop-ins of ours (as the
		// image's networkd and resolved ones are).
		"a package's socket and fed service with unit lines of ours":     {with(udev, lib+"systemd-udevd.service.d/p.conf", "[Service]\nEnvironment=X=1\n", etc+"systemd-udevd.service.d/z.conf", "[Unit]\nAfter=agentos-x.service\n", etc+"systemd-udevd-control.socket.d/z.conf", "[Unit]\nAfter=agentos-x.service\n"), ourEtc},
		"a package's accept socket and template with unit lines of ours": {with(ssh, etc+"ssh@.service.d/z.conf", "[Unit]\nAfter=agentos-x.service\n"), ourEtc},
		"a package's implicit service with unit lines of ours":           {with(dbus, etc+"dbus.service.d/z.conf", "[Unit]\nAfter=agentos-x.service\n"), ourEtc},
		// Any [Unit] line of ours on a service no package's socket feeds.
		"an unfed package service with unit lines of ours": {map[string]string{lib + "systemd-x.service": user, etc + "systemd-x.service.d/z.conf": "[Unit]\nJoinsNamespaceOf=agentos-x.service\nConditionPathExists=/run/x\nBindsTo=agentos-x.service\n"}, ourEtc},
		// A unit of ours may order itself after a package's socket, and
		// name units of ours or unfed ones in any [Unit] key.
		"a unit of ours with edges to units not held": {with(udev, lib+"systemd-x.service", user, etc+"agentos-y.service", ourX, etc+"agentos-x.service", "[Unit]\nDescription=x %i\nDocumentation=man:x(%p)\nAfter=systemd-udevd-control.socket\nRequires=systemd-udevd.service\nConflicts=agentos-y.service systemd-x.service\nJoinsNamespaceOf=agentos-y.service\nConditionPathExists=/run/x-100%%\n"+ourX), ourEtc},
	} {
		t.Run(name, func(t *testing.T) {
			if err := underSystemd(t, c.files, c.ours); err != nil {
				t.Fatal(err)
			}
		})
	}
}

// TestUnitRulesListedUnderSystemd: a unit file or drop-in a package lists
// must be read as installed, or its unit gone whole (#5072 round 5:
// provenance by current bytes made one changed in place ours, and a
// deleted drop-in left no file of ours to refuse).
func TestUnitRulesListedUnderSystemd(t *testing.T) {
	const lib = "/usr/lib/systemd/system/"
	all := func(string) bool { return true }
	none := func(string) bool { return false }
	root := "[Service]\nExecStart=/usr/lib/systemd/systemd-udevd\n"
	udev := map[string]string{lib + "systemd-udevd.service": root, lib + "systemd-udevd-control.socket": "[Socket]\nService=systemd-udevd.service\nListenSequentialPacket=/run/udev/control\nSocketMode=0600\n"}
	open := map[string]string{lib + "systemd-udevd.service": root, lib + "systemd-udevd-control.socket": "[Socket]\nService=systemd-udevd.service\nListenSequentialPacket=/run/udev/control\nSocketMode=0666\n"}
	for name, c := range map[string]struct {
		files  map[string]string
		ours   func(string) bool
		listed []string
		want   string
	}{
		"a package's socket and service replaced in place": {open, all, []string{lib + "systemd-udevd-control.socket", lib + "systemd-udevd.service"}, `systemd-udevd-control.socket: a package's unit file or drop-in that systemd does not read as the package installed it`},
		"a package socket's drop-in deleted":               {udev, none, []string{lib + "systemd-udevd-control.socket.d/p.conf"}, `systemd-udevd-control.socket.d/p.conf: a package's unit file`},
		"a package's fragment deleted and supplied again":  {map[string]string{lib + "systemd-udevd.service": root, "/etc/systemd/system/systemd-udevd-control.socket": open[lib+"systemd-udevd-control.socket"]}, func(p string) bool { return strings.HasPrefix(p, "/etc/") }, []string{lib + "systemd-udevd-control.socket"}, `/usr/lib/systemd/system/systemd-udevd-control.socket: a package's unit file`},
		"a unit removed whole":                             {udev, none, []string{lib + "dpkg-db-backup.service", lib + "dpkg-db-backup.timer"}, ""},
	} {
		t.Run(name, func(t *testing.T) {
			err := underSystemdListed(t, c.files, c.ours, c.listed)
			if c.want == "" && err != nil || c.want != "" && (err == nil || !strings.Contains(err.Error(), c.want)) {
				t.Fatalf("got %v, want %q", err, c.want)
			}
		})
	}
}

// underSystemd lays files out as a root file system (fsTree), runs
// image/unit_rules.py --fixture on it as root, and holds the records it
// prints to the unit rules. It skips the test when not root or with no
// systemd, unless AGENTOS_REQUIRE_SYSTEMD=1.
func underSystemd(t *testing.T, files map[string]string, ours func(string) bool) error {
	t.Helper()
	return underSystemdListed(t, files, ours, nil)
}

// underSystemdListed is underSystemd with listed, paths a package lists
// that files does not hold as the package installed them (changed,
// replaced or gone).
func underSystemdListed(t *testing.T, files map[string]string, ours func(string) bool, listed []string) error {
	t.Helper()
	if os.Geteuid() != 0 || !hasSystemd() {
		if os.Getenv("AGENTOS_REQUIRE_SYSTEMD") == "1" {
			t.Fatal("AGENTOS_REQUIRE_SYSTEMD=1, but this is not root or has no /usr/lib/systemd/systemd")
		}
		t.Skip("needs root and systemd; the image workflow runs these")
	}
	if ours == nil {
		ours = func(string) bool { return true }
	}
	dir := t.TempDir()
	fs := fsTree(t, files)
	var packaged []string
	for p, text := range files {
		if !strings.HasPrefix(text, "-> ") && !ours(p) {
			packaged = append(packaged, p)
		}
	}
	sort.Strings(packaged)
	for _, p := range listed {
		packaged = append(packaged, "listed "+p)
	}
	list := filepath.Join(dir, "packaged")
	if err := os.WriteFile(list, []byte(strings.Join(packaged, "\n")+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("python3", "-I", filepath.Join(repoRoot(t), "image", "unit_rules.py"), "--fixture", fs, list)
	var stderr strings.Builder
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("unit_rules.py: %v: %s", err, stderr.String())
	}
	var recs unitRecords
	if err := json.Unmarshal(out, &recs); err != nil {
		t.Fatal(err)
	}
	if recs.Links == nil {
		t.Fatal("unit_rules.py printed no links")
	}
	return builtUnits(recs, filepath.Join(dir, "tree"))
}

func hasSystemd() bool {
	_, err := os.Stat("/usr/lib/systemd/systemd")
	return err == nil
}

// TestBuiltUnits holds the records image/unit_rules.py printed for a tree CI
// built (AGENTOS_UNIT_RECORDS, a directory with tree.json and control.json)
// to the unit rules. The tree must pass, and the control, the same tree with
// a drop-in of ours on a packaged root unit planted, must be refused, or a
// pass means nothing. Both must hold a file of ours and a package's.
func TestBuiltUnits(t *testing.T) {
	dir := os.Getenv("AGENTOS_UNIT_RECORDS")
	if dir == "" {
		t.Skip("AGENTOS_UNIT_RECORDS unset; the image workflow sets it for each tree it builds")
	}
	for _, name := range []string{"tree.json", "control.json"} {
		t.Run(name, func(t *testing.T) {
			b, err := os.ReadFile(filepath.Join(dir, name))
			if err != nil {
				t.Fatal(err)
			}
			var recs unitRecords
			if err := json.Unmarshal(b, &recs); err != nil {
				t.Fatal(err)
			}
			// The control is told by its file, not by its own want
			// (#4779 L3 release 3).
			if (recs.Want != "") != (name == "control.json") {
				t.Fatalf("%s wants %q", name, recs.Want)
			}
			// The tree's links are read from the records, never assumed
			// (#5620 R-i): records without them are a stale reader's.
			if recs.Links == nil {
				t.Fatalf("%s holds no links", name)
			}
			kinds := map[bool]bool{}
			for _, u := range recs.Units {
				for _, f := range u.Files {
					kinds[f.Ours] = true
				}
			}
			if !kinds[true] || !kinds[false] {
				t.Fatalf("records of %d units hold a file of ours %v and a package's %v; want both", len(recs.Units), kinds[true], kinds[false])
			}
			err = builtUnits(recs, t.TempDir())
			switch {
			case recs.Want == "" && err != nil:
				t.Fatal(err)
			case recs.Want != "" && (err == nil || !strings.Contains(err.Error(), recs.Want)):
				t.Fatalf("control: got %v, want a refusal with %q", err, recs.Want)
			}
		})
	}
}

// #4737 L3 release 4: a dash in an instance truncates nothing.
func TestDropinDirs(t *testing.T) {
	if got := strings.Join(dropinDirs("foo-x@a-b.service"), " "); got != "foo-x@a-b.service.d foo-x@.service.d foo-.service.d service.d" {
		t.Fatalf("dropinDirs: %s", got)
	}
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
		// #4626 R-1: the generator follows /var/run before the .., where
		// path.Clean folds it as text; R-2: a held mount takes a closed list
		// of options, so libmount makes no mount point another uid writes.
		"a .. in an fstab target":        {"image/mkosi/mkosi.extra/etc/fstab", "tmpfs /var/run/../etc/udev/rules.d tmpfs nosuid 0 0\n", `target /var/run/../etc/udev/rules.d has a ..`},
		"a .. target with an owner":      {"image/mkosi/mkosi.extra/etc/fstab", "tmpfs /var/run/../etc tmpfs mode=0755,uid=1 0 0\n", `has a ..`},
		"an X-mount.mkdir in fstab":      {"image/mkosi/mkosi.extra/etc/fstab", "/dev/x /etc/x ext4 X-mount.mkdir=0777 0 0\n", `option X-mount.mkdir=0777`},
		"a bare X-mount.mkdir in a unit": {"image/x/usr-lib-agentos.mount", "[Mount]\nWhat=/dev/x\nType=ext4\nOptions=ro,X-mount.mkdir\n", `option X-mount.mkdir`},
		"an X-mount.subdir over /usr":    {"image/mkosi/mkosi.extra/etc/fstab", "/dev/x /usr/lib/agentos ext4 X-mount.subdir=x 0 0\n", `option X-mount.subdir=x`},
		"an unlisted option on /":        {"image/x/-.mount", "[Mount]\nWhat=/dev/x\nType=ext4\nOptions=ro,context=x\n", `option context=x`},
		"an empty option over /etc":      {"image/mkosi/mkosi.extra/etc/fstab", "/dev/x /etc/x ext4 ro,,nosuid 0 0\n", `heldOptions lists`},
		// #4677 L3-R1: these stay off heldOptions.
		"a makefs over /etc":   {"image/mkosi/mkosi.extra/etc/fstab", "/dev/x /etc/x ext4 x-systemd.makefs 0 0\n", `option x-systemd.makefs`},
		"a growfs over /etc":   {"image/mkosi/mkosi.extra/etc/fstab", "/dev/x /etc/x ext4 x-systemd.growfs 0 0\n", `option x-systemd.growfs`},
		"a requires over /etc": {"image/mkosi/mkosi.extra/etc/fstab", "/dev/x /etc/x ext4 x-systemd.requires=x.service 0 0\n", `option x-systemd.requires=x.service`},
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
		files["image/mkosi/mkosi.extra/etc/fstab"] += "tmpfs /run/systemd/x tmpfs mode=1755,nosuid 0 0\nramfs /etc/y ramfs mode=700 0 0\n" +
			"/dev/y /etc/z ext4 defaults,ro,nodev,noexec,noatime,nofail 0 0\n" +
			"/dev/w /etc/w ext4 ro,lazytime,nosymfollow,_netdev,x-initrd.mount,x-systemd.device-timeout=10s 0 0\n/dev/z /var/lib/z ext4 X-mount.mkdir=0777,uid=1 0 0\n"
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
		"image/mkosi/agentos-side.service":        "[Service]\nUser=agentos-side\nExecStart=/usr/lib/agentos/agentos-side\nExecStartPre=+/opt/x/agentos-x\nExecStartPre=+/var/run/agentos-v/x\n",
		modprobe:                                  "# agentos-side\nblacklist btusb\n\talias usb:v1 btusb\noptions btusb x=1\nsoftdep btusb pre: btmtk\nweakdep btusb btmtk\ninstall btusb /bin/false\n",
		sysctl:                                    "; agentos-side\n# kernel.modprobe=/usr/lib/agentos/agentos-side\nkernel.core_pattern = core.%p\nfs.suid_dumpable=0\n-kernel.hotplug\n-net.ipv4.ip_forward = 0\n",
		extra + "usr/lib/modprobe.d/README":       "install btusb /usr/lib/agentos/agentos-side\n",
		"image/mkosi/agentos-x.conf":              "install btusb /usr/lib/agentos/agentos-side\nkernel.modprobe=/usr/lib/agentos/agentos-side\n",
		extra + "usr/lib/udev/rules.d/60-x.rules": "KERNEL==\"x\", MODE=\"0600\"\n",
		tmpfiles:                            "# w /proc/sys/kernel/modprobe - - - - /usr/lib/agentos/agentos-side\nd /var/lib/agentos-x 0700 agentos-x agentos-x -\nd /var/lib/agentos-y 0770 - agentos-y\nz /etc/agentos 0755 root agentos-x\nz /sys/class/leds/x/brightness 0660 root root -\nw /proc/sys/kernel/core_pattern - - - - core.%p\nw- /proc/sys/vm/swappiness - - - - 10\nR /var/tmp/agentos-x\nd /var/tmp/agentos-y 1777 root root -\nd /run/agentos-y :0750 root root -\nz /run/agentos-y ~0755\n",
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
		"a glob key":                    {sysctl, "kernel.core_*=|/usr/lib/agentos/agentos-side\n", `could name kernel.core_pattern`},
		"a glob component":              {sysctl, "*.modprobe=/usr/lib/agentos/agentos-side\n", `could name kernel.modprobe`},
		"a negated class":               {sysctl, "kernel.[!x]otplug=/usr/lib/agentos/agentos-side\n", `could name kernel.hotplug`},
		"a glob under binfmt_misc":      {sysctl, "fs.binfmt_*.register=:x:E::bin::/usr/lib/agentos/agentos-side:\n", `could name fs.binfmt_misc`},
		"a glob over binfmt_misc":       {sysctl, "f?.*.*=1\n", `could name fs.binfmt_misc`},
		"a bad glob":                    {sysctl, "kernel.[=1\n", `could name`},
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
		"a tmpfiles owned /var/run unit program": {tmpfiles, "z /run/agentos-v/x 0755 agentos-side\n", `in or above /run/agentos-v/x`},
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
			if _, err := set(t, files); err != nil {
				t.Fatalf("%s alone: %v", prog, err)
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

func TestUnitVarsAreUsed(t *testing.T) {
	used := map[string]bool{}
	err := filepath.WalkDir(filepath.Join(repoRoot(t), "image"), func(p string, d os.DirEntry, err error) error {
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
	for name := range unitVars {
		if !used[name] {
			t.Errorf("unitVars lists %s, which no unit under image/ passes", name)
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

// fsTree writes files, by their path in the tree, under a new root file
// system and returns it; a value "-> target" is a link to target.
func fsTree(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for p, text := range files {
		f := filepath.Join(root, filepath.FromSlash(p))
		if err := os.MkdirAll(filepath.Dir(f), 0o755); err != nil {
			t.Fatal(err)
		}
		if target, ok := strings.CutPrefix(text, "-> "); ok {
			if err := os.Symlink(target, f); err != nil {
				t.Fatal(err)
			}
			continue
		}
		if err := os.WriteFile(f, []byte(text), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

// imageUnits places the units and drop-ins of a fakeRepo's files in
// /usr/lib/systemd/system, as an image installs them.
func imageUnits(files map[string]string) map[string]string {
	out := map[string]string{}
	for p, text := range files {
		dir := path.Base(path.Dir(p))
		switch {
		case !strings.HasPrefix(p, "image/"):
		case unitTypes[path.Ext(p)]:
			out["/usr/lib/systemd/system/"+path.Base(p)] = text
		case strings.HasSuffix(p, ".conf") && isDropinDir(dir):
			out["/usr/lib/systemd/system/"+dir+"/"+path.Base(p)] = text
		}
	}
	return out
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
		"agentosd's -owner value: the unit's AGENTOS_OWNER= overrides the manager's environment, and only /etc/agentos/agentosd.env (0600 in root's 0700 /etc/agentos, written by onboarding, image ASSUMPTIONS I6) fills it; with-uids runs agentosd, its first argument, and passes this one on as data"},
}

// unitVar pins where a unitVars variable may appear: only in unit, in a
// command that starts with cmd, right after the word flag, and only when
// every EnvironmentFile= is envFile (#4494 Security delta 2 and 3) and the
// unit clears it with NAME= that no Environment= reset undoes and no
// PassEnvironment= names (#4533). systemd lays Environment= over the
// manager's environment (DefaultEnvironment=, systemd.setenv=) and
// PassEnvironment=, and EnvironmentFile= over all three, so the value is
// the env file's or empty. A PAMName= session lays pam_env's variables over
// all of these, so a unit that sets one is refused (#4626).
type unitVar struct {
	unit    string
	cmd     []string
	flag    string
	envFile string
	reason  string
}

// envLine is one Environment=, EnvironmentFile=, PassEnvironment= or
// PAMName= of a unit, in the order systemd reads its files and lines.
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
		case "PAMName":
			return false
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
	return cleared
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

// rootPathKeys are the settings of a unit, besides Environment= and
// EnvironmentFile=, that decide what its commands read, run, write or search:
// the root it sees and how it is verified, the images and trees mounted into
// it, its working directory, program search path, standard streams,
// credentials, handed-over files, terminal, namespaces and BPF programs:
// each a path the manager opens for it as root. In a unit with a root command each
// path one names must be rootOwned, and a TemporaryFileSystem= is held to the
// mount rules (#4589, #4677 Security R-2).
var rootPathKeys = map[string]bool{
	"RootDirectory": true, "RootImage": true, "MountImages": true, "ExtensionDirectories": true, "ExtensionImages": true,
	"BindPaths": true, "BindReadOnlyPaths": true, "TemporaryFileSystem": true, "WorkingDirectory": true, "ExecSearchPath": true,
	"RootHash": true, "RootHashSignature": true, "RootVerity": true, "StandardInput": true, "StandardOutput": true, "StandardError": true,
	"LoadCredential": true, "LoadCredentialEncrypted": true, "TTYPath": true, "NetworkNamespacePath": true, "IPCNamespacePath": true,
	"OpenFile": true, "ImportCredential": true, "BPFProgram": true, "IPIngressFilterPath": true, "IPEgressFilterPath": true,
}

// wholePaths are the keys whose value, after a - that lets it be missing,
// is one path, read whole: a : or blank in it is part of the name (#4677
// Security R-3).
var wholePaths = map[string]bool{
	"WorkingDirectory": true, "RootDirectory": true, "RootImage": true, "EnvironmentFile": true,
	"RootVerity": true, "TTYPath": true, "NetworkNamespacePath": true, "IPCNamespacePath": true,
	"IPIngressFilterPath": true, "IPEgressFilterPath": true,
}

// pathSetting is the bytes a rootPathKeys value may hold: no quote,
// escape, % specifier or ~ for a home, each of which the lint would have to
// expand. pathByte finds the first other one.
var (
	pathSetting = regexp.MustCompile(`^[A-Za-z0-9_./@:,=+ \t-]*$`)
	pathByte    = regexp.MustCompile(`[^A-Za-z0-9_./@:,=+ \t-]`)
)

// rootEnv are the only variables a unit with a root command may set in
// Environment=: each picks no file, library or program its commands load
// (as LD_PRELOAD, BASH_ENV, PYTHONPATH or SSL_CERT_FILE would), and PATH=
// is held to rootOwned. A closed list is read rather than a list of the
// names that do load (#4677 Security R-2).
var rootEnv = map[string]bool{"PATH": true, "AGENTOS_OWNER": true, "GOMEMLIMIT": true}

// rootHash is a RootHash= given as hex rather than a path.
var rootHash = regexp.MustCompile(`^[0-9a-fA-F]+$`)

// rootOwned reports whether p is an absolute path, with no .., in rootTrees,
// which runBinaries lets no other uid write. It is rootTrees, not every path
// root owns: a root unit's WorkingDirectory=/var/lib/agentos is refused
// (#4677 L3-R3).
func rootOwned(p string) bool {
	if !strings.HasPrefix(p, "/") || dotdot(p) {
		return false
	}
	_, ok := inTree(path.Clean(p), rootTrees)
	return ok
}

// rootPathSetting holds one setting of a unit with a root command, a
// rootPathKeys one or an Environment= or EnvironmentFile=, to the rules
// rootPathKeys gives: Environment= only in what PATH= it sets, where an
// empty entry is the working directory, and in holding no % specifier. Any other key passes.
func rootPathSetting(k, v string) error {
	var paths []string
	switch {
	case k == "Environment":
		cmds, err := execWords(v)
		if err != nil {
			return err
		}
		for _, cmd := range cmds {
			for _, w := range cmd {
				// systemd expands a specifier in Environment= (%I turns
				// - into /), so a value the lint cannot see is refused
				// (#4656 Security 1).
				if substitutes(w, '%') {
					return fmt.Errorf("word %q holds a %% specifier, whose value the lint cannot see", w)
				}
				name, val, _ := strings.Cut(w, "=")
				if !rootEnv[name] {
					return fmt.Errorf("variable %q; a unit with a root command sets only the variables rootEnv lists, none of which picks what its commands load", name)
				}
				if name == "PATH" {
					paths = append(paths, strings.Split(val, ":")...)
				}
			}
		}
	case k != "EnvironmentFile" && !rootPathKeys[k]:
	case k == "ImportCredential" && v != "":
		// A glob over the credential stores, /run/credstore among them,
		// which the lint does not hold, as a LoadCredential= with no path.
		return fmt.Errorf("ImportCredential= searches credential stores the lint does not hold; a unit with a root command loads a credential only by LoadCredential= with a rootOwned path")
	case !pathSetting.MatchString(v):
		return fmt.Errorf("byte %q, a byte other than a letter, digit, blank or one of _./@:,=+-, which the lint would have to expand", pathByte.FindString(v))
	case v == "":
		// An empty value resets the setting.
	case wholePaths[k]:
		paths = []string{strings.TrimPrefix(v, "-")}
	case k == "ExtensionDirectories":
		for _, w := range strings.Fields(v) {
			paths = append(paths, strings.TrimPrefix(w, "-"))
		}
	case k == "ExecSearchPath":
		paths = strings.Split(v, ":")
	case k == "RootHash" && rootHash.MatchString(v), k == "RootHashSignature" && strings.HasPrefix(v, "base64:"):
		// The hash or signature itself, not a file holding it.
	case k == "RootHash" || k == "RootHashSignature":
		paths = []string{v}
	case strings.HasPrefix(k, "Standard"):
		// file:, append: and truncate: name a path root opens; the
		// others (journal, socket, null, tty, fd:x, data) name none.
		kind, p, _ := strings.Cut(v, ":")
		if kind == "file" || kind == "append" || kind == "truncate" {
			paths = []string{p}
		}
	case strings.HasPrefix(k, "LoadCredential"):
		// ID:PATH; with no path, or a relative one, systemd searches
		// credential stores (/run/credstore among them) the lint does not
		// hold, so the path is read as given and must be rootOwned.
		_, p, _ := strings.Cut(v, ":")
		paths = []string{p}
	case k == "OpenFile":
		// PATH[:NAME[:OPTIONS]]: the manager opens PATH, or connects to
		// it, as root and hands the command the descriptor (#4698
		// Security 1).
		p, _, _ := strings.Cut(v, ":")
		paths = []string{p}
	case k == "BPFProgram":
		// TYPE:PATH: the manager loads the pinned program at PATH.
		_, p, _ := strings.Cut(v, ":")
		paths = []string{p}
	case k == "TemporaryFileSystem":
		for _, w := range strings.Fields(v) {
			p, opts, _ := strings.Cut(w, ":")
			if !strings.HasPrefix(p, "/") || dotdot(p) {
				return fmt.Errorf("TemporaryFileSystem= path %q; want an absolute path with no ..", p)
			}
			// systemd's default mode is 0755.
			_, held := inOrAbove(path.Clean(p), rootTrees)
			if _, err := mountOptions(opts, held); opts != "" && err != nil {
				return err
			}
		}
	default:
		// Each word is [-]SOURCE[:DEST[:OPTIONS]]; - lets it be missing.
		for _, w := range strings.Fields(v) {
			p, _, _ := strings.Cut(strings.TrimPrefix(w, "-"), ":")
			paths = append(paths, p)
		}
	}
	for _, p := range paths {
		if !rootOwned(p) {
			return fmt.Errorf("path %q; a unit with a root command reads, runs and searches only absolute paths, with no .., in the trees root owns (rootTrees)", p)
		}
	}
	return nil
}

// dirBases are the directories systemd makes a unit's *Directory= paths
// in. All but ConfigurationDirectory='s go to its User= and Group=, and a
// *DirectoryMode= (0755 if unset) sets their mode (systemd.exec(5)); with
// DynamicUser= a state, cache or logs directory is the private/ one,
// linked from the plain path.
var dirBases = map[string]string{
	"RuntimeDirectory": "/run", "StateDirectory": "/var/lib", "CacheDirectory": "/var/cache",
	"LogsDirectory": "/var/log", "ConfigurationDirectory": "/etc",
}

// dirName is a *Directory= path systemd takes: relative and normalized. A %
// specifier is refused only in a grant, whose path the lint must see
// (#4677 L3-R2).
var dirName = regexp.MustCompile(`^[A-Za-z0-9_.@+%-]+(/[A-Za-z0-9_.@+%-]+)*$`)

// unitGrants returns the paths a unit's *Directory= settings let another
// uid write (#4584): every one but a ConfigurationDirectory= of a unit with
// a User= or DynamicUser= that is or may be another uid (a User=%i template
// among them; a drop-in's User=root does not undo it), and every one whose *DirectoryMode= has a group or
// other write bit. Each path, and each name after a : that links to it, is
// a plain relative path.
func unitGrants(root string, settings []envLine, asUser bool) ([]grant, error) {
	open := map[string]string{} // key -> a *DirectoryMode= that lets another uid write
	for _, l := range settings {
		key, mode := strings.CutSuffix(l.key, "Mode")
		if m, err := strconv.ParseUint(l.value, 8, 32); mode && (err != nil || m&0o022 != 0) {
			open[key] = "mode " + l.value
		}
	}
	var out []grant
	for _, l := range settings {
		base := dirBases[l.key]
		if base == "" {
			continue
		}
		rel, _ := filepath.Rel(root, l.file)
		where := fmt.Sprintf("%s: %s=%s", filepath.ToSlash(rel), l.key, l.value)
		how := open[l.key]
		if asUser && l.key != "ConfigurationDirectory" {
			how = "the unit's user owns"
		}
		for _, w := range strings.Fields(l.value) {
			for _, p := range strings.Split(w, ":") {
				// "." is the base itself: /run/. is not seen as above
				// /run/systemd (#4677 Security R-5).
				if !dirName.MatchString(p) || dotdot(p) || p == "." || path.Clean(p) != p {
					return nil, fmt.Errorf("%s: %q; want a plain relative path below the base, with no quote or ..", where, p)
				}
				if how == "" {
					continue
				}
				if strings.Contains(p, "%") {
					return nil, fmt.Errorf("%s: %q; a directory %s holds a %% specifier, whose path the lint cannot see", where, p, how)
				}
				out = append(out, grant{where, how, base + "/" + p})
				if base != "/run" && base != "/etc" {
					out = append(out, grant{where, how, base + "/private/" + p})
				}
			}
		}
	}
	return out, nil
}

// nameToken is a run of the bytes of a word that can belong to a program's name;
// any other ends a token (a quote, =, :, ;, $, a parenthesis or blank).
var nameToken = regexp.MustCompile(`[A-Za-z0-9_./@+-]+`)

// rootBinaries returns the broker packages (as ./path, relative to broker/)
// of the binaries a unit under image/ starts as root or a runKinds file
// names.
func rootBinaries(root string) ([]string, error) {
	units := map[string]string{}     // unit file path -> name
	dropins := map[string][]string{} // drop-in directory name -> its .conf paths
	var fstabs []string
	err := filepath.WalkDir(filepath.Join(root, "image"), func(p string, d os.DirEntry, err error) error {
		dir := filepath.Base(filepath.Dir(p))
		switch {
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
	pkgs, err := binaryPackages(root)
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
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
			if _, err := mountLines(root, []string{f}, ""); err != nil {
				return nil, err
			}
		}
	}
	for _, f := range fstabs {
		if err := fstabLines(root, f); err != nil {
			return nil, err
		}
	}
	// A unit is read with every drop-in under image/ of a name systemd
	// reads for it. A packaged unit's drop-ins, and units a package or build
	// step ships, are read on the built root file systems (builtUnits, #4677).
	c := &unitCheck{root: root, pkgs: pkgs, seen: seen}
	for p, name := range units {
		paths := []string{p}
		for _, dir := range dropinDirs(name) {
			paths = append(paths, dropins[dir]...)
		}
		if err := c.unit(name, paths, false, nil); err != nil {
			return nil, err
		}
	}
	if err := runBinaries(root, pkgs, seen, c.progs, c.grants); err != nil {
		return nil, err
	}

	var out []string
	for pkg := range seen {
		out = append(out, pkg)
	}
	sort.Strings(out)
	return out, nil
}

// unitCheck holds what reading units finds: the broker packages (by pkgs)
// a root command names, the programs units run as root and the paths they
// let another uid write.
type unitCheck struct {
	root   string            // a message names a file relative to it
	pkgs   map[string]string // broker binary name -> package
	seen   map[string]bool
	progs  []string // run as root by a line not trusted
	grants []grant  // made by a line not trusted
	// What trusted lines alone run as root or let another uid write.
	pkgProgs  []string
	pkgGrants []grant
	// Sockets whose endpoint is a package's (unit_rules.py's package).
	pkgSockets map[string]bool
	// Services a package's socket hands its connections or fds to.
	pkgFed map[string]bool
	// Every name of those sockets and services, and the pre@ prefixes of
	// fed templates (unit_rules.py's held).
	held    map[string]bool
	heldPre []string
	// The paths a package's socket listens on or links (pkgListenPaths).
	pkgListen []listenPat
	// The built tree's links (unitRecords.Links), and whether a socket of
	// ours may listen only on a path: set for a built tree, where the
	// package sockets and daemons whose ports it may share are.
	links     map[string]string
	pathsOnly bool
}

// namesHeld returns the first word of a [Unit] line, key k, that names a
// package's socket or a service it feeds (c.held), or that holds a
// specifier, which may expand to a whole unit name (Conflicts=%i, #5072 L3
// round 6) and this cannot resolve; "" if none. Only Description= and
// Documentation= name no unit.
func (c *unitCheck) namesHeld(k, v string) string {
	if k == "Description" || k == "Documentation" {
		return ""
	}
	for _, w := range strings.Fields(v) {
		if strings.Contains(strings.ReplaceAll(w, "%%", ""), "%") {
			return w
		}
		if path.Ext(w) != ".service" && path.Ext(w) != ".socket" {
			continue // held holds only sockets and services
		}
		if c.held[w] {
			return w
		}
		for _, p := range c.heldPre {
			if strings.HasPrefix(w, p) && path.Ext(w) == ".service" {
				return w
			}
		}
	}
	return ""
}

// orderKeys are the only [Unit] keys a line of ours may set on a package's
// socket or a service it feeds: what starts with it and in what order. Any
// other (JoinsNamespaceOf=, BindsTo=, Condition*=, Conflicts=) changes where
// or whether the package's lines run (#5072 round 4); the image's networkd
// and resolved drop-ins set Requires= and After=.
var orderKeys = map[string]bool{"After": true, "Before": true, "Requires": true, "Wants": true}

// owners are the keys that set the owner systemd gives a unit's *Directory=
// trees (setup_exec_directory chowns them to the unit's uid and gid): with
// *DirectoryMode=, the whole input of that chown and chmod (#4821 Security 1).
var owners = map[string]bool{"User": true, "Group": true, "DynamicUser": true}

// unit reads the unit name from paths: its unit file and the drop-ins
// systemd reads for it, or, alone, one drop-in read with no unit file, as a
// unit that runs as root and whose user owns its directories. A file in
// trusted is a package's: its User=, DynamicUser= and *Directory= lines are
// read, and a command in it that may run as root holds the unit's other
// files to a root command's rules, but its own commands and settings are
// not held (#4677).
func (c *unitCheck) unit(name string, paths []string, alone bool, trusted map[string]bool) error {
	if filepath.Ext(name) == ".mount" {
		unit := name
		if alone {
			unit = ""
		}
		_, err := mountLines(c.root, paths, unit)
		return err
	}
	// A later User= or DynamicUser= replaces an earlier one, and drop-ins
	// sort across directories, so any assignment that runs as root (an
	// empty, root or 0 User=, a false DynamicUser=) counts as root
	// wherever it sits: an over-approximation that never drops a root
	// binary (#3951 L3 3).
	asUser, asRoot := false, alone
	owned := alone // a User= or DynamicUser= that may be another uid owns the unit's directories
	type execLine struct {
		file, key, value string
		trusted          bool
	}
	var lines []execLine
	var env []envLine
	var settings []envLine // rootPathKeys and dirBases lines
	section := map[string]string{".service": "Service", ".socket": "Socket"}[filepath.Ext(name)]
	userOurs := false             // an owner line (owners) not trusted
	modeOurs := map[string]bool{} // a *Directory= key whose mode a line not trusted sets
	reread := ""                  // the first such line, which changes how a package's lines read
	ours := ""                    // the first line of the type's section not trusted
	takes := ""                   // the first Sockets= line not trusted
	unitOurs := ""                // the first [Unit] line not trusted, but an ordering one (orderKeys)
	edgeOurs := ""                // the first such line naming a package's socket or a service it feeds
	pkgFile := false              // a file in trusted
	listen := ""                  // the first Listen*= line of ours on a package socket's path (pkgListen)
	// Every refusal the unit reaches is reported, and reading goes on past
	// it, so its root programs still reach c.progs for grantsHeld (#5075 R2).
	var errs []error
	for _, f := range paths {
		b, err := os.ReadFile(f)
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(c.root, f)
		ul, err := unitLines(string(b))
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %v", filepath.ToSlash(rel), err))
			continue
		}
		pkgFile = pkgFile || trusted[f]
		for _, line := range ul {
			k, v := line.key, line.value
			if ours == "" && line.section == section && !trusted[f] {
				ours = filepath.ToSlash(rel) + ": " + k + "=" + v
			}
			if unitOurs == "" && line.section == "Unit" && !trusted[f] && !orderKeys[k] {
				unitOurs = filepath.ToSlash(rel) + ": " + k + "=" + v
			}
			if edgeOurs == "" && line.section == "Unit" && !trusted[f] && !orderKeys[k] && c.namesHeld(k, v) != "" {
				edgeOurs = filepath.ToSlash(rel) + ": " + k + "=" + v
			}
			if takes == "" && section == "Service" && line.section == section && !trusted[f] && k == "Sockets" {
				takes = filepath.ToSlash(rel) + ": " + k + "=" + v
			}
			if listen == "" && section == "Socket" && line.section == section && !trusted[f] {
				words, plain := endpointWords(k, v)
				if !plain {
					listen = filepath.ToSlash(rel) + ": " + k + "=" + v + ": a listen path of ours is quoted or escaped, which systemd reads and this does not; write it plainly"
				}
				for _, w := range words {
					if why := c.onPkgListen(w); listen == "" && why != "" {
						listen = filepath.ToSlash(rel) + ": " + k + "=" + v + ": a listen path of ours " + why
						break
					}
				}
			}
			if section == "Socket" && line.section == section && !trusted[f] && k == "DirectoryMode" && openMode(v) {
				errs = append(errs, fmt.Errorf("%s: %s=%s: a directory mode of ours lets another uid write, or is not a plain octal mode; PID 1 makes a listen path's missing parents with it, and another uid could plant a package's path below them (#5620 R-a)", filepath.ToSlash(rel), k, v))
			}
			if line.section == section && !trusted[f] {
				userOurs = userOurs || owners[k]
				key, mode := strings.CutSuffix(k, "Mode")
				if mode && dirBases[key] != "" {
					modeOurs[key] = true
				}
				if reread == "" && (owners[k] || mode && dirBases[key] != "") {
					rel, _ := filepath.Rel(c.root, f)
					reread = filepath.ToSlash(rel) + ": " + k + "=" + v
				}
			}
			switch {
			case line.section != section:
				// systemd reads a unit's User= and Exec lines only in its
				// type's own section.
			case trusted[f] && k != "User" && k != "DynamicUser" && dirBases[strings.TrimSuffix(k, "Mode")] == "" && !strings.HasPrefix(k, "Exec"):
				// A package's setting.
			case k == "Environment" || k == "EnvironmentFile" || k == "PassEnvironment" || k == "PAMName":
				env = append(env, envLine{f, k, v})
			case k == "User" && (v == "" || v == "root" || v == "0" || mayBeRoot(v)):
				// A User=%i template is root for its root instance, and
				// every other instance owns its directories (#4656 L3 1).
				asRoot, owned = true, owned || mayBeRoot(v)
			case k == "User":
				asUser = true
			case k == "DynamicUser" && (v == "yes" || v == "true" || v == "1" || v == "on"):
				asUser = true
			case k == "DynamicUser":
				asRoot = true
			case rootPathKeys[k] || dirBases[strings.TrimSuffix(k, "Mode")] != "":
				settings = append(settings, envLine{f, k, v})
			case k == "ExecPaths":
				// Paths that may run, not commands.
			case strings.HasPrefix(k, "Exec"):
				lines = append(lines, execLine{f, k, v, trusted[f]})
			}
		}
	}
	// A file read alone may apply to units the tree does not list, whose
	// lines are not in view; an owner line (owners) or directory mode of
	// ours would change how those read (a package's grant becomes ours), so
	// alone is the worst context only without one (#4779 re-plan).
	if alone && reread != "" {
		errs = append(errs, fmt.Errorf("%s: a file read alone may apply to units not in view, so it may not set a directory's owner or mode", reread))
	}
	// A package's socket and what it activates are the package's: no
	// [Socket] line of ours on a socket one of whose files, its name or the
	// service it feeds is a package's (pkgSockets), or in a file read alone,
	// and no [Service] line of ours, fragment or drop-in, on a service such
	// a socket hands its connections or listening fds to (pkgFed). A closed
	// form: each key list before it missed a route (#5072 Security rounds
	// 1-3). Our own sockets, all of whose files are ours, set their own.
	if section == "Socket" && ours != "" && (alone || pkgFile || c.pkgSockets[name]) {
		errs = append(errs, fmt.Errorf("%s: a line of ours on a package's socket (by a file, its name or the service it feeds), or in a file read alone, may not set any [Socket] setting", ours))
	}
	if section == "Service" && ours != "" && c.pkgFed[name] {
		errs = append(errs, fmt.Errorf("%s: a line of ours on a service a package's socket feeds (its connections or listening fds) may not set any [Service] setting", ours))
	}
	// A socket of ours, name and service ours, on a package socket's path
	// takes the package's endpoint: systemd unlinks a path in use and binds
	// again (#5075 R3).
	if listen != "" {
		errs = append(errs, errors.New(listen))
	}
	pkgSocket := section == "Socket" && (alone || pkgFile || c.pkgSockets[name])
	if unitOurs != "" && (pkgSocket || section == "Service" && c.pkgFed[name]) {
		errs = append(errs, fmt.Errorf("%s: a [Unit] line of ours on a package's socket or a service it feeds may set only After=, Before=, Requires= or Wants=", unitOurs))
	}
	// systemd puts an edge on both units (JoinsNamespaceOf= is symmetric,
	// Conflicts= adds ConflictedBy=, PropagatesStopTo= StopPropagatedFrom=),
	// so the same keys are held from our side too, in every unit (#5072
	// Security round 5 point 2).
	if edgeOurs != "" {
		errs = append(errs, fmt.Errorf("%s: a [Unit] line of ours naming a package's socket or a service it feeds may set only After=, Before=, Requires= or Wants=", edgeOurs))
	}
	if alone && takes != "" {
		errs = append(errs, fmt.Errorf("%s: a file read alone may not make a service take a socket", takes))
	}
	rootCmd := false
	for _, l := range lines {
		if l.trusted {
			// A package's command is not held, but one that may run as
			// root holds the unit's own settings as a root command's.
			if l.value != "" && (!asUser || asRoot || strings.ContainsAny(l.value, "+!")) {
				rootCmd = true
				c.pkgProgs = append(c.pkgProgs, execProgs(l.value)...)
			}
			continue
		}
		rel, _ := filepath.Rel(c.root, l.file)
		cmds, err := execWords(l.value)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %s=%s: %v", filepath.ToSlash(rel), l.key, l.value, err))
			continue
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
				errs = append(errs, fmt.Errorf("%s: %s=%s: want a program that is a plain absolute path, with no | prefix, %% or $", filepath.ToSlash(rel), l.key, l.value))
				continue
			}
			for _, w := range words {
				if substitutes(w, '%') {
					errs = append(errs, fmt.Errorf("%s: %s=%s: word %q holds a %% specifier, whose value the reader cannot see", filepath.ToSlash(rel), l.key, l.value, w))
					break
				}
			}
			if asUser && !asRoot && !strings.ContainsAny(prefix, "+!") {
				continue
			}
			rootCmd = true
			c.progs = append(c.progs, prog)
			// systemd fills in $X and ${X} before a wrapper or shell runs
			// the result, so a root command holds none but a whole-word
			// ${X} of unitVars (#4494).
			for i, w := range words[1:] {
				if !allowedVar(name, words, i+1, env) && substitutes(w, '$') {
					errs = append(errs, fmt.Errorf("%s: %s=%s: word %q holds a $ substitution, whose value a wrapper or shell may run; only a whole-word ${X} of unitVars is read", filepath.ToSlash(rel), l.key, l.value, w))
					break
				}
			}
			// A program's arguments may name another a wrapper (with-uids
			// execs "$@") or shell runs: every absolute token counts, in a
			// quoted shell script too.
			for _, w := range append([]string{prog}, words[1:]...) {
				for _, tok := range nameToken.FindAllString(w, -1) {
					if pkg, ok := c.pkgs[path.Base(tok)]; ok && strings.HasPrefix(tok, "/") {
						c.seen[pkg] = true
					}
				}
			}
		}
	}
	// What the unit makes for its user is a grant (#4584), and what a
	// root command reads, runs and searches lies in trees root owns
	// (#4589).
	// A grant is ours when its *Directory= line, a mode line for it, or a
	// User= or DynamicUser= is; a package's own is held only against what
	// ours runs as root (#4737 Security 4, L3 3).
	var modes []envLine
	for _, l := range settings {
		if strings.HasSuffix(l.key, "Mode") {
			modes = append(modes, l)
		}
	}
	for _, l := range settings {
		if dirBases[l.key] == "" {
			continue
		}
		pkgGrant := !userOurs && trusted[l.file] && !modeOurs[l.key]
		g, err := unitGrants(c.root, append([]envLine{l}, modes...), asUser || owned)
		switch {
		case err != nil && pkgGrant:
			// A package's own directory the reader cannot read (a %
			// specifier, a .. step): its lines are the package's, as a
			// root command's are (#4737 Security 6588498486 R1).
			continue
		case err != nil:
			errs = append(errs, err)
			continue
		}
		if !pkgGrant {
			c.grants = append(c.grants, g...)
		} else {
			c.pkgGrants = append(c.pkgGrants, g...)
		}
	}
	if !rootCmd && !alone {
		return errors.Join(errs...)
	}
	for _, l := range append(settings, env...) {
		if err := rootPathSetting(l.key, l.value); err != nil {
			rel, _ := filepath.Rel(c.root, l.file)
			errs = append(errs, fmt.Errorf("%s: %s=%s: %v", filepath.ToSlash(rel), l.key, l.value, err))
		}
	}
	return errors.Join(errs...)
}

// sharedRuns are trees many units' sockets sit in, so a package socket's
// directory among them holds no path of ours to it (#5075 R3).
var sharedRuns = map[string]bool{"/": true, "/run": true, "/tmp": true, "/var/tmp": true, "/dev": true, "/dev/shm": true}

// Specifier placeholders in an expanded path: one whose value holds no
// slash (specWord), and one whose value may (specPath).
const (
	specWord = "\x00"
	specPath = "\x01"
)

// The system manager's specifiers, read by one model (systemd.unit(5)
// "Specifiers", #5614 L3 round 2): fixedRoots have one constant value for
// the system manager and are expanded; oneWord are names systemd validates
// to hold no / (unit-name parts as escaped, user and group names and ids,
// host names, machine and boot ids), each within one component; any other
// (%T, %V and %h, which PID 1's environment sets; %I, %J, %P and %f
// unescaped; %d, %y, %Y, %q, os-release fields, a lone %) may span
// components (#5614 Security round 3 R-g).
var fixedRoots = map[byte]string{'t': "/run", 'S': "/var/lib", 'C': "/var/cache", 'L': "/var/log", 'E': "/etc"}

const oneWord = "ijnNpuUgGHlmb"

// openMode says whether a DirectoryMode= value is not an allowed one: an
// octal mode (systemd's parse_mode) of at most 07777 with no group or
// other write bit.
func openMode(v string) bool {
	m, err := strconv.ParseUint(v, 8, 32)
	return err != nil || m > 0o7777 || m&0o022 != 0
}

// resolveDirs reads p's directories through the tree's links (each
// target resolved in the tree, as image/unit_rules.py prints them), its
// last component unfollowed, as bind(2) and symlink(2) leave it. via names
// the first link crossed, "" if none.
func resolveDirs(p string, links map[string]string) (r, via string) {
	dir, last := path.Split(p)
	cur := "/"
	for _, c := range strings.Split(dir, "/") {
		if c == "" {
			continue
		}
		cur = path.Join(cur, c)
		if t, ok := links[cur]; ok {
			if via == "" {
				via = cur + " -> " + t
			}
			cur = t
		}
	}
	return path.Join(cur, last), via
}

// expandListen reads an endpoint word as the system manager does, in one
// left-to-right pass: %% is a literal %, a fixed root is expanded, and any
// other specifier becomes a placeholder. ok is false only for a word that
// names no path (a port, an address, an abstract socket, ListenNetlink=, a
// lone name): one that begins with / or with a placeholder that may hold
// one is a path. canon is the word as expanded, before cleaning; p is
// cleaned, or "" when a .. component in it names a place the kernel
// resolves only after following links.
func expandListen(v string) (p, canon string, ok bool) {
	var b strings.Builder
	for i := 0; i < len(v); i++ {
		switch {
		case v[i] != '%':
			b.WriteByte(v[i])
			continue
		case i+1 == len(v):
			b.WriteString(specPath)
			continue
		}
		i++
		switch x := v[i]; {
		case x == '%':
			b.WriteByte('%')
		case fixedRoots[x] != "":
			b.WriteString(fixedRoots[x])
		case strings.IndexByte(oneWord, x) >= 0:
			b.WriteString(specWord)
		default:
			b.WriteString(specPath)
		}
	}
	canon = b.String()
	if !strings.HasPrefix(canon, "/") && !strings.HasPrefix(canon, specPath) {
		return "", "", false
	}
	for _, c := range strings.Split(canon, "/") {
		if c == ".." {
			return "", canon, true
		}
	}
	return path.Clean(canon), canon, true
}

// ourRuns is the only tree an endpoint path of ours may name: /run/agentos
// and /run/agentos-*, and what lies under them. A path of ours elsewhere
// may name an alias link the reader maps (/var/run, which an endpoint of
// ours there would unlink), a tree it holds as shared, an ancestor of a
// package's path, or a link the kernel follows before .., none of which
// the reader can hold apart (#5614 Security round 3, L3 round 3).
func inOurRuns(p string) bool {
	rest, ok := strings.CutPrefix(p, "/run/")
	first, _, _ := strings.Cut(rest, "/")
	return ok && strings.HasPrefix(first, "agentos")
}

// endpointWords returns the words of a [Socket] line that name a path PID
// 1 binds, creates or unlinks for the socket: a Listen*= value, read raw as
// systemd reads it, and each Symlinks= word (#5614 L3 1), which systemd
// splits with its quotes removed and escapes read (extract_first_word,
// EXTRACT_UNQUOTE). plain is false for a Symlinks= value holding a quote
// or a backslash: its quotes are removed here, but an escape is not read,
// so the value is returned whole as its one word (#5614 Security round 2).
func endpointWords(k, v string) (words []string, plain bool) {
	switch {
	case strings.HasPrefix(k, "Listen"):
		return []string{v}, true
	case k != "Symlinks":
		return nil, true
	case strings.Contains(v, "\\"):
		return []string{v}, false
	}
	plain = !strings.ContainsAny(v, "\"'")
	for v = strings.TrimLeft(v, " \t"); v != ""; v = strings.TrimLeft(v, " \t") {
		w := ""
		for v != "" && v[0] != ' ' && v[0] != '\t' {
			if q := v[0]; q == '"' || q == '\'' {
				end := strings.IndexByte(v[1:], q)
				if end < 0 {
					return []string{w + v}, false
				}
				w, v = w+v[1:1+end], v[2+end:]
				continue
			}
			w, v = w+v[:1], v[1:]
		}
		words = append(words, w)
	}
	return words, plain
}

// listenPat is a package socket's endpoint path as a pattern: re matches
// the path and every path under it, dir its directory and every path under
// that, or nil when the directory is one of sharedRuns. A specifier
// matches any value it may take (#5614 Security 1).
type listenPat struct {
	raw     string
	re, dir *regexp.Regexp
}

// patternOf compiles an expanded path, its placeholders read as wildcards.
func patternOf(p string) *regexp.Regexp {
	q := regexp.QuoteMeta(p)
	q = strings.ReplaceAll(q, specWord, "[^/]*")
	q = strings.ReplaceAll(q, specPath, ".*")
	return regexp.MustCompile("^" + strings.TrimSuffix(q, "/") + "(/.*)?$")
}

// pkgListenPaths returns every path a package's file in a socket unit of
// recs listens on or links, a word with a specifier as a pattern.
func pkgListenPaths(recs unitRecords) []listenPat {
	var out []listenPat
	for _, u := range recs.Units {
		if path.Ext(u.Unit) != ".socket" {
			continue
		}
		for _, f := range u.Files {
			ul, err := unitLines(f.Text)
			if f.Ours || err != nil {
				continue
			}
			for _, l := range ul {
				if l.section != "Socket" {
					continue
				}
				words, plain := endpointWords(l.key, l.value)
				for _, w := range words {
					if !plain && strings.Contains(w, "\\") {
						// An escape this does not read: any path.
						out = append(out, listenPat{raw: w, re: regexp.MustCompile("")})
						continue
					}
					p, _, ok := expandListen(w)
					if !ok {
						continue
					}
					if p == "" {
						// A .. the kernel reads after links: any path.
						out = append(out, listenPat{raw: w, re: regexp.MustCompile("")})
						continue
					}
					out = append(out, pkgListenPat(w, p, recs.Links))
				}
			}
		}
	}
	return out
}

// pkgListenPat holds a package's endpoint word w, expanded and cleaned to
// p, as a pattern read through the tree's links (#5620 R-c, R-i). Its
// directories up to the first placeholder are resolved; if a link may
// be a directory of any expansion past it, the word is any path. A
// placeholder that may span components in the last component makes the
// directory every path up to it (R-e); a directory of one placeholder is
// any directory, which the path's own pattern spans; and a directory
// among sharedRuns holds nothing apart. A name placeholder directly under
// sharedRuns stays held (R-h, kept): an instance of ours may name it.
func pkgListenPat(w, p string, links map[string]string) listenPat {
	comps := strings.Split(strings.TrimPrefix(p, "/"), "/")
	last := comps[len(comps)-1]
	cur, i := "/", 0
	for ; i < len(comps)-1 && !strings.ContainsAny(comps[i], specWord+specPath); i++ {
		cur = path.Join(cur, comps[i])
		if t, ok := links[cur]; ok {
			cur = t
		}
	}
	rest := comps[i:]
	if i < len(comps)-1 || strings.Contains(last, specPath) {
		// An ancestor pattern of every expansion past cur: each directory
		// component in turn, a spanning one ending the nesting.
		q, closing := "", ""
		for j, c := range rest {
			if j == len(rest)-1 && !strings.Contains(c, specPath) {
				break
			}
			if pre, _, span := strings.Cut(c, specPath); span {
				q += "(/" + strings.ReplaceAll(regexp.QuoteMeta(pre), specWord, "[^/]*") + ".*"
				closing += ")?"
				break
			}
			q += "(/" + strings.ReplaceAll(regexp.QuoteMeta(c), specWord, "[^/]*")
			closing += ")?"
		}
		anc := regexp.MustCompile("^" + regexp.QuoteMeta(strings.TrimSuffix(cur, "/")) + q + closing + "$")
		for k := range links {
			if k != cur && anc.MatchString(k) {
				return listenPat{raw: w, re: regexp.MustCompile("")}
			}
		}
	}
	p = path.Join(append([]string{cur}, rest...)...)
	lp := listenPat{raw: w, re: patternOf(p)}
	d := path.Dir(p)
	if pre, _, span := strings.Cut(path.Base(p), specPath); span {
		lp.dir = patternOf(path.Join(d, pre) + specPath)
	} else if !sharedRuns[d] && d != specWord && d != specPath {
		lp.dir = patternOf(d)
	}
	return lp
}

// onPkgListen says why an endpoint word of ours is refused; "" if it is
// not. Our side reads no specifier model (#5614 L3 round 4 step back): an
// allow-list on the raw word, where only %% (a literal %) and %t (/run)
// are read and any other specifier is refused, so no expansion of ours can
// differ from systemd's. A word that then does not begin with / names no
// path (a port or an address). A path must be canonical (no . or ..
// component, no doubled or trailing slash: the kernel resolves .. after
// following links), lie on no package socket's endpoint path or its
// directory (unless one of sharedRuns), and lie under /run/agentos*
// (inOurRuns), so it names no alias link, shared tree or ancestor of a
// package's path, which PID 1 would unlink or replace.
func (c *unitCheck) onPkgListen(v string) string {
	var b strings.Builder
	for i := 0; i < len(v); i++ {
		switch {
		case v[i] != '%':
			b.WriteByte(v[i])
		case i+1 < len(v) && v[i+1] == '%':
			b.WriteByte('%')
			i++
		case i+1 < len(v) && v[i+1] == 't':
			b.WriteString("/run")
			i++
		default:
			return "holds a specifier other than %t, whose value the reader does not read"
		}
	}
	p := b.String()
	switch {
	case !strings.HasPrefix(p, "/") && c.pathsOnly:
		return "names no path: in a built tree a socket of ours listens only on a path under /run/agentos*, since a port, address, abstract name, netlink group or vsock address may be a package socket's or a package daemon's own, which PID 1 may share as root (SO_REUSEPORT, #5620 R-b)"
	case !strings.HasPrefix(p, "/"):
		return ""
	case p != path.Clean(p):
		return "is not canonical (a . or .. component, or a doubled or trailing slash), and the kernel follows links before .."
	}
	q, via := resolveDirs(p, c.links)
	for _, l := range c.pkgListen {
		if l.re.MatchString(q) || l.dir != nil && l.dir.MatchString(q) {
			return "on a package socket's path, " + l.raw
		}
	}
	if via != "" {
		return "passes through a link in the tree, " + via + "; every directory on a listen path of ours must be a real one (#5620 R-c)"
	}
	if !inOurRuns(p) {
		return "lies outside /run/agentos*, the only tree the reader holds as ours"
	}
	return ""
}

// execProgs returns the programs an Exec line names, read loosely: each
// command's first word that is an absolute path, its prefix dropped.
func execProgs(v string) []string {
	cmds, err := execWords(v)
	if err != nil {
		cmds = [][]string{strings.Fields(v)}
	}
	var out []string
	for _, w := range cmds {
		if len(w) > 0 {
			if p := strings.TrimLeft(w[0], "@-:+!|"); strings.HasPrefix(p, "/") {
				out = append(out, p)
			}
		}
	}
	return out
}

// unitRecords are what image/unit_rules.py prints for a root file system:
// each unit its own systemd loads, with the files systemd applies to it in
// systemd's order after every mask (its fragment, then its drop-ins), or a
// drop-in of ours to read alone; /etc/fstab when it is ours; and, for a
// control, the refusal wanted.
type unitRecords struct {
	Units []struct {
		Unit    string `json:"unit"`
		Alone   bool   `json:"alone"`
		Package bool   `json:"package"`
		Fed     bool   `json:"fed"`
		Files   []struct {
			Path string `json:"path"`
			Ours bool   `json:"ours"`
			Text string `json:"text"`
		} `json:"files"`
	} `json:"units"`
	Fstab *struct {
		Path string `json:"path"`
		Text string `json:"text"`
	} `json:"fstab"`
	Masks []struct {
		Path  string `json:"path"`
		Hides string `json:"hides"`
	} `json:"masks"`
	Held struct {
		Names    []string `json:"names"`
		Prefixes []string `json:"prefixes"`
	} `json:"held"`
	// Every link in the tree that does not resolve to a file other than a
	// directory, mapped to its target resolved in the tree.
	Links map[string]string `json:"links"`
	Want  string            `json:"want"`
}

// builtUnits holds a built root file system's units, as its systemd loads
// them (recs), to the unit rules (#4677). Which files a unit reads and in
// what order is systemd's (image/unit_rules.py); this reads only whose
// lines they are: a file not ours is a package's (unitCheck.unit's
// trusted). A mount is held when one of its files is ours. A grant of ours
// may not lie in or above rootTrees or a program any unit runs as root, and
// a package's grant not in or above a program of ours runs as root. The
// files are written under dir, so a message names a file by its path in
// the tree.
func builtUnits(recs unitRecords, dir string) error {
	write := func(p, text string) (string, error) {
		f := filepath.Join(dir, filepath.FromSlash(path.Clean("/"+p)))
		if err := os.MkdirAll(filepath.Dir(f), 0o755); err != nil {
			return "", err
		}
		return f, os.WriteFile(f, []byte(text), 0o644)
	}
	c := &unitCheck{root: dir, seen: map[string]bool{}, pkgSockets: map[string]bool{}, pkgFed: map[string]bool{},
		held: map[string]bool{}, heldPre: recs.Held.Prefixes, pkgListen: pkgListenPaths(recs),
		links: recs.Links, pathsOnly: true}
	for _, n := range recs.Held.Names {
		c.held[n] = true
	}
	for _, u := range recs.Units {
		c.pkgSockets[u.Unit] = c.pkgSockets[u.Unit] || u.Package
		c.pkgFed[u.Unit] = c.pkgFed[u.Unit] || u.Fed
	}
	// Every refusal is reported, so one does not hide the rest of the
	// tree (#4821 Security R3).
	var errs []error
	for _, u := range recs.Units {
		var paths []string
		trusted := map[string]bool{}
		held := false
		for _, rf := range u.Files {
			f, err := write(rf.Path, rf.Text)
			if err != nil {
				return err
			}
			paths = append(paths, f)
			trusted[f] = !rf.Ours
			held = held || rf.Ours
		}
		if path.Ext(u.Unit) == ".mount" && !held {
			continue
		}
		if err := c.unit(u.Unit, paths, u.Alone, trusted); err != nil {
			errs = append(errs, fmt.Errorf("%s: %v", u.Unit, err))
		}
	}
	// A file of ours named as a package's drop-in, or a unit file a package
	// lists that systemd does not read as installed (changed, replaced or
	// gone while its unit loads), drops the package's lines: a closed form
	// for every unit (#5072 rounds 4 and 5).
	for _, m := range recs.Masks {
		if m.Path == m.Hides {
			errs = append(errs, fmt.Errorf("%s: a package's unit file or drop-in that systemd does not read as the package installed it", m.Path))
			continue
		}
		errs = append(errs, fmt.Errorf("%s: a file of ours hides a package's drop-in, %s, and with it the package's lines", m.Path, m.Hides))
	}
	if recs.Fstab != nil {
		f, err := write(recs.Fstab.Path, recs.Fstab.Text)
		if err != nil {
			return err
		}
		if err := fstabLines(dir, f); err != nil {
			errs = append(errs, err)
		}
	}
	errs = append(errs, grantsHeld(c.grants, append(append(append([]string{}, rootTrees...), c.progs...), c.pkgProgs...)))
	errs = append(errs, grantsHeld(c.pkgGrants, c.progs))
	return errors.Join(errs...)
}

// TestBuiltUnitsEveryRefusal: builtUnits reports every refusal in one
// pass, so the first does not hide the rest of the tree (#4821 Security R3).
func TestBuiltUnitsEveryRefusal(t *testing.T) {
	var recs unitRecords
	b := `{"units": [
		{"unit": "a.service", "alone": true, "files": [{"path": "/etc/systemd/system/a.service.d/z.conf", "ours": true, "text": "[Service]\nEnvironment=LD_PRELOAD=/tmp/a.so\n"}]},
		{"unit": "b.service", "alone": true, "files": [{"path": "/etc/systemd/system/b.service.d/z.conf", "ours": true, "text": "[Service]\nWorkingDirectory=/tmp/b\n"}]},
		{"unit": "c.service", "alone": false, "files": [{"path": "/etc/systemd/system/c.service", "ours": true, "text": "[Service]\nUser=c\nExecStart=/usr/bin/c\nStateDirectory=c\nStateDirectoryMode=0777\n"}]},
		{"unit": "d.service", "alone": false, "files": [{"path": "/etc/systemd/system/d.service", "ours": true, "text": "[Service]\nExecStart=/var/lib/c/run\n"}]}]}`
	if err := json.Unmarshal([]byte(b), &recs); err != nil {
		t.Fatal(err)
	}
	err := builtUnits(recs, t.TempDir())
	for _, want := range []string{`a.service: `, `variable "LD_PRELOAD"`, `b.service: `, `path "/tmp/b"`, `in or above /var/lib/c/run`} {
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("got %v, want every refusal, with %q", err, want)
		}
	}
}

// TestBuiltUnitsRefusedUnitPrograms: a unit refused before or among its
// commands still gives grantsHeld every program it runs as root, so the
// report names a grant above one (#5075 R2).
func TestBuiltUnitsRefusedUnitPrograms(t *testing.T) {
	grant := `{"unit": "c.service", "alone": false, "files": [{"path": "/etc/systemd/system/c.service", "ours": true, "text": "[Service]\nUser=c\nExecStart=/usr/bin/c\nStateDirectory=c\nStateDirectoryMode=0777\n"}]}`
	for name, c := range map[string]struct {
		unit string
		want string
	}{
		"refused before its commands": {`{"unit": "d.service", "alone": false, "fed": true, "files": [{"path": "/etc/systemd/system/d.service", "ours": true, "text": "[Service]\nExecStart=/var/lib/c/run\n"}]}`, `a line of ours on a service a package's socket feeds`},
		"refused among its commands":  {`{"unit": "d.service", "alone": false, "files": [{"path": "/etc/systemd/system/d.service", "ours": true, "text": "[Service]\nExecStartPre=run\nExecStart=/var/lib/c/run\n"}]}`, `want a program that is a plain absolute path`},
		"refused for a word":          {`{"unit": "d.service", "alone": false, "files": [{"path": "/etc/systemd/system/d.service", "ours": true, "text": "[Service]\nExecStart=/var/lib/c/run %i\n"}]}`, `holds a % specifier`},
		"refused for a setting":       {`{"unit": "d.service", "alone": false, "files": [{"path": "/etc/systemd/system/d.service", "ours": true, "text": "[Service]\nEnvironment=LD_PRELOAD=/tmp/x.so\nExecStart=/var/lib/c/run\n"}]}`, `variable "LD_PRELOAD"`},
	} {
		t.Run(name, func(t *testing.T) {
			var recs unitRecords
			if err := json.Unmarshal([]byte(`{"units": [`+c.unit+`, `+grant+`]}`), &recs); err != nil {
				t.Fatal(err)
			}
			err := builtUnits(recs, t.TempDir())
			for _, want := range []string{c.want, `in or above /var/lib/c/run`} {
				if err == nil || !strings.Contains(err.Error(), want) {
					t.Errorf("got %v, want every refusal, with %q", err, want)
				}
			}
		})
	}
}

// TestBuiltUnitsPackageListenPatterns: every endpoint word, a Listen*=
// value or a Symlinks= word, is read by one model of systemd's specifiers
// (expandListen): %% a literal %, the system manager's fixed roots
// expanded, a validated name within one component, any other across
// components. A package's word is held as that pattern; a word of ours
// holding any but a fixed root, or quoted or escaped, is refused. One row
// per repro from every review round on #5614.
func TestBuiltUnitsPackageListenPatterns(t *testing.T) {
	const lib, etc = "/usr/lib/systemd/system/", "/etc/systemd/system/"
	devlog := "[Socket]\nListenDatagram=/run/systemd/journal/dev-log\nSymlinks=/dev/log\n"
	for name, c := range map[string]struct {
		pkgUnit, pkgText, ours, want string // ours: a ListenStream= value, or a whole [Socket] text
	}{
		// #5075 R3: a plain path, its /var/run and %t spellings, and its directory.
		"a package's path":                {"pkg.socket", "[Socket]\nListenStream=/run/pkg/s\n", "/run/pkg/s", `on a package socket's path, /run/pkg/s`},
		"a package's path by /var/run":    {"pkg.socket", "[Socket]\nListenStream=/run/pkg/s\n", "/var/run/pkg/s", `on a package socket's path, /run/pkg/s`},
		"a package's path by %t":          {"pkg.socket", "[Socket]\nListenStream=/run/pkg/s\n", "%t/pkg/s", `on a package socket's path, /run/pkg/s`},
		"a package path's directory":      {"pkg.socket", "[Socket]\nListenStream=/run/pkg/s\n", "/run/pkg/x", `on a package socket's path, /run/pkg/s`},
		"beside a package's path in /run": {"pkg.socket", "[Socket]\nListenStream=/run/pkg.sock\n", "/run/agentos-x/s", ""},
		"a specifier of ours":             {"pkg.socket", "[Socket]\nListenStream=/run/pkg/s\n", "/run/%I", `holds a specifier`},
		// #5614 Security round 1: a package's specifier is a pattern.
		"a journal namespace's socket":  {"systemd-journald@agentos-unit-lint.socket", "[Socket]\nListenStream=/run/systemd/journal.%i/stdout\n", "/run/systemd/journal.ns/stdout", `on a package socket's path, /run/systemd/journal.%i/stdout`},
		"a template's socket":           {"tpl@agentos-unit-lint.socket", "[Socket]\nListenStream=/run/tpl/%i.sock\n", "/run/tpl/a.sock", `on a package socket's path, /run/tpl/%i.sock`},
		"an instance path in /run":      {"tpl@agentos-unit-lint.socket", "[Socket]\nListenStream=/run/tpl-%i.sock\n", "/run/tpl-a.sock", `on a package socket's path, /run/tpl-%i.sock`},
		"an unescaped instance path":    {"tpl@agentos-unit-lint.socket", "[Socket]\nListenStream=/run/%I.sock\n", "/run/a/b.sock", `on a package socket's path, /run/%I.sock`},
		"a pattern's directory":         {"systemd-journald@agentos-unit-lint.socket", "[Socket]\nListenStream=/run/systemd/journal.%i/stdout\n", "/run/systemd/journal.ns/x", `on a package socket's path`},
		"beside a template in /run":     {"tpl@agentos-unit-lint.socket", "[Socket]\nListenStream=/run/tpl-%i.sock\n", "/run/agentos-x/s", ""},
		"beside a journal namespace":    {"systemd-journald@agentos-unit-lint.socket", "[Socket]\nListenStream=/run/systemd/journal.%i/stdout\n", "/run/agentos-x/stdout", ""},
		"a glob character in a package": {"tpl.socket", "[Socket]\nListenStream=/run/agentos-t[p]l/s\n", "/run/agentos-tpl/s", ""},
		// #5614 L3 round 1: Symlinks= on both sides; %% before %t.
		"ours on a package's link":           {"dev-log.socket", devlog, "[Socket]\nListenDatagram=/dev/log\n", `on a package socket's path, /dev/log`},
		"a link of ours on a package's link": {"dev-log.socket", devlog, "[Socket]\nListenStream=/run/agentos-x/s\nSymlinks=/run/agentos-x/l /dev/log\n", `on a package socket's path, /dev/log`},
		"a link of ours on a package's path": {"dev-log.socket", devlog, "[Socket]\nListenStream=/run/agentos-x/s\nSymlinks=/run/systemd/journal/dev-log\n", `on a package socket's path, /run/systemd/journal/dev-log`},
		"a literal %t in a package's path":   {"pkg.socket", "[Socket]\nListenStream=/run/pkg/%%t\n", "/run/pkg/%%t", `on a package socket's path, /run/pkg/%%t`},
		"a literal %t in ours":               {"pkg.socket", "[Socket]\nListenStream=/run/pkg/s\n", "/run/agentos-x/%%t", ""},
		// #5614 Security round 2: systemd unquotes and unescapes Symlinks=.
		"a quoted link of ours":                {"dev-log.socket", devlog, "[Socket]\nListenStream=/run/agentos-x/s\nSymlinks=\"/dev/log\"\n", `is quoted or escaped`},
		"an escaped link of ours":              {"dev-log.socket", devlog, "[Socket]\nListenStream=/run/agentos-x/s\nSymlinks=/dev/\\log\n", `is quoted or escaped`},
		"ours on a package's quoted link":      {"dev-log.socket", "[Socket]\nListenDatagram=/run/systemd/journal/dev-log\nSymlinks=\"/dev/log\"\n", "[Socket]\nListenDatagram=/dev/log\n", `on a package socket's path, /dev/log`},
		"ours beside a package's escaped link": {"dev-log.socket", "[Socket]\nListenDatagram=/run/systemd/journal/dev-log\nSymlinks=/dev/\\log\n", "/run/agentos-x/log", `on a package socket's path, /dev/\log`},
		// #5614 L3 round 2: a leading specifier is a path; %P may hold a /.
		"ours by %S on a package's path":      {"pkg.socket", "[Socket]\nListenStream=/var/lib/pkg/s\n", "%S/pkg/s", `holds a specifier other than %t`},
		"a leading %T of ours":                {"pkg.socket", "[Socket]\nListenStream=/run/pkg/s\n", "%T/x", `holds a specifier`},
		"a leading %d of ours":                {"pkg.socket", "[Socket]\nListenStream=/run/pkg/s\n", "%d/x", `holds a specifier`},
		"ours on a package's %S path":         {"pkg.socket", "[Socket]\nListenStream=%S/pkg/s\n", "/var/lib/pkg/s", `on a package socket's path, %S/pkg/s`},
		"ours on a package's %S link":         {"pkg.socket", "[Socket]\nListenStream=/run/pkg/s\nSymlinks=%S/pkg/l\n", "/var/lib/pkg/l", `on a package socket's path, %S/pkg/l`},
		"ours on a package's leading %d":      {"pkg.socket", "[Socket]\nListenStream=%d/s\n", "/run/credentials/pkg.socket/s", `on a package socket's path, %d/s`},
		"ours on a package's pretty hostname": {"pkg.socket", "[Socket]\nListenStream=/run/%q.sock\n", "/run/a/b.sock", `on a package socket's path, /run/%q.sock`},
		// #5614 Security round 3: the kernel resolves .. after links
		// (/var/lock -> /run/lock), so a path of ours must be canonical; a
		// package's .. matches every path; /var/lock is read as /run/lock.
		"ours through /var/lock/..":            {"pkg.socket", "[Socket]\nListenStream=/run/udev/control\n", "/var/lock/../udev/control", `is not canonical`},
		"ours through /var/lock/.. on dbus":    {"dbus.socket", "[Socket]\nListenStream=/run/dbus/system_bus_socket\n", "/var/lock/../dbus/system_bus_socket", `is not canonical`},
		"ours through /var/lock/.. on dev-log": {"dev-log.socket", devlog, "[Socket]\nListenDatagram=/var/lock/../systemd/journal/dev-log\n", `is not canonical`},
		"a dot of ours":                        {"pkg.socket", "[Socket]\nListenStream=/run/pkg/s\n", "/run/agentos-x/./s", `is not canonical`},
		"a doubled slash of ours":              {"pkg.socket", "[Socket]\nListenStream=/run/pkg/s\n", "/run/agentos-x//s", `is not canonical`},
		"a link of ours through ..":            {"pkg.socket", "[Socket]\nListenStream=/run/pkg/s\n", "[Socket]\nListenStream=/run/agentos-x/s\nSymlinks=/var/lock/../pkg/s\n", `is not canonical`},
		"ours by /var/lock":                    {"pkg.socket", "[Socket]\nListenStream=/run/lock/pkg/s\n", "/var/lock/pkg/s", `on a package socket's path, /run/lock/pkg/s`},
		"ours on a package's ..":               {"pkg.socket", "[Socket]\nListenStream=/run/pkg/../x/s\n", "/run/agentos-x/s", `on a package socket's path, /run/pkg/../x/s`},
		"a %h of ours":                         {"pkg.socket", "[Socket]\nListenStream=/run/pkg/s\n", "%h/s", `holds a specifier`},
		"ours on a package's %T path":          {"pkg.socket", "[Socket]\nListenStream=%T/pkg/s\n", "/tmp/pkg/s", `on a package socket's path, %T/pkg/s`},
		// #5614 L3 round 3: an alias the reader maps, or a tree it holds as
		// shared, is no endpoint of ours: PID 1 would unlink or replace it.
		"a link of ours on /var/run":           {"dbus.socket", "[Socket]\nListenStream=/run/dbus/system_bus_socket\n", "[Socket]\nListenStream=/run/agentos-x/a\nSymlinks=/var/run\nRemoveOnStop=yes\n", `Symlinks=/var/run: a listen path of ours lies outside /run/agentos*`},
		"ours on /var/run":                     {"dbus.socket", "[Socket]\nListenStream=/run/dbus/system_bus_socket\n", "/var/run", `lies outside /run/agentos*`},
		"a link of ours under /var/run":        {"dbus.socket", "[Socket]\nListenStream=/run/dbus/system_bus_socket\n", "[Socket]\nListenStream=/run/agentos-x/b\nSymlinks=/var/run/agentos-x/l\nDirectoryMode=0777\n", `Symlinks=/var/run/agentos-x/l: a listen path of ours passes through a link in the tree, /var/run -> /run`},
		"ours on /var/lock":                    {"pkg.socket", "[Socket]\nListenStream=/run/pkg/s\n", "/var/lock/agentos-x", `passes through a link in the tree, /var/lock -> /run/lock`},
		"ours on /run":                         {"pkg.socket", "[Socket]\nListenStream=/run/pkg/s\n", "[Socket]\nListenStream=/run/agentos-x/s\nSymlinks=/run\n", `Symlinks=/run: a listen path of ours lies outside /run/agentos*`},
		"ours above a package's path":          {"pkg.socket", "[Socket]\nListenStream=/run/pkg/s\n", "[Socket]\nListenStream=/run/agentos-x/s\nSymlinks=/run/pkg\n", `Symlinks=/run/pkg: a listen path of ours`},
		"ours on /tmp":                         {"pkg.socket", "[Socket]\nListenStream=/run/pkg/s\n", "/tmp/agentos-x", `lies outside /run/agentos*`},
		"ours by /lib":                         {"pkg.socket", "[Socket]\nListenStream=/usr/lib/pkg/s\n", "/lib/pkg/s", `on a package socket's path, /usr/lib/pkg/s`},
		"a package's port by a name specifier": {"pkg@agentos-unit-lint.socket", "[Socket]\nListenStream=%i\n", "/run/agentos-x/s", ""},
		// #5614 L3 round 4: a leading name specifier of ours may expand to
		// nothing (%j of a name ending in -); ours reads only %% and %t.
		"a leading %j of ours":                 {"systemd-udevd-control.socket", "[Socket]\nListenSequentialPacket=/run/udev/control\n", "%j/run/udev/control", `holds a specifier other than %t`},
		"a leading %j link of ours":            {"systemd-udevd-control.socket", "[Socket]\nListenSequentialPacket=/run/udev/control\n", "[Socket]\nListenStream=/run/agentos-x/s\nSymlinks=%j/run/udev/control\n", `Symlinks=%j/run/udev/control: a listen path of ours holds a specifier other than %t`},
		"a leading %i of ours":                 {"systemd-udevd-control.socket", "[Socket]\nListenStream=/run/udev/control\n", "%i/run/udev/control", `holds a specifier other than %t`},
		"a %S of ours":                         {"pkg.socket", "[Socket]\nListenStream=/run/pkg/s\n", "%S/agentos-x/s", `holds a specifier other than %t`},
		"a %t of ours in its tree":             {"pkg.socket", "[Socket]\nListenStream=/run/pkg/s\n", "%t/agentos-x/s", ""},
		"a port of ours":                       {"pkg.socket", "[Socket]\nListenStream=/run/pkg/s\n", "127.0.0.1:7777", `names no path`},
		"ours on a package's unescaped prefix": {"a-b.socket", "[Socket]\nListenStream=/run/%P.sock\n", "/run/a/b.sock", `on a package socket's path, /run/%P.sock`},
	} {
		t.Run(name, func(t *testing.T) {
			u := func(unit, p, text string, ours bool) map[string]any {
				return map[string]any{"unit": unit, "files": []any{map[string]any{"path": p, "ours": ours, "text": text}}}
			}
			ours := c.ours
			if !strings.HasPrefix(ours, "[Socket]") {
				ours = "[Socket]\nListenStream=" + ours + "\nSocketMode=0666\n"
			}
			b, _ := json.Marshal(map[string]any{"links": debianLinks, "units": []any{
				u(c.pkgUnit, lib+c.pkgUnit, c.pkgText, false),
				u("agentos-x.service", etc+"agentos-x.service", "[Service]\nUser=agentos-x\nExecStart=/usr/lib/agentos/x\n", true),
				u("agentos-x.socket", etc+"agentos-x.socket", ours, true),
			}})
			var recs unitRecords
			if err := json.Unmarshal(b, &recs); err != nil {
				t.Fatal(err)
			}
			err := builtUnits(recs, t.TempDir())
			if c.want == "" && err != nil || c.want != "" && (err == nil || !strings.Contains(err.Error(), c.want)) {
				t.Fatalf("got %v, want %q", err, c.want)
			}
		})
	}
}

// debianLinks are a Debian trixie tree's directory links an endpoint path
// may name (base-files and merged /usr), as image/unit_rules.py prints them
// in the records' links.
var debianLinks = map[string]string{"/var/run": "/run", "/var/lock": "/run/lock", "/bin": "/usr/bin", "/sbin": "/usr/sbin", "/lib": "/usr/lib", "/lib64": "/usr/lib64"}

// TestBuiltUnitsOurSocketEndpoints: a socket of ours in a built tree is an
// allow-list (#5620): it listens only on a path under /run/agentos*, every
// directory on that path a real one in the tree (links holds none of
// them), and any DirectoryMode= of ours an octal mode no group or other may
// write. A package's endpoint is read through the tree's links, and a
// directory its specifier may name is held. One row per #5620 item.
func TestBuiltUnitsOurSocketEndpoints(t *testing.T) {
	const lib, etc = "/usr/lib/systemd/system/", "/etc/systemd/system/"
	udev := "[Socket]\nListenSequentialPacket=/run/udev/control\n"
	for name, c := range map[string]struct {
		pkgUnit, pkgText, ours string // ours: a ListenStream= value, or a whole [Socket] text
		links                  map[string]string
		want                   string // "" passes
	}{
		// R-a: an open DirectoryMode= of ours, on an ancestor of a package's path or not.
		"the issue's open mode over a package path": {"pkg.socket", "[Socket]\nListenStream=/run/foo/bar/control\n", "[Socket]\nListenStream=/run/foo/s\nDirectoryMode=0777\n", nil, `DirectoryMode=0777: a directory mode of ours lets another uid write`},
		"an open mode over a package path of ours":  {"pkg.socket", "[Socket]\nListenStream=/run/agentos-x/bar/control\n", "[Socket]\nListenStream=/run/agentos-x/s\nDirectoryMode=0777\n", nil, `DirectoryMode=0777: a directory mode of ours lets another uid write`},
		"an open mode of ours":                      {"pkg.socket", udev, "[Socket]\nListenStream=/run/agentos-x/s\nDirectoryMode=0777\n", nil, `DirectoryMode=0777: a directory mode of ours`},
		"a group-writable mode of ours":             {"pkg.socket", udev, "[Socket]\nListenStream=/run/agentos-x/s\nDirectoryMode=0775\n", nil, `DirectoryMode=0775: a directory mode of ours`},
		"a sticky open mode of ours":                {"pkg.socket", udev, "[Socket]\nListenStream=/run/agentos-x/s\nDirectoryMode=1777\n", nil, `DirectoryMode=1777: a directory mode of ours`},
		"an other-writable mode of ours":            {"pkg.socket", udev, "[Socket]\nListenStream=/run/agentos-x/s\nDirectoryMode=0702\n", nil, `DirectoryMode=0702: a directory mode of ours`},
		"a symbolic mode of ours":                   {"pkg.socket", udev, "[Socket]\nListenStream=/run/agentos-x/s\nDirectoryMode=u=rwx,go=rwx\n", nil, `DirectoryMode=u=rwx,go=rwx: a directory mode of ours`},
		"an empty mode of ours":                     {"pkg.socket", udev, "[Socket]\nListenStream=/run/agentos-x/s\nDirectoryMode=\n", nil, `DirectoryMode=: a directory mode of ours`},
		"a mode of ours past 07777":                 {"pkg.socket", udev, "[Socket]\nListenStream=/run/agentos-x/s\nDirectoryMode=17755\n", nil, `DirectoryMode=17755: a directory mode of ours`},
		"a later open mode of ours":                 {"pkg.socket", udev, "[Socket]\nListenStream=/run/agentos-x/s\nDirectoryMode=0755\nDirectoryMode=0777\n", nil, `DirectoryMode=0777: a directory mode of ours`},
		"a closed mode of ours":                     {"pkg.socket", udev, "[Socket]\nListenStream=/run/agentos-x/s\nDirectoryMode=0755\n", nil, ""},
		"a private mode of ours":                    {"pkg.socket", udev, "[Socket]\nListenStream=/run/agentos-x/s\nDirectoryMode=711\n", nil, ""},
		"a padded closed mode of ours":              {"pkg.socket", udev, "[Socket]\nListenStream=/run/agentos-x/s\nDirectoryMode=00750\n", nil, ""},
		// R-b: a socket of ours names no port, address, abstract name,
		// netlink group or vsock address, so none can be a package's
		// (with or without ReusePort=) or a package daemon's own (R-d).
		"the issue's reuse-port pair":    {"foo.socket", "[Socket]\nListenStream=0.0.0.0:2222\nReusePort=yes\n", "[Socket]\nListenStream=0.0.0.0:2222\nReusePort=yes\n", nil, `ListenStream=0.0.0.0:2222: a listen path of ours names no path`},
		"a package's reuse-port alone":   {"foo.socket", "[Socket]\nListenStream=0.0.0.0:2222\nReusePort=yes\n", "[Socket]\nListenStream=2222\n", nil, `ListenStream=2222: a listen path of ours names no path`},
		"a port of ours by IPv6":         {"pkg.socket", udev, "[::]:2222", nil, `names no path`},
		"a datagram port of ours":        {"pkg.socket", udev, "[Socket]\nListenDatagram=0.0.0.0:53\n", nil, `ListenDatagram=0.0.0.0:53: a listen path of ours names no path`},
		"an abstract name of ours":       {"pkg.socket", udev, "@agentos-x", nil, `names no path`},
		"a vsock address of ours":        {"pkg.socket", udev, "vsock:2:1234", nil, `names no path`},
		"a netlink group of ours":        {"pkg.socket", udev, "[Socket]\nListenNetlink=kobject-uevent 1\n", nil, `ListenNetlink=kobject-uevent 1: a listen path of ours names no path`},
		"a message queue of ours":        {"pkg.socket", udev, "[Socket]\nListenMessageQueue=/agentos-x\n", nil, `lies outside /run/agentos*`},
		"a path of ours with reuse-port": {"pkg.socket", udev, "[Socket]\nListenStream=/run/agentos-x/s\nReusePort=yes\n", nil, ""},
		// R-c, R-i: links read from the tree, on both sides.
		"a link of ours into /run/udev":           {"pkg.socket", udev, "/run/agentos-x/control", map[string]string{"/run/agentos-x": "/run/udev"}, `on a package socket's path, /run/udev/control`},
		"a link of ours between our trees":        {"pkg.socket", udev, "/run/agentos-x/s", map[string]string{"/run/agentos-x": "/run/agentos-y"}, `passes through a link in the tree, /run/agentos-x -> /run/agentos-y`},
		"a deep link of ours":                     {"pkg.socket", udev, "/run/agentos-x/a/s", map[string]string{"/run/agentos-x/a": "/run/other"}, `passes through a link in the tree, /run/agentos-x/a -> /run/other`},
		"a linked /run":                           {"pkg.socket", udev, "/run/agentos-x/s", map[string]string{"/run": "/var/run2"}, `passes through a link in the tree, /run -> /var/run2`},
		"a symlink of ours through a link":        {"pkg.socket", udev, "[Socket]\nListenStream=/run/agentos-x/s\nSymlinks=/run/agentos-y/control\n", map[string]string{"/run/agentos-y": "/run/udev"}, `Symlinks=/run/agentos-y/control: a listen path of ours on a package socket's path, /run/udev/control`},
		"a dangling link of ours":                 {"pkg.socket", udev, "/run/agentos-x/s", map[string]string{"/run/agentos-x": "/run/gone"}, `passes through a link in the tree`},
		"an endpoint of ours that is a link":      {"pkg.socket", udev, "/run/agentos-x/s", map[string]string{"/run/agentos-x/s": "/run/udev/control"}, ""},
		"a package path through a link to ours":   {"pkg.socket", "[Socket]\nListenStream=/run/pkglink/s\n", "/run/agentos-x/s", map[string]string{"/run/pkglink": "/run/agentos-x"}, `on a package socket's path, /run/pkglink/s`},
		"a package link through a link to ours":   {"pkg.socket", "[Socket]\nListenStream=/run/pkg/s\nSymlinks=/run/pkglink/l\n", "/run/agentos-x/l", map[string]string{"/run/pkglink": "/run/agentos-x"}, `on a package socket's path, /run/pkglink/l`},
		"a package path through two links":        {"pkg.socket", "[Socket]\nListenStream=/run/a/b/s\n", "/run/agentos-x/c/s", map[string]string{"/run/a": "/run/agentos-x", "/run/agentos-x/b": "/run/agentos-x/c"}, `on a package socket's path, /run/a/b/s`},
		"a package specifier over a link to ours": {"tpl@agentos-unit-lint.socket", "[Socket]\nListenStream=/run/pkg-%i/s\n", "/run/agentos-x/s", map[string]string{"/run/pkg-a": "/run/agentos-x"}, `on a package socket's path, /run/pkg-%i/s`},
		"a package's /var/lock without the link":  {"pkg.socket", "[Socket]\nListenStream=/var/lock/agentos-x/s\n", "/run/lock/agentos-x/s", map[string]string{}, `lies outside /run/agentos*`},
		"a package's linked path beside ours":     {"pkg.socket", "[Socket]\nListenStream=/run/pkglink/s\n", "/run/agentos-x/s", map[string]string{"/run/pkglink": "/run/pkg"}, ""},
		// R-e: a specifier that may span components, in the last
		// component, holds every directory it may name.
		"an unescaped instance holding our directory": {"tpl@agentos-unit-lint.socket", "[Socket]\nListenStream=/run/%I.sock\n", "/run/agentos-x/s", nil, `on a package socket's path, /run/%I.sock`},
		"a pretty hostname holding our directory":     {"pkg.socket", "[Socket]\nListenStream=/run/pkg-%q\n", "/run/agentos-x/s", nil, ""},
		"a spanning specifier after a /":              {"pkg.socket", "[Socket]\nListenStream=/run/pkg/%I.sock\n", "/run/agentos-x/s", nil, ""},
		// R-f: %q may hold a /.
		"a pretty hostname directory": {"pkg.socket", "[Socket]\nListenStream=/run/%q/s\n", "/run/agentos-x/s", nil, `on a package socket's path, /run/%q/s`},
		// R-h, kept: a name specifier directly under /run may be an
		// instance named agentos-x (Wants=pkg@agentos-x.socket of ours), so
		// its directory stays held (fail closed).
		"a name specifier directory under /run": {"tpl@agentos-unit-lint.socket", "[Socket]\nListenStream=/run/%i/s\n", "/run/agentos-x/a", nil, `on a package socket's path, /run/%i/s`},
	} {
		t.Run(name, func(t *testing.T) {
			u := func(unit, p, text string, ours bool) map[string]any {
				return map[string]any{"unit": unit, "files": []any{map[string]any{"path": p, "ours": ours, "text": text}}}
			}
			ours := c.ours
			if !strings.HasPrefix(ours, "[Socket]") {
				ours = "[Socket]\nListenStream=" + ours + "\n"
			}
			links := c.links
			if links == nil {
				links = debianLinks
			}
			b, _ := json.Marshal(map[string]any{"links": links, "units": []any{
				u(c.pkgUnit, lib+c.pkgUnit, c.pkgText, false),
				u("agentos-x.service", etc+"agentos-x.service", "[Service]\nUser=agentos-x\nExecStart=/usr/lib/agentos/x\n", true),
				u("agentos-x.socket", etc+"agentos-x.socket", ours, true),
			}})
			var recs unitRecords
			if err := json.Unmarshal(b, &recs); err != nil {
				t.Fatal(err)
			}
			err := builtUnits(recs, t.TempDir())
			if c.want == "" && err != nil || c.want != "" && (err == nil || !strings.Contains(err.Error(), c.want)) {
				t.Fatalf("got %v, want %q", err, c.want)
			}
		})
	}
}

// TestBuiltUnitsPackageSocketsAndFed: every [Socket] line of ours on a
// package's socket (by the package mark, a package's file, or read alone)
// and every [Service] line of ours on a fed service is refused; ordering
// [Unit] lines of ours and our own sockets pass (#5072 Security round 3).
func TestBuiltUnitsPackageSocketsAndFed(t *testing.T) {
	const lib, etc = "/usr/lib/systemd/system/", "/etc/systemd/system/"
	type file struct {
		path, text string
		ours       bool
	}
	pkgSock := file{lib + "s.socket", "[Socket]\nListenStream=/run/agentos-s\n", false}
	pkgSvc := file{lib + "f.service", "[Service]\nUser=f\nExecStart=/usr/bin/f\n", false}
	ourSock := file{etc + "s.socket", "[Socket]\nListenStream=/run/agentos-s\nReusePort=yes\n", true}
	for name, c := range map[string]struct {
		unit                 string
		alone, package_, fed bool
		files                []file
		want                 string // "" passes
	}{
		"socket by mark":        {"s.socket", false, true, false, []file{ourSock}, `ListenStream=/run/agentos-s: a line of ours on a package's socket`},
		"socket by a file":      {"s.socket", false, false, false, []file{pkgSock, {etc + "s.socket.d/z.conf", "[Socket]\nReusePort=yes\n", true}}, `ReusePort=yes: a line of ours on a package's socket`},
		"socket alone":          {".socket", true, false, false, []file{{etc + "socket.d/z.conf", "[Socket]\nMark=7\n", true}}, `Mark=7: a line of ours`},
		"socket of ours":        {"s.socket", false, false, false, []file{ourSock}, ""},
		"socket unit lines":     {"s.socket", false, true, false, []file{pkgSock, {etc + "s.socket.d/z.conf", "[Unit]\nAfter=x.service\n", true}}, ""},
		"fed exec drop-in":      {"f.service", false, false, true, []file{pkgSvc, {etc + "f.service.d/z.conf", "[Service]\nExecStart=\nExecStart=/usr/lib/agentos/x\n", true}}, `ExecStart=: a line of ours on a service a package's socket feeds`},
		"fed user drop-in":      {"f.service", false, false, true, []file{pkgSvc, {etc + "f.service.d/z.conf", "[Service]\nUser=agentos-x\n", true}}, `User=agentos-x: a line of ours on a service`},
		"fed preload drop-in":   {"f.service", false, false, true, []file{pkgSvc, {etc + "f.service.d/z.conf", "[Service]\nEnvironment=LD_PRELOAD=/usr/lib/agentos/x.so\n", true}}, `LD_PRELOAD=/usr/lib/agentos/x.so: a line of ours on a service`},
		"fed bind drop-in":      {"f.service", false, false, true, []file{pkgSvc, {etc + "f.service.d/z.conf", "[Service]\nBindReadOnlyPaths=/usr/lib/agentos/x:/usr/bin/f\n", true}}, `BindReadOnlyPaths=/usr/lib/agentos/x:/usr/bin/f: a line of ours on a service`},
		"fed fragment of ours":  {"f.service", false, false, true, []file{{etc + "f.service", "[Service]\nUser=agentos-x\nExecStart=/usr/lib/agentos/x\n", true}}, `User=agentos-x: a line of ours on a service`},
		"fed alone":             {"f@.service", true, false, true, []file{{etc + "f@.service.d/z.conf", "[Service]\nNice=1\n", true}}, `Nice=1: a line of ours on a service`},
		"fed unit lines":        {"f.service", false, false, true, []file{pkgSvc, {etc + "f.service.d/z.conf", "[Unit]\nAfter=x.service\n", true}}, ""},
		"not fed, user drop-in": {"f.service", false, false, false, []file{pkgSvc, {etc + "f.service.d/z.conf", "[Service]\nUser=agentos-x\n", true}}, ""},
	} {
		t.Run(name, func(t *testing.T) {
			u := map[string]any{"unit": c.unit, "alone": c.alone, "package": c.package_, "fed": c.fed}
			var fs []map[string]any
			for _, f := range c.files {
				fs = append(fs, map[string]any{"path": f.path, "ours": f.ours, "text": f.text})
			}
			u["files"] = fs
			b, _ := json.Marshal(map[string]any{"units": []any{u}})
			var recs unitRecords
			if err := json.Unmarshal(b, &recs); err != nil {
				t.Fatal(err)
			}
			err := builtUnits(recs, t.TempDir())
			if c.want == "" && err != nil || c.want != "" && (err == nil || !strings.Contains(err.Error(), c.want)) {
				t.Fatalf("got %v, want %q", err, c.want)
			}
		})
	}
}

// grantsHeld fails on each grant in or above held, a tree or program root
// reads or runs.
func grantsHeld(grants []grant, held []string) error {
	var errs []error
	for _, g := range grants {
		if h, ok := inOrAbove(g.path, held); ok {
			errs = append(errs, fmt.Errorf("%s: %s %s, in or above %s, which root reads or runs; no other uid may write there", g.where, g.how, g.path, h))
		}
	}
	return errors.Join(errs...)
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

// heldOptions are the only mount options a held mount may take: flags that
// set no owner, source or mount point, tmpfs's sizes, and mode=, which is
// read. Any other (uid=, upperdir=, bind, loop, X-mount.mkdir=,
// X-mount.mode= among them) could hand the tree, or a directory libmount
// makes for it, to another uid, so a closed list is read rather than a
// list of the options that do (#4494, #4516, #4626).
var heldOptions = map[string]bool{
	"defaults": true, "ro": true, "rw": true, "nosuid": true, "suid": true, "nodev": true, "dev": true,
	"noexec": true, "exec": true, "noatime": true, "relatime": true, "strictatime": true, "nodiratime": true,
	"sync": true, "async": true, "auto": true, "noauto": true, "nofail": true,
	"lazytime": true, "nosymfollow": true, "_netdev": true, "x-initrd.mount": true, "x-systemd.device-timeout": true,
	"size": true, "nr_blocks": true, "nr_inodes": true, "mode": true,
}

// mountOptions refuses an option list naming a helper: helper= and
// uhelper= make mount(8) or umount(8) run /sbin/umount.<name> as root.
// On a mount point in or above rootTrees (held), it also refuses an option
// heldOptions does not list, and a mode= with a group or other write bit.
// A held list is read only if every byte is in heldOptionBytes: libmount
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
		case held && !heldOptions[k]:
			return false, fmt.Errorf("option %s on a mount in or above a tree root reads or runs; such a mount takes only the options heldOptions lists", o)
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
// unit, the unit's name (a linked unit's file has another), one of them
// must set Type=; with none, a drop-in is read alone. Over a tree root reads or runs, What=
// must be heldSource, and a tmpfs or ramfs needs a mode= in every Options=
// (a later one replaces an earlier one, and drop-ins sort across
// directories), and at least one Options=.
func mountLines(root string, paths []string, unit string) (bool, error) {
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
		if unit != "" {
			name = unit
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
	if unit != "" && !typed {
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
			// The generator follows a link before a .., where path.Clean
			// folds it as text (/var/run/../etc is /etc), so a target, like
			// a held source, holds none (#4626).
			if dotdot(w[1]) {
				return fmt.Errorf("%s:%d: target %s has a .. component, which the fstab generator resolves after following the link before it", rel, n, w[1])
			}
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
// file; or an owner other than root), and each of grants (unitGrants'), fails
// on a path in or above rootTrees, progs (the programs units run as root)
// or a listed program (#4423, #4584).
func runBinaries(root string, pkgs map[string]string, seen map[string]bool, progs []string, grants []grant) error {
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
			read, err := kind.read(string(b))
			if err != nil {
				return fmt.Errorf("%s:%v", rel, err)
			}
			for _, prog := range read {
				if prog.grant != "" {
					grants = append(grants, grant{fmt.Sprintf("%s:%d", rel, prog.line), prog.grant, prog.path})
					continue
				}
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
	held := append(append([]string{}, rootTrees...), progs...)
	for path := range listed {
		held = append(held, path)
	}
	if err := grantsHeld(grants, held); err != nil {
		return err
	}
	for path, used := range listed {
		if !used {
			return fmt.Errorf("%s lists %s, which no file runs", programsFile, path)
		}
	}
	return nil
}

// ruleProgram is a program a runKinds file makes root run, or, with grant
// set to how, a path a tmpfiles.d line lets another uid write.
type ruleProgram struct {
	path  string
	line  int
	grant string
}

// grant is a path another uid may write: where says which file and line or
// setting lets it, and how.
type grant struct{ where, how, path string }

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

// sysctlKey is a dotted sysctl name: systemd-sysctl also takes / separators
// and empty components, which the reader refuses rather than resolves. A
// component may be a glob (#4810: net.ipv4.conf.*.rp_filter); sysctlGlobReach
// refuses one that could name a helper or anything under fs.binfmt_misc.
var sysctlKey = regexp.MustCompile(`^-?[A-Za-z0-9_*?\[\]!^-]+(\.[A-Za-z0-9_*?\[\]!^-]+)*$`)

// sysctlGlobReach returns the helper sysctl, or fs.binfmt_misc, that the glob
// key k could name, or "". systemd-sysctl globs /proc/sys one component at a
// time, as glob(3) does, where "[!" and "[^" both negate a class.
func sysctlGlobReach(k string) string {
	if !strings.ContainsAny(k, "*?[") {
		return ""
	}
	g := strings.Split(strings.ReplaceAll(k, "[!", "[^"), ".")
	matches := func(name string) bool {
		n := strings.Split(name, ".")
		if len(n) > len(g) {
			return false
		}
		for i, c := range n {
			if ok, err := path.Match(g[i], c); !ok || err != nil {
				return err != nil
			}
		}
		return len(n) == len(g) || name == "fs.binfmt_misc"
	}
	names := []string{"fs.binfmt_misc"}
	for h := range sysctlHelpers {
		names = append(names, h)
	}
	sort.Strings(names)
	for _, h := range names {
		if matches(h) {
			return h
		}
	}
	return ""
}

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
		case sysctlGlobReach(strings.TrimPrefix(k, "-")) != "":
			return fmt.Errorf("%d: the glob %s could name %s", n, k, sysctlGlobReach(strings.TrimPrefix(k, "-")))
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

// dropinDirs are the drop-in directories systemd reads for a unit, most
// specific first: name.d; for an instance, its template's; each
// dash-truncated prefix of the name before any @ ("agentos-x-y.service"
// reads "agentos-x-.service.d" and "agentos-.service.d"); and last its
// type's (service.d, socket.d).
func dropinDirs(name string) []string {
	ext := path.Ext(name)
	base := strings.TrimSuffix(name, ext)
	dirs := []string{name + ".d"}
	pre := base
	if at := strings.Index(base, "@"); at >= 0 {
		pre = base[:at]
		if at < len(base)-1 {
			dirs = append(dirs, base[:at+1]+ext+".d")
		}
	}
	for i := len(pre) - 1; i > 0; i-- {
		if pre[i] == '-' {
			dirs = append(dirs, pre[:i+1]+ext+".d")
		}
	}
	return append(dirs, ext[1:]+".d")
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
