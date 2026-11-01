package privfile

// REQ: KRN-2

// The root-side path lint (REV-CHK-links, #3900). A file operation a root
// process makes by path follows any link on that path, so a guest, clerk or
// other uid that can plant one in a directory on it redirects the write,
// removal or read (#3282, #3382, #3624). The root side is derived, not
// listed: every binary a shipped systemd unit starts with no User= or
// DynamicUser= (or on an Exec line with a + or ! prefix), every binary a
// udev rule file under image/ or broker/ runs (udev runs RUN, PROGRAM and
// IMPORT{program} as root, #3950; a rule may run only a path
// udev_programs.txt lists, #4257), and the module's packages those binaries
// link. Each package is type-checked, and in those packages each identifier
// that resolves to a path-based os function that follows links (pathOps)
// fails, whatever name spells it (#4256), unless it is os.OpenFile with the
// real O_NOFOLLOW, goes through privfile, or has an allow line in
// pathops_allow.txt naming the file, the function and the call, with a
// reason a review checks.
//
// Bound: an allow line's reason is held by review, as is a link planted
// through a path the reason deems safe (a parent directory another uid can
// write). Calls outside pathOps (os.Lstat, os.ReadDir, os.Symlink, os.Chtimes,
// os.Truncate, syscall and unix path calls), a binary that a script rather
// than a unit or udev rule starts, a binary built by a line
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
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// pathOps are the path-based os calls the brief names (briefs/REV-CHK.md).
var pathOps = map[string]bool{
	"Open": true, "OpenFile": true, "Create": true, "ReadFile": true, "WriteFile": true,
	"Remove": true, "RemoveAll": true, "Rename": true, "Chmod": true, "Chown": true,
	"Mkdir": true, "MkdirAll": true, "Stat": true, "Link": true,
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
			"Open": `""`, "OpenFile": `"", os.O_RDONLY, 0`, "Create": `""`, "ReadFile": `""`, "WriteFile": `"", nil, 0`,
			"Remove": `""`, "RemoveAll": `""`, "Rename": `"", ""`, "Chmod": `"", 0`, "Chown": `"", 0, 0`,
			"Mkdir": `"", 0`, "MkdirAll": `"", 0`, "Stat": `""`, "Link": `"", ""`,
		}
		for op := range pathOps {
			if args[op] == "" {
				t.Fatalf("no call arguments for os.%s", op)
			}
			// A value and a call take the same path (an identifier that
			// resolves to the function), so one value form is enough.
			for _, form := range []string{"call", "value", "alias call", "dot import"} {
				src := "package side\n\nimport \"os\"\n\nvar _ = os." + op + "\n"
				switch form {
				case "call":
					src = "package side\n\nimport \"os\"\n\nfunc F() { os." + op + "(" + args[op] + ") }\n"
				case "alias call":
					src = "package side\n\nimport o \"os\"\n\nfunc F() { o." + op + "(" + strings.ReplaceAll(args[op], "os.", "o.") + ") }\n"
				case "dot import":
					src = "package side\n\nimport . \"os\"\n\nfunc F() { " + op + "(" + strings.ReplaceAll(args[op], "os.", "") + ") }\n"
				}
				problems := lintFiles(t, map[string]string{"broker/side/side.go": src}, "")
				if len(problems) != 1 || !strings.Contains(problems[0], "os."+op) {
					t.Errorf("os.%s as a %s: got %q, want one problem", op, form, problems)
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
	t.Run("a type error fails the lint", func(t *testing.T) {
		bins := []string{"./cmd/agentos-side"}
		root := fakeRepo(t, map[string]string{
			"broker/side/side.go":             "package side\n\nimport \"os\"\n\nfunc F() { os.Remove() }\n",
			"broker/cmd/agentos-side/main.go": "package main\n\nimport _ \"example.test/broker/side\"\n\nfunc main() {}\n",
		})
		if _, err := rootSideUses(root, bins); err == nil {
			t.Fatal("a package that does not type-check was linted")
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
		rule:                               "ACTION==\"remove\", GOTO=\"end\"\nRUN+=\"/usr/lib/agentos/host-disk-unlink %k\"\nENV{X}=\"agentos-side\"\nOWNER=\"agentos-side\", GROUP:=\"agentos-side\", MODE=\"0600\"\n# RUN+=\"/usr/lib/agentos/agentos-side\"\n  # RUN+=\"/bin/sh -c 'agentos-side'\"\nLABEL=\"end\"\n",
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
		t.Fatalf("a rule running only another program, naming the binary in an ENV value, an account or a comment, and a file that is no .rules: got %q, %v, want none", bins, err)
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
	for name, text := range map[string]string{
		"a wrapper's word":            "RUN+=\"/usr/lib/agentos/with-uids /usr/lib/agentos/agentos-side\"\n",
		"a bare name udev resolves":   "RUN+=\"agentos-side %k\"\n",
		"a name an ENV value holds":   "ENV{P}=\"/usr/lib/agentos/agentos-side\"\nRUN+=\"$env{P}\"\n",
		"a $ substitution in an arg":  "RUN+=\"/usr/lib/agentos/agentos-side $env{P}\"\n",
		"a %c in the program":         "RUN+=\"/usr/lib/agentos/%c\"\n",
		"a continued line":            "ACTION==\"add\", \\\n  RUN+=\"/usr/lib/agentos/agentos-side\"\n",
		"a comment ending in \\":      "# old rule \\\nRUN+=\"/usr/lib/agentos/agentos-side\"\n",
		"sh -c":                       "RUN+=\"/bin/sh -c true;/usr/lib/agentos/agentos-side\"\n",
		"sh -c with quotes":           "RUN+=\"/bin/sh -c 'agentos-side'\"\n",
		"a quoted arg":                "RUN+=\"/usr/lib/agentos/agentos-side 'a b'\"\n",
		"a shell backslash escape":    "RUN+=\"/usr/lib/agentos/host-disk-unlink agentos\\-side\"\n",
		"udev \\x escapes":            "RUN+=e\"/usr/lib/agentos/agentos\\x2dside\"\n",
		"udev octal escapes":          "RUN+=e\"/usr/lib/agentos/\\141gentos-side\"\n",
		"an e\"...\" value":           "RUN+=e\"/usr/lib/agentos/agentos-side\"\n",
		"an escaped quote":            "RUN+=\"/usr/lib/agentos/host-disk-unlink \\\"x\"\n",
		"a single-quoted value":       "RUN+='/usr/lib/agentos/agentos-side'\n",
		"an unlisted path":            "RUN+=\"/usr/lib/agentos/agentos-other\"\n",
		"a key udev(7) lacks":         "RUNX+=\"/usr/lib/agentos/agentos-side\"\n",
		"a lower-case key":            "run+=\"/usr/lib/agentos/agentos-side\"\n",
		"RUN{other}":                  "RUN{prog}+=\"/usr/lib/agentos/agentos-side\"\n",
		"IMPORT{other}":               "IMPORT{programs}=\"/usr/lib/agentos/agentos-side\"\n",
		"PROGRAM{x}":                  "PROGRAM{x}==\"/usr/lib/agentos/agentos-side\"\n",
		"text after a value":          "RUN+=\"/usr/lib/agentos/agentos-side\" x\n",
		"an unclosed value":           "RUN+=\"/usr/lib/agentos/agentos-side\n",
		"a CR that udev splits at":    "# old\rRUN+=\"/usr/lib/agentos/agentos-side\"\n",
		"a NUL that udev splits at":   "# old\x00RUN+=\"/usr/lib/agentos/agentos-side\"\n",
		"a byte past ASCII":           "RUN+=\"/usr/lib/agentos/agentos\u2010side\"\n",
		"a rule under image, refused": "RUN+=\"/bin/sh -c x\"\n",
		"a core_pattern sysctl":       "SYSCTL{kernel.core_pattern}=\"|/usr/lib/agentos/agentos-side %p\"\n",
		"a modprobe sysctl":           "SYSCTL{kernel.modprobe}=\"/usr/lib/agentos/agentos-side\"\n",
		"an ATTR path":                "ATTR{../../kernel/uevent_helper}=\"/usr/lib/agentos/agentos-side\"\n",
		"an ATTR [subsystem/device]":  "ATTR{[module/x]parameters}=\"y\"\n",
		"an ATTRS path":               "ATTRS{device/x}==\"y\"\n",
	} {
		t.Run("refuses "+name, func(t *testing.T) {
			files := clone(files)
			path := rule
			if name == "a rule under image, refused" {
				path = "image/mkosi/rules.d/60-x.rules"
			}
			files[path] = files[path] + "RUN+=\"/usr/lib/agentos/agentos-side\"\n" + text
			if bins, err := set(t, files); err == nil {
				t.Fatalf("got %q and no error, want the rule refused", bins)
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

func TestStaleAllowEntryFails(t *testing.T) {
	files := map[string]string{"broker/side/side.go": "package side\n\nimport \"os\"\n\nfunc Drop(p string) error { return os.Remove(p) }\n"}
	for name, line := range map[string]string{
		"another function":  "allow broker/side/side.go Keep os.Remove reason\n",
		"another call":      "allow broker/side/side.go Drop os.Rename reason\n",
		"a missing file":    "allow broker/side/gone.go Drop os.Remove reason\n",
		"a non-root file":   "allow broker/elsewhere/x.go Drop os.Remove reason\n",
		"a doubled line":    "allow broker/side/side.go Drop os.Remove reason\nallow broker/side/side.go Drop os.Remove again\n",
		"a pending package": "pending broker/elsewhere #1 reason\n",
		"a malformed line":  "allow broker/side/side.go Drop\n",
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
		key := u.file + " " + u.fn + " os." + u.op
		if _, ok := allows[key]; ok {
			usedAllow[key] = true
			continue
		}
		if _, ok := pending[filepath.ToSlash(filepath.Dir(u.file))]; ok {
			usedPending[filepath.ToSlash(filepath.Dir(u.file))] = true
			continue
		}
		problems = append(problems, fmt.Sprintf("%s:%d: %s calls os.%s by path; use privfile, os.OpenFile with O_NOFOLLOW, or add \"allow %s <reason>\"", u.file, u.line, u.fn, u.op, key))
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
		case f[0] == "allow" && len(f) >= 5 && strings.HasPrefix(f[3], "os.") && pathOps[strings.TrimPrefix(f[3], "os.")]:
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
			bad = append(bad, fmt.Sprintf("%s line %d: want \"allow <file> <func> os.<Call> <reason>\" or \"pending <dir> #<issue> <reason>\", got %q", allowFile, i+1, line))
		}
	}
	return allows, pending, bad
}

// rootBinaries returns the broker packages (as ./path, relative to broker/)
// of the binaries a unit under image/ starts as root or a udev rule names.
func rootBinaries(root string) ([]string, error) {
	units := map[string]string{}     // unit file name -> path
	dropins := map[string][]string{} // drop-in directory name -> its .conf paths
	err := filepath.WalkDir(filepath.Join(root, "image"), func(p string, d os.DirEntry, err error) error {
		switch {
		case err != nil:
			return err
		case d.IsDir():
			return nil
		case strings.HasSuffix(p, ".service"):
			units[p] = d.Name()
		case strings.HasSuffix(p, ".conf") && strings.HasSuffix(filepath.Dir(p), ".service.d"):
			dir := filepath.Base(filepath.Dir(p))
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
	if err := ruleBinaries(root, pkgs, seen); err != nil {
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
// udev rule may run (#4257).
const programsFile = "broker/kernel/privfile/udev_programs.txt"

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

// ruleAttr is an ATTR or ATTRS name the reader accepts.
var ruleAttr = regexp.MustCompile(`^[A-Za-z0-9_]+$`)

// ruleArg is a word a listed program may take after its path: no shell or
// udev quoting, escape or $ substitution.
var ruleArg = regexp.MustCompile(`^[A-Za-z0-9_./:=%+@,-]+$`)

// ruleBinaries reads every .rules file under image/ and broker/ the way udev
// does and adds the package of each broker binary a rule runs. udev runs
// RUN, RUN{program}, PROGRAM and IMPORT{program} values as root (#3950), and
// a program's name could hide behind a shell (sh -c 'a;agentos-x'), a bare
// name udev resolves in /usr/lib/udev, an $env{X} substitution, or a udev
// or shell escape (agentos\x2dx, agentos\-x). Rather than decode each form,
// the reader refuses them (#4257): a rules file may hold only printable
// ASCII, no backslash anywhere (so no escape and no continuation), only
// udev(7)'s keys in plain "..." values, and each program value must be an
// absolute path programsFile lists, then words of ruleArg. A listed path
// that no rule runs fails too, so the list only holds what ships. Bound:
// what a listed program itself starts (host-disk-unlink is a script) is
// held by review of the list's reason.
func ruleBinaries(root string, pkgs map[string]string, seen map[string]bool) error {
	// A repository with no list lets a rule run nothing.
	b, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(programsFile)))
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	listed := map[string]bool{} // listed path -> a rule runs it
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
			case d.IsDir() || !strings.HasSuffix(p, ".rules"):
				return nil
			}
			b, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			rel, _ := filepath.Rel(root, p)
			progs, err := rulePrograms(string(b))
			if err != nil {
				return fmt.Errorf("%s:%v", filepath.ToSlash(rel), err)
			}
			for _, prog := range progs {
				if _, ok := listed[prog.path]; !ok {
					return fmt.Errorf("%s:%d: a rule runs %q, which %s does not list; a rule may run only a listed absolute path", filepath.ToSlash(rel), prog.line, prog.path, programsFile)
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
			return fmt.Errorf("%s lists %s, which no rule runs", programsFile, path)
		}
	}
	return nil
}

type ruleProgram struct {
	path string
	line int
}

// rulePrograms parses one rules file and returns the program each RUN,
// RUN{program}, PROGRAM and IMPORT{program} value runs, or an error naming
// the first line it refuses. udev splits lines at \n, \r and NUL and skips a
// line whose first non-blank byte is #; refusing every byte but printable
// ASCII, tab and \n makes its split and this one the same.
func rulePrograms(text string) ([]ruleProgram, error) {
	var progs []ruleProgram
	for i, line := range strings.Split(text, "\n") {
		n := i + 1
		for _, c := range []byte(line) {
			if c != '\t' && (c < 0x20 || c > 0x7e) {
				return nil, fmt.Errorf("%d: byte %#x; a rules file holds only printable ASCII and tabs", n, c)
			}
		}
		if strings.Contains(line, "\\") {
			return nil, fmt.Errorf("%d: a backslash; no escape or continuation is read, so none may be written", n)
		}
		rest := strings.TrimLeft(line, " \t")
		if rest == "" || rest[0] == '#' {
			continue
		}
		for rest != "" {
			m := ruleToken.FindStringSubmatch(rest)
			if m == nil {
				return nil, fmt.Errorf("%d: %q is not KEY[{attr}]OP\"value\" with a plain value", n, rest)
			}
			rest = rest[len(m[0]):]
			key, hasAttr, attr, value := m[1], m[2] != "", m[3], m[5]
			if !ruleKeys[key] {
				return nil, fmt.Errorf("%d: key %s is not one of udev(7)'s, or is SYSCTL", n, key)
			}
			// An ATTR name is a path under the device's sysfs directory, so
			// a / or [subsystem/device] form could reach another file (the
			// kernel's uevent_helper among them); only a plain name is read.
			if (key == "ATTR" || key == "ATTRS") && !ruleAttr.MatchString(attr) {
				return nil, fmt.Errorf("%d: %s{%s}; an attribute name is letters, digits and _ only", n, key, attr)
			}
			program := false
			switch key {
			case "RUN":
				switch {
				case !hasAttr || attr == "program":
					program = true
				case attr != "builtin":
					return nil, fmt.Errorf("%d: RUN{%s}; want RUN, RUN{program} or RUN{builtin}", n, attr)
				}
			case "PROGRAM":
				if hasAttr {
					return nil, fmt.Errorf("%d: PROGRAM takes no attribute", n)
				}
				program = true
			case "IMPORT":
				switch attr {
				case "program":
					program = true
				case "builtin", "file", "db", "cmdline", "parent":
				default:
					return nil, fmt.Errorf("%d: IMPORT{%s}; want program, builtin, file, db, cmdline or parent", n, attr)
				}
			}
			if !program {
				continue
			}
			words := strings.Fields(value)
			if len(words) == 0 || !strings.HasPrefix(words[0], "/") || strings.Contains(words[0], "%") {
				return nil, fmt.Errorf("%d: %s=%q does not start with an absolute program path", n, key, value)
			}
			for _, w := range words {
				if !ruleArg.MatchString(w) {
					return nil, fmt.Errorf("%d: %s=%q: word %q has a character a program value may not hold", n, key, value, w)
				}
			}
			progs = append(progs, ruleProgram{path: words[0], line: n})
		}
	}
	return progs, nil
}

// dropinDirs are the drop-in directories systemd reads for a unit:
// name.d, each dash-truncated prefix ("agentos-x-y.service" reads
// "agentos-x-.service.d" and "agentos-.service.d") and, for an instance, its
// template's.
func dropinDirs(name string) []string {
	base := strings.TrimSuffix(name, ".service")
	dirs := []string{name + ".d", "service.d"}
	if at := strings.Index(base, "@"); at >= 0 && at < len(base)-1 {
		dirs = append(dirs, base[:at+1]+".service.d")
	}
	for i := len(base) - 1; i > 0; i-- {
		if base[i] == '-' {
			dirs = append(dirs, base[:i+1]+".service.d")
		}
	}
	return dirs
}

var buildOut = regexp.MustCompile(`-o\s+"?[^"\s]*/([A-Za-z0-9._-]+)"?\s+"?(\./[A-Za-z0-9_./-]+)"?`)

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
				if !strings.Contains(m[2], "$") {
					if _, err := os.Stat(filepath.Join(root, "broker", m[2])); err == nil {
						pkgs[m[1]] = filepath.ToSlash(filepath.Clean(m[2]))
						if !strings.HasPrefix(pkgs[m[1]], ".") {
							pkgs[m[1]] = "./" + pkgs[m[1]]
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
	file, fn, op string // file is relative to the repository root
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
			info := &types.Info{Uses: map[*ast.Ident]types.Object{}}
			conf := types.Config{Importer: imp, Sizes: types.SizesFor("gc", arch)}
			if _, err := conf.Check(p.path, fset, files, info); err != nil {
				return nil, fmt.Errorf("type-checking %s (%s): %v", p.path, arch, err)
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

// fileUses finds each identifier in the file that resolves to a pathOps
// function of package os, called or not (a selector on any import name, a
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
				if f, ok := info.Uses[n].(*types.Func); ok && !safe[n] && isFunc(f, "os", f.Name()) && pathOps[f.Name()] {
					uses = append(uses, use{file: rel, fn: fn, op: f.Name(), line: fset.Position(n.Pos()).Line})
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
