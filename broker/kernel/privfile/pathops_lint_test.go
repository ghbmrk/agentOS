package privfile

// REQ: KRN-2

// The root-side path lint (REV-CHK-links, #3900). A file operation a root
// process makes by path follows any link on that path, so a guest, clerk or
// other uid that can plant one in a directory on it redirects the write,
// removal or read (#3282, #3382, #3624). The root side is derived, not
// listed: every binary a shipped systemd unit starts with no User= or
// DynamicUser= (or on an Exec line with a + or ! prefix), every binary a
// udev rule file under image/ or broker/ names (udev runs RUN, PROGRAM and
// IMPORT{program} as root, #3950), and the module's packages those binaries
// link. In those packages each use of a path-based os
// call that follows links (pathOps) fails unless it is os.OpenFile with
// O_NOFOLLOW, goes through privfile, or has an allow line in
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
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
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
		for op := range pathOps {
			for _, form := range []string{"call", "value", "value in a func", "alias"} {
				src := "package side\n\nimport \"os\"\n\nvar _ = os." + op + "\n"
				switch form {
				case "call":
					src = "package side\n\nimport \"os\"\n\nfunc F() { os." + op + "() }\n"
				case "alias":
					src = "package side\n\nimport o \"os\"\n\nfunc F() { _ = o." + op + " }\n"
				case "value in a func":
					src = "package side\n\nimport \"os\"\n\nfunc F() { _ = os." + op + " }\n"
				}
				problems := lintFiles(t, map[string]string{"broker/side/side.go": src}, "")
				if len(problems) != 1 || !strings.Contains(problems[0], "os."+op) {
					t.Errorf("os.%s as a %s: got %q, want one problem", op, form, problems)
				}
			}
		}
	})
	t.Run("O_NOFOLLOW opens pass, other flags fail", func(t *testing.T) {
		src := "package side\n\nimport (\n\t\"os\"\n\t\"syscall\"\n)\n\nfunc F(p string) { os.OpenFile(p, os.O_RDONLY|syscall.O_NOFOLLOW, 0) }\n"
		if problems := lintFiles(t, map[string]string{"broker/side/side.go": src}, ""); len(problems) != 0 {
			t.Fatalf("an O_NOFOLLOW open: got %q, want none", problems)
		}
		for _, flags := range []string{"os.O_RDONLY|syscall.O_CLOEXEC", "os.O_RDWR&^syscall.O_NOFOLLOW", "flags(syscall.O_NOFOLLOW)", "os.O_RDONLY|(syscall.O_NOFOLLOW^syscall.O_NOFOLLOW)", "os.O_RDONLY+syscall.O_NOFOLLOW", "os.O_RDONLY|O_NOFOLLOW", "os.O_RDONLY|cfg.O_NOFOLLOW"} {
			src := strings.Replace(src, "os.O_RDONLY|syscall.O_NOFOLLOW", flags, 1)
			if problems := lintFiles(t, map[string]string{"broker/side/side.go": src}, ""); len(problems) != 1 {
				t.Errorf("an open with flags %s: got %q, want one problem", flags, problems)
			}
		}
	})
	t.Run("a shadowed flag package fails", func(t *testing.T) {
		for _, src := range []string{
			"package side\n\nimport (\n\t\"os\"\n\t\"syscall\"\n)\n\nvar _ = syscall.O_RDONLY\n\nfunc F(p string) { syscall := struct{ O_NOFOLLOW int }{}; os.OpenFile(p, os.O_RDWR|syscall.O_NOFOLLOW, 0) }\n",
			"package side\n\nimport (\n\t\"os\"\n\tunix \"syscall\"\n)\n\nvar _ = unix.O_RDONLY\n\nfunc F(p string) { unix := struct{ O_NOFOLLOW int }{}; os.OpenFile(p, os.O_RDWR|unix.O_NOFOLLOW, 0) }\n",
			"package side\n\nimport (\n\t\"os\"\n\t\"syscall\"\n)\n\nvar _ = syscall.O_RDONLY\n\nvar G = func(p string, syscall struct{ O_NOFOLLOW int }) { os.OpenFile(p, os.O_RDWR|syscall.O_NOFOLLOW, 0) }\n",
		} {
			if problems := lintFiles(t, map[string]string{"broker/side/side.go": src}, ""); len(problems) != 1 {
				t.Errorf("got %q, want one problem for\n%s", problems, src)
			}
		}
	})
	t.Run("a dot import of os fails", func(t *testing.T) {
		src := "package side\n\nimport . \"os\"\n\nfunc F(p string) { Remove(p) }\n"
		problems := lintFiles(t, map[string]string{"broker/side/side.go": src}, "pending broker/side #1 even pending\n")
		if len(problems) != 2 || !strings.Contains(strings.Join(problems, "\n"), "dot import") {
			t.Fatalf("got %q, want the dot import refused (and the pending line stale)", problems)
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

// A udev rule runs its programs as root, so a broker binary a .rules file
// names joins the root side wherever the name sits (#3950).
func TestRootSideSetCountsUdevRulePrograms(t *testing.T) {
	const rule = "broker/side/udev/59-agentos-side.rules"
	files := map[string]string{
		"broker/side/side.go":              "package side\n\nimport \"os\"\n\nfunc Drop(p string) error { return os.Remove(p) }\n",
		"broker/cmd/agentos-side/main.go":  "package main\n\nimport \"example.test/broker/side\"\n\nfunc main() { side.Drop(\"\") }\n",
		"image/mkosi/agentos-side.service": "[Service]\nUser=agentos-side\nExecStart=/usr/lib/agentos/agentos-side\n",
		rule:                               "ACTION==\"remove\", GOTO=\"end\"\nRUN+=\"/usr/lib/agentos/host-disk-unlink %k\"\nENV{X}=\"agentos-sid\"\nOWNER=\"agentos-side\", GROUP:=\"agentos-side\", MODE=\"0600\"\n",
		"broker/side/udev/README":          "RUN+=\"/usr/lib/agentos/agentos-side\"\n",
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
		t.Fatalf("a rule naming only other programs, a prefix of the name or the binary's account, a file that is no .rules, a unit with User=: got %q, want none", bins)
	}
	for name, text := range map[string]string{
		"RUN+=":                        "ACTION==\"add\", RUN+=\"/usr/lib/agentos/agentos-side %k\"\n",
		"RUN{program}+=":               "RUN{program}+=\"/usr/lib/agentos/agentos-side\"\n",
		"IMPORT{program}=":             "ENV{DEVTYPE}==\"disk\", IMPORT{program}=\"/usr/lib/agentos/agentos-side classify %k\"\n",
		"PROGRAM==":                    "PROGRAM==\"/usr/lib/agentos/agentos-side %k\", SYMLINK+=\"x\"\n",
		"PROGRAM!= with no spaces":     "PROGRAM!=\"agentos-side\",GOTO=\"end\"\n",
		"a wrapper's word":             "RUN+=\"/usr/lib/agentos/with-uids /usr/lib/agentos/agentos-side\"\n",
		"a bare name udev resolves":    "RUN+=\"agentos-side %k\"\n",
		"a name an ENV value holds":    "ENV{P}=\"/usr/lib/agentos/agentos-side\"\nRUN+=\"$env{P}\"\n",
		"a continued line":             "ACTION==\"add\", \\\n  RUN+=\"/usr/lib/agentos/agentos-side\"\n",
		"after a comment ending in \\": "# old rule \\\nRUN+=\"/usr/lib/agentos/agentos-side\"\n",
		"a commented rule":             "# RUN+=\"/usr/lib/agentos/agentos-side %k\"\n",
		"a rule under image":           "RUN+=\"/usr/lib/agentos/agentos-side\"\n",
		"after ; in sh -c":             "RUN+=\"/bin/sh -c 'true;/usr/lib/agentos/agentos-side'\"\n",
		"after | in sh -c":             "RUN+=\"/bin/sh -c 'echo|agentos-side'\"\n",
		"inside ( )":                   "RUN+=\"/bin/sh -c '(agentos-side %k)'\"\n",
		"before a closing '":           "RUN+=\"/bin/sh -c 'agentos-side'\"\n",
		"inside backticks":             "RUN+=\"/bin/sh -c 'x=`agentos-side`'\"\n",
		"after &&":                     "RUN+=\"/bin/sh -c 'true&&agentos-side'\"\n",
		"spelled with \\x escapes":     "RUN+=e\"/usr/lib/agentos/agentos\\x2dside\"\n",
		"spelled with octal escapes":   "RUN+=e\"/usr/lib/agentos/\\141gentos-side\"\n",
		"after >":                      "RUN+=\"/bin/sh -c 'x>/dev/null;agentos-side'\"\n",
	} {
		t.Run(name, func(t *testing.T) {
			files := clone(files)
			path := rule
			if name == "a rule under image" {
				path = "image/mkosi/rules.d/60-x.rules"
			}
			files[path] = files[path] + text
			if bins := set(t, files); len(bins) != 1 || bins[0] != "./cmd/agentos-side" {
				t.Fatalf("got %q, want [./cmd/agentos-side]", bins)
			}
			if problems := lintFiles(t, files, ""); len(problems) != 1 || !strings.Contains(problems[0], "broker/side/side.go") {
				t.Fatalf("the rule's binary's linked package: got %q, want its os.Remove refused", problems)
			}
		})
	}
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
		if u.op == "." {
			problems = append(problems, fmt.Sprintf("%s:%d: a dot import of os; import it by name so the lint sees its calls", u.file, u.line))
			continue
		}
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

// ruleOwner is an OWNER= or GROUP= value, which names an account
// (agentos-modem is both a binary and a user), never a program.
var ruleOwner = regexp.MustCompile(`\b(?:OWNER|GROUP)\s*:?=\s*"[^"]*"`)

// ruleEscape is a C escape a udev e"..." value may spell a byte with: \xHH
// or \NNN octal.
var ruleEscape = regexp.MustCompile(`\\(?:x[0-9a-fA-F]{2}|[0-7]{3})`)

// ruleBinaries adds the package of every broker binary whose name a .rules
// file under image/ or broker/ contains anywhere outside an OWNER= or GROUP=
// value: as a path or bare, in any key, inside a shell command (sh -c
// 'a;agentos-x'), in a comment or a continuation. udev runs RUN, PROGRAM
// and IMPORT{program} values as root, resolves a bare name in
// /usr/lib/udev, and can take the program from an ENV value
// (RUN+="$env{X}"), so reading only those keys, or only whole words, could
// drop a root binary; a substring match is an over-approximation that adds
// names but never drops one (#3950). Escapes (\xHH, \NNN) are decoded
// first. Bound: a name a rule or a shell assembles from pieces, and a
// program another program's output names, are held by review.
func ruleBinaries(root string, pkgs map[string]string, seen map[string]bool) error {
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
			text := ruleOwner.ReplaceAllString(string(b), "")
			// Also the text with each \xHH or \NNN escape decoded, so a name
			// an e"..." value spells with escapes counts too.
			decoded := ruleEscape.ReplaceAllStringFunc(text, func(e string) string {
				base, digits := 8, e[1:]
				if e[1] == 'x' {
					base, digits = 16, e[2:]
				}
				v, err := strconv.ParseUint(digits, base, 8)
				if err != nil {
					return e
				}
				return string([]byte{byte(v)})
			})
			for name, pkg := range pkgs {
				if strings.Contains(text, name) || strings.Contains(decoded, name) {
					seen[pkg] = true
				}
			}
			return nil
		})
		if err != nil {
			return err
		}
	}
	return nil
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
func rootSideUses(root string, bins []string) ([]use, error) {
	if len(bins) == 0 {
		return nil, nil
	}
	files := map[string]bool{}
	for _, arch := range []string{"amd64", "arm64"} {
		cmd := exec.Command("go", append([]string{"list", "-deps", "-f", "{{with .Module}}{{if .Main}}{{$.Dir}}\t{{join $.GoFiles \" \"}}{{end}}{{end}}"}, bins...)...)
		cmd.Dir = filepath.Join(root, "broker")
		cmd.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS=linux", "GOARCH="+arch, "GOFLAGS=")
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		out, err := cmd.Output()
		if err != nil {
			return nil, fmt.Errorf("go list (%s): %v\n%s", arch, err, stderr.String())
		}
		sc := bufio.NewScanner(bytes.NewReader(out))
		for sc.Scan() {
			dir, names, ok := strings.Cut(sc.Text(), "\t")
			if !ok {
				continue
			}
			for _, n := range strings.Fields(names) {
				files[filepath.Join(dir, n)] = true
			}
		}
	}
	var uses []use
	fset := token.NewFileSet()
	for p := range files {
		f, err := parser.ParseFile(fset, p, nil, 0)
		if err != nil {
			return nil, err
		}
		rel, err := filepath.Rel(root, p)
		if err != nil {
			return nil, err
		}
		uses = append(uses, fileUses(fset, f, filepath.ToSlash(rel))...)
	}
	return uses, nil
}

// fileUses finds each pathOps selector on the file's os import, called or
// not, with the top-level function (Type.Method for a method, the first
// name for a package-level var) it sits in. An os.OpenFile call whose flag
// argument names O_NOFOLLOW is not a use.
func fileUses(fset *token.FileSet, f *ast.File, rel string) []use {
	osNames, flagNames := map[string]bool{}, map[string]bool{}
	var uses []use
	for _, imp := range f.Imports {
		p, _ := strconv.Unquote(imp.Path.Value)
		if p == "os" || p == "syscall" || p == "golang.org/x/sys/unix" {
			// Only these packages' O_NOFOLLOW counts, never a local
			// constant or field of that name (#3951 Security delta 2).
			name := filepath.Base(p)
			if imp.Name != nil {
				name = imp.Name.Name
			}
			flagNames[name] = true
		}
		if p == "os" {
			switch {
			case imp.Name == nil:
				osNames["os"] = true
			case imp.Name.Name == ".":
				// Bare calls are not tracked; a dot import is refused
				// outright (#3951 L3 2).
				uses = append(uses, use{file: rel, fn: "import", op: ".", line: fset.Position(imp.Pos()).Line})
			case imp.Name.Name != "_":
				osNames[imp.Name.Name] = true
			}
		}
	}
	if len(osNames) == 0 {
		return uses
	}
	for _, decl := range f.Decls {
		fn := declName(decl)
		safe := map[*ast.SelectorExpr]bool{}
		ast.Inspect(decl, func(n ast.Node) bool {
			switch n := n.(type) {
			case *ast.CallExpr:
				if sel, ok := n.Fun.(*ast.SelectorExpr); ok && isOS(sel, osNames) && sel.Sel.Name == "OpenFile" && len(n.Args) == 3 && namesNoFollow(n.Args[1], flagNames) {
					safe[sel] = true
				}
			case *ast.SelectorExpr:
				if isOS(n, osNames) && pathOps[n.Sel.Name] && !safe[n] {
					uses = append(uses, use{file: rel, fn: fn, op: n.Sel.Name, line: fset.Position(n.Pos()).Line})
				}
			}
			return true
		})
	}
	return uses
}

func isOS(sel *ast.SelectorExpr, osNames map[string]bool) bool {
	id, ok := sel.X.(*ast.Ident)
	return ok && osNames[id.Name]
}

// namesNoFollow reports whether a flag argument is an OR of named flags
// (parentheses allowed) with os., syscall. or unix.O_NOFOLLOW as one operand; any other shape,
// such as one that clears it with &^, is not (#3951 L3 1).
func namesNoFollow(e ast.Expr, flagNames map[string]bool) bool {
	switch e := e.(type) {
	case *ast.ParenExpr:
		return namesNoFollow(e.X, flagNames)
	case *ast.BinaryExpr:
		return e.Op == token.OR && orOfFlags(e.X) && orOfFlags(e.Y) && (namesNoFollow(e.X, flagNames) || namesNoFollow(e.Y, flagNames))
	case *ast.SelectorExpr:
		id, ok := e.X.(*ast.Ident)
		// An import never resolves to a local object; a variable or
		// parameter shadowing its name does (#3951 Security delta 3).
		return ok && id.Obj == nil && flagNames[id.Name] && e.Sel.Name == "O_NOFOLLOW"
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
