package durable

// REQ: OP-11, DEV-5, CRED-11, SM-JL-4, SM-JL-5

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
)

const durablePath = "github.com/ghbmrk/agentos/broker/durable"

var (
	lifecycleExempt = regexp.MustCompile(`lifecycle:exempt\s+\S`)
	storeKinds      = map[string]bool{"journal": true, "projection": true, "content": true, "external-session": true, "config": true, "debt": true}
)

// TestBrokerPackagesAreListed is the CI check that every broker package that
// persists is in stores.txt with its OP-11 kind, and that no listed package
// has stopped persisting. A new lifecycle belongs on the journal
// (journal.Lifecycle); a package that keeps one of its own must be listed,
// and so seen, as debt.
func TestBrokerPackagesAreListed(t *testing.T) {
	manifest, err := os.ReadFile("stores.txt")
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range storeProblems(t, "..", string(manifest)) {
		t.Error(p)
	}
}

// SM-JL-4: a package that persists and is not listed fails.
func TestUnlistedPersistingPackageFails(t *testing.T) {
	root := t.TempDir()
	writeGo(t, root, "listed/a.go", "package listed\n\nimport \"github.com/ghbmrk/agentos/broker/durable\"\n\nfunc f() error { return durable.WriteFile(\"x\", nil, 0o600) }\n")
	// An aliased import, and the writer taken as a value, still count.
	writeGo(t, root, "devices/a.go", "package devices\n\nimport d \"github.com/ghbmrk/agentos/broker/durable\"\n\nvar save = d.WriteFile\n")
	// So does a dot-import; another package's Rename field does not.
	writeGo(t, root, "dotted/a.go", "package dotted\n\nimport (\n\t\"os\"\n\t. \"github.com/ghbmrk/agentos/broker/durable\"\n)\n\nvar _ = os.Rename\n\nfunc f() error { return WriteFile(\"x\", nil, 0o600) }\n")
	writeGo(t, root, "fielded/a.go", "package fielded\n\nimport (\n\t\"os\"\n\t. \"github.com/ghbmrk/agentos/broker/durable\"\n)\n\nvar _ = os.Rename\nvar _ = SyncDir\n")
	// A rename the rename check exempts still persists.
	writeGo(t, root, "handoff/a.go", "package handoff\n\nimport \"os\"\n\nfunc f() error { return os.Rename(\"a\", \"b\") // durable:exempt test\n}\n")
	// Test files, testdata and vendor are not broker code.
	writeGo(t, root, "quiet/a_test.go", "package quiet\n\nimport \"github.com/ghbmrk/agentos/broker/durable\"\n\nvar _ = durable.Rename\n")
	writeGo(t, root, "quiet/testdata/a.go", "package x\n\nimport \"github.com/ghbmrk/agentos/broker/durable\"\n\nvar _ = durable.Rename\n")
	writeGo(t, root, "vendor/x/a.go", "package x\n\nimport \"github.com/ghbmrk/agentos/broker/durable\"\n\nvar _ = durable.Rename\n")
	// Another package's WriteFile is not durable's.
	writeGo(t, root, "other/a.go", "package other\n\nimport \"os\"\n\nfunc f() error { return os.WriteFile(\"x\", nil, 0o600) }\n")
	// A line that says why it is not a store is exempt.
	writeGo(t, root, "cache/a.go", "package cache\n\nimport \"github.com/ghbmrk/agentos/broker/durable\"\n\nfunc f() error {\n\treturn durable.WriteFile(\"x\", nil, 0o600) // lifecycle:exempt scratch, removed at boot\n}\n")

	got := storeProblems(t, root, "listed content\n")
	want := []string{"devices: persists", "dotted: persists", "handoff: persists"}
	if !matchProblems(got, want) {
		t.Fatalf("problems = %q, want one each starting %q", got, want)
	}
	if got := storeProblems(t, root, "listed content\ndevices debt debt:#1\ndotted config\nhandoff external-session\n"); len(got) != 0 {
		t.Fatalf("all listed: problems = %q", got)
	}
}

// SM-JL-5: a listed package that no longer persists fails, so the manifest
// cannot keep a stale exemption; so does a malformed line.
func TestStaleManifestEntryFails(t *testing.T) {
	root := t.TempDir()
	writeGo(t, root, "live/a.go", "package live\n\nimport \"github.com/ghbmrk/agentos/broker/durable\"\n\nfunc f() error { return durable.Rename(\"a\", \"b\") }\n")
	writeGo(t, root, "gone/a.go", "package gone\n\nfunc f() {}\n")

	got := storeProblems(t, root, "live content\ngone projection\nmissing config\n")
	if !matchProblems(got, []string{"gone: listed", "missing: listed"}) {
		t.Fatalf("stale: problems = %q", got)
	}
	for manifest, want := range map[string]string{
		"live\n":                       "stores.txt:1",
		"live store\n":                 "stores.txt:1",
		"live debt\n":                  "stores.txt:1",
		"live content debt:#1\n":       "stores.txt:1",
		"live debt ref\n":              "stores.txt:1",
		"live content\nlive content\n": "stores.txt:2",
	} {
		got := storeProblems(t, root, manifest)
		if len(got) != 1 || !strings.HasPrefix(got[0], want) {
			t.Errorf("manifest %q: problems = %q, want one at %s", manifest, got, want)
		}
	}
}

// storeProblems compares the packages under root that persist with the
// manifest and returns one line per mismatch.
func storeProblems(t *testing.T, root, manifest string) []string {
	t.Helper()
	var problems []string
	listed := map[string]bool{}
	for i, line := range strings.Split(manifest, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		at := "stores.txt:" + strconv.Itoa(i+1)
		f := strings.Fields(line)
		switch {
		case len(f) < 2 || len(f) > 3 || !storeKinds[f[1]]:
			problems = append(problems, at+": want <dir> <kind> [debt:<ref>]")
		case f[1] == "debt" && (len(f) != 3 || !strings.HasPrefix(f[2], "debt:") || len(f[2]) == len("debt:")):
			problems = append(problems, at+": a debt entry names its ref, debt:<ref>")
		case f[1] != "debt" && len(f) == 3:
			problems = append(problems, at+": only a debt entry carries a ref")
		case listed[f[0]]:
			problems = append(problems, at+": "+f[0]+" listed twice")
		default:
			listed[f[0]] = true
			continue
		}
		if len(f) > 0 {
			listed[f[0]] = true
		}
	}
	found := persisting(t, root)
	var dirs []string
	for d := range found {
		dirs = append(dirs, d)
	}
	sort.Strings(dirs)
	for _, d := range dirs {
		if !listed[d] {
			problems = append(problems, d+": persists ("+found[d]+") but is not in broker/durable/stores.txt; build a lifecycle as journal intents (journal.Lifecycle), or list the package with its OP-11 kind")
		}
	}
	var stale []string
	for d := range listed {
		if _, ok := found[d]; !ok {
			stale = append(stale, d)
		}
	}
	sort.Strings(stale)
	for _, d := range stale {
		problems = append(problems, d+": listed in broker/durable/stores.txt but no longer persists; remove the line")
	}
	return problems
}

// persisting maps each package directory under root (slash-separated,
// relative to root) whose non-test code writes durably to its first site.
// A site is a use of durable.WriteFile or durable.Rename, called or taken as
// a value, also through a dot-import, or a rename marked durable:exempt
// (TestNoBareRename sends every other rename through this package). A line
// marked `lifecycle:exempt <reason>` is not a site.
func persisting(t *testing.T, root string) map[string]string {
	t.Helper()
	self, err := filepath.Abs(".")
	if err != nil {
		t.Fatal(err)
	}
	found := map[string]string{}
	err = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			abs, _ := filepath.Abs(path)
			if abs == self || d.Name() == "vendor" || d.Name() == "testdata" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		src, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		lines := strings.Split(string(src), "\n")
		rel, err := filepath.Rel(root, filepath.Dir(path))
		if err != nil {
			return err
		}
		dir := filepath.ToSlash(rel)
		site := func(line int) {
			if line < 1 || line > len(lines) || lifecycleExempt.MatchString(lines[line-1]) {
				return
			}
			if _, ok := found[dir]; !ok {
				found[dir] = filepath.Base(path) + ":" + strconv.Itoa(line)
			}
		}
		for i, l := range lines {
			if bareRename.MatchString(l) && exempt.MatchString(l) {
				site(i + 1)
			}
		}
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, path, src, parser.SkipObjectResolution)
		if err != nil {
			return err
		}
		for _, imp := range f.Imports {
			if p, _ := strconv.Unquote(imp.Path.Value); p != durablePath {
				continue
			}
			name := "durable"
			if imp.Name != nil {
				name = imp.Name.Name
			}
			writer := func(s string) bool { return s == "WriteFile" || s == "Rename" }
			field := map[*ast.Ident]bool{} // x.Sel names, never a dot-imported writer
			ast.Inspect(f, func(n ast.Node) bool {
				switch n := n.(type) {
				case *ast.SelectorExpr:
					field[n.Sel] = true
					if x, ok := n.X.(*ast.Ident); ok && x.Name == name && writer(n.Sel.Name) {
						site(fset.Position(n.Pos()).Line)
					}
				case *ast.Ident:
					if name == "." && !field[n] && writer(n.Name) {
						site(fset.Position(n.Pos()).Line)
					}
				}
				return true
			})
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return found
}

func writeGo(t *testing.T, root, rel, src string) {
	t.Helper()
	p := filepath.Join(root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
}

// matchProblems: one problem per prefix, in order, and no others.
func matchProblems(got, prefixes []string) bool {
	if len(got) != len(prefixes) {
		return false
	}
	for i, p := range prefixes {
		if !strings.HasPrefix(got[i], p) {
			return false
		}
	}
	return true
}
