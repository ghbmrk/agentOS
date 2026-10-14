package durable

// REQ: OP-4, RES-4

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

var (
	bareRename = regexp.MustCompile(`\b(os|syscall|unix)\.Rename(at2?)?\(`)
	exempt     = regexp.MustCompile(`durable:exempt\s+\S`)
)

// TestNoBareRename is the CI check that every rename in the broker's
// non-test code goes through this package, so none skips the directory
// sync. A line that must rename otherwise says `durable:exempt <reason>`.
func TestNoBareRename(t *testing.T) {
	bad := bareRenames(t, "..")
	for _, b := range bad {
		t.Errorf("%s: rename outside broker/durable; use durable.WriteFile or durable.Rename, or mark the line durable:exempt <reason>", b)
	}
}

// The check itself finds a bare rename and accepts an exempt one.
func TestNoBareRenameCatches(t *testing.T) {
	root := t.TempDir()
	src := "package p\n\nimport \"os\"\n\nfunc f() {\n\tos.Rename(\"a\", \"b\")\n\tos.Rename(\"c\", \"d\") // durable:exempt same file, test only\n}\n"
	if err := os.WriteFile(filepath.Join(root, "p.go"), []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	got := bareRenames(t, root)
	if len(got) != 1 || !strings.HasSuffix(got[0], "p.go:6") {
		t.Fatalf("found %q, want p.go:6 only", got)
	}
}

func bareRenames(t *testing.T, root string) []string {
	t.Helper()
	self, err := filepath.Abs(".")
	if err != nil {
		t.Fatal(err)
	}
	var bad []string
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
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for i, line := range strings.Split(string(b), "\n") {
			if bareRename.MatchString(line) && !exempt.MatchString(line) {
				bad = append(bad, path+":"+strconv.Itoa(i+1))
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return bad
}
