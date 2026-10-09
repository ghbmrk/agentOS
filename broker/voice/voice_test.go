package voice

// REQ: CH-21

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// thirdPerson matches the box speaking of itself in the third person.
// Owner-facing text says "I"/"my" (SPEC CH-21); the one place the box is
// named in the third person is third-party text, which uses the box's name
// and never these phrases.
var thirdPerson = regexp.MustCompile(`(?i)\b(the box|this box|the agent)\b|\bagent:`)

// pending lists top-level broker directories not yet swept. Each later
// CH-21 part deletes its entries; the list may only shrink.
var pending = map[string]string{
	"owner": "CH-21e", // AgentPrefix "Agent: " goes only with CH-21e's withhold check
	"cmd":   "CH-21d",
}

// literals returns the string literals of every non-test Go file under
// root (relative to the broker module), keyed by "dir/file.go:line:col".
func literals(t *testing.T, root string) map[string]string {
	t.Helper()
	out := map[string]string{}
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case "vendor", "testdata", "voice":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
			return nil
		}
		lits, err := fileLiterals(p, nil)
		if err != nil {
			return err
		}
		for k, v := range lits {
			out[k] = v
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// fileLiterals returns one file's string literals keyed by
// "name:line:col", so two literals on one line stay distinct. src nil
// reads name from disk.
func fileLiterals(name string, src any) (map[string]string, error) {
	out := map[string]string{}
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, name, src, 0)
	if err != nil {
		return nil, err
	}
	ast.Inspect(f, func(n ast.Node) bool {
		if bl, ok := n.(*ast.BasicLit); ok && bl.Kind == token.STRING {
			if s, err := strconv.Unquote(bl.Value); err == nil {
				pos := fset.Position(bl.Pos())
				out[name+":"+strconv.Itoa(pos.Line)+":"+strconv.Itoa(pos.Column)] = s
			}
		}
		return true
	})
	return out, nil
}

// Two literals on one line must both be reported (CH-21 review 1).
func TestTwoLiteralsOnOneLineBothChecked(t *testing.T) {
	lits, err := fileLiterals("x.go", "package x\nvar _ = f(\"the box will\", \"Mon 2 Jan\")\n")
	if err != nil {
		t.Fatal(err)
	}
	if len(lits) != 2 {
		t.Fatalf("want both literals, got %v", lits)
	}
	hit := 0
	for _, s := range lits {
		if thirdPerson.MatchString(s) {
			hit++
		}
	}
	if hit != 1 {
		t.Fatalf("the third-person literal was hidden: %v", lits)
	}
}

func TestNoThirdPersonSelfReference(t *testing.T) {
	var bad []string
	for loc, s := range literals(t, "..") {
		top := strings.Split(filepath.ToSlash(loc), "/")[1]
		if _, ok := pending[top]; ok {
			continue
		}
		if thirdPerson.MatchString(s) {
			bad = append(bad, loc+": "+s)
		}
	}
	sort.Strings(bad)
	if len(bad) > 0 {
		t.Fatalf("third-person self-reference (say I/my; SPEC CH-21):\n%s", strings.Join(bad, "\n"))
	}
}

// The pattern must catch each phrase the sweep removes, and not catch
// first-person text.
func TestPatternSelfCheck(t *testing.T) {
	for _, s := range []string{"the box could not", "On this box", "Agent: hi", "tell the agent", "The BOX's page"} {
		if !thirdPerson.MatchString(s) {
			t.Errorf("not caught: %q", s)
		}
	}
	for _, s := range []string{"I could not save that.", "my page", "a boxed set", "agentOS"} {
		if thirdPerson.MatchString(s) {
			t.Errorf("false positive: %q", s)
		}
	}
}

// A pending entry whose directory is clean must be deleted, so the list
// only shrinks.
func TestPendingListIsNotStale(t *testing.T) {
	dirty := map[string]bool{}
	for loc, s := range literals(t, "..") {
		if thirdPerson.MatchString(s) {
			dirty[strings.Split(filepath.ToSlash(loc), "/")[1]] = true
		}
	}
	for dir, part := range pending {
		if !dirty[dir] {
			t.Errorf("%s (%s) has no third-person text left: remove it from pending", dir, part)
		}
	}
}
