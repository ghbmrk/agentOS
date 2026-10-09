package loops_test

// REQ: LOOP-9, LOOP-7

import (
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ghbmrk/agentos/broker/corpus"
	"github.com/ghbmrk/agentos/broker/loops"
	"github.com/ghbmrk/agentos/broker/owner"
)

// fuzzTargets is every top-level `func Fuzz…` in the broker's test files,
// as loop7 names them ("<package>.<func>").
func fuzzTargets(t *testing.T) []string {
	t.Helper()
	var out []string
	err := filepath.WalkDir("..", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() && (d.Name() == "vendor" || d.Name() == "testdata") {
			return filepath.SkipDir
		}
		if d.IsDir() || !strings.HasSuffix(p, "_test.go") {
			return nil
		}
		f, err := parser.ParseFile(token.NewFileSet(), p, nil, parser.SkipObjectResolution)
		if err != nil {
			return err
		}
		pkg := strings.TrimSuffix(f.Name.Name, "_test")
		for _, d := range f.Decls {
			if fn, ok := d.(*ast.FuncDecl); ok && fn.Recv == nil && strings.HasPrefix(fn.Name.Name, "Fuzz") {
				out = append(out, pkg+"."+fn.Name.Name)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// A1 R2: the plain-name map names every fuzz target in the tree, every
// canary registry target, every corpus check and the socket probe, so no
// LOOP-7 text falls back to the generic name for a known subject.
func TestThePlainNameMapCoversEveryLoop7Subject(t *testing.T) {
	var fs []loops.Finding
	targets := fuzzTargets(t)
	if len(targets) < 18 {
		t.Fatalf("found only %d fuzz targets: %q", len(targets), targets)
	}
	for _, s := range targets {
		fs = append(fs, loops.Finding{Check: loops.CheckFuzz, Subject: s})
	}
	b, err := os.ReadFile("../../assurance/canary-targets.json")
	if err != nil {
		t.Fatal(err)
	}
	var reg struct {
		Targets []struct {
			Name string `json:"name"`
		} `json:"targets"`
	}
	if err := json.Unmarshal(b, &reg); err != nil || len(reg.Targets) == 0 {
		t.Fatalf("registry: %v", err)
	}
	for _, x := range reg.Targets {
		fs = append(fs, loops.Finding{Check: loops.CheckCanary, Subject: x.Name})
	}
	for _, c := range corpus.Checks(nil, owner.Commitments{}) {
		fs = append(fs, loops.Finding{Check: loops.CheckCorpus, Subject: "item", Detail: c.Name})
	}
	fs = append(fs, loops.Finding{Check: loops.CheckProbe, Subject: "socket.vm1"})
	for _, f := range fs {
		name, ok := loops.PlainName(f)
		if !ok {
			t.Errorf("%s %s %s: no plain name", f.Check, f.Subject, f.Detail)
		}
		if strings.Contains(name, "Fuzz") || strings.ContainsAny(name, "/._") {
			t.Errorf("%s %s: plain name %q", f.Check, f.Subject, name)
		}
	}
}
