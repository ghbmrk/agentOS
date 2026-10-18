package main

import (
	"context"
	"flag"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/daemon"
	ownerch "github.com/ghbmrk/agentos/broker/owner"
)

// day0 is a fixed Monday the pacing tests start on.
var day0 = time.Date(2026, 10, 5, 0, 0, 0, 0, time.UTC)

// agentosdSources maps each non-test source of this package to its text.
func agentosdSources(t *testing.T) map[string]string {
	t.Helper()
	paths, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	srcs := map[string]string{}
	for _, p := range paths {
		if strings.HasSuffix(p, "_test.go") {
			continue
		}
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		srcs[p] = string(b)
	}
	return srcs
}

// digestParts are the names the daily digest ran by (DRB-1, DRB-2).
var digestParts = regexp.MustCompile(`\b(newDigestBox|digestBox|digestConfig|newDigestTransport|wireDigest|newDigestSources|prepareDigestDir|unclearSource|mailSource)\b|\bdg\.(run|register)\b|"github.com/ghbmrk/agentos/broker/digestqueue"|flag\.\w+\([^)]*"digest"`)

// digestRefs names each source line that builds, wires or starts a digest.
func digestRefs(srcs map[string]string) []string {
	var bad []string
	for p, src := range srcs {
		for i, l := range strings.Split(src, "\n") {
			if c := strings.Index(l, "//"); c >= 0 && !strings.Contains(l[:c], `"`) {
				l = l[:c]
			}
			if digestParts.MatchString(l) {
				bad = append(bad, fmt.Sprintf("%s:%d: %s", p, i+1, strings.TrimSpace(l)))
			}
		}
	}
	sort.Strings(bad)
	return bad
}

// DIG-RM-b DRB-1, DRB-2 (brief IDs).

// TestMainStartsNoDigest: no source of agentosd builds, wires or starts
// the daily digest, imports its queue, or takes its -digest flag.
func TestMainStartsNoDigest(t *testing.T) {
	srcs := agentosdSources(t)
	if bad := digestRefs(srcs); len(bad) != 0 {
		t.Fatalf("digest left in agentosd: %q", bad)
	}
	if _, err := os.Stat(filepath.Join("..", "..", "digestqueue")); !os.IsNotExist(err) {
		t.Fatalf("broker/digestqueue still exists: %v", err)
	}
	for name, line := range map[string]string{
		"run restored":  "\tgo dg.run(ctx)",
		"box restored":  "\tdg := newDigestBox(digestConfig{})",
		"flag restored": "\tflag.StringVar(&digestDir, \"digest\", \"/var/lib/agentos/digest\", \"\")",
		"queue import":  "import \"github.com/ghbmrk/agentos/broker/digestqueue\"",
		"wire restored": "\tlp.forgetOwner.wireDigest(dg, lp.forgotten.goals)",
	} {
		mut := map[string]string{"main.go": srcs["main.go"] + "\n" + line + "\n"}
		if len(digestRefs(mut)) == 0 {
			t.Errorf("%s: not caught", name)
		}
	}
}

// DIG-RM-b DRB-1 (brief ID).

// TestStartsWithOldDigestDir: an upgraded box keeps the old digest
// directory and its four files on disk. Nothing reads them, no unit passes
// the removed flag (which would stop agentosd at its flag parse), and the
// flag set main builds has no "digest" flag.
func TestStartsWithOldDigestDir(t *testing.T) {
	old := []string{"/var/lib/agentos/digest", "queue.json", "digest-sources.json", "unclear-digest.json", "mail-digest.json"}
	for p, src := range agentosdSources(t) {
		for _, o := range old {
			if strings.Contains(src, `"`+o+`"`) || strings.Contains(src, `"`+o+`/`) {
				t.Errorf("%s still names %s", p, o)
			}
		}
	}
	root := filepath.Join("..", "..", "..", "image")
	err := filepath.WalkDir(root, func(p string, e fs.DirEntry, err error) error {
		if err != nil || e.IsDir() {
			return err
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		s := string(b)
		if strings.Contains(s, "agentosd") && regexp.MustCompile(`(^|\s)--?digest(=|\s|$)`).MatchString(s) {
			t.Errorf("%s passes -digest to agentosd", p)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	src := agentosdSources(t)["main.go"]
	if regexp.MustCompile(`flag\.\w+\(&\w+, "digest"`).MatchString(src) {
		t.Fatal("main still defines -digest")
	}
	fs := flag.NewFlagSet("agentosd", flag.ContinueOnError)
	fs.SetOutput(new(strings.Builder))
	if err := fs.Parse([]string{"-digest", "/var/lib/agentos/digest"}); err == nil {
		t.Fatal("an undefined flag parsed")
	}
}

// waitNoText fails if the owner's phone gets any text while the fake
// clock moves through two days' mornings with the pacer ticking.
func waitNoText(t *testing.T, r *pacedOwnerRig) {
	t.Helper()
	for _, at := range []time.Duration{7*time.Hour + 59*time.Minute, 8 * time.Hour, 9 * time.Hour, 32 * time.Hour, 33 * time.Hour} {
		r.set(day0.Add(at))
		time.Sleep(5 * time.Millisecond)
		if got := r.sent(); len(got) != 0 {
			t.Fatalf("texted at %v with nothing to say: %q", at, got)
		}
	}
}

// DIG-RM-b DRB-1 (brief ID).

// TestNoDailyOwnerText: with main's pacer attached and its tick running,
// mornings come and go on the fake clock and the owner gets no text.
func TestNoDailyOwnerText(t *testing.T) {
	var cfg daemon.Config
	p := newOwnerPacer(&cfg)
	r := pacedOwner(t, ownerch.Pacing{}, day0.Add(7*time.Hour))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	p.attach(ctx, r.ch, time.Millisecond)
	waitNoText(t, r)
}

// DIG-RM-b DRB-1 (brief ID).

// TestNoDigestWhileLearningIsDown: the digest used to name learning being
// off once a day; now the line is in STATUS only, and nothing is texted.
func TestNoDigestWhileLearningIsDown(t *testing.T) {
	var cfg daemon.Config
	p := newOwnerPacer(&cfg)
	learningOff(&cfg)
	found := false
	for _, n := range cfg.Notes {
		found = found || n() == learningOffNote
	}
	if !found {
		t.Fatal("STATUS does not say learning is off")
	}
	r := pacedOwner(t, ownerch.Pacing{}, day0.Add(7*time.Hour))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	p.attach(ctx, r.ch, time.Millisecond)
	waitNoText(t, r)
}

// directSends are the calls in agentosd that put a text on the owner line
// without the owner channel (a two-argument Send on a link), each as
// "file:func"; the owner channel's own sends pace, hold and dedupe.
func directSends(srcs map[string]string) []string {
	var out []string
	fset := token.NewFileSet()
	for p, src := range srcs {
		f, err := parser.ParseFile(fset, p, src, 0)
		if err != nil {
			return []string{err.Error()}
		}
		for _, d := range f.Decls {
			fn, ok := d.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			name := fn.Name.Name
			if fn.Recv != nil && len(fn.Recv.List) == 1 {
				if id, ok := fn.Recv.List[0].Type.(*ast.Ident); ok {
					name = id.Name + "." + name
				}
				if s, ok := fn.Recv.List[0].Type.(*ast.StarExpr); ok {
					if id, ok := s.X.(*ast.Ident); ok {
						name = id.Name + "." + name
					}
				}
			}
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				switch n := n.(type) {
				case *ast.CallExpr:
					if s, ok := n.Fun.(*ast.SelectorExpr); ok && s.Sel.Name == "Send" && len(n.Args) == 2 {
						out = append(out, p+":"+name)
					}
				case *ast.SelectorExpr:
					// A Send taken as a value can be called anywhere.
					if n.Sel.Name == "Send" {
						out = append(out, p+":"+name)
					}
				}
				return true
			})
		}
	}
	sort.Strings(out)
	return out
}

// DIG-RM-b DRB-3 (brief ID).
// REQ: CH-15

// TestOwnerTextsLeaveOnlyByPushOrConversation: agentosd's texts to the
// owner go through the owner channel (its pushes, paced by the owner's
// setting), except the held-restore conversation, which answers the
// owner's own texts on the link while the channel is down. The digest's
// direct sender is gone with it.
func TestOwnerTextsLeaveOnlyByPushOrConversation(t *testing.T) {
	srcs := agentosdSources(t)
	got := directSends(srcs)
	allowed := map[string]bool{"held.go:heldMode.open": true, "held.go:heldMode.answer": true}
	seen := map[string]bool{}
	for _, s := range got {
		seen[s] = true
		if !allowed[s] {
			t.Errorf("an owner text leaves outside the owner channel: %s", s)
		}
	}
	for s := range allowed {
		if !seen[s] {
			t.Errorf("%s no longer sends: update this test", s)
		}
	}
	for name, body := range map[string]string{
		"daily sender": "func (b *box) run() { b.link.Send(b.owner, \"Today: 3 things.\") }",
		"send value":   "func sender(l link) func(string, string) error { return l.Send }",
	} {
		mut := map[string]string{"zz.go": "package main\n" + body + "\n"}
		if len(directSends(mut)) == 0 {
			t.Errorf("%s: not caught", name)
		}
	}
}
