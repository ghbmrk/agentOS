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
	"sync/atomic"
	"testing"
	"time"
	_ "time/tzdata"

	clockpkg "github.com/ghbmrk/agentos/broker/clock"
	"github.com/ghbmrk/agentos/broker/control"
	"github.com/ghbmrk/agentos/broker/daemon"
	"github.com/ghbmrk/agentos/broker/journal"
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

// TestStartsWithOldDigestDir: nothing reads the old digest directory or
// its four files (only removeOldDigest names the directory, to delete it),
// no unit passes the removed flag (which would stop agentosd at its flag
// parse), and the flag set main builds has no "digest" flag.
func TestStartsWithOldDigestDir(t *testing.T) {
	old := []string{"/var/lib/agentos/digest", "queue.json", "digest-sources.json", "unclear-digest.json", "mail-digest.json"}
	for p, src := range agentosdSources(t) {
		if p == "main.go" {
			src = strings.Replace(src, `const oldDigestDir = "/var/lib/agentos/digest"`, "", 1)
		}
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

// DIG-RM DRA-3 (brief ID); OP-2, CH-12.

// statusNow is the fixed clock the STATUS note tests read, in UTC.
var statusNow = time.Date(2026, 10, 12, 10, 0, 0, 0, time.UTC)

// statusEngine is an engine for control.Handler whose List is the effects
// the unclear note's parked intents leave open.
type statusEngine struct{ list []journal.Status }

func (statusEngine) Stop(context.Context) (journal.StopReport, error) {
	return journal.StopReport{}, nil
}
func (statusEngine) Resume() error            { return nil }
func (statusEngine) Stopped() bool            { return false }
func (e statusEngine) List() []journal.Status { return e.list }

// statusOwner is the owner, unlocked.
type statusOwner struct{}

func (statusOwner) IsOwner(string) bool            { return true }
func (statusOwner) SessionUnlocked(time.Time) bool { return true }

// wireStatusNotes adds the unclear note, empty until the daemon's state is
// set, before the capability lines. The texted STATUS, at its longest
// (parked effects in the header, a held clock, update checks off and the
// 99-byte model line), stays within one reply: the Wi-Fi page line, the
// owner channel's first note, is kept, and each note is shown whole or
// not at all.
func TestWireStatusNotes(t *testing.T) {
	var clock atomic.Pointer[string]
	ok := ""
	clock.Store(&ok)
	cfg := daemon.Config{Notes: []func() string{func() string { return *clock.Load() }}}
	unclear := wireStatusNotes(&cfg)
	if len(cfg.Notes) != 2 {
		t.Fatalf("%d notes", len(cfg.Notes))
	}
	for i, n := range cfg.Notes[1:] {
		if l := n(); l != "" {
			t.Fatalf("note %d before the daemon runs: %q", i, l)
		}
	}
	// As main wires them: no update-check loop, so that line is on, and
	// no model socket, so the 99-byte model line is on too.
	newCapLines(newCapState("")).wire(&cfg)

	label := journal.Intent{Action: strings.Repeat("a", 20), Account: strings.Repeat("b", 16)}
	var waiting []journal.ParkedIntent
	var open []journal.Status
	for i := 0; i < 4; i++ {
		waiting = append(waiting, journal.ParkedIntent{Intent: journal.Intent{Executor: "sms"}})
		open = append(open, journal.Status{Intent: label, State: journal.OutcomeUnknown})
	}
	unclear.set(func() []journal.ParkedIntent { return waiting })
	wifi := "2 waiting for you on my Wi-Fi page."
	h := &control.Handler{Engine: statusEngine{}, Auth: statusOwner{}, Machines: func() string { return strings.Repeat("m", 80) },
		// owner.Channel puts its page line first.
		Notes: append([]func() string{func() string { return wifi }}, cfg.Notes...)}
	held := clockpkg.Status{State: clockpkg.Held, Since: statusNow, Skew: 3 * time.Hour, Verified: true}.Line(time.UTC)
	for _, c := range []struct {
		name   string
		clock  string
		parked bool
	}{
		{"clock agrees, nothing open", clockpkg.Status{State: clockpkg.Agreed, Verified: true}.Line(time.UTC), false},
		{"worst case", held, true},
	} {
		clock.Store(&c.clock)
		e := statusEngine{}
		if c.parked {
			e.list = open
		}
		h.Engine = e
		var got []string
		for _, n := range cfg.Notes {
			if l := n(); l != "" {
				checkNote(t, l)
				got = append(got, l)
			}
		}
		if len(got) != 4 || got[0] != c.clock || !strings.Contains(got[1], "not retried") || got[2] != modelUnset || got[3] != updateChecksOff {
			t.Fatalf("%s: notes %q", c.name, got)
		}
		r := h.Handle(context.Background(), "owner", "STATUS")
		if len(r) != 1 || len(r[0]) > control.MaxText || control.Fit(r[0]) != r[0] {
			t.Fatalf("%s: reply (%d bytes) %q", c.name, len(r[0]), r)
		}
		s := r[0]
		if c.parked && !strings.Contains(s, "4 may have happened ("+label.Action+"/"+label.Account) {
			t.Fatalf("%s: no header sample: %q", c.name, s)
		}
		if !strings.Contains(s, " "+wifi) {
			t.Fatalf("%s: Wi-Fi page line lost: %q", c.name, s)
		}
		// Each note is in the reply whole or not at all.
		for _, l := range got {
			if i := strings.Index(s, l[:20]); i >= 0 && !strings.Contains(s, l) {
				t.Fatalf("%s: note cut: %q in %q", c.name, l, s)
			}
		}
		if page := h.Status(); !strings.Contains(page, wifi) || strings.Contains(page, "more line") {
			t.Fatalf("%s: page STATUS %q", c.name, page)
		}
	}
}

// main wires the STATUS notes before the daemon copies its config, sets
// the unclear note once it runs, and removes the old digest directory at
// start.
func TestMainWiresStatusNotes(t *testing.T) {
	var code []string
	for _, l := range strings.Split(agentosdSources(t)["main.go"], "\n") {
		if c := strings.Index(l, "//"); c >= 0 && !strings.Contains(l[:c], `"`) {
			l = l[:c]
		}
		code = append(code, strings.TrimSpace(l))
	}
	src := strings.Join(code, "\n")
	at := func(s string) int {
		t.Helper()
		i := strings.Index(src, s)
		if i < 0 || strings.Count(src, s) != 1 {
			t.Fatalf("main.go has %d of %q", strings.Count(src, s), s)
		}
		return i
	}
	parse := at("flag.Parse()")
	remove := at("removeOldDigest(oldDigestDir)")
	wire := at("unclear := wireStatusNotes(&cfg)")
	if caps := at("capLines.wire(&cfg)"); caps < wire {
		t.Fatal("capability lines wired before the waiting lines")
	}
	run := at("d, err := daemon.Run(ctx, cfg)")
	set := at("unclear.set(d.RetryWaiting)")
	if !(parse < remove && remove < wire && wire < run && run < set) {
		t.Fatalf("order: parse %d remove %d wire %d run %d set %d", parse, remove, wire, run, set)
	}
	if regexp.MustCompile(`cfg\.Notes\s*=\s*cfg\.Notes\[:`).MatchString(src) {
		t.Fatal("main drops notes it wired")
	}
}

// The old digest directory goes once at start, through no link.
func TestRemoveOldDigest(t *testing.T) {
	root := t.TempDir()
	outside := filepath.Join(root, "outside")
	if err := os.MkdirAll(outside, 0o700); err != nil {
		t.Fatal(err)
	}
	keep := filepath.Join(outside, "keep.json")
	if err := os.WriteFile(keep, []byte("synthetic"), 0o600); err != nil {
		t.Fatal(err)
	}

	dir := filepath.Join(root, "digest")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{"queue.json", "digest-sources.json", "unclear-digest.json", "mail-digest.json"} {
		if err := os.WriteFile(filepath.Join(dir, f), []byte(`{"canary":"synthetic"}`), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(outside, filepath.Join(dir, "link")); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "a", "b"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "a", "b", "c.json"), []byte("synthetic"), 0o600); err != nil {
		t.Fatal(err)
	}
	if removed, err := removeOldDigest(dir); !removed || err != nil {
		t.Fatalf("dir: %v %v", removed, err)
	}
	if _, err := os.Lstat(dir); !os.IsNotExist(err) {
		t.Fatalf("dir left: %v", err)
	}
	if _, err := os.Stat(keep); err != nil {
		t.Fatalf("followed a link inside: %v", err)
	}

	if err := os.Symlink(outside, dir); err != nil {
		t.Fatal(err)
	}
	if removed, err := removeOldDigest(dir); !removed || err != nil {
		t.Fatalf("link: %v %v", removed, err)
	}
	if _, err := os.Lstat(dir); !os.IsNotExist(err) {
		t.Fatalf("link left: %v", err)
	}
	if _, err := os.Stat(keep); err != nil {
		t.Fatalf("followed the link: %v", err)
	}

	if removed, err := removeOldDigest(dir); removed || err != nil {
		t.Fatalf("absent: %v %v", removed, err)
	}

	if err := os.WriteFile(dir, []byte("synthetic"), 0o600); err != nil {
		t.Fatal(err)
	}
	if removed, err := removeOldDigest(dir); !removed || err != nil {
		t.Fatalf("file: %v %v", removed, err)
	}
	if _, err := os.Lstat(dir); !os.IsNotExist(err) {
		t.Fatalf("file left: %v", err)
	}
}
