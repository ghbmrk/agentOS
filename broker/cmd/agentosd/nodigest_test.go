package main

import (
	"context"
	"encoding/json"
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

	"github.com/ghbmrk/agentos/broker/control"
	"github.com/ghbmrk/agentos/broker/daemon"
	"github.com/ghbmrk/agentos/broker/journal"
	"github.com/ghbmrk/agentos/broker/mail"
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

// DIG-RM DRA-3 (brief ID); ADP-2, OP-2, CH-12.

// statusNow is the fixed clock the STATUS note tests read, in UTC.
var statusNow = time.Date(2026, 10, 12, 10, 0, 0, 0, time.UTC)

// mailTrail is a journal trail with one Succeeded organize change per
// entry, made daysAgo days before statusNow; alert marks a guard hit.
type mailChange struct {
	daysAgo int
	alert   bool
}

func mailTrail(account string, cs []mailChange) []journal.Record {
	var out []journal.Record
	for i, c := range cs {
		id := fmt.Sprintf("i%d", i)
		at := statusNow.AddDate(0, 0, -c.daysAgo).Add(-time.Hour)
		op := mail.OpArchive
		if c.alert {
			op = mail.OpLabel
		}
		ev, _ := json.Marshal(mail.Change{Op: op, Record: "r" + id, From: "INBOX", Alert: c.alert})
		out = append(out,
			journal.Record{Type: journal.RecSubmitted, ID: id, At: at, Intent: &journal.Intent{ID: id, Account: account, Executor: mail.Tool, Action: op}},
			journal.Record{Type: journal.RecObserved, ID: id, At: at, Result: journal.ResultSucceeded, Evidence: string(ev)})
	}
	return out
}

func statusMailDays(cs []mailChange) *mailDays {
	trail := mailTrail("acct", cs)
	return &mailDays{account: "acct", key: []byte("synthetic-undo-key"), loc: time.UTC,
		now: func() time.Time { return statusNow }, trail: func() []journal.Record { return trail }, m: newLateMail()}
}

// Every complete day mailDays.undo still accepts has its UNDO on STATUS's
// mail line, newest first, and the alerts line sums those days' security
// alerts; today and lapsed days have neither.
func TestMailNoteEveryUndoableDay(t *testing.T) {
	days := statusMailDays([]mailChange{{0, true}, {1, false}, {1, true}, {3, false}, {6, true}, {7, true}})
	note := &mailNote{}
	note.days.Store(days)
	id := func(ago int) string { return undoID(days.key, "acct", statusNow.AddDate(0, 0, -ago).Format(dayFormat)) }
	want := "Mail UNDO codes, 7 days each: Sun " + id(1) + ", Fri " + id(3) + ", Tue " + id(6) + "."
	if got := note.codes(); got != want {
		t.Fatalf("codes %q, want %q", got, want)
	}
	if got := note.alerts(); got != "2 security alerts labelled but left in the inbox." {
		t.Fatalf("alerts %q", got)
	}
	for _, ago := range []int{1, 3, 6} {
		if s, ok := days.undo(context.Background(), id(ago)); !ok || !strings.Contains(s, "not connected") {
			t.Errorf("UNDO %s for a shown day: %v %q", id(ago), ok, s)
		}
	}
	if s, ok := days.undo(context.Background(), id(7)); !ok || !strings.Contains(s, "past its undo window") {
		t.Errorf("lapsed day: %v %q", ok, s)
	}
	note.days.Store(statusMailDays([]mailChange{{2, true}}))
	if got := note.alerts(); got != "1 security alert labelled but left in the inbox." {
		t.Errorf("one alert: %q", got)
	}
	note.days.Store(statusMailDays([]mailChange{{2, false}}))
	if got := note.alerts(); got != "" {
		t.Errorf("no alerts: %q", got)
	}
}

// statusEngine is an idle engine for control.Handler.
type statusEngine struct{}

func (statusEngine) Stop(context.Context) (journal.StopReport, error) {
	return journal.StopReport{}, nil
}
func (statusEngine) Resume() error          { return nil }
func (statusEngine) Stopped() bool          { return false }
func (statusEngine) List() []journal.Status { return nil }

// wireStatusNotes adds the unclear note and the two mail notes, all empty
// until the daemon's state is set. With every undoable day organized and
// alerting, and the unclear and machines lines at their longest, STATUS
// still fits one reply whole: every UNDO and the line after the notes
// (the owner channel's Wi-Fi page line) survive control.Fit.
func TestWireStatusNotes(t *testing.T) {
	cfg := daemon.Config{Notes: []func() string{func() string { return "clock" }}}
	unclear, mailStatus := wireStatusNotes(&cfg)
	if len(cfg.Notes) != 4 {
		t.Fatalf("%d notes", len(cfg.Notes))
	}
	for i, n := range cfg.Notes[1:] {
		if l := n(); l != "" {
			t.Fatalf("note %d before the daemon runs: %q", i, l)
		}
	}
	waiting := []journal.ParkedIntent{{Intent: journal.Intent{Executor: "sms"}}, {Intent: journal.Intent{Executor: "sms"}}}
	unclear.set(func() []journal.ParkedIntent { return waiting })
	var cs []mailChange
	for ago := 0; ago <= undoLookback; ago++ {
		for i := 0; i < 1000; i++ {
			cs = append(cs, mailChange{ago, false}, mailChange{ago, true})
		}
	}
	days := statusMailDays(cs)
	mailStatus.days.Store(days)
	var got []string
	for _, n := range cfg.Notes {
		if l := n(); l != "" {
			checkNote(t, l)
			got = append(got, l)
		}
	}
	if len(got) != 4 || got[0] != "clock" || !strings.Contains(got[1], "not retried") ||
		!strings.HasPrefix(got[2], "Mail UNDO codes, ") || got[3] != "6000 security alerts labelled but left in the inbox." {
		t.Fatalf("STATUS %q", got)
	}
	last := "999 waiting for you on my Wi-Fi page."
	h := &control.Handler{Engine: statusEngine{}, Machines: func() string { return strings.Repeat("m", 80) },
		Notes: append(cfg.Notes, func() string { return last })}
	s := h.Status()
	if control.Fit(s) != s || !strings.HasSuffix(s, " "+last) {
		t.Fatalf("STATUS cut (%d bytes): %q", len(s), s)
	}
	shown := 0
	for ago := 1; ago <= undoLookback; ago++ {
		id := undoID(days.key, "acct", statusNow.AddDate(0, 0, -ago).Format(dayFormat))
		r, _ := days.undo(context.Background(), id)
		if undoable := strings.Contains(r, "not connected"); undoable != strings.Contains(s, " "+id) {
			t.Errorf("day %d: undoable %v, shown %v", ago, undoable, !undoable)
		} else if undoable {
			shown++
		}
	}
	if shown != 6 {
		t.Fatalf("%d undoable days shown", shown)
	}
}

// main wires the STATUS notes before the daemon copies its config, sets
// the unclear note and the mail days once it runs, and removes the old
// digest directory at start.
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
	wire := at("unclear, mailStatus := wireStatusNotes(&cfg)")
	run := at("d, err := daemon.Run(ctx, cfg)")
	set := at("unclear.set(d.RetryWaiting)")
	mailWire := at("wireMail(ctx, mw, d, mailSocket, learn.Dir, mailStatus, cfg.Now)")
	if !(parse < remove && remove < wire && wire < run && run < set && run < mailWire) {
		t.Fatalf("order: parse %d remove %d wire %d run %d set %d mail %d", parse, remove, wire, run, set, mailWire)
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
