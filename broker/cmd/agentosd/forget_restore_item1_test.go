package main

// REQ: CAP-3, CH-12, R1A, R1B, R1C, R1D

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/daemon"
)

// W3-forget-b2c-f1-r1 (L3 release 2 on #559, UX U4 and Security 1 on
// #602; UX-182-3 of the UX lens on #182): a restore that replays an item 1
// forget still retrying owes the owner the done text forgetNotSaved
// promised; STATUS shows item 1 forgets still retrying; and a restore asks
// the digest queue to forget each restored goal again.

// restoreBox opens the learning plane in dir as a boot does, with the
// owner's texts and the digest queue's forgets recorded.
type restoreBox struct {
	t   *testing.T
	dir string
	cfg *daemon.Config

	mu      sync.Mutex
	texts   []string
	digests []string
}

func (b *restoreBox) open() *learning {
	b.t.Helper()
	b.cfg = &daemon.Config{JournalPath: filepath.Join(b.dir, "journal.log"), SocketDir: filepath.Join(b.dir, "run"), OwnerNumber: ownerNum}
	lp, err := openLearning(learnPaths{Dir: b.dir, Spare: filepath.Join(b.dir, "spare.json")}, false, b.cfg)
	if err != nil {
		b.t.Fatal(err)
	}
	f := lp.forgetOwner
	f.tell = func(s string) error { b.mu.Lock(); b.texts = append(b.texts, s); b.mu.Unlock(); return nil }
	f.inform = func(s string) { b.mu.Lock(); b.texts = append(b.texts, s); b.mu.Unlock() }
	f.digest = func(g string) error { b.mu.Lock(); b.digests = append(b.digests, g); b.mu.Unlock(); return nil }
	return lp
}

// attach is the part of learning.attach that texts what the boot owes.
func (b *restoreBox) attach(lp *learning) (texts, digests []string) {
	b.mu.Lock()
	b.texts, b.digests = nil, nil
	b.mu.Unlock()
	lp.forgetOwner.finishOwed(context.Background())
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]string(nil), b.texts...), append([]string(nil), b.digests...)
}

// cutOffRetrying runs an item 1 forget of goal whose first save fails,
// cut off while it retries, and returns the forget log entry it appended.
func cutOffRetrying(t *testing.T, goal string) loggedForget {
	t.Helper()
	r := newForgetRig(t)
	fl := &lockedForgetLog{}
	r.f.forgetLog = fl
	r.fail = 1
	r.f.sleep = func(context.Context, time.Duration) bool { return false }
	done := make(chan struct{})
	r.f.retried = func() { close(done) }
	r.f.Execute(context.Background(), forgetIntent(strings.TrimPrefix(goal, "owner:"), goal), 1)
	within(t, done)
	got := fl.entries()
	if len(got) != 1 || got[0].goal != goal {
		t.Fatalf("logged %+v", got)
	}
	return got[0]
}

func entryJSON(seq int, e loggedForget) string {
	s := fmt.Sprintf(`{"seq":%d,"goal":%q,"at":%q`, seq, e.goal, e.at.Format(time.RFC3339Nano))
	if !e.since.IsZero() {
		s += fmt.Sprintf(`,"since":%q`, e.since.Format(time.RFC3339Nano))
	}
	if e.agent {
		s += `,"agent":true`
	}
	return s + `,"prev":"p","mac":"m"}`
}

// restoredDone is the done text a restored retrying forget is told: the
// existing doneLater text, verbatim, for a logged forget with no count
// and no time.
const restoredDone = "A task you asked me to forget is forgotten now." + forgetLogged

// R1A, R1B: a forget cut off while it retries, then a restore from a
// backup taken before it: the boot after the restore tells the owner the
// done text once, and the boot after that does not tell it again.
func TestForgetRestoredRetryingIsToldDone(t *testing.T) {
	e := cutOffRetrying(t, "owner:a")
	if !e.since.IsZero() || e.agent {
		t.Fatalf("a retrying forget's entry has a since or agent: %+v", e)
	}
	b := &restoreBox{t: t, dir: t.TempDir()}
	lp := b.open()
	lp.tasks.put("owner:a", restoreCanary, false, viaSMS)
	if texts, _ := b.attach(lp); len(texts) != 0 {
		t.Fatalf("the backup tells %q", texts)
	}
	writeRestoredLog(t, b.dir, entryJSON(1, e))
	lp = b.open()
	if !lp.forgotten.has("owner:a") {
		t.Fatal("the restored forget was not replayed")
	}
	texts, digests := b.attach(lp)
	if len(texts) != 1 || texts[0] != restoredDone {
		t.Fatalf("after the restore the owner got %q, want one %q", texts, restoredDone)
	}
	for _, s := range texts {
		if strings.Contains(s, "gas") {
			t.Fatalf("a text names the task: %q", s)
		}
	}
	if !contains(digests, "owner:a") {
		t.Fatalf("the digest queue was not asked to forget the goal: %q", digests)
	}
	// The next boot re-reads the same restored log.
	lp = b.open()
	if texts, _ := b.attach(lp); len(texts) != 0 {
		t.Fatalf("the boot after the restore told %q again", texts)
	}
}

// R1A: a crash after the restore's owe and before the done text is sent
// is told after the restart: the owe holds before the tombstone.
func TestForgetRestoredRetryingCrashBeforeTextIsTold(t *testing.T) {
	e := cutOffRetrying(t, "owner:a")
	b := &restoreBox{t: t, dir: t.TempDir()}
	b.open()
	writeRestoredLog(t, b.dir, entryJSON(1, e))
	b.open() // crash: never attached
	lp := b.open()
	if texts, _ := b.attach(lp); len(texts) != 1 || texts[0] != restoredDone {
		t.Fatalf("after the crash the owner got %q", texts)
	}
}

// R1B: the restore owes nothing for an entry whose forget was told done
// at once (it has a since), nor for one the backup had already tombstoned
// and does not owe; one the backup owes (a crash between Execute's owe and
// its tombstone) is told once, with the backup's owed count and time.
func TestForgetRestoredToldOrBackedUpIsNotToldAgain(t *testing.T) {
	at := time.Date(2026, 10, 5, 14, 0, 0, 0, time.UTC)
	b := &restoreBox{t: t, dir: t.TempDir()}
	lp := b.open()
	if err := lp.forgotten.add("owner:t"); err != nil {
		t.Fatal(err)
	}
	if err := lp.forgetOwner.owed.owe("owner:o", owedForget{Since: at.Add(-2 * time.Hour), Undone: 2}); err != nil {
		t.Fatal(err)
	}
	writeRestoredLog(t, b.dir, strings.Join([]string{
		entryJSON(1, loggedForget{goal: "owner:s", at: at, since: at.Add(-time.Hour)}),
		entryJSON(2, loggedForget{goal: "owner:t", at: at}),
		entryJSON(3, loggedForget{goal: "owner:o", at: at}),
	}, ","))
	lp = b.open()
	want := lp.forgetOwner.doneLater(2, at.Add(-2*time.Hour), false, false)
	texts, digests := b.attach(lp)
	if len(texts) != 1 || texts[0] != want {
		t.Fatalf("the owner got %q, want only the owed one's %q once", texts, want)
	}
	for _, g := range []string{"owner:s", "owner:t", "owner:o"} {
		if !lp.forgotten.has(g) {
			t.Fatalf("%s not replayed", g)
		}
		if !contains(digests, g) {
			t.Fatalf("the digest queue was not asked to forget %s: %q", g, digests)
		}
	}
	lp = b.open()
	if texts, _ := b.attach(lp); len(texts) != 0 {
		t.Fatalf("the next boot told %q", texts)
	}
}

// R1D: every restored goal, item 2's take-backs included, is asked of the
// digest queue at each boot, whether or not a done text is owed for it.
func TestForgetRestoredGoalsArePurgedFromTheDigest(t *testing.T) {
	r := newForgetRig(t)
	var got []string
	r.f.digest = func(g string) error { got = append(got, g); return nil }
	r.f.restoredGoals = []string{"owner:a", "owner:b"}
	r.f.finishOwed(context.Background())
	if !contains(got, "owner:a") || !contains(got, "owner:b") {
		t.Fatalf("digest asked %q", got)
	}
	if len(r.texts) != 0 {
		t.Fatalf("a purge told %q", r.texts)
	}
}

// R1C: while an item 1 forget is still retrying, STATUS shows one line, a
// count with no task word; it goes once the forget is done.
func TestForgetRetryingShowsOnStatus(t *testing.T) {
	r := newForgetRig(t)
	r.task("owner:a", restoreCanary, r.now.Add(-time.Hour), viaSMS)
	if s := r.f.RetryNote(); s != "" {
		t.Fatalf("STATUS shows %q before any forget", s)
	}
	r.fail = 1
	waiting, release := make(chan struct{}), make(chan bool)
	r.f.sleep = func(context.Context, time.Duration) bool { waiting <- struct{}{}; return <-release }
	done := make(chan struct{})
	r.f.retried = func() { close(done) }
	r.f.Execute(context.Background(), forgetIntent("1", "owner:a"), 1)
	within(t, waiting)
	s := r.f.RetryNote()
	if s != retryNote(1) {
		t.Fatalf("STATUS shows %q while it retries, want %q", s, retryNote(1))
	}
	if strings.Contains(s, "gas") {
		t.Fatalf("STATUS names the task: %q", s)
	}
	release <- true
	within(t, done)
	if s := r.f.RetryNote(); s != "" {
		t.Fatalf("STATUS still shows %q once done", s)
	}
	if !strings.Contains(retryNote(2), "2 ") {
		t.Fatalf("the line is not a count: %q", retryNote(2))
	}
}

// R1C: the line is one of STATUS's notes, wired as item 2's is.
func TestForgetRetryNoteIsWired(t *testing.T) {
	b := &restoreBox{t: t, dir: t.TempDir()}
	lp := b.open()
	defer lp.forgetOwner.markRetrying("owner:a")()
	n := 0
	for _, note := range b.cfg.Notes {
		if note() == retryNote(1) {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("STATUS shows the retry line %d times", n)
	}
}

func contains(ss []string, s string) bool {
	for _, x := range ss {
		if x == s {
			return true
		}
	}
	return false
}
