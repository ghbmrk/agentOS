package main

// REQ: CAP-3, R2A, R2B
// Also serves the UX lens duty UX-182-3 (not a SPEC ID, so not in the marker).

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/change"
)

// W3-forget-b2c-f1-r2 (UX 2 on #610): once an item 1 forget's done text has
// sent, agentosd appends a done marker for its goal to the forget log, and
// a restore owes no done text for a goal its log marks told.

// markRig is an item 1 forget rig with a forget log and an owner channel
// that is up unless downed.
func markRig(t *testing.T) (*forgetRig, *lockedForgetLog, *downTell) {
	t.Helper()
	r := restartRig(t, &change.MemStore{})
	fl := &lockedForgetLog{}
	d := &downTell{up: true}
	r.f.forgetLog, r.f.tell = fl, d.tell
	return r, fl, d
}

// R2A: a forget told done at once is marked once, after its text.
func TestForgetDoneAtOnceIsMarked(t *testing.T) {
	r, fl, d := markRig(t)
	r.f.Execute(context.Background(), forgetIntent("1", "owner:a"), 1)
	if len(d.got()) != 1 || strings.Join(fl.marks(), ",") != "owner:a" {
		t.Fatalf("sent %q, marked %v", d.got(), fl.marks())
	}
	if len(r.f.owed.goals()) != 0 {
		t.Fatalf("still owed %v", r.f.owed.goals())
	}
}

// R2A: a retrying forget is marked once its done text sends.
func TestForgetDoneAfterRetryIsMarked(t *testing.T) {
	r, fl, d := markRig(t)
	r.fail = 1
	done := make(chan struct{})
	r.f.retried = func() { close(done) }
	r.f.Execute(context.Background(), forgetIntent("1", "owner:a"), 1)
	within(t, done)
	if len(d.got()) != 1 || strings.Join(fl.marks(), ",") != "owner:a" {
		t.Fatalf("sent %q, marked %v", d.got(), fl.marks())
	}
}

// R2A: a done text that did not send is not marked, not even at a
// shutdown; it is marked once it sends later.
func TestForgetDoneMarkedOnlyOnceItSends(t *testing.T) {
	r, fl, d := markRig(t)
	d.up = false
	ended := make(chan struct{})
	r.f.toldLater = func() { close(ended) }
	r.f.sleep = func(context.Context, time.Duration) bool {
		if len(fl.marks()) != 0 {
			t.Error("marked before the text sent")
		}
		d.setUp()
		return true
	}
	r.f.Execute(context.Background(), forgetIntent("1", "owner:a"), 1)
	within(t, ended)
	if len(d.got()) != 1 || strings.Join(fl.marks(), ",") != "owner:a" {
		t.Fatalf("sent %q, marked %v", d.got(), fl.marks())
	}

	r, fl, d = markRig(t)
	d.up = false
	ended = make(chan struct{})
	r.f.toldLater = func() { close(ended) }
	r.f.sleep = func(context.Context, time.Duration) bool { return false } // shutdown
	r.f.Execute(context.Background(), forgetIntent("1", "owner:a"), 1)
	within(t, ended)
	if len(fl.marks()) != 0 || len(r.f.owed.goals()) != 1 {
		t.Fatalf("an unsent text: marked %v, owed %v", fl.marks(), r.f.owed.goals())
	}
}

// R2A: no marker for a forget the log does not hold, for item 2's done
// text, or for the lost-owed text; a failed marker append changes nothing
// else.
func TestForgetDoneMarkerOnlyForLoggedItem1(t *testing.T) {
	r, fl, d := markRig(t)
	fl.always = true
	r.f.Execute(context.Background(), forgetIntent("1", "owner:a"), 1)
	if len(d.got()) != 1 || len(fl.marks()) != 0 {
		t.Fatalf("unlogged: sent %q, marked %v", d.got(), fl.marks())
	}

	r, fl, d = markRig(t)
	r.f.done(context.Background(), "owner:b", forgetAgentDone, owedForget{Agent: true, Logged: true})
	r.f.done(context.Background(), owedLostKey, forgetOwedLost, owedForget{Logged: true})
	if len(d.got()) != 2 || len(fl.marks()) != 0 {
		t.Fatalf("item 2 and lost: sent %q, marked %v", d.got(), fl.marks())
	}

	r, fl, d = markRig(t)
	fl.doneErr = errors.New("vault closed")
	r.f.Execute(context.Background(), forgetIntent("1", "owner:a"), 1)
	if len(d.got()) != 1 || len(r.f.owed.goals()) != 0 || len(fl.entries()) != 1 {
		t.Fatalf("failed marker: sent %q, owed %v, logged %v", d.got(), r.f.owed.goals(), fl.entries())
	}
}

// markerJSON is a done marker entry for goal, as AppendForget writes it.
func markerJSON(seq int, goal string, at time.Time) string {
	return strings.TrimSuffix(entryJSON(seq, loggedForget{goal: goal, at: at}), `,"prev":"p","mac":"m"}`) + `,"done":true,"prev":"p","mac":"m"}`
}

// R2B: R1A's case, a forget cut off while it retries and restored from a
// backup taken before it, with a done marker after its entry: the restore
// tells nothing, yet the goal is tombstoned and purged from the digest.
func TestForgetRestoredWithDoneMarkerIsNotToldAgain(t *testing.T) {
	e := cutOffRetrying(t, "owner:a")
	b := &restoreBox{t: t, dir: t.TempDir()}
	lp := b.open()
	lp.tasks.put("owner:a", restoreCanary, false, viaSMS)
	b.attach(lp)
	writeRestoredLog(t, b.dir, entryJSON(1, e)+","+markerJSON(2, "owner:a", e.at.Add(time.Minute)))
	lp = b.open()
	if !lp.forgotten.has("owner:a") {
		t.Fatal("a marked forget was not replayed")
	}
	texts, digests := b.attach(lp)
	if len(texts) != 0 {
		t.Fatalf("a forget told done before the restore was told %q again", texts)
	}
	if strings.Join(digests, ",") != "owner:a" {
		t.Fatalf("digest asked %q, want the goal once", digests)
	}
	lp = b.open()
	if texts, _ := b.attach(lp); len(texts) != 0 {
		t.Fatalf("the next boot told %q", texts)
	}
}

// R2B: the restored learn dir's own owe of a marked goal it has not
// tombstoned is dropped; a goal forgotten again after its marker is owed
// as R1A owes it.
func TestForgetRestoredMarkerDropsTheBackupsOwe(t *testing.T) {
	at := time.Date(2026, 10, 5, 14, 0, 0, 0, time.UTC)
	b := &restoreBox{t: t, dir: t.TempDir()}
	lp := b.open()
	if err := lp.forgetOwner.owed.owe("owner:o", owedForget{Since: at.Add(-2 * time.Hour), Undone: 2}); err != nil {
		t.Fatal(err)
	}
	writeRestoredLog(t, b.dir, strings.Join([]string{
		entryJSON(1, loggedForget{goal: "owner:o", at: at}),
		entryJSON(2, loggedForget{goal: "owner:r", at: at}),
		markerJSON(3, "owner:o", at.Add(time.Minute)),
		markerJSON(4, "owner:r", at.Add(time.Minute)),
		entryJSON(5, loggedForget{goal: "owner:r", at: at.Add(time.Hour)}),
	}, ","))
	lp = b.open()
	texts, digests := b.attach(lp)
	if len(texts) != 1 || texts[0] != restoredDone {
		t.Fatalf("the owner got %q, want only owner:r's %q", texts, restoredDone)
	}
	for _, g := range []string{"owner:o", "owner:r"} {
		if !lp.forgotten.has(g) || !contains(digests, g) {
			t.Fatalf("%s: tombstoned %v, digest asked %q", g, lp.forgotten.has(g), digests)
		}
	}
	if _, ok := lp.forgetOwner.owed.get("owner:o"); ok {
		t.Fatal("the backup's owe of a told goal is kept")
	}
}
