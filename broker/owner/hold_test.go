package owner

import (
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

// REQ: REV-3, CH-16

var holdRe = regexp.MustCompile(`UNDO ([A-Z][0-9]{1,2})`)

// heldItem is an approval item whose effect is held for an undo window
// after the owner approves it.
func heldItem(ref string) Item {
	it := lowItem(ref)
	it.UndoWindow = 10 * time.Minute
	return it
}

// TestApprovedEffectIsHeldWithUndoInItsConfirmation: approving an item
// with an undo window does not release it. The confirmation names the
// time it runs and its UNDO ID; the decision carries the hold; the effect
// is released only after the window, and UNDO inside it cancels it.
func TestApprovedEffectIsHeldWithUndoInItsConfirmation(t *testing.T) {
	r := newRig(t, nil)
	r.ch.Request([]Item{heldItem("e1")}, 0)
	m := lowCodeRe.FindStringSubmatch(r.inbox())
	got := r.say("YES " + m[1] + " " + m[2])
	u := holdRe.FindStringSubmatch(got)
	if u == nil || got != "Approved "+m[1]+". It runs at 12:10 unless you reply UNDO "+u[1]+"." {
		t.Fatalf("confirmation: %q", got)
	}
	ds := r.decisions()
	if len(ds) != 1 || ds[0].Ref != "e1" || !ds[0].Approved || ds[0].Hold != u[1] || !ds[0].Until.Equal(r.clock().Add(10*time.Minute)) {
		t.Fatalf("decisions %+v", ds)
	}
	r.advance(9 * time.Minute)
	if due := r.ch.DueAutoReplies(); len(due) != 0 {
		t.Fatalf("released inside the window: %+v", due)
	}
	r.advance(time.Minute)
	due := r.ch.DueAutoReplies()
	if len(due) != 1 || due[0].ID != u[1] || due[0].Reply.Ref != "e1" || !due[0].Held {
		t.Fatalf("due %+v", due)
	}
	if got := r.say("UNDO " + u[1]); got != u[1]+" is past its undo window; it was released." {
		t.Fatalf("undo after release: %q", got)
	}

	// UNDO inside the window cancels it.
	r.ch.Request([]Item{heldItem("e2")}, 0)
	m = lowCodeRe.FindStringSubmatch(r.inbox())
	u = holdRe.FindStringSubmatch(r.say("YES " + m[1] + " " + m[2]))
	r.decisions()
	if got := r.say("UNDO " + u[1]); got != "Cancelled "+u[1]+". It did not run." {
		t.Fatalf("undo: %q", got)
	}
	if ds := r.decisions(); len(ds) != 1 || ds[0].Ref != "e2" || ds[0].Approved || ds[0].Why != "undo" || ds[0].Request != u[1] {
		t.Fatalf("undo decisions %+v", ds)
	}
	r.advance(time.Hour)
	if due := r.ch.DueAutoReplies(); len(due) != 0 {
		t.Fatalf("cancelled effect released: %+v", due)
	}
}

// TestHeldBatchGetsOneUndoPerItem: a batch approval holds each held item
// under its own UNDO ID and states the earliest time any runs; an item
// without a window is approved as before, and a NO holds nothing.
func TestHeldBatchGetsOneUndoPerItem(t *testing.T) {
	r := newRig(t, nil)
	long := heldItem("b")
	long.UndoWindow = 30 * time.Minute
	r.ch.Request([]Item{heldItem("a"), long, lowItem("c")}, 0)
	m := lowCodeRe.FindStringSubmatch(r.inbox())
	got := r.say("YES " + m[1] + " " + m[2])
	ids := holdRe.FindAllStringSubmatch(got, -1)
	if !strings.HasPrefix(got, "Approved "+m[1]+". Held items run unless you reply UNDO and an ID: ") || len(ids) != 0 {
		t.Fatalf("confirmation: %q", got)
	}
	ds := r.decisions()
	if len(ds) != 3 || ds[0].Hold == "" || ds[1].Hold == "" || ds[0].Hold == ds[1].Hold || ds[2].Hold != "" || !ds[2].Approved {
		t.Fatalf("decisions %+v", ds)
	}
	if !strings.HasSuffix(got, ds[0].Hold+" for 1 at 12:10, "+ds[1].Hold+" for 2 at 12:30.") {
		t.Fatalf("confirmation IDs: %q", got)
	}
	if !ds[1].Until.Equal(r.clock().Add(30 * time.Minute)) {
		t.Fatalf("item 2 until %s", ds[1].Until)
	}

	// A full batch still fits CH-12's three segments (checkFormat).
	var full []Item
	for i := range 20 {
		full = append(full, heldItem(string(rune('a'+i))))
	}
	r.ch.Request(full, 0)
	m = lowCodeRe.FindStringSubmatch(r.inbox())
	if got := r.say("YES " + m[1] + " " + m[2]); !strings.Contains(got, " for 20.") {
		t.Fatalf("full batch: %q", got)
	}
	r.decisions()

	r.ch.Request([]Item{heldItem("d")}, 0)
	m = lowCodeRe.FindStringSubmatch(r.inbox())
	if got := r.say("NO " + m[1]); got != "Denied "+m[1]+"." {
		t.Fatalf("no: %q", got)
	}
	if ds := r.decisions(); len(ds) != 1 || ds[0].Approved || ds[0].Hold != "" {
		t.Fatalf("denied decisions %+v", ds)
	}
}

// TestHeldEffectsAreNotReleasedDuringStopAndDieAtRestart: STOP keeps a
// held effect from running (its window can pass meanwhile); a restart
// cancels what is held, reports it, and decides it as "restart".
func TestHeldEffectsAreNotReleasedDuringStopAndDieAtRestart(t *testing.T) {
	store := FileStore{Path: filepath.Join(t.TempDir(), "owner.json")}
	r := newRig(t, store)
	r.ch.Request([]Item{heldItem("e1")}, 0)
	m := lowCodeRe.FindStringSubmatch(r.inbox())
	u := holdRe.FindStringSubmatch(r.say("YES " + m[1] + " " + m[2]))
	r.decisions()
	r.eng.stopped = true
	r.advance(time.Hour)
	if due := r.ch.DueAutoReplies(); len(due) != 0 {
		t.Fatalf("released during STOP: %+v", due)
	}
	r.eng.stopped = false

	r.ch = r.open() // reboot
	r.ch.Boot()
	if got := r.inbox(); got != "Box restarted. Approved actions cancelled, not sent: "+u[1]+". They will be asked again." {
		t.Fatalf("boot text: %q", got)
	}
	if ds := r.decisions(); len(ds) != 1 || ds[0].Ref != "e1" || ds[0].Approved || ds[0].Why != "restart" {
		t.Fatalf("decisions %+v", ds)
	}
}

// TestUndoWorksUntilReleaseAndResumeGivesAFreshWindow (UX-76-1 on #76):
// a held effect or queued reply not yet released can be undone whatever
// the clock, so one the STOP kept past its window is still cancellable;
// RESUME names each that may now run with a short fresh window. Once
// released, UNDO says it ran.
func TestUndoWorksUntilReleaseAndResumeGivesAFreshWindow(t *testing.T) {
	r := newRig(t, nil)
	approve := func(ref string) string {
		r.ch.Request([]Item{heldItem(ref)}, 0)
		m := lowCodeRe.FindStringSubmatch(r.inbox())
		u := holdRe.FindStringSubmatch(r.say("YES " + m[1] + " " + m[2]))
		r.decisions()
		return u[1]
	}
	k1, k2 := approve("e1"), approve("e2")
	res, _ := r.ch.QueueAutoReply(AutoReply{Ref: "r1", Recipients: []string{"sam@example.com"}, Body: "Thanks."})
	r.inbox()
	r.say("STOP")
	r.advance(time.Hour)
	if got := r.say("UNDO " + k1); got != "Cancelled "+k1+". It did not run." {
		t.Fatalf("undo during STOP past the window: %q", got)
	}
	if got := r.say("UNDO " + res.Queued.ID); got != "Cancelled "+res.Queued.ID+". The reply was not sent." {
		t.Fatalf("reply undo during STOP: %q", got)
	}
	r.decisions()
	code := regexp.MustCompile(`RESUME ([0-9]{6})`).FindStringSubmatch(r.say("resume"))[1]
	got := r.say("RESUME " + code)
	if got != "Resumed. "+k2+" runs at 13:02 unless you reply UNDO "+k2+"." {
		t.Fatalf("resume: %q", got)
	}
	if due := r.ch.DueAutoReplies(); len(due) != 0 {
		t.Fatalf("released before the fresh window: %+v", due)
	}
	r.advance(ResumeWindow)
	if due := r.ch.DueAutoReplies(); len(due) != 1 || due[0].ID != k2 {
		t.Fatalf("due %+v", due)
	}
	if got := r.say("UNDO " + k2); got != k2+" is past its undo window; it was released." {
		t.Fatalf("undo after release: %q", got)
	}
}

// TestMixedWindowsGiveEachItemItsTime: items held for different windows
// each show their own run time.
func TestMixedWindowsGiveEachItemItsTime(t *testing.T) {
	r := newRig(t, nil)
	long := heldItem("b")
	long.UndoWindow = 30 * time.Minute
	r.ch.Request([]Item{heldItem("a"), long}, 0)
	m := lowCodeRe.FindStringSubmatch(r.inbox())
	got := r.say("YES " + m[1] + " " + m[2])
	ds := r.decisions()
	want := "Approved " + m[1] + ". Held items run unless you reply UNDO and an ID: " + ds[0].Hold + " for 1 at 12:10, " + ds[1].Hold + " for 2 at 12:30."
	if got != want {
		t.Fatalf("got  %q\nwant %q", got, want)
	}
}

// TestRestartDecisionsNameTheHold (PV1 on #76): a restart's decision on a
// held effect carries its hold, so the gate can tell a cancelled hold,
// which the agent may ask again, from the owner's refusal.
func TestRestartDecisionsNameTheHold(t *testing.T) {
	store := FileStore{Path: filepath.Join(t.TempDir(), "owner.json")}
	r := newRig(t, store)
	r.ch.Request([]Item{heldItem("e1")}, 0)
	m := lowCodeRe.FindStringSubmatch(r.inbox())
	u := holdRe.FindStringSubmatch(r.say("YES " + m[1] + " " + m[2]))
	r.decisions()
	r.ch = r.open()
	r.ch.Boot()
	r.inbox()
	if ds := r.decisions(); len(ds) != 1 || ds[0].Why != "restart" || ds[0].Hold != u[1] || ds[0].Approved {
		t.Fatalf("decisions %+v", ds)
	}
}
