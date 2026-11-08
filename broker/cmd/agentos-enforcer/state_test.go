package main

// REQ: KEY-7, STO-4

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/enforcer/policy"
	"github.com/ghbmrk/agentos/broker/enforcer/traffic"
)

// TestRevokeUnsaved (#4751): a revocation the head store cannot save is
// in force for the run and the page says it was not saved, so the owner
// taps again; the tap after the journal recovers saves it.
func TestRevokeUnsaved(t *testing.T) {
	x, a := enrolled(t, true)
	addr := x.serve()
	journal := filepath.Join(x.dir, fileHeads)
	os.Remove(journal)
	if err := os.Mkdir(journal, 0o700); err != nil { // every append fails
		t.Fatal(err)
	}
	w := x.b.act(a, "revoke-core", "")
	if w.Code != http.StatusConflict || !strings.Contains(w.Body.String(), "not saved: revoke it again") ||
		!strings.Contains(x.logText(), "revocation is in force but not saved") {
		t.Fatalf("an unsaved revocation: %d %s", w.Code, w.Body)
	}
	if _, ok := x.dial(addr, x.core); ok {
		t.Fatal("an unsaved revocation is not in force for the run")
	}
	if err := os.Remove(journal); err != nil {
		t.Fatal(err)
	}
	if w := x.b.act(a, "revoke-core", ""); w.Code != http.StatusOK || x.page("Key") != "revoked" {
		t.Fatalf("the revocation again: %d %s", w.Code, w.Body)
	}
	if !strings.Contains(x.logText(), "the owner revoked the core's channel key") {
		t.Fatal("the revocation was not logged")
	}
	x.restart()
	if _, ok := x.dial(x.serve(), x.core); ok || x.page("Key") != "revoked" {
		t.Fatal("the revocation saved on the second tap did not survive a restart")
	}
}

// spentBox is capped's box restarted on an unreadable saved day.
func spentBox(t *testing.T) (*box, *authenticator) {
	t.Helper()
	x, _, a := capped(t)
	x.writeState(fileTraffic, "{}")
	x.restart()
	if !x.d.net.spent {
		t.Fatal("fixture: the day is not spent")
	}
	return x, a
}

func (x *box) writeState(name, body string) {
	x.t.Helper()
	if err := os.WriteFile(filepath.Join(x.dir, name), []byte(body), 0o600); err != nil {
		x.t.Fatal(err)
	}
}

func (x *box) readState(name string) string {
	b, _ := os.ReadFile(filepath.Join(x.dir, name))
	return string(b)
}

// TestCancelAfterStart (Security on #5101): a cancel drawn before the
// fresh day starts and tapped after it answers that nothing is waiting,
// never done.
func TestCancelAfterStart(t *testing.T) {
	x, a := spentBox(t)
	if w := x.b.act(a, "fresh-day", ""); w.Code != http.StatusOK {
		t.Fatalf("fresh day: %d %s", w.Code, w.Body)
	}
	x.advance(time.Duration(policy.Wait)*time.Millisecond - 2*time.Second)
	r := x.b.json(http.MethodPost, "/challenge", map[string]string{"action": "cancel-fresh", "target": ""}, http.StatusOK)
	x.advance(5 * time.Second)
	if x.d.net.spent {
		t.Fatal("fixture: the fresh day did not start")
	}
	body := map[string]any{"action": "cancel-fresh"}
	for k, v := range a.assertion(r["id"].(string), r["challenge"].(string)) {
		body[k] = v
	}
	if w := x.b.do(http.MethodPost, "/act", body); w.Code == http.StatusOK || !strings.Contains(w.Body.String(), "no fresh day is waiting") {
		t.Fatalf("a cancel after the start: %d %s", w.Code, w.Body)
	}
}

// TestCancelBeatsStart (Security on #5101): a cancel that lands after
// the tick read the due time, while it waits for the firewall lock, stops
// the start. (Should the tick read after the cancel instead, it starts
// nothing either, so the test cannot pass wrongly by timing.)
func TestCancelBeatsStart(t *testing.T) {
	x, a := spentBox(t)
	if w := x.b.act(a, "fresh-day", ""); w.Code != http.StatusOK {
		t.Fatalf("fresh day: %d %s", w.Code, w.Body)
	}
	due := time.UnixMilli(x.d.net.freshDue)
	x.d.fwMu.Lock()
	done := make(chan struct{})
	go func() { x.d.tickFresh(due); close(done) }()
	time.Sleep(100 * time.Millisecond) // the tick reads the due time, then waits on fwMu
	if err := (pageCaps{x.d}).CancelFresh(); err != nil {
		t.Fatal(err)
	}
	x.d.fwMu.Unlock()
	<-done
	if !x.d.net.spent || x.readState(fileTraffic) != "{}" {
		t.Fatal("a cancelled fresh day started")
	}
}

// TestStaleFreshDay (L3 and Potency on #5101): an approval outlives
// neither the day it was for nor a fresh day's start. A fresh-day file
// beside a day that reads back is erased (and the daemon does not start
// while it cannot be), one for another unreadable day starts nothing, and
// a fresh day whose approval is not cleared does not start.
func TestStaleFreshDay(t *testing.T) {
	x, a := spentBox(t)
	if w := x.b.act(a, "fresh-day", ""); w.Code != http.StatusOK {
		t.Fatalf("fresh day: %d %s", w.Code, w.Body)
	}
	// The day fixed by hand before the wait ends: the approval goes.
	x.writeState(fileTraffic, string(traffic.NewCounter(time.Now, traffic.Caps{}).Save()))
	x.d.Close()
	x.fail(fileFresh, true)
	if _, err := x.open(); err == nil {
		t.Fatal("started with a stale approval it could not erase")
	}
	x.fail(fileFresh, false)
	x.start()
	if x.d.net.spent || x.readState(fileFresh) != "{}" {
		t.Fatalf("a stale approval beside a readable day was kept: %s", x.readState(fileFresh))
	}
	x.writeState(fileTraffic, "{}")
	x.restart()
	x.advance(time.Duration(policy.Wait) * time.Millisecond)
	if !x.d.net.spent {
		t.Fatal("a later unreadable day started afresh with no tap")
	}

	// An approval for another unreadable day starts nothing.
	if w := x.b.act(a, "fresh-day", ""); w.Code != http.StatusOK {
		t.Fatalf("fresh day: %d %s", w.Code, w.Body)
	}
	x.writeState(fileTraffic, `{"day":0}`)
	x.restart()
	x.advance(time.Duration(policy.Wait) * time.Millisecond)
	if !x.d.net.spent || x.d.net.freshDue != 0 || !strings.Contains(x.logText(), "approved for another unreadable day") {
		t.Fatal("an approval for another day was taken")
	}

	// A fresh day whose approval cannot be cleared does not start, and
	// starts at the tick after it clears.
	if w := x.b.act(a, "fresh-day", ""); w.Code != http.StatusOK {
		t.Fatalf("fresh day: %d %s", w.Code, w.Body)
	}
	x.fail(fileFresh, true)
	x.advance(time.Duration(policy.Wait) * time.Millisecond)
	if !x.d.net.spent || !strings.Contains(x.logText(), "not cleared, the fresh day tried again") {
		t.Fatal("a fresh day started with its approval still on disk")
	}
	x.fail(fileFresh, false)
	x.advance(time.Second)
	if x.d.net.spent || x.readState(fileFresh) != "{}" {
		t.Fatal("the fresh day did not start once its approval cleared")
	}
	x.writeState(fileTraffic, "{}")
	x.restart()
	x.advance(time.Duration(policy.Wait) * time.Millisecond)
	if !x.d.net.spent {
		t.Fatal("a spent approval started a later unreadable day")
	}
}
