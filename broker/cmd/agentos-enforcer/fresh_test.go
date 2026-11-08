package main

// REQ: NET-2, NET-4

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/enforcer/policy"
	"github.com/ghbmrk/agentos/broker/enforcer/traffic"
)

// The fresh byte-cap day (#5013, ASSUMPTIONS ENF-l-19): the owner's
// approval, its cancel and the start are each one write of traffic.json,
// and the run takes a saved start up only by starting again.

const torn = `{"day":20833,"bytes":{"203.0.113.5":` // a day cut short: traffic.ErrState

var wait = time.Duration(policy.Wait) * time.Millisecond

// spentBox is a capped box whose saved day did not read back, and its
// owner.
func spentBox(t *testing.T) (*box, policy.Document, *authenticator) {
	t.Helper()
	x, doc, a := capped(t)
	x.unreadable()
	x.setListing(listing(t, x, doc, 9, 0))
	return x, doc, a
}

// unreadable stops the daemon, puts a torn day in traffic.json and
// starts it again.
func (x *box) unreadable() {
	x.t.Helper()
	x.d.Close()
	if err := os.WriteFile(filepath.Join(x.dir, fileTraffic), []byte(torn), 0o600); err != nil {
		x.t.Fatal(err)
	}
	x.start()
	if !x.d.net.spent {
		x.t.Fatal("fixture: the torn day was not taken as spent")
	}
}

// day is traffic.json: the fresh-day record it holds, if any, and whether
// it reads back as a day.
func (x *box) day() (rec *freshStep, readsBack bool, raw string) {
	x.t.Helper()
	b, err := os.ReadFile(filepath.Join(x.dir, fileTraffic))
	if err != nil {
		x.t.Fatal(err)
	}
	var r freshRecord
	if json.Unmarshal(b, &r) == nil {
		rec = r.FreshDay
	}
	_, err = traffic.Restore(time.Now, traffic.Caps{}, b)
	return rec, err == nil, string(b)
}

// stopped reports whether the daemon asked its loop to stop for a saved
// fresh day.
func (x *box) stopped() bool {
	select {
	case err := <-x.d.freshStop:
		return errors.Is(err, errFreshDay)
	default:
		return false
	}
}

func (x *box) afterSave(f func(path string) error) {
	x.mu.Lock()
	x.after = f
	x.mu.Unlock()
}

// onTraffic fails only traffic.json's Saves after its new file is in
// place, first writing put there when it is not nil (a third content).
func onTraffic(put []byte) func(string) error {
	return func(path string) error {
		if filepath.Base(path) != fileTraffic {
			return nil
		}
		if put != nil {
			if err := os.WriteFile(path, put, 0o600); err != nil {
				return err
			}
		}
		return errors.New("sync dir: input/output error")
	}
}

// TestByteCapStateUnreadableFreshDay is TestByteCapStateUnreadable's page
// step (#5013, NET-2 Byte caps, D-255): the page shows the spent day and
// why, and the owner's tap starts it afresh after policy.Wait, cancellable
// meanwhile. The approval survives a restart; the start saves a day whose
// first reading is the running table as it was, so the bytes the spent
// drop dropped never count (Potency R1 on #5101), and the daemon stops to
// take it up.
func TestByteCapStateUnreadableFreshDay(t *testing.T) {
	x, doc, a := spentBox(t)
	home := x.b.do(http.MethodGet, "/", nil).Body.String()
	if !strings.Contains(home, "could not read its record of today's bytes") || !strings.Contains(home, `data-action="fresh-day"`) {
		t.Fatalf("home does not show the spent day and its step:\n%s", home)
	}
	if w := x.b.do(http.MethodPost, "/challenge", map[string]string{"action": "cancel-fresh", "target": ""}); w.Code != http.StatusNotFound {
		t.Fatalf("a cancel with nothing waiting: %d", w.Code)
	}
	x.setListing(listing(t, x, doc, 9, 500)) // the running table: 500 bytes the spent drop dropped
	if w := x.b.act(newAuthenticator(t), "fresh-day", ""); w.Code != http.StatusForbidden {
		t.Fatalf("a stranger's fresh day: %d", w.Code)
	}
	due := x.nowMS() + policy.Wait
	w := x.b.act(a, "fresh-day", "")
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"saved":true`) {
		t.Fatalf("fresh day: %d %s", w.Code, w.Body)
	}
	if rec, back, _ := x.day(); rec == nil || rec.Due != due || back {
		t.Fatalf("the approval is not the one record on disk: %+v reads back %v", rec, back)
	}
	home = x.b.do(http.MethodGet, "/", nil).Body.String()
	waiting := home[strings.Index(home, "<h2>Waiting to apply</h2>"):]
	if !strings.Contains(waiting, "A fresh byte-cap day starts at") || !strings.Contains(waiting, `data-action="cancel-fresh"`) || strings.Contains(home, `data-action="fresh-day"`) {
		t.Fatalf("the waiting fresh day is not under Waiting to apply:\n%s", home)
	}
	if w := x.b.do(http.MethodPost, "/challenge", map[string]string{"action": "fresh-day", "target": ""}); w.Code != http.StatusConflict {
		t.Fatalf("a second fresh day: %d", w.Code)
	}
	x.restart()
	if x.d.fresh.due != due || !x.d.net.spent {
		t.Fatalf("a restart lost the wait: due %d", x.d.fresh.due)
	}
	x.advance(wait - 2*time.Second)
	if _, back, _ := x.day(); back || x.stopped() {
		t.Fatal("the fresh day started before its wait")
	}
	x.advance(2 * time.Second)
	if _, back, _ := x.day(); !back || !x.stopped() {
		t.Fatal("the fresh day did not start when its wait ended, or the daemon did not stop to take it up")
	}
	if !x.d.net.spent {
		t.Fatal("the run took up the fresh day in place")
	}
	if w := x.b.do(http.MethodPost, "/challenge", map[string]string{"action": "cancel-fresh", "target": ""}); w.Code != http.StatusConflict ||
		!strings.Contains(w.Body.String(), "starting") {
		t.Fatalf("a cancel after the start: %d %s", w.Code, w.Body)
	}
	if _, err := (pageCaps{x.d}).CancelFresh(); !errors.Is(err, errStarting) {
		t.Fatalf("a cancel after the start: %v", err)
	}
	x.restart()
	if x.d.net.spent {
		t.Fatal("the fresh day was not taken up at the restart")
	}
	x.setListing(listing(t, x, doc, 9, 530))
	x.advance(readEvery)
	c, err := x.d.counts()
	if err != nil || len(c.Groups) != 1 || c.Groups[0].Count != 30 {
		t.Fatalf("the fresh day's first reading is not the zero: %+v %v", c, err)
	}
	if strings.Contains(x.b.do(http.MethodGet, "/", nil).Body.String(), "<h2>Byte caps</h2>") {
		t.Fatal("home still shows the spent day")
	}
}

// TestFreshDayCancel: a cancel is one write of a cancelled record. Nothing
// starts when the wait would have ended, or after a restart, and the
// owner's next approval needs a new tap and a new wait.
func TestFreshDayCancel(t *testing.T) {
	x, _, a := spentBox(t)
	if w := x.b.act(a, "fresh-day", ""); w.Code != http.StatusOK {
		t.Fatal(w.Code)
	}
	x.advance(wait / 2)
	w := x.b.act(a, "cancel-fresh", "")
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"saved":true`) {
		t.Fatalf("cancel: %d %s", w.Code, w.Body)
	}
	if rec, back, _ := x.day(); rec == nil || rec.Due != 0 || back {
		t.Fatalf("the cancel is not on disk: %+v", rec)
	}
	x.advance(wait)
	x.restart()
	x.advance(wait)
	if _, back, _ := x.day(); back || x.stopped() || x.d.fresh.due != 0 || !x.d.net.spent {
		t.Fatal("a cancelled fresh day started")
	}
	if !strings.Contains(x.b.do(http.MethodGet, "/", nil).Body.String(), `data-action="fresh-day"`) {
		t.Fatal("after a cancel the page does not offer a new fresh day")
	}
}

// TestFreshDayCancelRace (Security 6722053717 point 1): a cancel and the
// start on two goroutines under -race. Either the cancel answers saved
// and nothing starts, or it answers that the day is starting and the day
// on disk is the fresh one; a restart agrees with the answer each time.
func TestFreshDayCancelRace(t *testing.T) {
	x, _, _ := spentBox(t)
	won := 0
	for i := range 12 {
		if _, _, err := (pageCaps{x.d}).Fresh(x.nowMS()); err != nil {
			t.Fatal(err)
		}
		x.mu.Lock()
		x.now = x.now.Add(wait)
		x.mu.Unlock()
		var cerr error
		var wg sync.WaitGroup
		wg.Add(2)
		start := make(chan struct{})
		go func() { defer wg.Done(); <-start; x.d.tickFresh(context.Background(), x.d.dp.Now()) }()
		go func() { defer wg.Done(); <-start; _, cerr = (pageCaps{x.d}).CancelFresh() }()
		close(start)
		wg.Wait()
		x.restart()
		x.advance(time.Second)
		switch {
		case cerr == nil && (!x.d.net.spent || x.stopped()):
			t.Fatalf("round %d: the cancel answered done, yet the fresh day started", i)
		case errors.Is(cerr, errStarting) && x.d.net.spent:
			t.Fatalf("round %d: the cancel answered that it lost, yet no fresh day is on disk", i)
		case cerr != nil && !errors.Is(cerr, errStarting):
			t.Fatalf("round %d: %v", i, cerr)
		}
		if !x.d.net.spent {
			won++
			x.unreadable()
		}
	}
	t.Logf("the start won %d of 12 rounds", won)
}

// TestFreshDayStartFails: a start whose save fails is committed for the
// run: every cap stays spent, a cancel is refused, the page says the
// start is retried, the failure is logged once, and the next save that
// returns starts it. A crash meanwhile keeps the tapped and waited
// approval, which starts at the first tick.
func TestFreshDayStartFails(t *testing.T) {
	x, _, a := spentBox(t)
	if w := x.b.act(a, "fresh-day", ""); w.Code != http.StatusOK {
		t.Fatal(w.Code)
	}
	x.fail(fileTraffic, true)
	x.advance(wait)
	x.advance(time.Second)
	if _, back, _ := x.day(); back || x.stopped() || !x.d.net.spent {
		t.Fatal("a start that was not saved was taken up")
	}
	if _, err := (pageCaps{x.d}).CancelFresh(); !errors.Is(err, errStarting) {
		t.Fatalf("a cancel during a failing start: %v", err)
	}
	if !strings.Contains(x.b.do(http.MethodGet, "/", nil).Body.String(), "could not be saved. The enforcer tries again every second") {
		t.Fatal("the page does not say the start is being retried")
	}
	if n := strings.Count(x.logText(), "the fresh day was not saved"); n != 1 {
		t.Fatalf("the failing start was logged %d times, want once", n)
	}
	x.restart() // a crash: the approval is still the record on disk
	if rec, _, _ := x.day(); rec == nil || x.d.fresh.due == 0 {
		t.Fatal("the tapped and waited approval did not survive the crash")
	}
	x.fail(fileTraffic, false)
	x.advance(time.Second)
	if _, back, _ := x.day(); !back || !x.stopped() {
		t.Fatal("the approval whose wait passed did not start at the first tick")
	}
}

// TestFreshDayAfterRenameFaults (Security 6722588813, 6722774573): each
// step's Save errs after its new file is in place, or after a third
// content took its place (a read of it would fail or show neither). The
// answer is never a plain done: the step is in force for the run, the
// page says the disk has not confirmed it, and it is saved again until a
// Save returns nil. The start is committed whatever the file holds.
func TestFreshDayAfterRenameFaults(t *testing.T) {
	t.Run("approve", func(t *testing.T) {
		x, _, a := spentBox(t)
		x.afterSave(onTraffic(nil))
		w := x.b.act(a, "fresh-day", "")
		if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"saved":false`) || x.d.fresh.due == 0 {
			t.Fatalf("an approval not confirmed: %d %s", w.Code, w.Body)
		}
		if !strings.Contains(x.b.do(http.MethodGet, "/", nil).Body.String(), "the disk has not confirmed it yet") {
			t.Fatal("the page does not say the approval is not confirmed")
		}
		x.advance(time.Second)
		if x.d.fresh.unsaved == nil {
			t.Fatal("a save that erred again confirmed the approval")
		}
		x.afterSave(nil)
		x.advance(time.Second)
		if x.d.fresh.unsaved != nil {
			t.Fatal("the approval was not saved again")
		}
	})
	t.Run("cancel", func(t *testing.T) {
		x, _, a := spentBox(t)
		if w := x.b.act(a, "fresh-day", ""); w.Code != http.StatusOK {
			t.Fatal(w.Code)
		}
		approval := freshBytes(x.d.fresh.due)
		x.afterSave(onTraffic(approval)) // the rename rolled back: the approval is what the file holds
		w := x.b.act(a, "cancel-fresh", "")
		if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"saved":false`) {
			t.Fatalf("a cancel not confirmed answered: %d %s", w.Code, w.Body)
		}
		x.advance(wait)
		if x.stopped() || x.d.fresh.starting {
			t.Fatal("a cancel in force for the run did not stop the start")
		}
		x.afterSave(nil)
		x.advance(time.Second)
		if rec, _, _ := x.day(); rec == nil || rec.Due != 0 || x.d.fresh.unsaved != nil {
			t.Fatal("the cancel was not saved again")
		}
		x.restart()
		x.advance(time.Second)
		if !x.d.net.spent || x.stopped() {
			t.Fatal("a cancelled fresh day started after a restart")
		}
	})
	for name, put := range map[string][]byte{"start": nil, "start, third content": []byte(`{"garbage":`)} {
		t.Run(name, func(t *testing.T) {
			x, _, a := spentBox(t)
			if w := x.b.act(a, "fresh-day", ""); w.Code != http.StatusOK {
				t.Fatal(w.Code)
			}
			x.afterSave(onTraffic(put))
			x.advance(wait)
			if x.stopped() || !x.d.fresh.starting {
				t.Fatal("a start not confirmed was taken up, or not kept committed")
			}
			if _, err := (pageCaps{x.d}).CancelFresh(); !errors.Is(err, errStarting) {
				t.Fatalf("a cancel while the start is unconfirmed: %v", err)
			}
			x.afterSave(nil)
			x.advance(time.Second)
			if _, back, _ := x.day(); !back || !x.stopped() {
				t.Fatal("the start was not saved again")
			}
		})
	}
}

// TestFreshDayRecordOnlyInItsDay (L3 6722072364 point 1, Security
// 6722053717 blocker): an approval lives only inside the spent day it was
// approved for. Once a day that reads back replaces it, a later
// unreadable day starts nothing without a new tap and wait; a file left
// from the old two-file shape is not read.
func TestFreshDayRecordOnlyInItsDay(t *testing.T) {
	x, _, a := spentBox(t)
	if w := x.b.act(a, "fresh-day", ""); w.Code != http.StatusOK {
		t.Fatal(w.Code)
	}
	day := traffic.NewCounter(time.Now, traffic.Caps{}).Save()
	if err := os.WriteFile(filepath.Join(x.dir, fileTraffic), day, 0o600); err != nil { // the owner fixed it by hand
		t.Fatal(err)
	}
	stale := []byte(`{"due":1800000000000}`)
	if err := os.WriteFile(filepath.Join(x.dir, "fresh-day.json"), stale, 0o600); err != nil {
		t.Fatal(err)
	}
	x.restart()
	if x.d.net.spent {
		t.Fatal("fixture: the hand-made day does not read back")
	}
	x.unreadable()
	x.advance(2 * wait)
	if x.d.fresh.due != 0 || x.stopped() {
		t.Fatal("an approval outlived the day it was approved for")
	}
}
