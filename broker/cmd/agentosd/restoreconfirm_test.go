package main

// REQ: CAP-3, A8

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/modem"
	"github.com/ghbmrk/agentos/broker/recovery"
)

// heldDates are the dates of a hand-written question: far apart, oldest
// first, the answer at index 2 unless a test says otherwise.
var heldDates = []string{"2026-01-10", "2026-03-14", "2026-05-20", "2026-08-01"}

// The canary stands in for a forgotten goal in the restored log the
// question carries; no text to the owner may hold it.
const heldCanary = "synthetic-goal-canary-held"

// heldFixture is recovery's question format (TestTheConfirmFixtureIs-
// TheWritersFormat): an unanchored restore whose log holds heldCanary.
func heldFixture(t *testing.T) map[string]json.RawMessage {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "recovery", "testdata", "confirm-v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	var q map[string]json.RawMessage
	if err := json.Unmarshal(raw, &q); err != nil {
		t.Fatal(err)
	}
	return q
}

// writeHeld leaves a held restore in dir as recovery's restore does: the
// marker and the question beside it, from the fixture.
func writeHeld(t *testing.T, dir, reason string, answer int, newer []recovery.BackupEntry) {
	t.Helper()
	q := heldFixture(t)
	set := func(k string, v any) {
		b, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		q[k] = b
	}
	set("reason", reason)
	set("dates", heldDates)
	set("answer", answer)
	if !strings.Contains(string(q["log"]), heldCanary) {
		t.Fatal("the fixture's log lacks the canary")
	}
	if reason == recovery.PendingMissing {
		delete(q, "log")
	}
	delete(q, "newer")
	if newer != nil {
		set("newer", newer)
	}
	b, err := json.Marshal(q)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, forgetLogFile)
	if err := os.WriteFile(path+recovery.ConfirmSuffix, b, 0o600); err != nil {
		t.Fatal(err)
	}
	marker := reason + "\n" + recovery.PendingNotice(reason) + "\n"
	if err := os.WriteFile(path+recovery.PendingSuffix, []byte(marker), 0o600); err != nil {
		t.Fatal(err)
	}
}

func heldCases() []struct{ name, reason string } {
	return []struct{ name, reason string }{{"unanchored", recovery.PendingUnanchored}, {"missing", recovery.PendingMissing}}
}

// answerFor is the right answer's index in each case: the restored log's
// last forget, or "never" with no log.
func answerFor(reason string) int {
	if reason == recovery.PendingMissing {
		return len(heldDates) + 1
	}
	return 2
}

func mustHeldText(t *testing.T, dir string) string {
	t.Helper()
	text, ok, err := heldText(dir)
	if err != nil || !ok {
		t.Fatalf("held text: %v %v", ok, err)
	}
	return text
}

// checkOwnerText holds a text to CH-12: GSM-7, never past three segments,
// and it ends with the replies the owner can give.
func checkOwnerText(t *testing.T, text string) {
	t.Helper()
	n, gsm7 := modem.Segments(text)
	if !gsm7 || n > 2 { // CH-12 targets one and caps at three; six choices need two
		t.Fatalf("text takes %d segments (gsm7 %v):\n%s", n, gsm7, text)
	}
	if strings.Contains(text, heldCanary) {
		t.Fatalf("text holds forgotten content:\n%s", text)
	}
}

// Each case has its own header that names it, so the owner knows why the
// restore waits.
func TestHeldRestoreHeaderNamesItsCase(t *testing.T) {
	heads := map[string]string{}
	for _, c := range heldCases() {
		dir := t.TempDir()
		writeHeld(t, dir, c.reason, answerFor(c.reason), nil)
		text := mustHeldText(t, dir)
		checkOwnerText(t, text)
		head, _, _ := strings.Cut(text, "\n")
		heads[c.name] = head
	}
	if !strings.Contains(heads["unanchored"], "new PC") || !strings.Contains(heads["unanchored"], "can't check") {
		t.Fatalf("unanchored header: %q", heads["unanchored"])
	}
	if !strings.Contains(heads["missing"], "before") || !strings.Contains(heads["missing"], "forget list") {
		t.Fatalf("missing-log header: %q", heads["missing"])
	}
	if heads["unanchored"] == heads["missing"] {
		t.Fatal("both cases share a header")
	}
}

// The dates come in order, one format, dates only; "later than all of
// these" and "never" are always the last two choices, in that order,
// whether or not they can be right.
func TestHeldRestoreListsDatesThenLaterThenNever(t *testing.T) {
	for _, c := range heldCases() {
		for _, answer := range []int{0, 3, answerFor(c.reason)} {
			if c.reason == recovery.PendingMissing && answer != answerFor(c.reason) {
				continue // a missing log's answer is always "never"
			}
			dir := t.TempDir()
			writeHeld(t, dir, c.reason, answer, nil)
			text := mustHeldText(t, dir)
			checkOwnerText(t, text)
			lines := strings.Split(text, "\n")
			var opts []string
			for _, l := range lines {
				if len(l) > 2 && l[1] == ' ' && l[0] >= 'A' && l[0] <= 'F' {
					opts = append(opts, l)
				}
			}
			want := []string{"A 10 Jan 2026", "B 14 Mar 2026", "C 20 May 2026", "D 1 Aug 2026", "E Later than all of these", "F Never"}
			if strings.Join(opts, "|") != strings.Join(want, "|") {
				t.Fatalf("%s, answer %d: options\n%s", c.name, answer, text)
			}
			if !strings.HasSuffix(text, "Reply A, B, C, D, E or F.") {
				t.Fatalf("%s: text does not end with the replies:\n%s", c.name, text)
			}
		}
	}
}

// "Later than all of these" is offered in each case and is wrong in each:
// the real date is always among the dates.
func TestLaterIsOfferedAndKeepsTheHold(t *testing.T) {
	for _, c := range heldCases() {
		t.Run(c.name, func(t *testing.T) {
			dir := t.TempDir()
			writeHeld(t, dir, c.reason, answerFor(c.reason), nil)
			if !strings.Contains(mustHeldText(t, dir), "\nE Later than all of these\n") {
				t.Fatal("no later option")
			}
			reply, released, err := answerHeld(dir, "e")
			if err != nil || released || restoreHold(dir) == nil {
				t.Fatalf("later released the restore: %v %v", released, err)
			}
			checkOwnerText(t, reply)
			if !strings.Contains(reply, "older than your last forget") {
				t.Fatalf("reply: %q", reply)
			}
		})
	}
}

// "Never" is offered in each case: right for a backup with no log, wrong
// for one whose log holds a forget.
func TestNeverIsOfferedRightOnlyWithNoLog(t *testing.T) {
	for _, c := range heldCases() {
		t.Run(c.name, func(t *testing.T) {
			dir := t.TempDir()
			writeHeld(t, dir, c.reason, answerFor(c.reason), nil)
			if !strings.Contains(mustHeldText(t, dir), "\nF Never\n") {
				t.Fatal("no never option")
			}
			reply, released, err := answerHeld(dir, "F")
			if err != nil {
				t.Fatal(err)
			}
			checkOwnerText(t, reply)
			if want := c.reason == recovery.PendingMissing; released != want || (restoreHold(dir) == nil) != want {
				t.Fatalf("never released %v, want %v: %q", released, want, reply)
			}
		})
	}
}

// A wrong date keeps the restore held, says why, and offers the newest
// newer backup the restore found; a later guess changes nothing.
func TestAWrongReplyKeepsTheHoldAndOffersANewerBackup(t *testing.T) {
	newer := []recovery.BackupEntry{{Destination: "Cloud box", Created: time.Date(2026, 9, 30, 9, 0, 0, 0, time.UTC), Verified: true}}
	for _, c := range heldCases() {
		t.Run(c.name, func(t *testing.T) {
			dir := t.TempDir()
			writeHeld(t, dir, c.reason, answerFor(c.reason), newer)
			reply, released, err := answerHeld(dir, "  a. ")
			if err != nil || released || restoreHold(dir) == nil {
				t.Fatalf("a wrong date released it: %v %v", released, err)
			}
			checkOwnerText(t, reply)
			if !strings.Contains(reply, "older than your last forget") || !strings.Contains(reply, "Cloud box") ||
				!strings.Contains(reply, newer[0].Created.Local().Format("2 Jan 2006")) {
				t.Fatalf("reply: %q", reply)
			}
			right := string(rune('A' + answerFor(c.reason)))
			if _, released, err := answerHeld(dir, right); err != nil || released || restoreHold(dir) == nil {
				t.Fatalf("a second guess released it: %v %v", released, err)
			}
		})
	}
	dir := t.TempDir()
	writeHeld(t, dir, recovery.PendingUnanchored, 2, nil)
	reply, _, err := answerHeld(dir, "B")
	if err != nil || !strings.Contains(reply, "newer backup") {
		t.Fatalf("with no newer backup: %q %v", reply, err)
	}
}

// A reply that is no choice changes nothing and asks again.
func TestAnUnclearReplyAsksAgain(t *testing.T) {
	dir := t.TempDir()
	writeHeld(t, dir, recovery.PendingUnanchored, 2, nil)
	for _, msg := range []string{"", "yes", "G", "C D", "2"} {
		reply, released, err := answerHeld(dir, msg)
		if err != nil || released || restoreHold(dir) == nil {
			t.Fatalf("%q: %v %v", msg, released, err)
		}
		if !strings.HasSuffix(reply, "Reply A, B, C, D, E or F.") {
			t.Fatalf("%q: reply %q", msg, reply)
		}
	}
	if _, released, err := answerHeld(dir, "c"); err != nil || !released {
		t.Fatalf("the right answer after unclear replies: %v %v", released, err)
	}
}

// The right letter lifts the hold and hands the log on for the replay.
func TestTheRightReplyLiftsTheHold(t *testing.T) {
	for _, c := range heldCases() {
		t.Run(c.name, func(t *testing.T) {
			dir := t.TempDir()
			writeHeld(t, dir, c.reason, answerFor(c.reason), nil)
			reply, released, err := answerHeld(dir, "Reply "+string(rune('a'+answerFor(c.reason))))
			if err != nil || !released || restoreHold(dir) != nil {
				t.Fatalf("released %v err %v hold %v", released, err, restoreHold(dir))
			}
			checkOwnerText(t, reply)
			if _, ok, err := heldText(dir); ok || err != nil {
				t.Fatalf("a question remains: %v %v", ok, err)
			}
			_, err = os.Stat(filepath.Join(dir, forgetLogFile))
			if has := err == nil; has != (c.reason == recovery.PendingUnanchored) {
				t.Fatalf("log handed on: %v", has)
			}
		})
	}
}

// A restore held for a reason the owner cannot confirm asks nothing.
func TestARolledBackHoldAsksNothing(t *testing.T) {
	dir := t.TempDir()
	marker := recovery.PendingRolledBack + "\n" + recovery.PendingNotice(recovery.PendingRolledBack) + "\n"
	if err := os.WriteFile(filepath.Join(dir, forgetLogFile+recovery.PendingSuffix), []byte(marker), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, ok, err := heldText(dir); ok || err != nil {
		t.Fatalf("question for a rolled-back restore: %v %v", ok, err)
	}
	if _, released, err := answerHeld(dir, "A"); released || err == nil {
		t.Fatalf("answer taken: %v %v", released, err)
	}
}

// agentosd reads recovery's files without importing it: the names it
// uses are recovery's.
func TestHeldNamesAreRecoverys(t *testing.T) {
	if confirmSuffix != recovery.ConfirmSuffix || pendingUnanchored != recovery.PendingUnanchored ||
		pendingMissing != recovery.PendingMissing || ".pending" != recovery.PendingSuffix {
		t.Fatal("agentosd's names for the held restore drifted from recovery's")
	}
	dir := t.TempDir()
	q := heldFixture(t)
	b, _ := json.Marshal(q)
	if err := os.WriteFile(filepath.Join(dir, forgetLogFile+recovery.ConfirmSuffix), b, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, forgetLogFile+recovery.PendingSuffix), []byte(recovery.PendingUnanchored+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, released, err := answerHeld(dir, "C"); err != nil || !released {
		t.Fatalf("the fixture's right answer: %v %v", released, err)
	}
	got, err := readRestoredForgets(dir)
	if err != nil || len(got) != 1 || got[0].Goal != heldCanary {
		t.Fatalf("handed on %+v %v", got, err)
	}
}

// A question that does not read keeps the restore held and asks nothing.
func TestAnUnreadableQuestionKeepsTheHold(t *testing.T) {
	for _, body := range []string{"{", `{"format":"x"}`,
		`{"format":"agentos-restore-confirm-v1","reason":"forget-log-forged","dates":["2026-01-01"],"answer":0}`,
		`{"format":"agentos-restore-confirm-v1","reason":"forget-log-missing","dates":["2026-02-01","2026-01-01"],"answer":0}`,
		`{"format":"agentos-restore-confirm-v1","reason":"forget-log-missing","dates":["2026-01-01"],"answer":1}`,
		`{"format":"agentos-restore-confirm-v1","reason":"forget-log-missing","dates":["2026-01-01"],"answer":7}`,
		`{"format":"agentos-restore-confirm-v1","reason":"forget-log-missing","dates":["2026-01-01"],"answer":2,"extra":1}`,
	} {
		dir := t.TempDir()
		writeHeld(t, dir, recovery.PendingMissing, 5, nil)
		if err := os.WriteFile(filepath.Join(dir, forgetLogFile+recovery.ConfirmSuffix), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, ok, err := heldText(dir); ok || err == nil {
			t.Fatalf("%s read: %v %v", body, ok, err)
		}
		for _, msg := range []string{"A", "B", "C"} {
			if _, released, err := answerHeld(dir, msg); released || err == nil || restoreHold(dir) == nil {
				t.Fatalf("%s: %q released %v %v", body, msg, released, err)
			}
		}
	}
}
