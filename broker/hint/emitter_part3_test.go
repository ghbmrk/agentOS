package hint

import (
	"testing"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func TestOSS1RestartKeepsState(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hints.jsonl")
	log, err := OpenFileLog(path)
	if err != nil {
		t.Fatal(err)
	}
	r := newRig(t, Config{Log: log, Policy: map[string]Mode{"security": Ask}})
	emit(t, r.e, good())
	ask := emit(t, r.e, vuln)
	r.cfg.Log, err = OpenFileLog(path)
	if err != nil {
		t.Fatal(err)
	}
	r.restart()
	if res := emit(t, r.e, good()); res.Outcome != Duplicate {
		t.Fatalf("after restart: %s", res.Outcome)
	}
	if p := r.e.Pending(); len(p) != 1 || p[0].ID != ask.ID {
		t.Fatalf("pending after restart %+v", p)
	}
	if err := r.nextRelease(); err != nil {
		t.Fatal(err)
	}
	if got := r.out.all(); len(got) != 1 || got[0] != canon(t, good()) {
		t.Fatalf("sent %v", got)
	}
}

// TestOSS1LoggedBeforeSent: the batch's Forwarded record exists before
// the outbox is called, so nothing crosses unlogged. A failed send is
// logged and the same set is resent for the same day at the next release,
// also after a restart, ahead of hints queued since.
func TestOSS1LoggedBeforeSent(t *testing.T) {
	r := newRig(t, Config{})
	emit(t, r.e, good())
	emit(t, r.e, vuln)
	var refs int
	r.out.onSend = func() {
		refs = 0
		for _, rec := range records(t, r.log) {
			if rec.Outcome == Forwarded {
				refs += len(rec.Refs)
			}
		}
	}
	r.out.fail = errors.New("down")
	if err := r.nextRelease(); err == nil {
		t.Fatal("release with failing outbox succeeded")
	}
	if refs != 2 {
		t.Fatalf("log had %d forwarded hints when the outbox was called", refs)
	}
	emit(t, r.e, skill("email")) // queued after the failed batch
	r.out.fail = nil
	r.restart()
	r.now = r.now.Add(24 * time.Hour)
	if err := r.e.Release(); err != nil {
		t.Fatal(err)
	}
	if len(r.out.batches) != 1 || len(r.out.batches[0]) != 2 || contains(r.out.batches[0], canon(t, skill("email"))) || r.out.days[0] != "2026-10-06" {
		t.Fatalf("retry sent %v for %v", r.out.batches, r.out.days)
	}
}

// TestOSS5CrashBetweenSendAndCommit: a batch the outbox took but whose Sent
// record was never written is resent after a restart, the same set for the
// same day, so the outbox's idempotent Send can drop the repeat; a vuln
// hint in it is never lost. Then normal batches resume.
func TestOSS5CrashBetweenSendAndCommit(t *testing.T) {
	log := &failSent{}
	r := newRig(t, Config{Log: log})
	emit(t, r.e, vuln)
	emit(t, r.e, good())
	if err := r.nextRelease(); err == nil {
		t.Fatal("commit failure not reported")
	}
	r.cfg.Log = &log.MemLog // the restarted box writes normally
	r.restart()
	emit(t, r.e, skill("email"))
	r.now = r.now.Add(time.Hour)
	if err := r.e.Release(); err != nil {
		t.Fatal(err)
	}
	if len(r.out.batches) != 2 || r.out.days[0] != r.out.days[1] || strings.Join(r.out.batches[0], "|") != strings.Join(r.out.batches[1], "|") {
		t.Fatalf("resend %v for %v", r.out.batches, r.out.days)
	}
	if err := r.nextRelease(); err != nil {
		t.Fatal(err)
	}
	if len(r.out.batches) != 3 || r.out.batches[2][0] != canon(t, skill("email")) {
		t.Fatalf("next batch %v", r.out.batches)
	}
	var sent int
	for _, rec := range records(t, r.log) {
		if rec.Outcome == Sent {
			sent++
		}
	}
	if sent != 2 {
		t.Fatalf("%d Sent records", sent)
	}
}

// TestOSS7AsksBoundedAndExpire: open asks are bounded, and an ask the
// owner has not answered within DedupeDays expires as declined.
func TestOSS7AsksBoundedAndExpire(t *testing.T) {
	r := newRig(t, Config{Policy: map[string]Mode{"skills": Ask}, MaxPending: 2})
	emit(t, r.e, skill("calendar"))
	emit(t, r.e, skill("email"))
	if res := emit(t, r.e, skill("notes")); res.Outcome != OverLimit {
		t.Fatalf("third ask: %s", res.Outcome)
	}
	r.now = day0.Add(7 * 24 * time.Hour)
	if res := emit(t, r.e, skill("notes")); res.Outcome != Asked {
		t.Fatalf("after expiry: %s", res.Outcome)
	}
	if p := r.e.Pending(); len(p) != 1 {
		t.Fatalf("pending %+v", p)
	}
	var expired int
	for _, rec := range records(t, r.log) {
		if rec.Outcome == Expired {
			expired++
		}
	}
	if expired != 2 {
		t.Fatalf("%d expired", expired)
	}
	r.restart()
	if p := r.e.Pending(); len(p) != 1 {
		t.Fatalf("pending after restart %+v", p)
	}
}

// TestOSS1TornLogTail: a log whose last line was cut off by a crash mid-write
// opens with that line removed (nothing it described happened, since a
// record is written before its effect) and a note of the repair.
func TestOSS1TornLogTail(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hints.jsonl")
	l, err := OpenFileLog(path)
	if err != nil {
		t.Fatal(err)
	}
	l.Append(Record{Seq: 1, Day: "2026-10-05", Outcome: Refused})
	f, _ := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600)
	f.WriteString(`{"seq":2,"day":"2026-10-0`)
	f.Close()
	l2, err := OpenFileLog(path)
	if err != nil {
		t.Fatal(err)
	}
	if !l2.Repaired() {
		t.Fatal("repair not reported")
	}
	if err := l2.Append(Record{Seq: 2, Day: "2026-10-05", Outcome: Refused}); err != nil {
		t.Fatal(err)
	}
	if rs := records(t, l2); len(rs) != 2 || rs[1].Seq != 2 {
		t.Fatalf("records %+v", rs)
	}
	// Damage before the last line is not a torn write; it still fails.
	os.WriteFile(path, []byte("{bad\n{\"seq\":1}\n"), 0o600)
	if _, err := OpenFileLog(path); err == nil {
		t.Fatal("corrupt middle line accepted")
	}
}
