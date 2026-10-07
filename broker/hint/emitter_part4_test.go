package hint

import (
	"testing"
	"bytes"
	"errors"
	"strings"
	"time"
)

func TestOSS1DedupeSevenDays(t *testing.T) {
	r := newRig(t, Config{})
	if r.e.cfg.DailyLimit != 5 || r.e.cfg.EmbargoReserve != 2 || r.e.cfg.DedupeDays != 7 {
		t.Fatalf("defaults %d/%d/%d", r.e.cfg.DailyLimit, r.e.cfg.EmbargoReserve, r.e.cfg.DedupeDays)
	}
	emit(t, r.e, good())
	if err := r.nextRelease(); err != nil || len(r.out.all()) != 1 {
		t.Fatalf("release: %v %v", err, r.out.all())
	}
	r.now = day0.Add(6 * 24 * time.Hour)
	r.restart()
	if res := emit(t, r.e, good()); res.Outcome != Duplicate {
		t.Fatalf("day 6: %s", res.Outcome)
	}
	r.now = day0.Add(7 * 24 * time.Hour)
	if res := emit(t, r.e, good()); res.Outcome != Queued {
		t.Fatalf("day 7: %s", res.Outcome)
	}
}

// TestOSS5ResendIsTheRecordedSet: the resend after a restart is the
// canonical bytes recorded when the batch was formed, so a schema change
// in between (here a new version) cannot alter or empty the set.
func TestOSS5ResendIsTheRecordedSet(t *testing.T) {
	log := &failSent{}
	r := newRig(t, Config{Log: log})
	emit(t, r.e, vuln)
	emit(t, r.e, good())
	r.nextRelease()
	v2, err := Parse(bytes.Replace(publicSchema, []byte(`"version": 1`), []byte(`"version": 2`), 1))
	if err != nil {
		t.Fatal(err)
	}
	r.cfg.Log, r.cfg.Schema = &log.MemLog, v2
	r.restart()
	r.now = r.now.Add(time.Hour)
	if err := r.e.Release(); err != nil {
		t.Fatal(err)
	}
	if len(r.out.batches) != 2 || strings.Join(r.out.batches[0], "|") != strings.Join(r.out.batches[1], "|") || r.out.days[0] != r.out.days[1] {
		t.Fatalf("resend %v for %v", r.out.batches, r.out.days)
	}
}

// TestOSS5CrashBeforeSend: a crash after the Forwarded record but before
// the outbox is called leaves no SendFailed record; the restart still
// resends the batch.
func TestOSS5CrashBeforeSend(t *testing.T) {
	r := newRig(t, Config{})
	emit(t, r.e, vuln)
	r.out.onSend = func() { panic("crash") }
	func() {
		defer func() { recover() }()
		r.nextRelease()
	}()
	r.out.onSend = nil
	for _, rec := range records(t, r.log) {
		if rec.Outcome == SendFailed || rec.Outcome == Sent {
			t.Fatalf("unexpected %s record", rec.Outcome)
		}
	}
	r.restart()
	r.now = r.now.Add(time.Minute)
	if err := r.e.Release(); err != nil {
		t.Fatal(err)
	}
	if got := r.out.all(); len(got) != 1 || got[0] != canon(t, vuln) {
		t.Fatalf("sent %v", got)
	}
}

// TestOSS1SendFailureLoggedOnce: repeated failed retries of one batch log
// one SendFailed record, also across a restart; Pending never lists an
// expired ask.
func TestOSS1SendFailureLoggedOnce(t *testing.T) {
	r := newRig(t, Config{Policy: map[string]Mode{"security": Ask}})
	emit(t, r.e, good())
	ask := emit(t, r.e, vuln)
	r.out.fail = errors.New("down")
	r.nextRelease()
	for i := 0; i < 3; i++ {
		r.now = r.now.Add(time.Hour)
		r.e.Release()
	}
	r.restart()
	r.now = r.now.Add(time.Hour)
	r.e.Release()
	n := 0
	for _, rec := range records(t, r.log) {
		if rec.Outcome == SendFailed {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("%d SendFailed records", n)
	}
	r.now = day0.Add(8 * 24 * time.Hour)
	for _, p := range r.e.Pending() {
		if p.ID == ask.ID {
			t.Fatal("Pending lists an expired ask")
		}
	}
}

// TestOSS5LegacyForwardedWithoutBatch: a Forwarded record written before
// records carried the batch bytes is rebuilt from its Refs, never resent as
// an empty set and committed.
func TestOSS5LegacyForwardedWithoutBatch(t *testing.T) {
	log := &MemLog{}
	log.Append(Record{Seq: 1, Day: "2026-10-05", Outcome: Queued, Category: "security", Kind: vuln.Kind, Fields: vuln.Fields})
	log.Append(Record{Seq: 2, Day: "2026-10-06", Outcome: Forwarded, Refs: []int{1}})
	r := newRig(t, Config{Log: log})
	r.now = time.Date(2026, 10, 6, 0, 0, 0, 0, time.UTC).Add(DefaultReleaseAt)
	if err := r.e.Release(); err != nil {
		t.Fatal(err)
	}
	if got := r.out.all(); len(got) != 1 || got[0] != canon(t, vuln) || r.out.days[0] != "2026-10-06" {
		t.Fatalf("sent %v for %v", got, r.out.days)
	}
}
