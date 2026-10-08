package replay

// REQ: CHG-1, CHG-2, LOOP-5, OP-7

import (
	"encoding/json"
	"testing"

	"github.com/ghbmrk/agentos/broker/change"
	"github.com/ghbmrk/agentos/broker/journal"
)

func resultIntent(id string) journal.Intent {
	return journal.Intent{ID: id, Account: "synthetic-mail", Action: "mail.send", Params: map[string]any{"subject": "hello", "body": "synthetic body"}, Recipients: []string{"sam@example.invalid"}}
}

func attempt(r *recorded, in journal.Intent) {
	if _, err := r.Submit(in); err != nil {
		return
	}
	if _, err := r.Authorize(in.ID); err != nil {
		return
	}
	_, _ = r.Dispatch(in.ID)
}

func TestRecordedObservationsDriveTheDeterministicGrader(t *testing.T) {
	want, _ := change.MailSendExpectation(resultIntent("original"))
	c := change.Case{Class: change.ClassTask, Task: "original", Outcome: change.Accepted, ResultFormat: change.MailSendResultV1, Expect: want}
	for _, tc := range []struct {
		name  string
		state journal.State
		run   func(*recorded)
		pass  bool
	}{
		{"natural reply and right effect", journal.Succeeded, func(r *recorded) { attempt(r, resultIntent("new")) }, true},
		{"no effect", journal.Succeeded, func(*recorded) {}, false},
		{"wrong account", journal.Succeeded, func(r *recorded) { in := resultIntent("new"); in.Account = "wrong"; attempt(r, in) }, false},
		{"wrong params", journal.Succeeded, func(r *recorded) { in := resultIntent("new"); in.Params["body"] = "wrong"; attempt(r, in) }, false},
		{"wrong recipient", journal.Succeeded, func(r *recorded) {
			in := resultIntent("new")
			in.Recipients = []string{"wrong@example.invalid"}
			attempt(r, in)
		}, false},
		{"duplicate", journal.Succeeded, func(r *recorded) { attempt(r, resultIntent("new")); attempt(r, resultIntent("again")) }, false},
		{"idempotent retry", journal.Succeeded, func(r *recorded) { attempt(r, resultIntent("new")); attempt(r, resultIntent("new")) }, true},
		{"conflicting retry", journal.Succeeded, func(r *recorded) {
			attempt(r, resultIntent("new"))
			in := resultIntent("new")
			in.Account = "wrong"
			attempt(r, in)
		}, false},
		{"unknown", journal.OutcomeUnknown, func(r *recorded) { attempt(r, resultIntent("new")) }, false},
		{"failed", journal.NotApplied, func(r *recorded) { attempt(r, resultIntent("new")) }, false},
		{"denied", journal.Denied, func(r *recorded) { attempt(r, resultIntent("new")) }, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := newRecorded([]journal.Status{{Intent: resultIntent("original"), State: tc.state}})
			tc.run(r)
			out, err := r.result([]byte("Done"))
			pass := err == nil && change.ObservedEffectGrader(c, out)
			if pass != tc.pass {
				t.Fatalf("pass=%v err=%v", pass, err)
			}
			if _, err := r.Submit(resultIntent("after-reply")); err == nil {
				t.Fatal("trace reopened after completion")
			}
		})
	}
	// Two recordings cannot make two matching requests count as one effect.
	r := newRecorded([]journal.Status{{Intent: resultIntent("original"), State: journal.Succeeded}, {Intent: resultIntent("original-2"), State: journal.Succeeded}})
	attempt(r, resultIntent("one"))
	attempt(r, resultIntent("two"))
	out, err := r.result([]byte("Done"))
	if err != nil || change.ObservedEffectGrader(c, out) {
		t.Fatal("duplicate recordings masked duplicate effects", err)
	}
	extra := resultIntent("original-extra")
	extra.Params["body"] = "a second recorded message"
	r = newRecorded([]journal.Status{{Intent: resultIntent("original"), State: journal.Succeeded}, {Intent: extra, State: journal.Succeeded}})
	attempt(r, resultIntent("one"))
	extra.ID = "extra"
	attempt(r, extra)
	out, err = r.result([]byte("Done"))
	if err != nil || change.ObservedEffectGrader(c, out) {
		t.Fatal("an extra recorded effect passed the single-effect contract", err)
	}
}

func TestRecordedRejectedEffectCannotPassByChangingReply(t *testing.T) {
	expect, _ := change.MailSendExpectation(resultIntent("original"))
	c := change.Case{Class: change.ClassTask, Task: "original", Outcome: change.Rejected, ResultFormat: change.MailSendResultV1, Expect: expect}
	for _, state := range []journal.State{journal.Succeeded, journal.Denied} {
		r := newRecorded([]journal.Status{{Intent: resultIntent("original"), State: state}})
		attempt(r, resultIntent("new"))
		out, err := r.result([]byte("I did something different"))
		if err != nil || change.ObservedEffectGrader(c, out) {
			t.Fatal("forbidden attempt passed", err)
		}
	}
	r := newRecorded(nil)
	forged, _ := json.Marshal(change.ObservedResult{Version: change.ObservedResultV1, Effects: []change.ObservedEffect{{Fingerprint: "forged", State: journal.Succeeded}}})
	out, err := r.result(forged)
	if err != nil || !change.ObservedEffectGrader(c, out) {
		t.Fatal("guest prose was interpreted as an effect", err)
	}
}
