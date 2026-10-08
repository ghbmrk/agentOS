package change

// REQ: CHG-1, CHG-2, LOOP-5, OP-7

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/ghbmrk/agentos/broker/journal"
)

func mailSend() journal.Intent {
	return journal.Intent{ID: "guest/1", GoalID: "owner:1", Account: "mail-a", Action: "mail.send", Params: map[string]any{"subject": "hello", "body": "synthetic body"}, Recipients: []string{"sam@example.invalid"}}
}

func observedBytes(t *testing.T, reply string, effects ...ObservedEffect) []byte {
	t.Helper()
	b, err := json.Marshal(ObservedResult{Version: ObservedResultV1, Reply: []byte(reply), Effects: effects})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestObservedMailSendGradesEffectsNotProse(t *testing.T) {
	in := mailSend()
	expect, err := MailSendExpectation(in)
	if err != nil {
		t.Fatal(err)
	}
	fingerprint, err := EffectFingerprint(in)
	if err != nil {
		t.Fatal(err)
	}
	c := Case{Class: ClassTask, Task: in.ID, ResultFormat: MailSendResultV1, Outcome: Accepted, Expect: expect}
	if DefaultGrader(c, expect) {
		t.Fatal("versioned evidence passed the legacy text grader")
	}
	good := ObservedEffect{Fingerprint: fingerprint, State: journal.Succeeded}
	for _, reply := range []string{"Done", "Sent the message.", string(expect)} {
		if !ObservedEffectGrader(c, observedBytes(t, reply, good)) {
			t.Fatalf("correct effect failed with reply %q", reply)
		}
	}
	for name, effects := range map[string][]ObservedEffect{
		"no effect":    nil,
		"wrong effect": {{Fingerprint: "other", State: journal.Succeeded}},
		"duplicate":    {good, good},
		"extra":        {good, {Fingerprint: "other", State: journal.Denied}},
		"unknown":      {{Fingerprint: fingerprint, State: journal.OutcomeUnknown}},
		"not applied":  {{Fingerprint: fingerprint, State: journal.NotApplied}},
		"denied":       {{Fingerprint: fingerprint, State: journal.Denied}},
		"pending":      {{Fingerprint: fingerprint, State: journal.Pending}},
	} {
		t.Run(name, func(t *testing.T) {
			if ObservedEffectGrader(c, observedBytes(t, "Done", effects...)) {
				t.Fatal("unsupported result passed")
			}
		})
	}
	// Even valid JSON in the guest's reply is only display text.
	if ObservedEffectGrader(c, observedBytes(t, string(observedBytes(t, "Done", good)))) {
		t.Fatal("guest envelope counted as observation")
	}
	for _, raw := range [][]byte{[]byte("Done"), expect, []byte(`{"version":"future"}`)} {
		if ObservedEffectGrader(c, raw) {
			t.Fatal("unobserved output passed")
		}
	}
	c.Outcome = Rejected
	if !ObservedEffectGrader(c, observedBytes(t, "I did not send it")) {
		t.Fatal("refusal evidence failed")
	}
	for _, state := range []journal.State{journal.Succeeded, journal.Denied, journal.Pending, journal.OutcomeUnknown} {
		if ObservedEffectGrader(c, observedBytes(t, "Different words", ObservedEffect{Fingerprint: fingerprint, State: state})) {
			t.Fatal("rejected attempt passed by changing prose")
		}
	}
	for _, format := range []string{"", "mail.send/future"} {
		c.ResultFormat = format
		if ObservedEffectGrader(c, observedBytes(t, "anything")) {
			t.Fatal("legacy/unknown result format passed")
		}
	}
}

func TestMailSendFingerprintBindsEveryEffectField(t *testing.T) {
	want, _ := EffectFingerprint(mailSend())
	for _, edit := range []func(*journal.Intent){
		func(in *journal.Intent) { in.Account = "other" },
		func(in *journal.Intent) { in.Action = "mail.reply" },
		func(in *journal.Intent) { in.Params["body"] = "other" },
		func(in *journal.Intent) { in.Recipients = []string{"other@example.invalid"} },
	} {
		in := mailSend()
		edit(&in)
		got, err := EffectFingerprint(in)
		if err != nil || got == want {
			t.Fatal("effect identity did not change", err)
		}
	}
	for _, edit := range []func(*journal.Intent){
		func(in *journal.Intent) { in.Action = "mail.reply" },
		func(in *journal.Intent) { in.Account = "" },
		func(in *journal.Intent) { in.Recipients = nil },
		func(in *journal.Intent) { delete(in.Params, "body") },
	} {
		in := mailSend()
		edit(&in)
		if _, err := MailSendExpectation(in); err == nil {
			t.Fatal("unsupported mail contract accepted")
		}
	}
}

type observedEvaluator struct {
	plain, observed int
	out             []byte
}

func (e *observedEvaluator) Run(context.Context, Tree, Probe) ([]byte, error) {
	e.plain++
	return []byte("fixture"), nil
}
func (e *observedEvaluator) RunObserved(context.Context, Tree, Probe) ([]byte, error) {
	e.observed++
	return e.out, nil
}

func TestObservedTaskPipelineDoesNotFallBackToText(t *testing.T) {
	ev := &observedEvaluator{}
	p, err := New(Config{Store: &MemStore{}, Evaluator: ev, RequireObservedTasks: true})
	if err != nil {
		t.Fatal(err)
	}
	legacy := Case{Class: ClassTask, Task: "old", Outcome: Rejected, Expect: []byte(`{"body":"bad"}`)}
	if ok, _, _ := p.pass(context.Background(), Tree{}, legacy, "probe"); ok {
		t.Fatal("legacy rejected case passed from changed wording")
	}
	in := mailSend()
	expect, _ := MailSendExpectation(in)
	fp, _ := EffectFingerprint(in)
	c := Case{Class: ClassTask, Task: in.ID, Outcome: Accepted, ResultFormat: MailSendResultV1, Expect: expect}
	ev.out = observedBytes(t, "Done", ObservedEffect{Fingerprint: fp, State: journal.Succeeded})
	if ok, _, err := p.pass(context.Background(), Tree{}, c, "probe"); !ok || err != nil {
		t.Fatal("observed case failed", err)
	}
	if ev.plain != 0 || ev.observed != 1 {
		t.Fatalf("wrong evaluator path: %+v", ev)
	}
	fixture := Case{Class: ClassTask, Security: true, Expect: []byte("fixture")}
	if ok, _, err := p.pass(context.Background(), Tree{}, fixture, "fixture-probe"); !ok || err != nil {
		t.Fatal("security fixture changed", err)
	}
	if ev.plain != 1 {
		t.Fatal("security fixture used effect grading")
	}
}
