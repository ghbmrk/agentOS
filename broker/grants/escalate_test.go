package grants

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/ghbmrk/agentos/broker/journal"
)

// REQ: ADP-2

// escVerifier is an adapter verifier that also escalates organize effects
// by record: "alert" hides a security alert, "over" is past the daily
// bound, "trash" is a target the adapter refuses.
type escVerifier struct{ *fakeVerifier }

func (v escVerifier) Escalate(_ context.Context, in journal.Intent) (Escalation, error) {
	switch rec, _ := in.Params[ParamRecord].(string); rec {
	case "alert":
		return Escalation{Verb: "change-account", Reason: "hides an alert from bank.example"}, nil
	case "over":
		return Escalation{Ask: true, Reason: "past today's 200"}, nil
	case "trash":
		return Escalation{}, errors.New("not an allowed target")
	}
	return Escalation{}, nil
}

// TestOrganizeEscalatesOnlyWhatTheAdapterFlags: organize is reversible
// and runs without asking, except where the adapter's guards say the
// effect hides an alert (asked as change-account), is past the day's
// bound (asked), or targets something never allowed (denied).
func TestOrganizeEscalatesOnlyWhatTheAdapterFlags(t *testing.T) {
	r := newRig(t, func(c *Config) {
		c.Declared["mail"]["message.archive"] = "organize"
		c.Verifiers["mail"] = escVerifier{&fakeVerifier{records: map[string]Verified{}}}
	})
	ops := mailOps()
	ops["message.archive"] = "organize"
	r.grant(Spec{Account: "mail", Executor: "mail", Ops: ops})

	if st := r.effect("agent/a1", "message.archive", map[string]any{"record": "news"}); st.State != journal.Succeeded {
		t.Fatalf("plain archive: %s %q", st.State, st.Permission.Reason)
	}
	st := r.effect("agent/a2", "message.archive", map[string]any{"record": "alert"})
	if st.State != journal.Pending || r.exec.runs("agent/a2") != 0 {
		t.Fatalf("archiving an alert ran: %s", st.State)
	}
	st = r.effect("agent/a3", "message.archive", map[string]any{"record": "over"})
	if st.State != journal.Pending || r.exec.runs("agent/a3") != 0 {
		t.Fatalf("archive past the bound ran: %s", st.State)
	}
	r.g.Flush()
	_, items := r.own.last(t)
	verbs, details := map[string]string{}, map[string]string{}
	for _, it := range items {
		verbs[it.Ref], details[it.Ref] = it.Facts.Verb, it.Detail
	}
	// Each ask says why, in the adapter's fixed words.
	if verbs["agent/a2"] != "change-account" || verbs["agent/a3"] != "organize" ||
		details["agent/a2"] != "hides an alert from bank.example" || details["agent/a3"] != "past today's 200" {
		t.Fatalf("asked %+v", items)
	}
	if st := r.effect("agent/a4", "message.archive", map[string]any{"record": "trash"}); st.State != journal.Denied || !strings.Contains(st.Permission.Reason, "guard") {
		t.Fatalf("refused target: %s %q", st.State, st.Permission.Reason)
	}
	r.decide(true, "owner")
	if r.exec.runs("agent/a2") != 1 || r.exec.runs("agent/a3") != 1 {
		t.Fatal("approved organize effects did not run")
	}
}
