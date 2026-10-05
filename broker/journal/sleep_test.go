package journal

import (
	"errors"
	"testing"
)

// REQ: RES-1

// PE7 (condition 12): every sleep and wake of the agent is journaled as a
// fixed record: the machine and enumerated codes only, kept across a
// restart, changing no intent, and written while STOP holds dispatch.
func TestSleepRecords(t *testing.T) {
	st := &MemStore{}
	e := mustOpen(t, st, newPolicy(), newService())
	must(e.Submit(intent("a", "acct")))
	if _, err := e.Stop(ctx); err != nil {
		t.Fatal(err)
	}
	notes := []SleepNote{
		{Machine: "agent", Event: SleepAsleep},
		{Machine: "agent", Event: SleepAwake, Cause: "owner_message", Cold: "started_since"},
	}
	for _, n := range notes {
		if err := e.RecordSleep(n); err != nil {
			t.Fatalf("record %+v: %v", n, err)
		}
	}
	for _, bad := range []SleepNote{
		{Event: SleepAsleep},
		{Machine: "agent", Event: "dreaming"},
		{Machine: "agent", Event: SleepAwake, Cause: "the owner said hello"},
	} {
		if err := e.RecordSleep(bad); !errors.Is(err, ErrInvalid) {
			t.Fatalf("%+v: %v, want ErrInvalid", bad, err)
		}
	}
	e2 := mustOpen(t, st, newPolicy(), newService())
	var got []SleepNote
	for _, r := range e2.Trail() {
		if r.Type == RecSleep {
			got = append(got, *r.Sleep)
		}
	}
	if len(got) != 2 || got[0] != notes[0] || got[1] != notes[1] {
		t.Fatalf("after a restart: %+v", got)
	}
	if s, err := e2.Get("a"); err != nil || s.State != Pending {
		t.Fatalf("an intent changed: %+v %v", s, err)
	}
}
