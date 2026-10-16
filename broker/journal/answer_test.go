package journal

// REQ: OP-11, OP-12, SM-AJ-1
//
// The owner_answer record (SM-approval-journal): legal only on a pending
// intent, refused when malformed, replayed as it was committed, and its
// item digest removed by an erase (CAP-3).

import (
	"errors"
	"strings"
	"testing"
)

const testSum = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func TestAnswerRecordGuard(t *testing.T) {
	n := AnswerNote{Approved: true, Why: "owner", Request: "R1", Sum: testSum, Asked: true, Went: []string{"agent/x"}}
	for _, c := range guardCases() {
		t.Run(c.name, func(t *testing.T) {
			e, st, svc := c.build(t)
			err := e.RecordAnswer("a", n)
			if c.state == Pending {
				if err != nil {
					t.Fatalf("answer on a pending intent: %v", err)
				}
				if s := must(e.Get("a")).State; s != Pending {
					t.Fatalf("an answer changed the state to %s", s)
				}
				checkReplay(t, e, st, svc)
				return
			}
			if !errors.Is(err, ErrState) {
				t.Fatalf("answer from %s: err = %v, want ErrState", c.state, err)
			}
			checkReplay(t, e, st, svc)
			appendRaw(t, e, st, Record{Type: RecAnswer, ID: "a", Answer: &n})
			if _, err := reopen(st, svc); !errors.Is(err, ErrCorrupt) {
				t.Fatalf("replay of an answer from %s: err = %v, want ErrCorrupt", c.state, err)
			}
		})
	}
}

func TestAnswerNoteRefusedWhenMalformed(t *testing.T) {
	for name, n := range map[string]AnswerNote{
		"sum not a digest":    {Approved: true, Sum: "zebracorn"},
		"request not a token": {Approved: true, Request: "R 1"},
		"why on two lines":    {Why: "owner\nzebracorn"},
		"why too long":        {Why: strings.Repeat("x", maxAnswerText+1)},
		"empty repeat":        {Approved: true, Went: []string{""}},
		"confirm with sum":    {Confirm: true, Sum: testSum},
		"negative tries":      {Tries: -1},
	} {
		t.Run(name, func(t *testing.T) {
			st, svc := &MemStore{}, newService()
			e := mustOpen(t, st, newPolicy(), svc)
			must(e.Submit(intent("a", "acct")))
			if err := e.RecordAnswer("a", n); !errors.Is(err, ErrInvalid) {
				t.Fatalf("err = %v, want ErrInvalid", err)
			}
			if err := commitLocked(e, Record{Type: RecAnswer, ID: "a", Answer: &n}); !errors.Is(err, ErrState) {
				t.Fatalf("commit: err = %v, want ErrState", err)
			}
			checkReplay(t, e, st, svc)
		})
	}
}

// An erase removes the answer's item digest with the rest of the
// intent's content; the verdict stays as audit.
func TestAnswerDigestErased(t *testing.T) {
	st, svc := &MemStore{}, newService()
	e := mustOpen(t, st, newPolicy(), svc)
	must(e.Submit(intent("a", "acct")))
	if err := e.RecordAnswer("a", AnswerNote{Approved: true, Why: "owner", Sum: testSum}); err != nil {
		t.Fatal(err)
	}
	must(e.Authorize(ctx, "a"))
	must(e.Dispatch(ctx, "a"))
	if _, _, err := e.Erase([]string{"a"}); err != nil {
		t.Fatal(err)
	}
	data := must(st.ReadAll())
	if strings.Contains(string(data), testSum) {
		t.Fatal("an erased intent's item digest remains in the journal")
	}
	e2, err := reopen(st, svc)
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, r := range e2.Trail() {
		if r.Type == RecAnswer && r.ID == "a" {
			found = r.Answer != nil && r.Answer.Approved
		}
	}
	if !found {
		t.Fatal("the erased intent's answer was not kept as audit")
	}
}
