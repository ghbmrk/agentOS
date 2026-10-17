package change

import (
	"context"
	"encoding/json"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/update"
)

// REQ: OP-7, CH-12, CH-19
//
// SR3-4f-3-f1: a security Concern whose withdrawal has not finished a day
// after it was raised gets one follow-up digest line, which names the
// day it was already waiting on and asks nothing of the owner: no owner
// step settles a stuck withdrawal (ASSUMPTIONS C45).

// The follow-up lines for update 41, raised on concernDay.
const (
	wontStartFollowUp = "Update 41 failed a security check and is still waiting to be undone, as it was on Mon 12 Oct; I will not start it. Nothing is needed from you."
	mayStartFollowUp  = "Update 41 failed a security check and is still waiting to be undone, as it was on Mon 12 Oct; it may start before I can undo it. Nothing is needed from you."
)

var concernDay = time.Date(2026, 10, 12, 9, 0, 0, 0, time.UTC)

// clock holds the pipeline's time at *at, which the test moves.
func (e *env) clock(at *time.Time) {
	e.p.cfg.Now = func() time.Time { return *at }
}

// refusedConcern is TestRefusedSecurityRevertSetsConcern's setup: a
// security recheck of update 41 the applier refuses, its first line shown.
func refusedConcern(t *testing.T, starts bool) (*env, Report, *time.Time) {
	t.Helper()
	e, r, w := pendingStaged(t)
	now := concernDay
	e.clock(&now)
	e.failsSecurity(r.ID)
	w.err = installing{starts: starts}
	if ids, err := e.p.Recheck(bg); err != nil || slices.Contains(ids, r.ID) {
		t.Fatalf("recheck: %v %v", ids, err)
	}
	line := wontStartLine
	if starts {
		line = mayStartLine
	}
	if d := e.p.Digest(); !slices.Contains(d, line) {
		t.Fatalf("first digest: %q", d)
	}
	return e, r, &now
}

func followUps(d []string) []string {
	var out []string
	for _, l := range d {
		if strings.Contains(l, "still waiting to be undone") {
			out = append(out, l)
		}
	}
	return out
}

// Mutant: drop the ConcernFollowedUp guard, and the second Digest says it
// again.
func TestOpenSecurityConcernFollowsUpAfterADay(t *testing.T) {
	for name, starts := range map[string]bool{"will not start": false, "may start": true} {
		t.Run(name, func(t *testing.T) {
			want := wontStartFollowUp
			if starts {
				want = mayStartFollowUp
			}
			e, _, now := refusedConcern(t, starts)
			*now = concernDay.Add(ConcernFollowUpAfter - time.Minute)
			if d := followUps(e.p.Digest()); len(d) != 0 {
				t.Fatalf("follow-up before a day: %q", d)
			}
			*now = concernDay.Add(ConcernFollowUpAfter)
			d := followUps(e.p.Digest())
			if len(d) != 1 || d[0] != want {
				t.Fatalf("follow-up after a day: %q", d)
			}
			if len(d[0]) > 160 {
				t.Fatalf("follow-up is %d characters, over one text", len(d[0]))
			}
			for _, l := range d {
				if strings.Contains(l, "UNDO") || strings.Contains(l, "restart") || strings.Contains(l, "Reply") {
					t.Fatalf("follow-up offers a step that does not settle it: %q", l)
				}
			}
			*now = concernDay.Add(30 * ConcernFollowUpAfter)
			e.reopen()
			if d := followUps(e.p.Digest()); len(d) != 0 {
				t.Fatalf("second follow-up: %q", d)
			}
		})
	}
}

func TestFollowUpSilentOnceReverted(t *testing.T) {
	e, r, now := refusedConcern(t, false)
	w := &withdrawer{}
	e.p.SetWithdrawer(w)
	e.failsSecurity(r.ID)
	if ids, err := e.p.Recheck(bg); err != nil || !slices.Contains(ids, r.ID) {
		t.Fatalf("recheck once it can withdraw: %v %v", ids, err)
	}
	*now = concernDay.Add(2 * ConcernFollowUpAfter)
	if d := followUps(e.p.Digest()); len(d) != 0 {
		t.Fatalf("follow-up after the revert: %q", d)
	}
	if a := e.adoption(r.ID); a.Reverted != WhySecurity || a.ConcernFollowedUp {
		t.Fatalf("adoption %+v", a)
	}
}

// A protected adoption's Concern keeps its UNDO line, said once, and is
// never followed up: the owner decides it (arbitrator R2).
func TestProtectedConcernKeepsItsUndoLine(t *testing.T) {
	e, r, _ := pendingStaged(t)
	now := concernDay
	e.clock(&now)
	ev := e.p.cfg.Evaluator
	e.p.cfg.Evaluator = evalFunc(func(ctx context.Context, tr Tree, pr Probe) ([]byte, error) {
		if string(tr["host-image/release"]) == update.Digest([]byte("b")) && string(pr.Input) == exfilProbe {
			return []byte("leaked"), nil
		}
		return ev.Run(ctx, tr, pr)
	})
	if a := e.adoption(r.ID); !a.protected() {
		t.Fatal("fixture adoption is not protected")
	}
	if _, err := e.p.Recheck(bg); err != nil {
		t.Fatal(err)
	}
	a := e.adoption(r.ID)
	if a.Concern != WhySecurity || a.Reverted != "" || !a.ConcernAt.IsZero() {
		t.Fatalf("adoption %+v", a)
	}
	undo := "fails a newer security check. Reply UNDO " + r.Short
	d := e.p.Digest()
	if !slices.ContainsFunc(d, func(l string) bool { return strings.Contains(l, undo) }) {
		t.Fatalf("digest: %q", d)
	}
	now = concernDay.Add(2 * ConcernFollowUpAfter)
	if d := e.p.Digest(); len(followUps(d)) != 0 || slices.ContainsFunc(d, func(l string) bool { return strings.Contains(l, undo) }) {
		t.Fatalf("later digest: %q", d)
	}
}

// T5: ConcernAt and ConcernFollowedUp survive a reload; an adoption saved
// before them loads, and its clock starts at the next digest, so its line
// names a day it was known to be waiting.
func TestConcernFollowUpStateRoundTrip(t *testing.T) {
	e, r, now := refusedConcern(t, false)
	e.reopen()
	if a := e.adoption(r.ID); !a.ConcernAt.Equal(concernDay) || a.ConcernFollowedUp {
		t.Fatalf("reloaded mid-count: %+v", a)
	}
	*now = concernDay.Add(ConcernFollowUpAfter)
	if d := followUps(e.p.Digest()); len(d) != 1 {
		t.Fatalf("follow-up after a reload: %q", d)
	}
	e.reopen()
	if a := e.adoption(r.ID); !a.ConcernFollowedUp {
		t.Fatalf("follow-up not saved: %+v", a)
	}

	var old Adoption
	if err := json.Unmarshal([]byte(`{"id":"c1","concern":"security","concern_seen":true}`), &old); err != nil {
		t.Fatal("state without the fields:", err)
	}
	if !old.ConcernAt.IsZero() || old.ConcernFollowedUp {
		t.Fatalf("old adoption %+v", old)
	}
	if b, err := json.Marshal(Adoption{}); err != nil || strings.Contains(string(b), "concern_at") || strings.Contains(string(b), "concern_followed_up") {
		t.Fatalf("new fields not omitted when empty: %s %v", b, err)
	}

	// A Concern saved with no ConcernAt: the clock starts at the next
	// digest, and the line names that day, not an unknown earlier one.
	e2, r2, now2 := refusedConcern(t, false)
	e2.p.mu.Lock()
	e2.p.adoptionByIDLocked(r2.ID).ConcernAt = time.Time{}
	e2.p.mu.Unlock()
	*now2 = concernDay.Add(48 * time.Hour) // Wed 14 Oct
	if d := followUps(e2.p.Digest()); len(d) != 0 {
		t.Fatalf("follow-up with no clock: %q", d)
	}
	*now2 = now2.Add(ConcernFollowUpAfter)
	if d := followUps(e2.p.Digest()); len(d) != 1 || !strings.Contains(d[0], "as it was on Wed 14 Oct") {
		t.Fatalf("follow-up of an old Concern: %q", d)
	}
}
