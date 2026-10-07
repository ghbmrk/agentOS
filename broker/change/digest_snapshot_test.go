package change

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

// REQ: CH-15, OP-1, OP-2
func TestDigestPeekDoesNotConsumeAndSurvivesRestart(t *testing.T) {
	e := newEnv(t, nil)
	if err := e.p.Notice("first", "Fixed first note."); err != nil {
		t.Fatal(err)
	}
	s, err := e.p.PeekDigest()
	if err != nil || s == nil {
		t.Fatal(s, err)
	}
	if e.p.st.Notices[0].Seen {
		t.Fatal("peek consumed notice")
	}
	again, err := e.p.PeekDigest()
	if err != nil || !reflect.DeepEqual(s, again) {
		t.Fatal("pending snapshot changed", again, err)
	}
	p, err := New(Config{Store: e.store, Evaluator: e.ev})
	if err != nil {
		t.Fatal(err)
	}
	reopened, err := p.PeekDigest()
	if err != nil || !reflect.DeepEqual(s, reopened) {
		t.Fatal(reopened, err)
	}
	if err = p.AckDigest(*s); err != nil {
		t.Fatal(err)
	}
	if next, err := p.PeekDigest(); err != nil || next != nil {
		t.Fatal("ack left old event pending", next, err)
	}
}
func TestDigestAckPreservesNoticesAddedAfterPeek(t *testing.T) {
	e := newEnv(t, nil)
	_ = e.p.Notice("first", "First.")
	s, err := e.p.PeekDigest()
	if err != nil {
		t.Fatal(err)
	}
	_ = e.p.Notice("later", "Later.")
	if err = e.p.AckDigest(*s); err != nil {
		t.Fatal(err)
	}
	next, err := e.p.PeekDigest()
	if err != nil || next == nil || len(next.Lines) != 1 || next.Lines[0] != "Later." || next.Generation <= s.Generation {
		t.Fatal(next, err)
	}
}
func TestDigestAckIsIdempotentAfterRestartAndLaterAck(t *testing.T) {
	e := newEnv(t, nil)
	_ = e.p.Notice("first", "First.")
	s, _ := e.p.PeekDigest()
	if err := e.p.AckDigest(*s); err != nil {
		t.Fatal(err)
	}
	_ = e.p.Notice("later", "Later.")
	next, _ := e.p.PeekDigest()
	if err := e.p.AckDigest(*next); err != nil {
		t.Fatal(err)
	}
	p, err := New(Config{Store: e.store, Evaluator: e.ev})
	if err != nil {
		t.Fatal(err)
	}
	if err = p.AckDigest(*s); err != nil {
		t.Fatal("old exact ack not idempotent", err)
	}
}
func TestDigestAckRejectsTamperedSnapshot(t *testing.T) {
	e := newEnv(t, nil)
	_ = e.p.Notice("first", "First.")
	s, _ := e.p.PeekDigest()
	s.Lines[0] = "Injected note."
	if err := e.p.AckDigest(*s); !errors.Is(err, ErrDigestSnapshot) {
		t.Fatal(err)
	}
	if e.p.st.Notices[0].Seen {
		t.Fatal("tampered ack consumed source")
	}
}
func TestDigestPeekFailureReturnsNoSnapshotAndStopsSource(t *testing.T) {
	e := newEnv(t, nil)
	_ = e.p.Notice("first", "First.")
	e.store.Fail = errors.New("write failed")
	if s, err := e.p.PeekDigest(); err == nil || s != nil {
		t.Fatal(s, err)
	}
	e.store.Fail = nil
	if _, err := e.p.PeekDigest(); err == nil {
		t.Fatal("uncertain pipeline stayed usable")
	}
	p, err := New(Config{Store: e.store, Evaluator: e.ev})
	if err != nil {
		t.Fatal(err)
	}
	if s, err := p.PeekDigest(); err != nil || s == nil || s.Generation != 1 {
		t.Fatal(s, err)
	}
}
func TestDigestAckFailureDoesNotConsumeInMemory(t *testing.T) {
	e := newEnv(t, nil)
	_ = e.p.Notice("first", "First.")
	s, _ := e.p.PeekDigest()
	e.store.Fail = errors.New("write failed")
	if err := e.p.AckDigest(*s); err == nil {
		t.Fatal("ack succeeded")
	}
	if e.p.st.Notices[0].Seen {
		t.Fatal("failed save consumed in memory")
	}
	e.store.Fail = nil
	p, err := New(Config{Store: e.store, Evaluator: e.ev})
	if err != nil {
		t.Fatal(err)
	}
	if pending, err := p.PeekDigest(); err != nil || pending == nil {
		t.Fatal(pending, err)
	}
}
func TestDigestSnapshotsAreOwnedCopies(t *testing.T) {
	e := newEnv(t, nil)
	_ = e.p.Notice("first", "First.")
	s, _ := e.p.PeekDigest()
	s.Lines[0] = "changed"
	s.Marks[0].ID = "changed"
	again, err := e.p.PeekDigest()
	if err != nil || again.Lines[0] != "First." || again.Marks[0].ID != "first" {
		t.Fatal(again, err)
	}
}
func TestLegacyDigestCannotConsumePendingSnapshot(t *testing.T) {
	e := newEnv(t, nil)
	_ = e.p.Notice("first", "First.")
	s, _ := e.p.PeekDigest()
	if lines := e.p.Digest(); len(lines) != 0 {
		t.Fatal("legacy reader bypassed queue source", lines)
	}
	if err := e.p.AckDigest(*s); err != nil {
		t.Fatal(err)
	}
}
func TestDigestOldOutageAckPreservesNewerCount(t *testing.T) {
	e := newEnv(t, nil)
	e.p.st.Outages = OutageAlert
	s, err := e.p.PeekDigest()
	if err != nil {
		t.Fatal(err)
	}
	e.p.st.Outages++
	if err = e.p.AckDigest(*s); err != nil {
		t.Fatal(err)
	}
	if e.p.st.OutageSeen {
		t.Fatal("old count hid newer outage")
	}
	next, err := e.p.PeekDigest()
	if err != nil || next == nil || !strings.Contains(next.Lines[0], "times") {
		t.Fatal(next, err)
	}
}
func TestSnapshotRendererMatchesLegacyDigest(t *testing.T) {
	e := newEnv(t, nil)
	_ = e.p.Notice("first", "First.")
	e.p.st.Outages = OutageAlert
	if err := e.p.saveLocked(); err != nil {
		t.Fatal(err)
	}
	legacyState, err := e.store.Load()
	if err != nil {
		t.Fatal(err)
	}
	other := &MemStore{}
	_ = other.Save(legacyState)
	p, err := New(Config{Store: other, Evaluator: e.ev})
	if err != nil {
		t.Fatal(err)
	}
	s, err := e.p.PeekDigest()
	if err != nil {
		t.Fatal(err)
	}
	if lines := p.Digest(); !reflect.DeepEqual(lines, s.Lines) {
		t.Fatal(lines, s.Lines)
	}
}

// P3-6d: the shared renderer, not only the old Digest loop, says a skill
// that removes a procedure can be undone. The legacy reader and the
// nonconsuming snapshot both show it, and a second peek still does.
func TestProcedureReplacementIsInBothDigestReaders(t *testing.T) {
	phrase := "(replaces the step-by-step version; undo brings it back)"
	adoption := func() []*Adoption {
		return []*Adoption{{
			Short:   "A1",
			Classes: []Class{ClassSkill},
			Basis:   BasisStanding,
			Edits: []Edit{
				{Path: "procedures/file", Before: []byte("step by step")},
				{Path: "skills/greet", After: []byte("hello")},
			},
			Score: Score{HeldOut: 4, Passed: 4, BaselinePassed: 4},
		}}
	}
	legacy := newEnv(t, nil)
	legacy.p.st.Active = Tree{"skills/greet": []byte("hello")}
	legacy.p.st.Adoptions = adoption()
	d := legacy.p.Digest()
	if len(d) != 1 || !strings.Contains(d[0], phrase) || !strings.Contains(d[0], "UNDO A1") {
		t.Fatalf("legacy: %q", d)
	}
	snap := newEnv(t, nil)
	snap.p.st.Active = Tree{"skills/greet": []byte("hello")}
	snap.p.st.Adoptions = adoption()
	s, err := snap.p.PeekDigest()
	if err != nil || s == nil || len(s.Lines) != 1 || !strings.Contains(s.Lines[0], phrase) {
		t.Fatalf("snapshot: %v %v", s, err)
	}
	again, err := snap.p.PeekDigest()
	if err != nil || again == nil || len(again.Lines) != 1 || !strings.Contains(again.Lines[0], phrase) {
		t.Fatalf("second peek consumed it: %v %v", again, err)
	}
	plain := newEnv(t, nil)
	plain.p.st.Active = Tree{"skills/greet": []byte("hello!")}
	plain.p.st.Adoptions = []*Adoption{{
		Short:   "A2",
		Classes: []Class{ClassSkill},
		Basis:   BasisStanding,
		Edits:   []Edit{{Path: "skills/greet", Before: []byte("hello"), After: []byte("hello!")}},
		Score:   Score{HeldOut: 4, Passed: 4, BaselinePassed: 4},
	}}
	if lines := plain.p.Digest(); len(lines) != 1 || strings.Contains(lines[0], phrase) {
		t.Fatalf("no procedure removed: %q", lines)
	}
}

// REQ: CAP-3
func TestForgetInvalidatesPendingGoalSnapshot(t *testing.T) {
	e := newEnv(t, nil)
	e.p.st.Adoptions = []*Adoption{{ID: "adopt-1", Short: "A2", Classes: []Class{ClassSkill}, Goals: []string{"goal-1"}}}
	s, err := e.p.PeekDigest()
	if err != nil || s == nil {
		t.Fatal(s, err)
	}
	if !reflect.DeepEqual(s.References, []string{"goal-1"}) {
		t.Fatal(s.References)
	}
	if _, err = e.p.ForgetGoal("goal-1"); err != nil {
		t.Fatal(err)
	}
	if e.p.st.DigestPending != nil {
		t.Fatal("pending forgotten reference retained")
	}
	if err = e.p.AckDigest(*s); !errors.Is(err, ErrDigestInvalidated) {
		t.Fatal("forgotten snapshot accepted", err)
	}
}

func TestDigestSnapshotDrainsBoundedAdoptionBatches(t *testing.T) {
	e := newEnv(t, nil)
	for i := 0; i < 70; i++ {
		e.p.st.Adoptions = append(e.p.st.Adoptions, &Adoption{ID: fmt.Sprintf("adoption-%d", i), Short: fmt.Sprintf("A%d", i), Classes: []Class{ClassSkill}})
	}
	first, err := e.p.PeekDigest()
	if err != nil || len(first.Lines) != 64 {
		t.Fatal(first, err)
	}
	if err = e.p.AckDigest(*first); err != nil {
		t.Fatal(err)
	}
	second, err := e.p.PeekDigest()
	if err != nil || len(second.Lines) != 6 {
		t.Fatal(second, err)
	}
	if err = e.p.AckDigest(*second); err != nil {
		t.Fatal(err)
	}
	if last, err := e.p.PeekDigest(); err != nil || last != nil {
		t.Fatal(last, err)
	}
}
func TestDigestOldStagedAckPreservesInstalledEvent(t *testing.T) {
	e := newEnv(t, nil)
	a := &Adoption{ID: "adopt-1", Short: "A2", Classes: []Class{ClassGuestImage}, Origin: "update:v1", Staged: true}
	e.p.st.Adoptions = []*Adoption{a}
	first, err := e.p.PeekDigest()
	if err != nil {
		t.Fatal(err)
	}
	a.Staged = false
	if err = e.p.AckDigest(*first); err != nil {
		t.Fatal(err)
	}
	if a.Listed {
		t.Fatal("staged ack consumed later installation")
	}
	next, err := e.p.PeekDigest()
	if err != nil || next == nil || !strings.Contains(next.Lines[0], "Installed update") {
		t.Fatal(next, err)
	}
}
func TestCorruptDigestCountersRefuseOpen(t *testing.T) {
	e := newEnv(t, nil)
	e.p.st.DigestAcked = 1
	if err := e.p.saveLocked(); err != nil {
		t.Fatal(err)
	}
	if _, err := New(Config{Store: e.store, Evaluator: e.ev}); !errors.Is(err, ErrDigestSnapshot) {
		t.Fatal(err)
	}
}

func TestCorruptDigestStateRefusesBeforeTargetRestoration(t *testing.T) {
	e := newEnv(t, nil)
	e.p.st.DigestAcked = 1
	if err := e.p.saveLocked(); err != nil {
		t.Fatal(err)
	}
	target := &fakeTarget{ns: "skills"}
	if _, err := New(Config{Store: e.store, Evaluator: e.ev, Targets: map[string]Target{"skills": target}}); !errors.Is(err, ErrDigestSnapshot) {
		t.Fatal(err)
	}
	if target.applied != nil {
		t.Fatal("invalid source state restored a target before refusal")
	}
}
