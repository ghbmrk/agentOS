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
