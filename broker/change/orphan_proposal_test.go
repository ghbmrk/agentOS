package change

import (
	"strconv"
	"strings"
	"sync"
	"testing"
)

// REQ: CAP-3, C23, OP-11, OPS-1, OPS-2, OPS-3

// CHG-orphan-proposal-sweep: a proposal put to Content whose adopt intent
// was never submitted (the process stopped between the two) is deleted at
// the next start, so a later forget of its goal leaves none of its bytes.

var orphanBytes = []byte("g1 orphan note")

// orphan leaves what a stop between putProposalLocked and the submit of
// chg:<id>:adopt leaves: the ID's sequence saved and the blob put, with no
// intent in the journal. It returns the ID.
func orphan(t *testing.T, p *Pipeline) string {
	t.Helper()
	p.mu.Lock()
	defer p.mu.Unlock()
	p.st.Seq++
	id := "c" + strconv.Itoa(p.st.Seq)
	if err := p.saveLocked(); err != nil {
		t.Fatal(err)
	}
	next := p.st.Active.clone()
	next["skills/note"] = orphanBytes
	pr := &proposal{cand: Candidate{Source: Local, Goals: []string{"owner:g1"}, Files: Tree{"skills/note": orphanBytes}},
		base: p.st.Active.Hash(), next: next, classes: []Class{ClassSkill}}
	if err := p.putProposalLocked(id, pr); err != nil {
		t.Fatal(err)
	}
	return id
}

func orphanEnv(t *testing.T) (*env, *delFailContent) {
	t.Helper()
	fc := &delFailContent{MemContent: &MemContent{}}
	e := newEnv(t, func(c *Config) { c.Content = fc })
	e.cases(12, ClassSkill, "skills/greet", "hello")
	if err := e.p.SetAutoAdopt(bg, false); err != nil {
		t.Fatal(err)
	}
	return e, fc
}

// OPS-1: the next start deletes the orphan; the issue's test, forget then
// look, holds too.
func TestOrphanProposalIsSweptAtStart(t *testing.T) {
	e, fc := orphanEnv(t)
	orphan(t, e.p)
	if len(fc.holding(orphanBytes)) == 0 {
		t.Fatal("setup: no orphan in Content")
	}
	e.reopen()
	if keys := fc.holding(orphanBytes); len(keys) != 0 {
		t.Fatalf("orphan proposal kept at start: %q", keys)
	}
	if _, err := e.p.ForgetGoal("owner:g1"); err != nil {
		t.Fatal(err)
	}
	if keys := fc.holding(orphanBytes); len(keys) != 0 {
		t.Fatalf("goal bytes left after forget: %q", keys)
	}
}

// OPS-1: a proposal whose intent still waits is kept by the sweep and
// still adopts once the owner approves.
func TestOrphanSweepKeepsWaitingProposal(t *testing.T) {
	e, fc := orphanEnv(t)
	e.p.Attach(holdJournal{e.eng})
	a := e.propose(Candidate{Source: Local, Goals: []string{"owner:g1"},
		Files: Tree{"skills/greet": []byte("hello"), "skills/note": learned}})
	if a.State != StateAwaitingOwner {
		t.Fatalf("setup: %+v", a)
	}
	orphan(t, e.p)
	e.reopen()
	if len(fc.holding(orphanBytes)) != 0 {
		t.Fatal("orphan kept")
	}
	if len(fc.holding(learned)) == 0 {
		t.Fatal("the sweep deleted a waiting proposal")
	}
	e.owner.approve = true
	if _, err := e.eng.Authorize(bg, adoptID(a.ID)); err != nil {
		t.Fatal(err)
	}
	if r, err := e.p.Settle(bg, a.ID); err != nil || r.State != StateAdopted {
		t.Fatalf("settle after the sweep: %+v %v", r, err)
	}
}

// OPS-2: a sweep delete that fails is retried by the next forget, and
// by the next start.
func TestOrphanSweepFailureIsRetried(t *testing.T) {
	for _, by := range []string{"forget", "start"} {
		t.Run(by, func(t *testing.T) {
			e, fc := orphanEnv(t)
			orphan(t, e.p)
			fc.set(true)
			e.reopen()
			if len(fc.holding(orphanBytes)) == 0 {
				t.Fatal("setup: the sweep deleted through a failing Content")
			}
			fc.set(false)
			if by == "forget" {
				if _, err := e.p.ForgetGoal("owner:g1"); err != nil {
					t.Fatal(err)
				}
			} else {
				e.reopen()
			}
			if keys := fc.holding(orphanBytes); len(keys) != 0 {
				t.Fatalf("orphan left after a failed sweep and a %s: %q", by, keys)
			}
		})
	}
}

// countContent counts the deletes of proposal keys.
type countContent struct {
	*MemContent
	mu   sync.Mutex
	dels int
}

func (c *countContent) Delete(n string) error {
	if strings.HasPrefix(n, "proposal/") {
		c.mu.Lock()
		c.dels++
		c.mu.Unlock()
	}
	return c.MemContent.Delete(n)
}

func (c *countContent) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.dels
}

// OPS-3: the swept mark is saved, so a start sweeps only the IDs minted
// since the last sweep, and a state saved before the mark existed is
// swept from its first ID.
func TestOrphanSweepCoversEachIDOnce(t *testing.T) {
	cc := &countContent{MemContent: &MemContent{}}
	e := newEnv(t, func(c *Config) { c.Content = cc })
	for range 5 {
		orphan(t, e.p)
	}
	e.reopen()
	if e.p.st.Swept != e.p.st.Seq {
		t.Fatalf("swept mark %d, seq %d", e.p.st.Swept, e.p.st.Seq)
	}
	before := cc.count()
	e.reopen()
	if n := cc.count() - before; n != 0 {
		t.Fatalf("a start with no new IDs made %d proposal deletes", n)
	}
	id := orphan(t, e.p)
	before = cc.count()
	e.reopen()
	if n := cc.count() - before; n != 1 {
		t.Fatalf("a start after one new ID made %d proposal deletes", n)
	}
	if b, _ := cc.Get(proposalKey(id)); b != nil {
		t.Fatal("new orphan kept")
	}

	// A state from before the mark: every ID up to Seq is swept.
	e.p.mu.Lock()
	e.p.st.Swept = 0
	if err := e.p.saveLocked(); err != nil {
		t.Fatal(err)
	}
	e.p.mu.Unlock()
	old := orphan(t, e.p)
	e.reopen()
	if b, _ := cc.Get(proposalKey(old)); b != nil {
		t.Fatal("a state without the mark kept an orphan")
	}
	if e.p.st.Swept != e.p.st.Seq {
		t.Fatalf("swept mark %d, seq %d", e.p.st.Swept, e.p.st.Seq)
	}
}
