package change

import (
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/ghbmrk/agentos/broker/journal"
)

// Outcome is the owner's outcome on the real task a case came from (CHG-1).
type Outcome string

const (
	Accepted  Outcome = "accepted"
	Corrected Outcome = "corrected"
	Rejected  Outcome = "rejected"
)

// Case is one evaluation case. Task cases come from a journaled intent the
// owner judged; security cases are fixtures the broker adds (LOOP-9).
type Case struct {
	ID    string `json:"id"`
	Class Class  `json:"class"`
	Input []byte `json:"input"`
	// Expect is what the owner accepted, or the owner's correction. For a
	// rejected outcome it is the output the owner rejected, which a
	// candidate must not reproduce.
	Expect  []byte  `json:"expect"`
	Outcome Outcome `json:"outcome,omitempty"`
	// Task is the journal intent the owner's outcome was recorded on.
	Task string `json:"task,omitempty"`
	// Goal is the goal ID the journal stamped on that intent, never the
	// caller's: it decides the case's side of the split (CHG-1).
	Goal string `json:"goal,omitempty"`
	// Public marks a case built only from public inputs; only public cases
	// count toward evidence in a shared package (CHG-4).
	Public   bool `json:"public,omitempty"`
	Security bool `json:"security,omitempty"`
	// Implicit marks a case from an implicit acceptance (loops L6): it
	// counts half, never anchors an auto-adoption, and is never shown to
	// the owner as an example (security B1, potency C3 on #90).
	Implicit bool `json:"implicit,omitempty"`
	// At is when the case was added, for owner-facing examples.
	At time.Time `json:"at,omitempty"`
}

// split is which side of the held-out boundary a case is on.
type split int

const (
	dev split = iota
	heldOut
)

// splitOf assigns a case to dev or held-out with a keyed hash, so neither a
// candidate nor whoever named the case can choose its side.
func splitOf(key []byte, id string, devPercent int) split {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(id))
	if int(m.Sum(nil)[0])*100 < devPercent*256 {
		return dev
	}
	return heldOut
}

// splitKey is what decides a case's side. Every case of one goal shares a
// side, so a goal's siblings are never both training and evidence (CHG-1).
// A case without a goal hashes on its bare ID, as every case did before
// goals were stamped, so a persisted suite never reshuffles.
func splitKey(c Case) string {
	if c.Goal != "" {
		return "goal:" + c.Goal
	}
	return c.ID
}

var (
	ErrProvenance = errors.New("change: case has no owner outcome behind it")
	ErrDuplicate  = errors.New("change: case already in the suite")
)

// AddTaskCase adds a case from a real task. The intent it names must carry
// a quality verdict whose source is the owner (OP-7), and the verdict must
// agree with the stated outcome. Verdicts from any other source, including
// text in content the agent read, never make a case (CHG-1, CAP-3). Growth
// from owner outcomes is the suite's defined input, not a change to the
// suite, so it needs no approval; removing a case does (CHG-2).
func (p *Pipeline) AddTaskCase(c Case) error {
	if c.ID == "" || c.Task == "" || c.Security {
		return fmt.Errorf("%w: a task case needs an id and a task", ErrProvenance)
	}
	if strings.HasPrefix(c.ID, "goal:") {
		// splitKey would hash it like that goal's cases, letting whoever
		// names the case put it beside a goal it does not belong to.
		return fmt.Errorf("%w: a case id may not start with goal:", ErrProvenance)
	}
	st, err := p.j.Get(c.Task)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrProvenance, err)
	}
	q := st.Quality
	// The journal's source decides whether a case is implicit, never the
	// caller (loops L6): an implicit acceptance is only ever good.
	c.Implicit = q.Source == p.cfg.OwnerSource+ImplicitSuffix
	if q.Source != p.cfg.OwnerSource && !c.Implicit {
		return fmt.Errorf("%w: verdict source is %q", ErrProvenance, q.Source)
	}
	switch {
	case c.Implicit && (c.Outcome != Accepted || q.Verdict != journal.VerdictGood):
		return fmt.Errorf("%w: an implicit acceptance makes only an accepted case", ErrProvenance)
	case c.Outcome == Accepted && q.Verdict == journal.VerdictGood:
	case (c.Outcome == Corrected || c.Outcome == Rejected) && q.Verdict == journal.VerdictWrong:
	default:
		return fmt.Errorf("%w: outcome %q does not match verdict %q", ErrProvenance, c.Outcome, q.Verdict)
	}
	c.Goal = st.Intent.GoalID
	c.At = p.cfg.Now()
	return p.addCase(c)
}

// ImplicitSuffix marks the verdict source of an implicit acceptance: the
// owner's source plus it (loops L6), so it is never read as the owner's.
const ImplicitSuffix = "-implicit"

// AddSecurityCase adds a security fixture. The security suite only grows;
// removing a fixture is an owner-approved intent (LOOP-10, CHG-2).
func (p *Pipeline) AddSecurityCase(c Case) error {
	if c.ID == "" {
		return errors.New("change: a security case needs an id")
	}
	c.Security, c.Task, c.Outcome, c.Goal = true, "", "", ""
	return p.addCase(c)
}

// ForgetGoal removes every task case harvested from goal and saves the
// suite without them, returning their IDs, sorted (W3-tasks, CAP-3). It is
// the owner's deletion of a task: only the broker's handling of an
// authenticated owner forget calls it, never a candidate or a loop
// (TestOnlyTheDaemonForgets holds every other package to that), so unlike
// RemoveCase it takes no second approval (CHG-2 guards the suite against
// changes the owner did not make). Security fixtures carry no goal and
// never go. In the same save it undoes every adoption learned from goal
// and clears its files from history, and drops proposals built from it;
// a candidate from goal still being evaluated is never adopted (security
// C1 on #120, C23). On a failed save the saved state is reloaded and
// re-applied, so a retry does it all again.
func (p *Pipeline) ForgetGoal(goal string) ([]string, error) {
	if goal == "" {
		return nil, errors.New("change: forget needs a goal")
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.broken != nil {
		return nil, p.broken
	}
	if p.gone == nil {
		p.gone = map[string]bool{}
	}
	p.gone[goal] = true
	var ids []string
	for id, c := range p.st.Cases {
		if !c.Security && c.Goal == goal {
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	tree, ads, touched, changed := p.forgetAdoptionsLocked(goal)
	if len(ids) == 0 && !changed {
		return nil, nil
	}
	next := p.st.copyCases()
	for _, id := range ids {
		delete(next, id)
	}
	if err := p.activateLocked(p.st.Active, tree, touched); err != nil {
		return nil, err
	}
	p.st.Cases, p.st.Adoptions, p.st.Active = next, ads, tree
	p.dropOldBasesLocked(tree.Hash())
	if err := p.saveLocked(); err != nil {
		if rerr := p.reloadLocked(); rerr != nil {
			p.markBroken(err, rerr)
		}
		return nil, err
	}
	return ids, nil
}

// LearnedFrom counts the active adoptions learned from goal: what a
// ForgetGoal of it would undo now (W3-forget's notice, before anything is
// deleted). It changes nothing.
func (p *Pipeline) LearnedFrom(goal string) int {
	p.mu.Lock()
	defer p.mu.Unlock()
	n := 0
	for _, a := range p.st.Adoptions {
		if a.Reverted == "" && slices.Contains(a.Goals, goal) {
			n++
		}
	}
	return n
}

func (p *Pipeline) addCase(c Case) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if _, dup := p.st.Cases[c.ID]; dup {
		return ErrDuplicate
	}
	next := p.st.copyCases()
	next[c.ID] = c
	old := p.st.Cases
	p.st.Cases = next
	if err := p.saveLocked(); err != nil {
		p.st.Cases = old
		return err
	}
	return nil
}

// Dev returns the dev split for a class: the only cases a candidate's
// builder may see (CHG-1). Held-out and security cases are never returned,
// and an implicit case comes without its input and reply (C17).
func (p *Pipeline) Dev(class Class) []Case {
	p.mu.Lock()
	defer p.mu.Unlock()
	var out []Case
	for _, c := range p.st.Cases {
		if !c.Security && (c.Class == class || c.Class == ClassTask && taskClasses[class]) && splitOf(p.key, splitKey(c), p.cfg.DevPercent) == dev {
			if c.Implicit {
				// Counted, never read: its reply is one no owner looked
				// at, which an injected guest may have written (C17;
				// arbitrator "count, not content", L3 MUST-3 on #109).
				c.Input, c.Expect = nil, nil
			}
			out = append(out, c)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// frozen is the evaluation set fixed when a candidate is proposed: the
// held-out cases relevant to its classes, and every security fixture.
type frozen struct {
	heldOut  []Case
	security []Case
}

func (p *Pipeline) freezeLocked(classes []Class) frozen {
	rel := map[Class]bool{}
	images := false
	taskRel := false
	for _, c := range classes {
		rel[c] = true
		images = images || c == ClassGuestImage || c == ClassHostImage
		taskRel = taskRel || taskClasses[c]
	}
	var f frozen
	for _, c := range p.st.Cases {
		switch {
		case c.Security:
			f.security = append(f.security, c)
		case splitOf(p.key, splitKey(c), p.cfg.DevPercent) == dev:
		case rel[c.Class] || images || c.Class == ClassTask && taskRel:
			// A new image runs every task, so every held-out case is
			// relevant to it.
			f.heldOut = append(f.heldOut, c)
		}
	}
	sort.Slice(f.heldOut, func(i, j int) bool { return f.heldOut[i].ID < f.heldOut[j].ID })
	sort.Slice(f.security, func(i, j int) bool { return f.security[i].ID < f.security[j].ID })
	return f
}

// ForgetTasks removes every task case recorded on one of tasks, because a
// record the task used was deleted (CAP-3): the case's input and expected
// output may hold it. This is erasure, not a suite change, so unlike an
// owner's removal (CHG-2) it needs no approval; security fixtures carry no
// task and are never removed this way. A smaller held-out set fails closed:
// below MinHeldOut no candidate qualifies. Returns how many went.
func (p *Pipeline) ForgetTasks(tasks ...string) (int, error) {
	set := map[string]bool{}
	for _, t := range tasks {
		if t != "" {
			set[t] = true
		}
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	next := p.st.copyCases()
	n := 0
	for id, c := range next {
		if !c.Security && set[c.Task] {
			delete(next, id)
			n++
		}
	}
	if n == 0 {
		return 0, nil
	}
	old := p.st.Cases
	p.st.Cases = next
	p.st.Forgotten += n
	if err := p.saveLocked(); err != nil {
		p.st.Cases = old
		p.st.Forgotten -= n
		return 0, err
	}
	return n, nil
}
