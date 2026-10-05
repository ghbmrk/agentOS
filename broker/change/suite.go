package change

import (
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"fmt"
	"sort"
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
	// Public marks a case built only from public inputs; only public cases
	// count toward evidence in a shared package (CHG-4).
	Public   bool `json:"public,omitempty"`
	Security bool `json:"security,omitempty"`
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
	st, err := p.j.Get(c.Task)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrProvenance, err)
	}
	q := st.Quality
	if q.Source != p.cfg.OwnerSource {
		return fmt.Errorf("%w: verdict source is %q", ErrProvenance, q.Source)
	}
	switch {
	case c.Outcome == Accepted && q.Verdict == journal.VerdictGood:
	case (c.Outcome == Corrected || c.Outcome == Rejected) && q.Verdict == journal.VerdictWrong:
	default:
		return fmt.Errorf("%w: outcome %q does not match verdict %q", ErrProvenance, c.Outcome, q.Verdict)
	}
	c.At = p.cfg.Now()
	return p.addCase(c)
}

// AddSecurityCase adds a security fixture. The security suite only grows;
// removing a fixture is an owner-approved intent (LOOP-10, CHG-2).
func (p *Pipeline) AddSecurityCase(c Case) error {
	if c.ID == "" {
		return errors.New("change: a security case needs an id")
	}
	c.Security, c.Task, c.Outcome = true, "", ""
	return p.addCase(c)
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
// builder may see (CHG-1). Held-out and security cases are never returned.
func (p *Pipeline) Dev(class Class) []Case {
	p.mu.Lock()
	defer p.mu.Unlock()
	var out []Case
	for _, c := range p.st.Cases {
		if !c.Security && (c.Class == class || c.Class == ClassTask && taskClasses[class]) && splitOf(p.key, c.ID, p.cfg.DevPercent) == dev {
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
		case splitOf(p.key, c.ID, p.cfg.DevPercent) == dev:
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
