package change

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// ErrInterrupted: the evaluation's context ended part way, as when the
// loop scheduler preempts spare-time work for the owner's (LOOP-1,
// RES-1). It is never a verdict: nothing is proposed, reverted, or
// counted, and the pairs that completed are kept so the next evaluation
// of the same trees runs only the rest (PE1). It wraps the context's
// error.
var ErrInterrupted = errors.New("change: evaluation interrupted; completed pairs kept")

// ErrOwnerPreempt marks an interruption no candidate can cause (PE5):
// STOP, the owner's accepted work arriving without memory pressure, or
// admission with no room for the replay machine, which it reckons on
// declared budgets. Such a cut never counts toward MaxInterruptions. Only
// host code attaches it, as an error value: the loop scheduler as its
// job context's cause, and the replay evaluator around admission's
// ErrNoRoom (arbitrator on PE5). It is never derived from replay or guest
// output, so its text in an error is just text.
var ErrOwnerPreempt = errors.New("change: interrupted for the owner's work")

// The host's exempt causes, each logged by a fixed class only (security
// P5 on PE5). Each wraps ErrOwnerPreempt; ErrOwnerPreempt alone logs as
// owner-work.
var (
	// ErrOwnerStop: STOP, LOOPS OFF, or the owner pausing a loop.
	ErrOwnerStop = fmt.Errorf("change: stopped by the owner: %w", ErrOwnerPreempt)
	// ErrOwnerWork: the owner's accepted work arrived without pressure.
	ErrOwnerWork = fmt.Errorf("change: the owner's work needs the box: %w", ErrOwnerPreempt)
	// ErrNoRoomPreempt: admission had no room for the replay machine's
	// fixed budget, with no other replay machine holding room.
	ErrNoRoomPreempt = fmt.Errorf("change: no room for the replay machine: %w", ErrOwnerPreempt)
	// ErrClassRevoke: admission revoked the replay machine for the owner's
	// higher-class work without pressure, as it recorded when it chose
	// the victim.
	ErrClassRevoke = fmt.Errorf("change: revoked for the owner's work: %w", ErrOwnerPreempt)
)

// MaxExempt is how many exempt interruptions one candidate may take before
// it is parked (security P4 on PE5): it is not struck and gets no verdict,
// but its evaluation is refused with ErrParked unless the scheduler marks
// the evaluator idle (WithIdle). Parking ends the pass for that candidate,
// but the idle second pass may pick it again at once, so MaxExempt bounds
// what one pass spends, not what one candidate spends. The count is per
// process and resets on restart. What bounds one candidate is
// MaxExemptPerCase, saved across restarts (PE5b), and the idle evaluator
// takes parked candidates in turns (parkedMayRunLocked).
const MaxExempt = 6

// ErrParked: the candidate was cut short for the owner MaxExempt times and
// waits until the evaluator is idle. It wraps ErrInterrupted, so callers
// keep the candidate and the pipeline keeps its pairs (ResumeFor,
// MaxKeptPairs).
var ErrParked = fmt.Errorf("change: candidate parked until the evaluator is idle: %w", ErrInterrupted)

type idleKey struct{}

// WithIdle marks ctx as the evaluator's idle time: nothing else is waiting
// for it, so a parked candidate may run. Only the loop scheduler sets it.
func WithIdle(ctx context.Context) context.Context { return context.WithValue(ctx, idleKey{}, true) }

// IsIdle reports whether ctx carries WithIdle's mark.
func IsIdle(ctx context.Context) bool { v, _ := ctx.Value(idleKey{}).(bool); return v }

// maxExemptCandidates bounds the exempt counts kept; past it the oldest
// is dropped.
const maxExemptCandidates = 1024

// MaxExemptPerCase is how many exempt cuts one candidate-side run of one
// case may take (PE5b, security B2 on #127). The next cut of that pair
// counts as an ordinary interruption under MaxInterruptions, so owner
// cuts can re-roll a case a bounded number of times, however often the
// candidate is parked and resumed.
const MaxExemptPerCase = 2

// maxCuts bounds the saved cut counts; past it the oldest is dropped.
const maxCuts = 1024

// cutCount is one (candidate, case) pair's cuts of its candidate-side
// run: exempt ones (MaxExemptPerCase) and counted ones
// (MaxInterruptions). It is saved with the pipeline's state, so a restart
// cannot reset it, and it lasts as long as the pair could be resumed
// (ResumeFor). Counts and a time only; the key is resumeKey's hash.
type cutCount struct {
	Exempt  int       `json:"exempt,omitempty"`
	Counted int       `json:"counted,omitempty"`
	At      time.Time `json:"at"`
}

// cutsLocked returns key's cut counts, dropping them once expired.
func (p *Pipeline) cutsLocked(key string) cutCount {
	c, ok := p.st.Cuts[key]
	if ok && p.cfg.Now().Sub(c.At) > ResumeFor {
		delete(p.st.Cuts, key)
		return cutCount{}
	}
	return c
}

// cutLocked records one cut of key's candidate-side run and reports
// whether it counts: a cut that is not exempt, or an exempt cut past
// MaxExemptPerCase. The caller saves the state.
func (p *Pipeline) cutLocked(key string, exempt bool) (counted bool) {
	c := p.cutsLocked(key)
	if exempt && c.Exempt < MaxExemptPerCase {
		c.Exempt++
	} else {
		c.Counted++
		counted = true
	}
	c.At = p.cfg.Now()
	if p.st.Cuts == nil {
		p.st.Cuts = map[string]cutCount{}
	}
	p.st.Cuts[key] = c
	for len(p.st.Cuts) > maxCuts {
		oldest := ""
		for k, v := range p.st.Cuts {
			if oldest == "" || v.At.Before(p.st.Cuts[oldest].At) || v.At.Equal(p.st.Cuts[oldest].At) && k < oldest {
				oldest = k
			}
		}
		delete(p.st.Cuts, oldest)
	}
	return counted
}

// parkMark is a parked candidate's place in the idle evaluator's turns
// (PE5b): when it was last refused, last ran idle, and last yielded to
// another, as values of Pipeline.parkSeq.
type parkMark struct{ refused, ran, yielded uint64 }

// parkedMayRunLocked reports whether candidate ck may be evaluated now.
// One that is not parked may. A parked one runs only when ctx marks the
// evaluator idle, and then not straight after its own idle run while
// another parked candidate has been waiting since; that one goes first.
// Yielding is recorded, so a candidate that waited once and was not
// offered again holds the evaluator back at most one idle pass.
func (p *Pipeline) parkedMayRunLocked(ctx context.Context, ck string) bool {
	if p.exempt[ck] < MaxExempt {
		return true
	}
	if p.parks == nil {
		p.parks = map[string]*parkMark{}
	}
	m := p.parks[ck]
	if m == nil {
		m = &parkMark{}
		p.parks[ck] = m
	}
	p.parkSeq++
	if !IsIdle(ctx) {
		m.refused = p.parkSeq
		return false
	}
	if m.ran > 0 {
		since := max(m.ran, m.yielded)
		for k, o := range p.parks {
			if k != ck && o.refused > since && o.ran < m.ran {
				m.yielded = p.parkSeq
				return false
			}
		}
	}
	m.ran = p.parkSeq
	return true
}

// exemptClass is an exempt cut's fixed log class.
func exemptClass(cause error) string {
	switch {
	case errors.Is(cause, ErrOwnerStop):
		return "owner-stop"
	case errors.Is(cause, ErrNoRoomPreempt):
		return "no-room"
	case errors.Is(cause, ErrClassRevoke):
		return "class-revoke"
	}
	return "owner-work"
}

// ErrPressurePreempt is the scheduler's cause for a preemption under
// memory pressure, which a candidate can drive by thrashing in its own
// machine: it counts, and pressure wins when both hold (arbitrator on
// PE5).
var ErrPressurePreempt = errors.New("change: interrupted under memory pressure")

// ResumeFor is how long a preempted evaluation's completed pairs are
// kept, and MaxKeptPairs how many at most, oldest dropped first.
const (
	ResumeFor    = 12 * time.Hour
	MaxKeptPairs = 4096
)

// MaxInterruptions is how many times a candidate-side run of one case may
// be cut short, for a cause the candidate could have driven, before the
// candidate is failed on that case without another run (security F1 on
// #103; ErrOwnerPreempt's cuts are not counted, PE5). A candidate can drive host memory
// pressure, and so the scheduler's preemption, by thrashing in its own
// machine; without a limit it could re-roll a case it is failing until it
// passes. An owner's preemption seldom lands on the same pair twice.
const MaxInterruptions = 2

// cutClass is a counted cut's fixed log class, never the error's text.
func cutClass(cause error, evaluator bool) string {
	switch {
	case errors.Is(cause, ErrPressurePreempt):
		return "pressure"
	case evaluator:
		return "refused or revoked"
	}
	return "unknown"
}

// pairResult is one case's outcome on the two trees of an evaluation:
// booleans only, never case content or output. baseDone and nextDone say
// which sides finished. Cut counts are kept apart, in the saved state
// (cutCount).
type pairResult struct {
	BaseOK, BaseEv, NextOK, NextEv bool
	baseDone, nextDone             bool
	at                             time.Time
	seq                            uint64 // put order (Pipeline.keptOrder)
}

// resumeKey binds a pair to the exact base tree, candidate tree, case
// (its full content, so a case changed since is run afresh), and the
// evaluator's identity (Config.EvaluatorID), so results from two
// evaluator configurations never mix (security R1 on #103).
func (p *Pipeline) resumeKey(base, next Tree, c Case) string {
	id := ""
	if p.cfg.EvaluatorID != nil {
		id = p.cfg.EvaluatorID()
	}
	return resumeKey(id, base, next, c)
}

func resumeKey(evaluator string, base, next Tree, c Case) string {
	cb, _ := json.Marshal(c)
	h := sha256.New()
	h.Write([]byte(evaluator))
	h.Write([]byte{0})
	h.Write([]byte(base.Hash()))
	h.Write([]byte{0})
	h.Write([]byte(next.Hash()))
	h.Write([]byte{0})
	h.Write(cb)
	return hex.EncodeToString(h.Sum(nil))
}

// keptLocked returns the kept pair for key, if it has not expired.
func (p *Pipeline) keptLocked(key string) (pairResult, bool) {
	r, ok := p.kept[key]
	if !ok {
		return pairResult{}, false
	}
	if p.cfg.Now().Sub(r.at) > ResumeFor {
		delete(p.kept, key)
		return pairResult{}, false
	}
	return r, true
}

// keepLocked keeps what finished of a pair, dropping expired entries and
// then the oldest while over MaxKeptPairs.
func (p *Pipeline) keepLocked(key string, r pairResult) {
	p.putLocked(key, r)
}

func (p *Pipeline) putLocked(key string, r pairResult) {
	p.keptSeq++
	r.at, r.seq = p.cfg.Now(), p.keptSeq
	p.kept[key] = r
	p.keptOrder = append(p.keptOrder, keptAt{key, r.seq})
	// Drop the oldest while over the cap. An order entry whose key was
	// put again since, or removed, is stale and skipped, so each entry is
	// looked at once: amortized O(1) per put (L3 nit on #103).
	for len(p.kept) > MaxKeptPairs && len(p.keptOrder) > 0 {
		o := p.keptOrder[0]
		p.keptOrder = p.keptOrder[1:]
		if v, ok := p.kept[o.key]; ok && v.seq == o.seq {
			delete(p.kept, o.key)
		}
	}
	if len(p.keptOrder) > 2*MaxKeptPairs {
		p.compactKeptLocked()
	}
}

// keptAt is an entry of the pipeline's kept order: a key and its put's
// sequence number.
type keptAt struct {
	key string
	seq uint64
}

// compactKeptLocked rebuilds the kept order from the kept entries, oldest
// first, dropping stale order entries.
func (p *Pipeline) compactKeptLocked() {
	var live []keptAt
	for _, o := range p.keptOrder {
		if v, ok := p.kept[o.key]; ok && v.seq == o.seq {
			live = append(live, o)
		}
	}
	p.keptOrder = live
}

// keptPairs counts the pairs kept with both sides finished.
func (p *Pipeline) keptPairs() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	n := 0
	for _, r := range p.kept {
		if r.baseDone && r.nextDone {
			n++
		}
	}
	return n
}

// keptSides counts the finished sides kept.
func (p *Pipeline) keptSides() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	n := 0
	for _, r := range p.kept {
		if r.baseDone {
			n++
		}
		if r.nextDone {
			n++
		}
	}
	return n
}

// candidateKey names one candidate's evaluation: the evaluator's identity
// and the two trees.
func (p *Pipeline) candidateKey(base, next Tree) string {
	id := ""
	if p.cfg.EvaluatorID != nil {
		id = p.cfg.EvaluatorID()
	}
	h := sha256.New()
	h.Write([]byte(id))
	h.Write([]byte{0})
	h.Write([]byte(base.Hash()))
	h.Write([]byte{0})
	h.Write([]byte(next.Hash()))
	return hex.EncodeToString(h.Sum(nil))
}

// exemptLocked adds one exempt interruption to key's count, dropping the
// oldest key past maxExemptCandidates.
func (p *Pipeline) exemptLocked(key string) {
	if p.exempt == nil {
		p.exempt = map[string]int{}
	}
	if _, ok := p.exempt[key]; !ok {
		p.exemptOrder = append(p.exemptOrder, key)
	}
	p.exempt[key]++
	for len(p.exemptOrder) > maxExemptCandidates {
		delete(p.exempt, p.exemptOrder[0])
		delete(p.parks, p.exemptOrder[0])
		p.exemptOrder = p.exemptOrder[1:]
	}
}
