package change

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"
)

// ErrInterrupted: the evaluation's context ended part way, as when the
// loop scheduler preempts spare-time work for the owner's (LOOP-1,
// RES-1). It is never a verdict: nothing is proposed, reverted, or
// counted, and the pairs that completed are kept so the next evaluation
// of the same trees runs only the rest (PE1). It wraps the context's
// error.
var ErrInterrupted = errors.New("change: evaluation interrupted; completed pairs kept")

// ResumeFor is how long a preempted evaluation's completed pairs are
// kept, and MaxKeptPairs how many at most, oldest dropped first.
const (
	ResumeFor    = 12 * time.Hour
	MaxKeptPairs = 4096
)

// MaxInterruptions is how many times a candidate-side run of one case may
// be cut short before the candidate is failed on that case without
// another run (security F1 on #103). A candidate can drive host memory
// pressure, and so the scheduler's preemption, by thrashing in its own
// machine; without a limit it could re-roll a case it is failing until it
// passes. An owner's preemption seldom lands on the same pair twice.
const MaxInterruptions = 2

// pairResult is one case's outcome on the two trees of an evaluation:
// booleans only, never case content or output. baseDone and nextDone say
// which sides finished; interrupted counts candidate-side runs cut short.
type pairResult struct {
	BaseOK, BaseEv, NextOK, NextEv bool
	baseDone, nextDone             bool
	interrupted                    int
	at                             time.Time
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
	now := p.cfg.Now()
	r.at = now
	p.kept[key] = r
	if len(p.kept) <= MaxKeptPairs {
		return
	}
	for k, v := range p.kept {
		if now.Sub(v.at) > ResumeFor {
			delete(p.kept, k)
		}
	}
	for len(p.kept) > MaxKeptPairs {
		oldest := ""
		for k, v := range p.kept {
			if oldest == "" || v.at.Before(p.kept[oldest].at) || v.at.Equal(p.kept[oldest].at) && k < oldest {
				oldest = k
			}
		}
		delete(p.kept, oldest)
	}
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
