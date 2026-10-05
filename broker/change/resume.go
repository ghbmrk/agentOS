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

// pairResult is one case's outcome on both trees of an evaluation:
// booleans only, never case content or output.
type pairResult struct {
	BaseOK, BaseEv, NextOK, NextEv bool
	at                             time.Time
}

// resumeKey binds a pair to the exact base tree, candidate tree, and case
// (its full content, so a case changed since is run afresh).
func resumeKey(base, next Tree, c Case) string {
	cb, _ := json.Marshal(c)
	h := sha256.New()
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

// keepLocked keeps a completed pair, dropping expired pairs and then the
// oldest while over MaxKeptPairs.
func (p *Pipeline) keepLocked(key string, r pairResult) {
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

// keptPairs counts the pairs kept for resuming.
func (p *Pipeline) keptPairs() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.kept)
}
