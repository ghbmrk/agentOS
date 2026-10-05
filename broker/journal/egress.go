package journal

import (
	"fmt"
	"strings"
	"sync"
	"time"
)

// EgressNote is an egress decision that is not an intent: a request the
// egress proxy denied (ADP-10), or a model call the spend meter refused
// (OP-8). It names where the request came from and why it stopped, never
// the request's path, headers, or body.
type EgressNote struct {
	Machine   string `json:"machine"`
	Adapter   string `json:"adapter,omitempty"`
	Operation string `json:"operation,omitempty"`
	Method    string `json:"method,omitempty"`
	Status    int    `json:"status,omitempty"`
	Reason    string `json:"reason"`
	// Suppressed counts notes like this one (same machine and reason) that
	// were folded into it rather than journaled one by one.
	Suppressed int `json:"suppressed,omitempty"`
}

// RecordEgress journals an egress decision. It is audit only: it changes no
// intent, and STOP does not hold it.
func (e *Engine) RecordEgress(n EgressNote) error {
	if n.Machine == "" || n.Reason == "" || n.Suppressed < 0 {
		return fmt.Errorf("%w: egress note needs a machine and a reason", ErrInvalid)
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.broken != nil {
		return e.broken
	}
	return e.commit(Record{Type: RecEgress, Egress: &n})
}

// scrubEgress keeps identifiers only when they look like identifiers (the
// method is guest-chosen) and redacts and clips the reason, which can quote
// guest input.
func (e *Engine) scrubEgress(n EgressNote) EgressNote {
	n.Machine, n.Adapter, n.Operation, n.Method = token(n.Machine), token(n.Adapter), token(n.Operation), token(n.Method)
	n.Reason = e.text(n.Reason)
	return n
}

// token returns s if it is a short identifier, "?" if it is not.
func token(s string) string {
	if s == "" {
		return ""
	}
	if len(s) > 64 {
		return "?"
	}
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_' || c == '.' || c == ':') {
			return "?"
		}
	}
	return s
}

// EgressGate coalesces egress denials so a looping guest cannot fill the
// journal: per machine and reason class (EgressReasonClass), the first
// note in a window (default one minute) is admitted, the rest are
// counted, and the count rides on the next admitted note for that machine
// and reason (Suppressed). Past maxEgressKeys live entries, new classes
// share one overflow entry per machine. The zero value is ready to use.
type EgressGate struct {
	Window time.Duration    // default 1 minute
	Now    func() time.Time // default time.Now

	mu   sync.Mutex
	seen map[[2]string]*egressSeen
}

type egressSeen struct {
	since      time.Time
	suppressed int
}

// maxEgressKeys bounds the coalescing table; past it, expired entries are
// pruned.
const maxEgressKeys = 4096

// EgressReasonClass is a denial reason without its quoted parts: the fixed
// text the denier chose, never anything the request named.
func EgressReasonClass(reason string) string {
	if i := strings.IndexByte(reason, '"'); i >= 0 {
		return reason[:i]
	}
	return reason
}

// Admit reports whether n is journaled now, and sets its Suppressed count.
func (g *EgressGate) Admit(n *EgressNote) bool {
	win, now := g.Window, time.Now()
	if win <= 0 {
		win = time.Minute
	}
	if g.Now != nil {
		now = g.Now()
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.seen == nil {
		g.seen = map[[2]string]*egressSeen{}
	}
	k := [2]string{n.Machine, EgressReasonClass(n.Reason)}
	d := g.seen[k]
	if d != nil && now.Sub(d.since) < win {
		d.suppressed++
		return false
	}
	if d != nil {
		n.Suppressed = d.suppressed
	}
	if len(g.seen) >= maxEgressKeys && d == nil {
		for k2, d2 := range g.seen {
			if now.Sub(d2.since) >= win {
				delete(g.seen, k2)
			}
		}
	}
	if len(g.seen) >= maxEgressKeys && d == nil {
		// Every key is live: fold the note into the machine's overflow
		// entry, never admit it untracked. Machine names are the
		// broker's, so overflow entries are bounded by the machines.
		k = [2]string{n.Machine, egressOverflow}
		if d = g.seen[k]; d != nil && now.Sub(d.since) < win {
			d.suppressed++
			return false
		}
		if d != nil {
			n.Suppressed = d.suppressed
		}
	}
	g.seen[k] = &egressSeen{since: now}
	return true
}

// egressOverflow is the reason class of a machine's overflow entry; no
// reason class starts with a NUL.
const egressOverflow = "\x00overflow"
