package journal

import "fmt"

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
