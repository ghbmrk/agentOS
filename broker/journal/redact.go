package journal

import (
	"crypto/sha256"
	"fmt"
)

// scrub returns a copy of r with every free-text field redacted and clipped.
func (e *Engine) scrub(r Record) Record {
	r.Evidence = e.text(r.Evidence)
	r.Reason = e.text(r.Reason)
	r.Guest = e.text(r.Guest)
	if r.Intent != nil {
		in := e.scrubIntent(*r.Intent)
		r.Intent = &in
	}
	if r.Egress != nil {
		n := e.scrubEgress(*r.Egress)
		r.Egress = &n
	}
	return r
}

func (e *Engine) scrubIntent(in Intent) Intent {
	if in.Params != nil {
		in.Params = e.value(in.Params).(map[string]any)
	}
	in.Recipients = e.strings(in.Recipients)
	in.Preconditions = e.strings(in.Preconditions)
	return in
}

func (e *Engine) strings(ss []string) []string {
	if ss == nil {
		return nil
	}
	out := make([]string, len(ss))
	for i, s := range ss {
		out[i] = e.redact(s)
	}
	return out
}

// value redacts every string inside a decoded JSON value.
func (e *Engine) value(v any) any {
	switch t := v.(type) {
	case string:
		return e.redact(t)
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, x := range t {
			out[k] = e.value(x)
		}
		return out
	case []any:
		out := make([]any, len(t))
		for i, x := range t {
			out[i] = e.value(x)
		}
		return out
	}
	return v
}

// text redacts, then clips, free text.
func (e *Engine) text(s string) string {
	s = e.redact(s)
	if len(s) <= MaxTextBytes {
		return s
	}
	return fmt.Sprintf("%s…[cut %d bytes, sha256 %x]", s[:MaxTextBytes], len(s)-MaxTextBytes, sha256.Sum256([]byte(s)))
}
