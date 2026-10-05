package meter

import (
	"bytes"
	"encoding/json"
	"math"
	"net/http"
	"strings"
)

// usageWriter passes a model response to the guest and reads the usage the
// provider reported in it. Once a write to the guest fails (it hung up),
// the rest is discarded, but the writer keeps accepting it, so the model
// egress reads the provider's answer to the end and its usage is charged.
type usageWriter struct {
	w    http.ResponseWriter
	max  int64 // largest body or stream line examined
	dead bool  // the guest stopped reading
	mode int   // 0 undecided, 1 JSON body, 2 event stream
	n    int64 // bytes seen

	buf  bytes.Buffer // JSON body, or the current stream line
	skip bool         // the current stream line passed max
	over bool         // the JSON body passed max

	u   usage
	rep *usage // reported beside the body (ReportUsage), if any
}

// usage is what the provider reported, plus an estimate from content.
type usage struct {
	in, out       int64 // reported; max seen, since stream counts are cumulative
	sawIn, sawOut bool
	chars         int64 // content and argument characters seen
	unread        int64 // bytes that could not be examined
	done          bool  // the stream reached its end marker
}

func (u *usageWriter) Header() http.Header { return u.w.Header() }

func (u *usageWriter) WriteHeader(code int) {
	if !u.dead {
		u.w.WriteHeader(code)
	}
}

func (u *usageWriter) Write(b []byte) (int, error) {
	if u.mode == 0 {
		u.mode = 1
		if strings.HasPrefix(strings.ToLower(u.w.Header().Get("Content-Type")), "text/event-stream") {
			u.mode = 2
		}
	}
	u.n += int64(len(b))
	u.observe(b)
	if !u.dead {
		if _, err := u.w.Write(b); err != nil {
			u.dead = true
		}
	}
	return len(b), nil
}

func (u *usageWriter) Flush() {
	if f, ok := u.w.(http.Flusher); ok && !u.dead {
		f.Flush()
	}
}

func (u *usageWriter) observe(b []byte) {
	if u.mode == 1 {
		if u.over {
			return
		}
		if int64(u.buf.Len()+len(b)) > u.max {
			u.over = true
			u.buf.Reset()
			return
		}
		u.buf.Write(b)
		return
	}
	for len(b) > 0 {
		i := bytes.IndexByte(b, '\n')
		part := b
		if i >= 0 {
			part = b[:i]
		}
		if !u.skip {
			if int64(u.buf.Len()+len(part)) > u.max {
				u.skip = true
				u.u.unread += int64(u.buf.Len())
				u.buf.Reset()
			} else {
				u.buf.Write(part)
			}
		}
		if u.skip {
			u.u.unread += int64(len(part))
		}
		if i < 0 {
			return
		}
		if !u.skip {
			u.line(u.buf.Bytes())
		}
		u.buf.Reset()
		u.skip = false
		b = b[i+1:]
	}
}

// line reads one event-stream line; only data lines carry JSON.
func (u *usageWriter) line(l []byte) {
	l = bytes.TrimSuffix(l, []byte("\r"))
	d, ok := bytes.CutPrefix(l, []byte("data:"))
	if !ok {
		return
	}
	d = bytes.TrimSpace(d)
	if bytes.Equal(d, []byte("[DONE]")) {
		u.u.done = true // OpenAI's end of stream
		return
	}
	u.u.doc(d)
}

// used is the call's total use (OP-8, arbitrator's rule). A response that
// completed normally and carries provider-reported usage is charged that
// usage. Otherwise output is the content the broker counted itself, and on
// a stream cut off before its end that count is also the least output
// charged, whatever usage arrived before the cut. Input without reported
// usage is in, the request estimate. A body too large to read is charged
// by its size.
func (u *usageWriter) used(in int64) int64 {
	complete := false
	switch u.mode {
	case 1:
		if u.over {
			u.u.unread += u.n
		} else {
			complete = u.u.doc(u.buf.Bytes())
		}
	case 2:
		if u.buf.Len() > 0 && !u.skip {
			u.line(u.buf.Bytes()) // a last line with no newline
		}
		complete = u.u.done
	}
	rin, rout, sawIn, sawOut := u.u.in, u.u.out, u.u.sawIn, u.u.sawOut
	if r := u.rep; r != nil {
		// The usage the vault process reported in the provider's own
		// shape outranks what the router rendered into the body.
		if r.sawIn {
			rin, sawIn = r.in, true
		}
		if r.sawOut {
			rout, sawOut = r.out, true
		}
		complete = complete && r.done
	}
	if sawIn {
		in = rin
	}
	counted := Tokens(u.u.chars + u.u.unread)
	out := counted
	if sawOut && complete {
		out = rout
	} else if sawOut {
		out = max(rout, counted)
	}
	return in + out
}

// doc reads one JSON document: an OpenAI or Anthropic response, or one
// stream event of either. It reports whether the document parsed.
func (u *usage) doc(b []byte) bool {
	if len(b) == 0 || b[0] != '{' {
		return false
	}
	var d map[string]any
	if json.Unmarshal(b, &d) != nil {
		u.unread += int64(len(b))
		return false
	}
	u.report(d["usage"])
	if msg, ok := d["message"].(map[string]any); ok {
		u.report(msg["usage"]) // Anthropic message_start
	}
	if d["type"] == "message_stop" {
		u.done = true // Anthropic's end of stream
	}
	u.chars += content(d, "", 0)
	return true
}

// Cached input is charged at the provider's cached weight. Anthropic:
// cache reads 0.1, cache writes 1.25 of base input. OpenAI's discount
// varies by model (50 to 90 percent off); the smallest, 50, is used.
const (
	anthropicCacheRead  = 0.1
	anthropicCacheWrite = 1.25
	openAICached        = 0.5
)

// report reads a usage object. OpenAI: prompt_tokens (cached_tokens among
// them), completion_tokens (reasoning included). Anthropic: input_tokens
// plus cache reads and writes, output_tokens (cumulative in a stream).
func (u *usage) report(v any) {
	m, ok := v.(map[string]any)
	if !ok {
		return
	}
	num := func(m map[string]any, k string) (float64, bool) {
		f, ok := m[k].(float64)
		if !ok || f < 0 || f > 1e12 {
			return 0, false
		}
		return f, true
	}
	in, okIn := num(m, "prompt_tokens")
	if okIn {
		if d, ok := m["prompt_tokens_details"].(map[string]any); ok {
			if c, ok := num(d, "cached_tokens"); ok && c <= in {
				in -= c * (1 - openAICached)
			}
		}
	} else if a, ok := num(m, "input_tokens"); ok {
		in, okIn = a, true
		if c, ok := num(m, "cache_read_input_tokens"); ok {
			in += c * anthropicCacheRead
		}
		if c, ok := num(m, "cache_creation_input_tokens"); ok {
			in += c * anthropicCacheWrite
		}
	}
	if okIn {
		u.in, u.sawIn = max(u.in, int64(math.Ceil(in))), true
	}
	out, okOut := num(m, "completion_tokens")
	if !okOut {
		out, okOut = num(m, "output_tokens")
	}
	if okOut {
		u.out, u.sawOut = max(u.out, int64(out)), true
	}
}

// contentKeys hold model output: text, tool arguments, and reasoning.
var contentKeys = map[string]bool{
	"content": true, "text": true, "arguments": true, "partial_json": true,
	"thinking": true, "reasoning": true, "reasoning_content": true, "refusal": true,
}

// content totals the characters of strings under contentKeys.
func content(v any, key string, depth int) int64 {
	if depth > 32 {
		return 0
	}
	switch v := v.(type) {
	case string:
		if contentKeys[key] {
			return int64(len(v))
		}
	case map[string]any:
		var n int64
		for k, e := range v {
			n += content(e, k, depth+1)
		}
		return n
	case []any:
		var n int64
		for _, e := range v {
			n += content(e, key, depth+1)
		}
		return n
	}
	return 0
}
