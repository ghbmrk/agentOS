package meter

import (
	"bytes"
	"encoding/json"
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

	u usage
}

// usage is what the provider reported, plus an estimate from content.
type usage struct {
	in, out       int64 // reported; max seen, since stream counts are cumulative
	sawIn, sawOut bool
	chars         int64 // content and argument characters seen
	unread        int64 // bytes that could not be examined
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
	u.u.doc(bytes.TrimSpace(d))
}

// used is the call's total use: reported usage where the provider gave it,
// otherwise in (the request estimate) for input and the content estimate
// for output. A body too large to read is charged by its size.
func (u *usageWriter) used(in int64) int64 {
	if u.mode == 1 {
		if u.over {
			u.u.unread += u.n
		} else {
			u.u.doc(u.buf.Bytes())
		}
	} else if u.mode == 2 && u.buf.Len() > 0 && !u.skip {
		u.u.doc(u.buf.Bytes()) // a last line with no newline
	}
	if u.u.sawIn {
		in = u.u.in
	}
	out := Tokens(u.u.chars + u.u.unread)
	if u.u.sawOut {
		out = u.u.out
	}
	return in + out
}

// doc reads one JSON document: an OpenAI or Anthropic response, or one
// stream event of either.
func (u *usage) doc(b []byte) {
	if len(b) == 0 || b[0] != '{' {
		return
	}
	var d map[string]any
	if json.Unmarshal(b, &d) != nil {
		u.unread += int64(len(b))
		return
	}
	u.report(d["usage"])
	if msg, ok := d["message"].(map[string]any); ok {
		u.report(msg["usage"]) // Anthropic message_start
	}
	u.chars += content(d, "", 0)
}

// report reads a usage object. OpenAI: prompt_tokens, completion_tokens
// (which include reasoning tokens). Anthropic: input_tokens plus cache
// reads and writes, output_tokens (cumulative in a stream).
func (u *usage) report(v any) {
	m, ok := v.(map[string]any)
	if !ok {
		return
	}
	num := func(k string) (int64, bool) {
		f, ok := m[k].(float64)
		if !ok || f < 0 || f > 1e12 {
			return 0, false
		}
		return int64(f), true
	}
	in, okIn := num("prompt_tokens")
	if !okIn {
		if a, ok := num("input_tokens"); ok {
			in, okIn = a, true
			for _, k := range []string{"cache_creation_input_tokens", "cache_read_input_tokens"} {
				if c, ok := num(k); ok {
					in += c
				}
			}
		}
	}
	if okIn {
		u.in, u.sawIn = max(u.in, in), true
	}
	out, okOut := num("completion_tokens")
	if !okOut {
		out, okOut = num("output_tokens")
	}
	if okOut {
		u.out, u.sawOut = max(u.out, out), true
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
