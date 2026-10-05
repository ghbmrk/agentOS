package meter

import (
	"bytes"
	"context"
	"encoding/json"
	"math"
	"net/http"
	"strings"
	"sync"
)

// Usage is what the handler that served a metered call (the model router)
// read from the provider: input excluding cached tokens, cache reads and
// writes, and output; Reported says the provider gave the counts, Complete
// that the response ended normally, OutputChars the content, argument,
// and reasoning characters the provider produced. Provider names the
// egress adapter, which sets the cache weights.
type Usage struct {
	Provider                             string
	Input, Output, CacheRead, CacheWrite int64
	Reported, Complete                   bool
	OutputChars                          int64
}

type reportKey struct{}

type reportSlot struct {
	mu sync.Mutex
	u  *Usage
}

func (s *reportSlot) get() *Usage {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.u
}

// Report gives the metered call running on ctx its provider's usage. The
// meter settles from it instead of from the response the guest received,
// which may not carry usage. It reports whether ctx is a metered call.
// Only broker code holds the context; a guest cannot reach it.
func Report(ctx context.Context, u Usage) bool {
	s, ok := ctx.Value(reportKey{}).(*reportSlot)
	if !ok {
		return false
	}
	s.mu.Lock()
	s.u = &u
	s.mu.Unlock()
	return true
}

// cacheWeights are what a provider bills cached input at, relative to
// base input: reads and writes. A provider not listed counts reads in full
// and writes at the higher Anthropic weight.
func cacheWeights(provider string) (read, write float64) {
	switch provider {
	case "anthropic":
		return anthropicCacheRead, anthropicCacheWrite
	case "openai":
		return openAICached, 1
	}
	return 1, anthropicCacheWrite
}

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
	if !u.u.doc(d) {
		u.u.unread += int64(len(d))
	}
}

// used is the call's total use (OP-8, arbitrator's rule). A response that
// completed normally and carries provider-reported usage is charged that
// usage. Otherwise output is the content counted (by the server's report
// or by the broker itself, whichever is larger), and on a response cut
// off before its end that count is also the least output charged,
// whatever usage arrived before the cut. Input without reported usage is
// in, the request estimate. A body that could not be read (too large, or
// not the JSON it claimed to be) is charged by its size. A report from
// the serving handler (rep) takes the place of what the broker read from
// the response.
func (u *usageWriter) used(in int64, rep *Usage) int64 {
	complete := false
	switch u.mode {
	case 1:
		if u.over || !u.u.doc(u.buf.Bytes()) {
			u.u.unread += u.n
		} else {
			complete = true
		}
	case 2:
		if u.buf.Len() > 0 && !u.skip {
			u.line(u.buf.Bytes()) // a last line with no newline
		}
		complete = u.u.done
	}
	counted := Tokens(u.u.chars + u.u.unread)
	reported, sawIn, sawOut, outRep := u.u.in, u.u.sawIn, u.u.sawOut, u.u.out
	if rep != nil {
		complete = rep.Complete
		counted = max(counted, Tokens(max(rep.OutputChars, 0)))
		sawIn, sawOut = rep.Reported, rep.Reported
		if rep.Reported {
			r, w := cacheWeights(rep.Provider)
			reported = max(rep.Input, 0) + int64(math.Ceil(float64(max(rep.CacheRead, 0))*r+float64(max(rep.CacheWrite, 0))*w))
			outRep = max(rep.Output, 0)
		}
	}
	if sawIn {
		in = reported
	}
	out := counted
	if sawOut && complete {
		out = outRep
	} else if sawOut {
		out = max(outRep, counted)
	}
	return in + out
}

// doc reads one JSON document: an OpenAI or Anthropic response, or one
// stream event of either. It reports whether the document parsed.
func (u *usage) doc(b []byte) bool {
	var d map[string]any
	if len(b) == 0 || b[0] != '{' || json.Unmarshal(b, &d) != nil {
		return false
	}
	u.report(d["usage"])
	if msg, ok := d["message"].(map[string]any); ok {
		u.report(msg["usage"]) // Anthropic message_start
	}
	if d["type"] == "message_stop" {
		u.done = true // Anthropic's end of stream
	}
	if delta, ok := d["delta"].(map[string]any); ok && d["type"] == "message_delta" && delta["stop_reason"] != nil {
		u.done = true // Anthropic's stop reason: the message ended normally
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
