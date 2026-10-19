package meter

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
)

// errBusy is a bound call that waited for the machine's other calls in
// flight to settle, and they did not before its wait ended.
var errBusy = errors.New("meter: the machine's other model calls are still in flight")

// flight counts a machine's WrapBound calls in flight. idle, when set, is
// closed once the count reaches zero.
type flight struct {
	n    int
	idle chan struct{}
}

// startBound admits a WrapBound call. A call with none of its machine's
// calls in flight is admitted at the input estimate, as Wrap admits it: it
// is the only call whose shortfall is not yet charged, so a limit is soft
// by that one call. A call that overlaps others is admitted at bound, one
// token per input byte. One refused at bound waits for the others to
// settle and tries again, so it gets 429 only when the estimate itself
// does not fit (a refusal at bound is not a spent limit). The wait ends
// with ctx (errBusy). It returns the input the call was admitted at, and
// a func to call after the call has settled.
func (m *Meter) startBound(ctx context.Context, machine string, goal string, in, bound, reserve int64) (*Call, int64, func(), error) {
	for {
		m.fmu.Lock()
		f := m.flights[machine]
		if f == nil {
			f = &flight{}
			m.flights[machine] = f
		}
		admit := bound
		if f.n == 0 {
			admit = in
		}
		c, err := m.start(machine, goal, admit, reserve, admit == in)
		if err == nil {
			f.n++
			m.fmu.Unlock()
			return c, admit, func() { m.land(machine) }, nil
		}
		if f.n == 0 {
			delete(m.flights, machine)
		}
		if admit == in || !errors.Is(err, ErrExhausted) {
			m.fmu.Unlock()
			return nil, 0, nil, err
		}
		if f.idle == nil {
			f.idle = make(chan struct{})
		}
		idle := f.idle
		m.fmu.Unlock()
		select {
		case <-idle:
		case <-ctx.Done():
			return nil, 0, nil, errBusy
		}
	}
}

func (m *Meter) land(machine string) {
	m.fmu.Lock()
	defer m.fmu.Unlock()
	f := m.flights[machine]
	if f.n--; f.n == 0 {
		if f.idle != nil {
			close(f.idle)
		}
		delete(m.flights, machine)
	}
}

// Overhead is what a WrapBound call is admitted at beyond its body's
// bytes: the system prompt a provider adds of its own (Anthropic's for
// tool use is a few hundred tokens) and the few tokens per message its
// chat template adds.
const Overhead = 1024

// textTypes are the part and item types a WrapBound call may carry in
// its messages: text, tool calls and their results, reasoning, citations
// and cache marks, which a provider bills by their tokens, at most one per
// byte. Images, audio, documents and files are billed by their pixels,
// duration or pages, which the bytes do not bound (a 530-byte inline PNG
// bills ~1,600 tokens, and a URL ~40 bytes), so any other type is refused.
var textTypes = map[string]bool{
	"text": true, "input_text": true, "output_text": true, "refusal": true,
	"message": true, "function": true, "function_call": true, "function_call_output": true,
	"tool_use": true, "tool_result": true, "thinking": true, "redacted_thinking": true,
	"reasoning": true, "summary_text": true, "ephemeral": true,
	"char_location": true, "page_location": true, "content_block_location": true,
}

// toolTypes are the tools a WrapBound call may declare: the guest's own,
// which run in the guest and come back as tool results in a later body.
// A provider-side tool (web search, code execution, a file search, an MCP
// server) brings content into the call the body does not hold.
var toolTypes = map[string]bool{"function": true, "custom": true}

// fetchKeys are top-level keys that bring content into the call the body
// does not hold: provider-side tools, and stored context (an earlier
// response, a conversation, a stored prompt). A WrapBound call carrying
// one, other than as null, is refused.
var fetchKeys = []string{"web_search_options", "mcp_servers", "container", "previous_response_id", "conversation", "prompt"}

// errBound is a body whose input tokens its bytes do not bound.
type errBound string

func (e errBound) Error() string {
	return string(e) + " is not accepted on this socket: the spend limit counts at most a token per byte, so only text, the guest's own tools and reasoning are"
}

// bounded refuses a body whose billed input its bytes may not bound
// (Overhead aside): one with a fetchKeys key, a tool outside toolTypes, or
// a part or item outside textTypes in its messages ("messages", "system",
// or the Responses API's "input"), at any depth, since an Anthropic tool
// result holds content blocks and a Responses function output holds
// items. A tool call's arguments ("input" below the top level,
// "arguments") are the model's own data and are not read. Keys compare
// case-folded, as in Object, so a refusal cannot be dodged by case. The
// body is limit's output, so it is valid JSON; the scan reads it in place,
// allocating only for an escaped key or type, so it adds nothing to what
// the route reserves (inflight.Model).
func bounded(body []byte) error {
	s := &scan{b: body}
	s.ws()
	if !s.eat('{') {
		return nil
	}
	err := s.object(func(k []byte) error {
		switch {
		case foldIn(k, fetchKeys...):
			s.ws()
			if bytes.HasPrefix(s.b[s.i:], []byte("null")) {
				s.i += 4
				return nil
			}
			return errBound(fmt.Sprintf("%q", s.key(k)))
		case foldIn(k, "messages", "system", "input"):
			return s.value(textTypes, "content of type %q")
		case foldIn(k, "tools"):
			return s.tools()
		}
		return s.value(nil, "")
	})
	if _, ok := err.(errBound); ok {
		return err
	}
	if err != nil {
		return errBound("a body the meter cannot read")
	}
	return nil
}

// errSyntax ends a scan of a body that is not valid JSON.
var errSyntax = errors.New("meter: unreadable body")

// scan reads JSON in place.
type scan struct {
	b []byte
	i int
}

func (s *scan) ws() {
	for s.i < len(s.b) && (s.b[s.i] == ' ' || s.b[s.i] == '\t' || s.b[s.i] == '\n' || s.b[s.i] == '\r') {
		s.i++
	}
}

func (s *scan) eat(c byte) bool {
	s.ws()
	if s.i < len(s.b) && s.b[s.i] == c {
		s.i++
		return true
	}
	return false
}

// str reads a string and returns its raw bytes, quotes excluded.
func (s *scan) str() ([]byte, error) {
	if !s.eat('"') {
		return nil, errSyntax
	}
	start := s.i
	for s.i < len(s.b) {
		switch s.b[s.i] {
		case '\\':
			s.i += 2
		case '"':
			s.i++
			return s.b[start : s.i-1], nil
		default:
			s.i++
		}
	}
	return nil, errSyntax
}

// key returns a raw string's value, unescaped.
func (s *scan) key(raw []byte) string {
	if bytes.IndexByte(raw, '\\') < 0 {
		return string(raw)
	}
	var v string
	if json.Unmarshal(append(append([]byte{'"'}, raw...), '"'), &v) != nil {
		return string(raw)
	}
	return v
}

// object reads an object's members, its '{' already read, calling f with
// each raw key once the reader is at its value; f reads the value.
func (s *scan) object(f func(k []byte) error) error {
	if s.eat('}') {
		return nil
	}
	for {
		k, err := s.str()
		if err != nil {
			return err
		}
		if !s.eat(':') {
			return errSyntax
		}
		if err := f(k); err != nil {
			return err
		}
		if s.eat(',') {
			continue
		}
		if s.eat('}') {
			return nil
		}
		return errSyntax
	}
}

// value reads one value. With allow, it refuses an object whose "type" is
// a string outside allow, naming it with what, and reads on below it;
// without, it only skips the value.
func (s *scan) value(allow map[string]bool, what string) error {
	s.ws()
	if s.i >= len(s.b) {
		return errSyntax
	}
	switch s.b[s.i] {
	case '{':
		s.i++
		return s.object(func(k []byte) error {
			switch {
			case allow != nil && foldIn(k, "type"):
				return s.typed(allow, what)
			case foldIn(k, "input", "arguments"):
				return s.value(nil, "")
			}
			return s.value(allow, what)
		})
	case '[':
		s.i++
		if s.eat(']') {
			return nil
		}
		for {
			if err := s.value(allow, what); err != nil {
				return err
			}
			if s.eat(',') {
				continue
			}
			if s.eat(']') {
				return nil
			}
			return errSyntax
		}
	case '"':
		_, err := s.str()
		return err
	}
	for s.i < len(s.b) && bytes.IndexByte([]byte(",]} \t\n\r"), s.b[s.i]) < 0 {
		s.i++
	}
	return nil
}

// typed reads a "type" value and refuses a string outside allow.
func (s *scan) typed(allow map[string]bool, what string) error {
	s.ws()
	if s.i < len(s.b) && s.b[s.i] == '"' {
		raw, err := s.str()
		if err != nil {
			return err
		}
		if v := s.key(raw); !allow[v] {
			return errBound(fmt.Sprintf(what, v))
		}
		return nil
	}
	return s.value(nil, "")
}

// tools reads a tools list, refusing an entry whose "type" is a string
// outside toolTypes. A tool's schema is not read.
func (s *scan) tools() error {
	s.ws()
	if s.i >= len(s.b) || s.b[s.i] != '[' {
		return s.value(nil, "")
	}
	s.i++
	if s.eat(']') {
		return nil
	}
	for {
		s.ws()
		if s.i < len(s.b) && s.b[s.i] == '{' {
			s.i++
			err := s.object(func(k []byte) error {
				if foldIn(k, "type") {
					return s.typed(toolTypes, "a tool of type %q")
				}
				return s.value(nil, "")
			})
			if err != nil {
				return err
			}
		} else if err := s.value(nil, ""); err != nil {
			return err
		}
		if s.eat(',') {
			continue
		}
		if s.eat(']') {
			return nil
		}
		return errSyntax
	}
}

// foldIn reports whether raw key k equals one of names case-folded, as
// Object compares keys. A key with an escape is unescaped first.
func foldIn(k []byte, names ...string) bool {
	if bytes.IndexByte(k, '\\') >= 0 {
		k = []byte((&scan{}).key(k))
	}
	for _, n := range names {
		if bytes.EqualFold(k, []byte(n)) {
			return true
		}
	}
	return false
}
