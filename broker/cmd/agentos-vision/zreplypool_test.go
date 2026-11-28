package main

// REQ: DEV-7

import (
	"bytes"
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/ghbmrk/agentos/broker/vision"
)

// An enrol reply's template never reaches encoding/json, whose pooled
// encode buffer is not zeroed after a Marshal; the line still decodes to
// the reply write was given (DEV-7, #6564).
func TestReplyTemplateNeverMarshalled(t *testing.T) {
	var seen []vision.Reply
	defer func(m func(any) ([]byte, error)) { marshal = m }(marshal)
	marshal = func(v any) ([]byte, error) {
		seen = append(seen, v.(vision.Reply))
		return json.Marshal(v)
	}
	s := newService(Config{}, &stubRT{}, nil)
	for _, want := range []vision.Reply{
		{Template: f32s(0.25, -0.5, 1, 2)},
		{State: vision.StateReady, Template: f32s(3, 4, 5)},
		{State: vision.StateReady},
	} {
		seen = nil
		tpl := append([]byte(nil), want.Template...)
		in := want
		in.Template = append([]byte(nil), tpl...)
		c := &scriptConn{in: bytes.NewReader(nil)}
		if !s.write(c, in) {
			t.Fatal("write failed")
		}
		if len(seen) != 1 || seen[0].Template != nil {
			t.Fatalf("encoding/json was given %+v", seen)
		}
		line := c.writes[0]
		if !strings.HasSuffix(string(line), "}\n") {
			t.Fatalf("line %q", line)
		}
		var got vision.Reply
		dec := json.NewDecoder(bytes.NewReader(line))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&got); err != nil {
			t.Fatalf("line %q: %v", line, err)
		}
		want.Template = tpl
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("line %q decodes to %+v, want %+v", line, got, want)
		}
		if want.State == "" {
			b, _ := json.Marshal(want)
			if string(line) != string(b)+"\n" {
				t.Fatalf("wrote %q, want %q", line, b)
			}
		}
	}
}

// The one buffer that held the encoded template is the line handed to the
// conn: it holds the newline too, fills its capacity exactly (so no append
// copied it), and is zeroed after the write, a failed one too (DEV-7).
func TestReplyLineIsOneOwnedBufferZeroed(t *testing.T) {
	s := newService(Config{}, &stubRT{}, nil)
	for _, r := range []vision.Reply{
		{Template: f32s(0.25, -0.5, 1, 2)},
		{State: vision.StateReady, Template: f32s(1)},
		{Error: vision.NoFace},
	} {
		for _, fail := range []bool{false, true} {
			r.Template = append([]byte(nil), r.Template...)
			c := &scriptConn{in: bytes.NewReader(nil), failWrite: fail}
			if ok := s.write(c, r); ok == fail {
				t.Fatalf("write with a failing conn %v returned %v", fail, ok)
			}
			if len(c.sent) != 1 {
				t.Fatalf("wrote %q", c.writes)
			}
			sent, w := c.sent[0], c.writes[0]
			if len(sent) != cap(sent) || w[len(w)-1] != '\n' {
				t.Fatalf("line %q has len %d cap %d", w, len(sent), cap(sent))
			}
			if !zero(sent) {
				t.Fatalf("the sent line was left in memory (failing %v): %q", fail, sent)
			}
			if !zero(r.Template) {
				t.Fatalf("the template was left in memory (failing %v)", fail)
			}
		}
	}
}

// A line of exactly MaxReplyLine bytes, without its newline, goes; one
// byte over goes as Unavailable, with the template still zeroed.
func TestReplyLineBound(t *testing.T) {
	tpl := make([]byte, 3*8000)
	for i := range tpl {
		tpl[i] = byte(i) | 1
	}
	base := len(replyLine(vision.Reply{Model: "a"}, tpl)) - 1
	pad := vision.MaxReplyLine - base
	if pad < 0 {
		t.Fatal("fixture too long")
	}
	at := vision.Reply{Model: strings.Repeat("a", 1+pad)}
	if l := replyLine(at, tpl); len(l) != vision.MaxReplyLine+1 {
		t.Fatalf("line at the bound has %d bytes", len(l))
	}
	over := vision.Reply{Model: strings.Repeat("a", 2+pad)}
	if replyLine(over, tpl) != nil {
		t.Fatal("a line over the bound was built")
	}
	log := &lockedBuffer{}
	s := newService(Config{}, &stubRT{}, log)
	over.Template = append([]byte(nil), tpl...)
	c := &scriptConn{in: bytes.NewReader(nil)}
	if !s.write(c, over) {
		t.Fatal("write failed")
	}
	if got := string(c.writes[0]); got != `{"error":"unavailable"}`+"\n" {
		t.Fatalf("wrote %q", got)
	}
	if !zero(over.Template) || !zero(c.sent[0]) {
		t.Fatal("an over-bound reply left its template or line in memory")
	}
	if !strings.Contains(log.String(), "reply over") {
		t.Fatalf("log %q", log.String())
	}
}
