package main

// REQ: DEV-7

import (
	"bytes"
	"errors"
	"testing"

	"github.com/ghbmrk/agentos/broker/vision"
)

// A reply that does not marshal goes out as an Unavailable line, never as
// an empty or partial line (DEV-7, #6564).
func TestReplyMarshalFailureSendsUnavailable(t *testing.T) {
	defer func(m func(any) ([]byte, error)) { marshal = m }(marshal)
	calls := 0
	marshal = func(v any) ([]byte, error) {
		calls++
		if calls == 1 {
			return nil, errors.New("synthetic marshal failure")
		}
		return []byte(`{"error":"unavailable"}`), nil
	}
	s := newService(Config{}, &stubRT{}, nil)
	for _, tpl := range [][]byte{nil, f32s(1, 2, 3)} {
		calls = 0
		c := &scriptConn{in: bytes.NewReader(nil)}
		if !s.write(c, vision.Reply{State: vision.StateReady, Template: tpl}) {
			t.Fatal("write failed")
		}
		if calls != 2 || len(c.writes) != 1 {
			t.Fatalf("marshal calls %d, writes %d", calls, len(c.writes))
		}
		if got := string(c.writes[0]); got != "{\"error\":\"unavailable\"}\n" {
			t.Fatalf("wrote %q", got)
		}
	}
}
