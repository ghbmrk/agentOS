package sockets

import (
	"bufio"
	"context"
	"encoding/json"
	"net"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// LOOP-7 bullet 2 (P3-4b-3): each frame the socket refuses before any op
// runs is told to Refused with the socket's peer and the fixed code, so the
// broker can journal it; an op's own answer, refusal or not, is not.
// REQ: LOOP-7
func TestEachProtocolRefusalIsTold(t *testing.T) {
	var mu sync.Mutex
	var got []string
	ep := Endpoint{Name: "g.sock", Peer: Peer{Kind: "guest", ID: "m1"}, Ops: map[string]Handler{
		"ping": echoPeer,
		"no":   func(context.Context, Peer, json.RawMessage) (any, error) { return nil, Code("no") },
		"boom": func(context.Context, Peer, json.RawMessage) (any, error) { panic("x") },
	}, Refused: func(p Peer, c Code) {
		mu.Lock()
		got = append(got, p.ID+" "+string(c))
		mu.Unlock()
	}}
	_, dir := serve(t, ep)
	p := filepath.Join(dir, "g.sock")
	for _, req := range []string{`not json`, `{"op":"nope"}`, `{"op":"ping"}`, `{"op":"no"}`, `{"op":"boom"}`,
		`{"op":"ping","args":"` + strings.Repeat("a", MaxRequest) + `"}`} {
		call(t, p, req)
	}
	mu.Lock()
	defer mu.Unlock()
	want := []string{"m1 " + string(ErrMalformed), "m1 " + string(ErrUnknownOp), "m1 " + string(ErrInternal), "m1 " + string(ErrTooLarge)}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("told %q, want %q", got, want)
	}
}

// A connection refused for the cap is told too.
// REQ: LOOP-7
func TestARefusedConnectionIsTold(t *testing.T) {
	told := make(chan Code, 4)
	_, dir := serve(t, Endpoint{Name: "g.sock", Peer: Peer{Kind: "guest", ID: "m1"}, MaxConns: 1,
		Ops: map[string]Handler{"ping": echoPeer}, Refused: func(_ Peer, c Code) { told <- c }})
	p := filepath.Join(dir, "g.sock")
	held, err := net.Dial("unix", p)
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close()
	held.Write([]byte(`{"op":"ping"}` + "\n"))
	bufio.NewReader(held).ReadBytes('\n') // the first connection is being served
	if r := call(t, p, `{"op":"ping"}`); r.Error != string(ErrTooMany) {
		t.Fatalf("second connection: %+v", r)
	}
	if c := <-told; c != ErrTooMany {
		t.Fatalf("told %q", c)
	}
}
