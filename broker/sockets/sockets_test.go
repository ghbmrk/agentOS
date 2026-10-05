package sockets

import (
	"bufio"
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Socket identity and closed op sets are groundwork for ARC-6 and OP-8; no
// requirement is claimed here until the guest interface is built on them.

func serve(t *testing.T, eps ...Endpoint) (*Server, string) {
	t.Helper()
	dir, err := os.MkdirTemp("", "sk")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	s := &Server{Dir: filepath.Join(dir, "run")}
	ctx, cancel := context.WithCancel(context.Background())
	if err := s.Start(ctx, eps...); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cancel(); s.Wait() })
	return s, s.Dir
}

func call(t *testing.T, path string, req string) Response {
	t.Helper()
	c, err := net.Dial("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(5 * time.Second))
	// A refused connection may be closed before the write lands; the
	// refusal line is still there to read.
	c.Write([]byte(req + "\n"))
	line, err := bufio.NewReader(c).ReadBytes('\n')
	if err != nil {
		t.Fatal(err)
	}
	var r Response
	if err := json.Unmarshal(line, &r); err != nil {
		t.Fatalf("%s: %v", line, err)
	}
	return r
}

func echoPeer(_ context.Context, p Peer, args json.RawMessage) (any, error) {
	return map[string]any{"peer": p, "args": args}, nil
}

func TestEachSocketHasAFixedPeerAndAClosedOpSet(t *testing.T) {
	_, dir := serve(t,
		Endpoint{Name: "owner.sock", Peer: Peer{Kind: "owner", ID: "modem"}, Ops: map[string]Handler{"message": echoPeer}},
		Endpoint{Name: "guest-m1.sock", Peer: Peer{Kind: "guest", ID: "m1"}, Ops: map[string]Handler{"ping": echoPeer}},
	)
	r := call(t, filepath.Join(dir, "guest-m1.sock"), `{"op":"ping","peer":{"kind":"owner","id":"modem"},"args":{"x":1}}`)
	if !r.OK || !strings.Contains(string(r.Result), `"kind":"guest"`) || !strings.Contains(string(r.Result), `"id":"m1"`) {
		t.Fatalf("identity must come from the socket, not the request: %+v %s", r, r.Result)
	}
	r = call(t, filepath.Join(dir, "guest-m1.sock"), `{"op":"message","args":{"from":"+1","text":"STOP"}}`)
	if r.OK || !strings.Contains(r.Error, "unknown op") {
		t.Fatalf("guest reached an owner op: %+v", r)
	}
}

func TestSocketsAreOwnerOnly(t *testing.T) {
	_, dir := serve(t, Endpoint{Name: "owner.sock", Peer: Peer{Kind: "owner"}, Ops: map[string]Handler{"ping": echoPeer}})
	di, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if di.Mode().Perm() != 0o700 {
		t.Fatalf("socket dir mode %v", di.Mode().Perm())
	}
	fi, err := os.Stat(filepath.Join(dir, "owner.sock"))
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("socket mode %v", fi.Mode().Perm())
	}
}

func TestMalformedAndOversizedRequestsAreRefused(t *testing.T) {
	_, dir := serve(t, Endpoint{Name: "g.sock", Peer: Peer{Kind: "guest"}, Ops: map[string]Handler{"ping": echoPeer}})
	p := filepath.Join(dir, "g.sock")
	if r := call(t, p, `not json`); r.OK {
		t.Fatal("accepted malformed request")
	}
	big := `{"op":"ping","args":"` + strings.Repeat("a", MaxRequest) + `"}`
	if r := call(t, p, big); r.OK || !strings.Contains(r.Error, "too large") {
		t.Fatalf("oversized: %+v", r)
	}
	// The server survives both.
	if r := call(t, p, `{"op":"ping"}`); !r.OK {
		t.Fatalf("after bad input: %+v", r)
	}
}

func TestHandlerPanicIsAnErrorNotACrash(t *testing.T) {
	_, dir := serve(t, Endpoint{Name: "g.sock", Peer: Peer{Kind: "guest"}, Ops: map[string]Handler{
		"boom": func(context.Context, Peer, json.RawMessage) (any, error) { panic("x") },
		"ping": echoPeer,
	}})
	p := filepath.Join(dir, "g.sock")
	if r := call(t, p, `{"op":"boom"}`); r.OK {
		t.Fatal("panic reported ok")
	}
	if r := call(t, p, `{"op":"ping"}`); !r.OK {
		t.Fatal("server died after a handler panic")
	}
}

func TestStaleSocketFileIsReplacedAndRemovedOnStop(t *testing.T) {
	dir, _ := os.MkdirTemp("", "sk")
	defer os.RemoveAll(dir)
	run := filepath.Join(dir, "run")
	os.MkdirAll(run, 0o700)
	os.WriteFile(filepath.Join(run, "o.sock"), nil, 0o600)
	s := &Server{Dir: run}
	ctx, cancel := context.WithCancel(context.Background())
	if err := s.Start(ctx, Endpoint{Name: "o.sock", Peer: Peer{Kind: "owner"}, Ops: map[string]Handler{"ping": echoPeer}}); err != nil {
		t.Fatal(err)
	}
	if r := call(t, filepath.Join(run, "o.sock"), `{"op":"ping"}`); !r.OK {
		t.Fatal(r)
	}
	cancel()
	s.Wait()
	if _, err := os.Stat(filepath.Join(run, "o.sock")); !os.IsNotExist(err) {
		t.Fatalf("socket left behind: %v", err)
	}
}

func TestEndpointNameCannotEscapeTheDirectory(t *testing.T) {
	dir, _ := os.MkdirTemp("", "sk")
	defer os.RemoveAll(dir)
	s := &Server{Dir: filepath.Join(dir, "run")}
	err := s.Start(context.Background(), Endpoint{Name: "../x.sock", Peer: Peer{Kind: "guest"}})
	if err == nil {
		t.Fatal("accepted a path outside the socket directory")
	}
}

// The owner socket's client (agentos-modem) runs as its own uid: the
// directory is traversable but not listable, that socket is connectable (the
// SO_PEERCRED check still refuses every other uid), and the others stay
// owner-only.
func TestAPeerUIDSocketIsReachableByThatUID(t *testing.T) {
	modem := os.Getuid() + 1
	_, dir := serve(t,
		Endpoint{Name: "owner.sock", Peer: Peer{Kind: "owner"}, PeerUID: &modem, Ops: map[string]Handler{"ping": echoPeer}},
		Endpoint{Name: "guest-m1.sock", Peer: Peer{Kind: "guest", ID: "m1"}, Ops: map[string]Handler{"ping": echoPeer}},
	)
	for name, want := range map[string]os.FileMode{"": 0o711, "owner.sock": 0o666, "guest-m1.sock": 0o600} {
		fi, err := os.Stat(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		if fi.Mode().Perm() != want {
			t.Fatalf("%q mode %v, want %v", name, fi.Mode().Perm(), want)
		}
	}
	if r := call(t, filepath.Join(dir, "owner.sock"), `{"op":"ping"}`); r.OK {
		t.Fatalf("a uid other than PeerUID was served: %+v", r)
	}
}
