package sockets

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

// flakyListener fails Accept with EMFILE a few times, then delegates.
type flakyListener struct {
	net.Listener
	fails atomic.Int32
}

func (l *flakyListener) Accept() (net.Conn, error) {
	if l.fails.Add(-1) >= 0 {
		return nil, &net.OpError{Op: "accept", Net: "unix", Err: os.NewSyscallError("accept4", syscall.EMFILE)}
	}
	return l.Listener.Accept()
}

func TestAcceptSurvivesTemporaryErrors(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "x.sock")
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	fl := &flakyListener{Listener: ln}
	fl.fails.Store(3)
	s := &Server{}
	ctx, cancel := context.WithCancel(context.Background())
	s.wg.Add(1)
	go s.accept(ctx, fl, Endpoint{Name: "x.sock", Ops: map[string]Handler{"ping": echoPeer}})
	if r := call(t, path, `{"op":"ping"}`); !r.OK {
		t.Fatalf("after EMFILE: %+v", r)
	}
	cancel()
	ln.Close()
	s.Wait()
}

func TestGuestFloodCannotStarveOtherSockets(t *testing.T) {
	_, dir := serve(t,
		Endpoint{Name: "owner.sock", Peer: Peer{Kind: "owner"}, Ops: map[string]Handler{"ping": echoPeer}},
		Endpoint{Name: "g.sock", Peer: Peer{Kind: "guest"}, MaxConns: 4, Ops: map[string]Handler{"ping": echoPeer}},
	)
	var held []net.Conn
	defer func() {
		for _, c := range held {
			c.Close()
		}
	}()
	for i := 0; i < 4; i++ {
		c, err := net.Dial("unix", filepath.Join(dir, "g.sock"))
		if err != nil {
			t.Fatal(err)
		}
		held = append(held, c)
	}
	// Let the server count the held connections.
	if r := call(t, filepath.Join(dir, "owner.sock"), `{"op":"ping"}`); !r.OK {
		t.Fatal(r)
	}
	deadline := time.Now().Add(2 * time.Second)
	for {
		r := call(t, filepath.Join(dir, "g.sock"), `{"op":"ping"}`)
		if r.Error == string(ErrTooMany) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("fifth guest connection not refused: %+v", r)
		}
		time.Sleep(10 * time.Millisecond)
	}
	if r := call(t, filepath.Join(dir, "owner.sock"), `{"op":"ping"}`); !r.OK {
		t.Fatalf("owner socket starved: %+v", r)
	}
	held[0].Close()
	held = held[1:]
	deadline = time.Now().Add(2 * time.Second)
	for {
		if r := call(t, filepath.Join(dir, "g.sock"), `{"op":"ping"}`); r.OK {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("slot not freed after a guest connection closed")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestIdleConnectionIsClosed(t *testing.T) {
	_, dir := serve(t, Endpoint{Name: "g.sock", Peer: Peer{Kind: "guest"}, IdleTimeout: 50 * time.Millisecond,
		Ops: map[string]Handler{"ping": echoPeer}})
	c, err := net.Dial("unix", filepath.Join(dir, "g.sock"))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := c.Read(make([]byte, 1)); err == nil || errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("idle connection not closed by the server: %v", err)
	}
}

func TestPeerUIDIsChecked(t *testing.T) {
	me, other := os.Getuid(), os.Getuid()+1
	_, dir := serve(t,
		Endpoint{Name: "ok.sock", Peer: Peer{Kind: "owner"}, PeerUID: &me, Ops: map[string]Handler{"ping": echoPeer}},
		Endpoint{Name: "no.sock", Peer: Peer{Kind: "owner"}, PeerUID: &other, Ops: map[string]Handler{"ping": echoPeer}},
	)
	if r := call(t, filepath.Join(dir, "ok.sock"), `{"op":"ping"}`); !r.OK {
		t.Fatalf("right uid refused: %+v", r)
	}
	if r := call(t, filepath.Join(dir, "no.sock"), `{"op":"ping"}`); r.OK || r.Error != string(ErrPeer) {
		t.Fatalf("wrong uid accepted: %+v", r)
	}
}

func TestHandlerErrorsBecomeFixedCodes(t *testing.T) {
	_, dir := serve(t, Endpoint{Name: "g.sock", Peer: Peer{Kind: "guest"}, Ops: map[string]Handler{
		"leak": func(context.Context, Peer, json.RawMessage) (any, error) {
			return nil, errors.New("open /var/lib/agentos/vault: secret detail")
		},
		"coded": func(context.Context, Peer, json.RawMessage) (any, error) { return nil, Code("bad_message") },
	}})
	p := filepath.Join(dir, "g.sock")
	if r := call(t, p, `{"op":"leak"}`); r.Error != string(ErrFailed) {
		t.Fatalf("raw error reached the peer: %+v", r)
	}
	if r := call(t, p, `{"op":"coded"}`); r.Error != "bad_message" {
		t.Fatalf("%+v", r)
	}
}

func TestSecondServerOnTheSameDirectoryIsRefused(t *testing.T) {
	_, dir := serve(t, Endpoint{Name: "o.sock", Peer: Peer{Kind: "owner"}, Ops: map[string]Handler{"ping": echoPeer}})
	s2 := &Server{Dir: dir}
	err := s2.Start(context.Background(), Endpoint{Name: "o.sock", Peer: Peer{Kind: "owner"}})
	if err == nil || !strings.Contains(err.Error(), "another broker") {
		t.Fatalf("second broker took over: %v", err)
	}
	if r := call(t, filepath.Join(dir, "o.sock"), `{"op":"ping"}`); !r.OK {
		t.Fatal("first server lost its socket")
	}
}

func TestSymlinkedSocketDirectoryIsRefused(t *testing.T) {
	base := t.TempDir()
	real := filepath.Join(base, "real")
	if err := os.Mkdir(real, 0o755); err != nil {
		t.Fatal(err)
	}
	// mkdir is masked by the runner's umask; establish the mode this
	// regression deliberately checks before testing refusal of the link.
	if err := os.Chmod(real, 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(base, "run")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	s := &Server{Dir: link}
	if err := s.Start(context.Background(), Endpoint{Name: "o.sock", Peer: Peer{Kind: "owner"}}); err == nil {
		t.Fatal("followed a symlinked socket directory")
	}
	if fi, err := os.Stat(real); err != nil || fi.Mode().Perm() != 0o755 {
		t.Fatalf("changed the symlink target's mode: %v", err)
	}
}

func TestDuplicateEndpointNamesAreRefused(t *testing.T) {
	s := &Server{Dir: filepath.Join(t.TempDir(), "run")}
	ep := Endpoint{Name: "g.sock", Peer: Peer{Kind: "guest"}}
	if err := s.Start(context.Background(), ep, ep); err == nil {
		t.Fatal("accepted two sockets with one name")
	}
}

// L3 on #170: a long poll's context ends when its peer hangs up, so an
// answer is not handed to a closed connection; other ops run to the end.
func TestAHangupEndsALongPoll(t *testing.T) {
	ended := make(chan error, 1)
	_, dir := serve(t, Endpoint{Name: "p.sock", Peer: Peer{Kind: "owner"}, HangupOps: map[string]bool{"poll": true},
		Ops: map[string]Handler{
			"poll": func(ctx context.Context, _ Peer, _ json.RawMessage) (any, error) {
				select {
				case <-ctx.Done():
					ended <- ctx.Err()
				case <-time.After(time.Second):
					ended <- nil
				}
				return nil, nil
			},
			"ping": echoPeer,
		}})
	path := filepath.Join(dir, "p.sock")
	c, err := net.Dial("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	c.Write([]byte(`{"op":"poll"}` + "\n"))
	time.Sleep(50 * time.Millisecond)
	c.Close()
	select {
	case err := <-ended:
		if err == nil {
			t.Fatal("the poll ran on after its peer hung up")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("the poll ran on after its peer hung up")
	}
	// A pipelined request after a watched one is kept and answered.
	c, err = net.Dial("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(10 * time.Second))
	c.Write([]byte(`{"op":"poll"}` + "\n" + `{"op":"ping"}` + "\n"))
	rd := bufio.NewReader(c)
	for i := 0; i < 2; i++ {
		line, err := rd.ReadBytes('\n')
		if err != nil {
			t.Fatalf("answer %d: %v", i+1, err)
		}
		var r Response
		if json.Unmarshal(line, &r) != nil || !r.OK {
			t.Fatalf("answer %d: %s", i+1, line)
		}
	}
	<-ended
}
