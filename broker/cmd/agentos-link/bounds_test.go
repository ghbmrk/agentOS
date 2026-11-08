package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/edgelink"
)

// REQ: HW-15, HW-16

// These tests pin the link's bounds and fail-closed branches one by one:
// each names the statement whose deletion it fails (REV-CHK-names-3, #5035,
// the mutation gate's survivors once the hostile-text corpus test made every
// covered line a target).

// within runs f and reports whether it returned within d: a deadlock
// mutant fails the test instead of hanging it.
func within(d time.Duration, f func()) bool {
	done := make(chan struct{})
	go func() { f(); close(done) }()
	select {
	case <-done:
		return true
	case <-time.After(d):
		return false
	}
}

// deadlines records the deadlines set on a connection, then sets them.
type deadlines struct {
	net.Conn
	mu  sync.Mutex
	all []string // "rw", "r" or "w", each followed by the deadline set
	at  []time.Time
}

func (c *deadlines) note(kind string, t time.Time) {
	c.mu.Lock()
	c.all = append(c.all, kind)
	c.at = append(c.at, t)
	c.mu.Unlock()
}

func (c *deadlines) SetDeadline(t time.Time) error {
	c.note("rw", t)
	return c.Conn.SetDeadline(t)
}

func (c *deadlines) SetReadDeadline(t time.Time) error {
	c.note("r", t)
	return c.Conn.SetReadDeadline(t)
}

func (c *deadlines) SetWriteDeadline(t time.Time) error {
	c.note("w", t)
	return c.Conn.SetWriteDeadline(t)
}

func (c *deadlines) snapshot() ([]string, []time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]string(nil), c.all...), append([]time.Time(nil), c.at...)
}

// recording hands out each accepted connection wrapped in deadlines.
type recording struct {
	net.Listener
	conns chan *deadlines
}

func (l recording) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	d := &deadlines{Conn: c}
	l.conns <- d
	return d, nil
}

func TestHandshakeHoldsItsDeadlineOnlyUntilItCompletes(t *testing.T) {
	k := newFakeKernel(t)
	pub, _ := k.LinkKey()
	cfg, err := edgelink.ServerConfig(linkSigner{k, pub})
	if err != nil {
		t.Fatal(err)
	}
	server, client := net.Pipe()
	rec := &deadlines{Conn: server}
	e := newEdge(t)
	ccfg, err := edgelink.ClientConfig(e.signer, pub)
	if err != nil {
		t.Fatal(err)
	}
	go tls.Client(client, ccfg).Handshake()
	before := time.Now()
	conn, key, err := handshake(rec, cfg)
	if err != nil || !key.Equal(e.key()) {
		t.Fatalf("handshake: %v", err)
	}
	kinds, at := rec.snapshot()
	client.Close()
	conn.Close()
	// Mutant link.go:95, the handshake deadline dropped: an edge that
	// never finishes holds a slot forever.
	if len(kinds) == 0 || kinds[0] != "rw" || at[0].Before(before.Add(handshakeFor-time.Second)) {
		t.Fatalf("deadlines %v %v: want the handshake's %v first", kinds, at, handshakeFor)
	}
	// Mutant link.go:99, the deadline not cleared: a live edge would be cut
	// handshakeFor after it connected.
	if last := len(kinds) - 1; kinds[last] != "rw" || !at[last].IsZero() {
		t.Fatalf("deadlines %v %v: want the handshake's cleared last", kinds, at)
	}
}

func TestAnEdgeThatSendsNoHelloIsClosedAtTheWait(t *testing.T) {
	c := newCore(t)
	e := newEdge(t)
	conn := e.dial(c.addr, c.pin)
	defer conn.Close()
	// Mutant: readHello's read deadline dropped, so the silent edge holds
	// its slot.
	if !closedWithin(conn, 3*time.Second) {
		t.Fatal("an edge that sent nothing stayed connected past the wait")
	}
}

func TestAHelloIsTakenAtTheTrailNotTheWait(t *testing.T) {
	c := newCore(t)
	c.s.wait = 5 * time.Second
	e := newEdge(t)
	conn := e.dial(c.addr, c.pin)
	defer conn.Close()
	conn.Write(helloFrame(t, e.helloBody(conn, nil)))
	// The edge keeps the connection open. Mutant link.go:83, the trail
	// deadline dropped: the second-frame read waits out the whole wait.
	if !eventually(t, 2*time.Second, func() bool { _, n := c.k.counts(); return n == 1 }) {
		t.Fatal("the hello was not taken within the trail")
	}
}

// failingKernel refuses what its fields say, and otherwise is k.
type failingKernel struct {
	*fakeKernel
	linkKey ed25519.PublicKey
	keyErr  error
	edgeErr error
}

func (k failingKernel) LinkKey() (ed25519.PublicKey, error) {
	if k.keyErr != nil || k.linkKey != nil {
		return k.linkKey, k.keyErr
	}
	return k.fakeKernel.LinkKey()
}

func (k failingKernel) EdgeKey(e ed25519.PublicKey) (Edge, error) {
	if k.edgeErr != nil {
		k.fakeKernel.EdgeKey(e)
		return Edge{}, k.edgeErr
	}
	return k.fakeKernel.EdgeKey(e)
}

func TestNewServerNeedsTheKernelsLinkKey(t *testing.T) {
	// Mutant link.go:152, the LinkKey error ignored.
	_, err := newServer(failingKernel{fakeKernel: newFakeKernel(t), keyErr: ErrUnreachable}, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "names no link key") {
		t.Fatalf("newServer with no link key: %v", err)
	}
}

func TestServeLoopsEndWhenTheirListenersClose(t *testing.T) {
	s, err := newServer(newFakeKernel(t), io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	for name, loop := range map[string]func(net.Listener) error{"serve": s.serve, "serveConsumer": s.serveConsumer} {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		done := make(chan error, 1)
		go func() { done <- loop(ln) }()
		ln.Close()
		// Mutants link.go:167-168 and consumer.go:35-36: the closed
		// listener read as a retry, so the loop spins for ever.
		select {
		case err := <-done:
			if err != nil {
				t.Fatalf("%s: %v", name, err)
			}
		case <-time.After(2 * time.Second):
			t.Fatalf("%s ran on after its listener closed", name)
		}
	}
}

func TestAFailedHandshakeIsClosedCountedAndNeverAsked(t *testing.T) {
	c := newCore(t)
	raw, err := net.Dial("tcp", c.addr)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	raw.Write([]byte("not a TLS client hello, and no edge\r\n\r\n"))
	// Mutant link.go:202, the failed connection left open.
	if !closedWithin(raw, 3*time.Second) {
		t.Fatal("a failed handshake left the connection open")
	}
	if !eventually(t, time.Second, func() bool { return strings.Contains(c.log.String(), "on a fault (1 so far)") }) {
		// Mutant link.go:186, the fault's log line dropped.
		t.Fatalf("log %q: want the fault counted", c.log.String())
	}
	// Mutant link.go:201, the handshake's error ignored: the kernel is
	// asked about a key no edge proved.
	if asked, _ := c.k.counts(); asked != 0 {
		t.Fatalf("the kernel was asked %d times after a failed handshake", asked)
	}
}

func TestAKernelThatDoesNotAnswerTakesNoHello(t *testing.T) {
	k := failingKernel{fakeKernel: newFakeKernel(t), edgeErr: ErrLost}
	log := &syncBuffer{}
	s, err := newServer(k, log)
	if err != nil {
		t.Fatal(err)
	}
	s.wait = time.Second
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go s.serve(ln)
	pub, _ := k.LinkKey()
	e := newEdge(t)
	conn := e.dial(ln.Addr().String(), pub)
	defer conn.Close()
	conn.Write(helloFrame(t, e.helloBody(conn, nil)))
	if !closedWithin(conn, 3*time.Second) {
		t.Fatal("the connection stayed open")
	}
	// Mutant link.go:208, the kernel's error ignored: the hello is read
	// and handed on as a candidate the kernel never vetted.
	said := eventually(t, 2*time.Second, func() bool { return strings.Contains(log.String(), "did not answer") })
	if _, n := k.counts(); n != 0 || !said {
		t.Fatalf("candidates %d, log %q", n, log.String())
	}
	// Mutant link.go:211, the return after it dropped: the closed
	// connection's hello read fails and is counted as the edge's fault.
	time.Sleep(500 * time.Millisecond)
	if _, n := k.counts(); n != 0 || s.faults.Load() != 0 {
		t.Fatalf("candidates %d, faults %d: the hello went on being read after the kernel's silence", n, s.faults.Load())
	}
}

// liveCore is newCore with each accepted connection's deadlines recorded.
func liveCore(t *testing.T) (*core, chan *deadlines) {
	t.Helper()
	k := newFakeKernel(t)
	s, err := newServer(k, &syncBuffer{})
	if err != nil {
		t.Fatal(err)
	}
	s.every = 20 * time.Millisecond
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	conns := make(chan *deadlines, 64)
	t.Cleanup(func() { ln.Close() })
	go s.serve(recording{ln, conns})
	pub, _ := k.LinkKey()
	return &core{t: t, k: k, s: s, addr: ln.Addr().String(), pin: pub}, conns
}

// liveNow reports whether s serves a live connection.
func liveNow(s *server) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.live != nil
}

func TestSendReachesOnlyTheLiveEdgeAndNeverHangs(t *testing.T) {
	c, conns := liveCore(t)
	out := edgelink.Frame{Kind: edgelink.KindFetch, Origin: "example.org", Body: []byte("GET /")}
	var err error
	// Mutants link.go:321 (no live edge read as one: a nil dereference)
	// and :320 (the lock kept: the second send hangs).
	for i := 0; i < 2; i++ {
		if !within(time.Second, func() { err = c.s.send(out) }) || err != errNoEdge {
			t.Fatalf("send %d with no live edge: %v", i, err)
		}
	}
	// Mutant link.go:315, AppendFrame's refusal ignored: a frame the edge
	// stream does not carry is reported as no edge.
	if err := c.s.send(edgelink.Frame{Kind: edgelink.KindText, Origin: "example.org", Body: []byte("x")}); err == nil || err == errNoEdge {
		t.Fatalf("a text frame toward the edge: %v", err)
	}

	e := newEdge(t)
	c.k.setLive(e.key())
	conn := e.dial(c.addr, c.pin)
	rec := <-conns
	if !eventually(t, 2*time.Second, func() bool { return liveNow(c.s) }) {
		t.Fatal("the live edge was not served")
	}
	// Mutant link.go:325, the write lock kept: the second send hangs.
	for i := 0; i < 2; i++ {
		if !within(2*time.Second, func() { err = c.s.send(out) }) || err != nil {
			t.Fatalf("send %d to the live edge: %v", i, err)
		}
	}
	r := bufio.NewReader(conn)
	for i := 0; i < 2; i++ {
		conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		if f, err := edgelink.ReadFrame(r, edgelink.ToEdge); err != nil || f.Kind != edgelink.KindFetch {
			t.Fatalf("frame %d at the edge: %+v, %v", i, f, err)
		}
	}
	// Mutant link.go:326, no write deadline: an edge that stops reading
	// holds the sender for ever.
	kinds, at := rec.snapshot()
	var wrote bool
	for i, k := range kinds {
		wrote = wrote || k == "w" && !at[i].IsZero()
	}
	if !wrote {
		t.Fatalf("deadlines %v: no write deadline on a send", kinds)
	}

	// The edge leaves. Mutant link.go:250, serveLive's cleanup keeps the
	// lock: every later send hangs.
	conn.Close()
	if !eventually(t, 2*time.Second, func() bool {
		done := within(time.Second, func() { err = c.s.send(out) })
		return done && err == errNoEdge
	}) {
		t.Fatalf("send after the live edge left: %v", err)
	}
}

func TestAReconnectClosesTheOlderConnection(t *testing.T) {
	c, _ := liveCore(t)
	e := newEdge(t)
	c.k.setLive(e.key())
	first := e.dial(c.addr, c.pin)
	defer first.Close()
	if !eventually(t, 2*time.Second, func() bool { return liveNow(c.s) }) {
		t.Fatal("the live edge was not served")
	}
	second := e.dial(c.addr, c.pin)
	defer second.Close()
	// Mutant link.go:240, the older connection kept: two served at once,
	// one of them never written to.
	if !closedWithin(first, 2*time.Second) {
		t.Fatal("the older connection stayed open after a reconnect")
	}
	// Mutant link.go:258, the done case dropped: a connection the link
	// closed itself is counted as the edge's fault.
	time.Sleep(100 * time.Millisecond)
	if n := c.s.faults.Load(); n != 0 {
		t.Fatalf("faults %d after a reconnect", n)
	}
}

func TestRecheckStopsWithTheConnection(t *testing.T) {
	c, _ := liveCore(t)
	e := newEdge(t)
	c.k.setLive(e.key())
	conn := e.dial(c.addr, c.pin)
	if !eventually(t, 2*time.Second, func() bool { asked, _ := c.k.counts(); return asked >= 3 }) {
		t.Fatal("the live connection was not rechecked")
	}
	conn.Close()
	if !eventually(t, 2*time.Second, func() bool { return !liveNow(c.s) }) {
		t.Fatal("the live connection was not let go")
	}
	time.Sleep(100 * time.Millisecond)
	before, _ := c.k.counts()
	time.Sleep(300 * time.Millisecond)
	// Mutant link.go:282 (and the select case at :281): recheck goes on
	// asking the kernel about a connection that is gone.
	if after, _ := c.k.counts(); after != before {
		t.Fatalf("the kernel was asked %d more times after the connection closed", after-before)
	}
}

func TestALiveConnectionGivesBackItsSlotOnce(t *testing.T) {
	c, _ := liveCore(t)
	// One handshake in flight holds a slot (a raw connection that sends
	// nothing waits out handshakeFor).
	held, err := net.Dial("tcp", c.addr)
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close()
	if !eventually(t, 2*time.Second, func() bool { return len(c.s.slots) == 1 }) {
		t.Fatalf("slots %d, want the silent handshake's 1", len(c.s.slots))
	}
	e := newEdge(t)
	c.k.setLive(e.key())
	conn := e.dial(c.addr, c.pin)
	if !eventually(t, 2*time.Second, func() bool { return liveNow(c.s) }) {
		t.Fatal("the live edge was not served")
	}
	conn.Close()
	if !eventually(t, 2*time.Second, func() bool { return !liveNow(c.s) }) {
		t.Fatal("the live connection was not let go")
	}
	time.Sleep(100 * time.Millisecond)
	// Mutant link.go:195, held not cleared: handle's deferred release gives
	// a second slot back, the silent handshake's.
	if n := len(c.s.slots); n != 1 {
		t.Fatalf("slots %d after the live connection ended, want 1", n)
	}
}

// consumerCore is a server with its consumer socket and one live edge.
func consumerCore(t *testing.T) (*server, string, *tls.Conn) {
	t.Helper()
	c, _ := liveCore(t)
	cl, err := net.Listen("unix", filepath.Join(t.TempDir(), "items.sock"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cl.Close() })
	go c.s.serveConsumer(cl)
	e := newEdge(t)
	c.k.setLive(e.key())
	conn := e.dial(c.addr, c.pin)
	t.Cleanup(func() { conn.Close() })
	if !eventually(t, 2*time.Second, func() bool { return liveNow(c.s) }) {
		t.Fatal("the live edge was not served")
	}
	return c.s, cl.Addr().String(), conn
}

func TestTheConsumerSocketServesOneConsumerAfterAnother(t *testing.T) {
	_, addr, edge := consumerCore(t)
	first, err := net.Dial("unix", addr)
	if err != nil {
		t.Fatal(err)
	}
	// The first consumer stops writing. Mutant consumer.go:48, consume
	// returns without closing its side: the consumer never sees the end.
	first.(*net.UnixConn).CloseWrite()
	if !closedWithin(first, 2*time.Second) {
		t.Fatal("the consumer's connection stayed open after it stopped writing")
	}
	first.Close()
	// Mutants consumer.go:51 (gone never closed) and :73-74 (consume not
	// told its reader ended): the next consumer is never served.
	second, err := net.Dial("unix", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	// Mutant consumer.go:53, the scanner's buffer left at its 64 KiB
	// default: a full fetch body's line is dropped.
	body := make([]byte, 64<<10)
	line, _ := json.Marshal(wireItem{Kind: edgelink.KindFetch, Origin: "example.org", Body: body})
	second.Write(append(line, '\n'))
	edge.SetReadDeadline(time.Now().Add(3 * time.Second))
	if f, err := edgelink.ReadFrame(bufio.NewReader(edge), edgelink.ToEdge); err != nil || len(f.Body) != len(body) {
		t.Fatalf("the second consumer's %d-byte frame at the edge: %v", len(line), err)
	}
}

func TestKernelCallsFailClosed(t *testing.T) {
	dir, err := os.MkdirTemp("", "kc")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	listen := func(t *testing.T, name string) net.Listener {
		ln, err := net.Listen("unix", filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { ln.Close() })
		return ln
	}

	t.Run("no kernel listens", func(t *testing.T) {
		// Mutant kernel.go:97, the dial's error ignored: a nil connection.
		var err error
		if !within(time.Second, func() { _, err = kernelConn{filepath.Join(dir, "none.sock"), os.Getuid()}.LinkKey() }) || err != ErrUnreachable {
			t.Fatalf("no kernel: %v", err)
		}
	})

	t.Run("another uid holds the socket", func(t *testing.T) {
		ln := listen(t, "other.sock")
		got := make(chan int, 1)
		go func() {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			defer c.Close()
			n, _ := io.Copy(io.Discard, c)
			got <- int(n)
		}()
		// Mutant kernel.go:101, the peer's uid not checked: the call goes
		// to whoever holds the socket.
		if _, err := (kernelConn{ln.Addr().String(), os.Getuid() + 1}).LinkKey(); err != ErrUnreachable {
			t.Fatalf("another uid's socket: %v", err)
		}
		if n := <-got; n != 0 {
			t.Fatalf("%d bytes sent to another uid's socket", n)
		}
	})

	t.Run("each call closes its connection", func(t *testing.T) {
		ln := listen(t, "k.sock")
		closed := make(chan bool, 1)
		go func() {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			defer c.Close()
			bufio.NewReader(c).ReadBytes('\n')
			c.Write([]byte(`{"result":null}` + "\n"))
			closed <- closedWithin(c, 2*time.Second)
		}()
		if err := (kernelConn{ln.Addr().String(), os.Getuid()}).EdgeCandidate(identityKey, nil, nil); err != nil {
			t.Fatal(err)
		}
		// Mutant kernel.go:100, the call's connection left open.
		if !<-closed {
			t.Fatal("the call left its connection open")
		}
	})

	t.Run("an answer that is not JSON", func(t *testing.T) {
		ln := listen(t, "garbled.sock")
		go func() {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			defer c.Close()
			bufio.NewReader(c).ReadBytes('\n')
			c.Write([]byte("not an answer\n"))
		}()
		// Mutant kernel.go:110, the undecodable answer read as success.
		if err := (kernelConn{ln.Addr().String(), os.Getuid()}).EdgeCandidate(identityKey, nil, nil); err != ErrLost {
			t.Fatalf("a garbled answer: %v", err)
		}
	})

	t.Run("a kernel that never answers", func(t *testing.T) {
		t.Parallel()
		ln := listen(t, "mute.sock")
		go func() {
			c, err := ln.Accept()
			if err == nil {
				defer c.Close()
				time.Sleep(callFor + 5*time.Second)
			}
		}()
		// Mutant kernel.go:104, no deadline: the call waits for ever.
		var err error
		if !within(callFor+3*time.Second, func() { _, err = kernelConn{ln.Addr().String(), os.Getuid()}.LinkKey() }) || err != ErrLost {
			t.Fatalf("a mute kernel: %v", err)
		}
	})
}

func TestTheLinkKeySignsEd25519Only(t *testing.T) {
	k := newFakeKernel(t)
	pub, _ := k.LinkKey()
	// Mutant kernel.go:159, a hashed signature asked of the link key
	// passed to linksign as if it were Ed25519's.
	if _, err := (linkSigner{k, pub}).Sign(nil, make([]byte, 32), crypto.SHA256); err == nil {
		t.Fatal("the link key signed a SHA-256 digest")
	}
}

func TestCaptureHelpersRefuseWhatTheyCannotTake(t *testing.T) {
	// Mutant capture.go:40, the length unchecked: a short capture panics.
	for _, b := range [][]byte{nil, make([]byte, captureLen-1), make([]byte, captureLen+1)} {
		var ok bool
		func() {
			defer func() {
				if recover() != nil {
					ok = true
				}
			}()
			ok = validCapture(b)
		}()
		if ok {
			t.Fatalf("validCapture took %d bytes", len(b))
		}
	}
	// Mutant capture.go:78, CreateTemp's error ignored: a nil file.
	dir := t.TempDir()
	var err error
	if !within(time.Second, func() {
		defer func() {
			if recover() != nil {
				err = nil
			}
		}()
		err = writeCapture(filepath.Join(dir, "missing", "first-edge"), filepath.Join(dir, "store"), make([]byte, captureLen))
	}) || err == nil {
		t.Fatalf("a capture into a missing directory: %v", err)
	}
	// Mutant bind_linux.go:36, a listener that is not TCP read as one.
	ln, err := net.Listen("unix", filepath.Join(dir, "u.sock"))
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	var derr error
	func() {
		defer func() {
			if recover() != nil {
				derr = nil
			}
		}()
		_, derr = boundDevice(ln)
	}()
	if derr == nil {
		t.Fatal("boundDevice took a Unix listener")
	}
}

func TestFirstHelloClosesFaultsAndEndsWithItsListener(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := captureConfig()
	if err != nil {
		t.Fatal(err)
	}
	pin := cfg.Certificates[0].PrivateKey.(crypto.Signer).Public().(ed25519.PublicKey)
	log := &syncBuffer{}
	type result struct {
		h   hello
		err error
	}
	done := make(chan result, 1)
	go func() {
		h, err := firstHello(ln, cfg, log, 2*time.Second)
		done <- result{h, err}
	}()

	// A badly signed hello: Mutant capture.go:144, its connection left
	// open while the capture waits on.
	e := newEdge(t)
	bad := e.dial(ln.Addr().String(), pin)
	defer bad.Close()
	bad.Write(helloFrame(t, e.helloBody(bad, make([]byte, edgelink.NonceLen))))
	if !closedWithin(bad, 3*time.Second) {
		t.Fatal("a bad hello's connection stayed open")
	}
	good := e.dial(ln.Addr().String(), pin)
	defer good.Close()
	good.Write(helloFrame(t, e.helloBody(good, nil)))
	if r := <-done; r.err != nil || !r.h.key.Equal(e.key()) {
		t.Fatalf("firstHello: %v", r.err)
	}
	// Mutant capture.go:152, the return after the hello is taken dropped:
	// the good hello is also logged as a fault.
	time.Sleep(100 * time.Millisecond)
	if n := strings.Count(log.String(), "on a fault"); n != 1 {
		t.Fatalf("%d faults logged for one bad hello: %q", n, log.String())
	}
	// Mutant capture.go:124, stop never closed: a fault after the capture
	// ended is still reported as one before the store.
	n := strings.Count(log.String(), "on a fault")
	late := e.dial(ln.Addr().String(), pin)
	late.Write([]byte("junk"))
	closedWithin(late, 3*time.Second)
	late.Close()
	time.Sleep(100 * time.Millisecond)
	if m := strings.Count(log.String(), "on a fault"); m != n {
		t.Fatalf("a fault after the capture ended was logged: %q", log.String())
	}

	// Mutant capture.go:132, the accept error never sent: firstHello on a
	// closed listener waits for ever.
	ln.Close()
	ln2, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ln2.Close()
	if !within(2*time.Second, func() { _, err = firstHello(ln2, cfg, log, time.Second) }) || err == nil {
		t.Fatalf("firstHello on a closed listener: %v", err)
	}
}

func TestAwaitCaptureEndsItsContextAndStartsErrors(t *testing.T) {
	dir := t.TempDir()
	c := config{capture: filepath.Join(dir, "first-edge"), store: filepath.Join(dir, "store")}
	boom := errors.New("the child did not start")
	// Mutant main.go:193, start's error ignored: a nil reader is read.
	var err error
	if !within(2*time.Second, func() {
		defer func() { recover() }()
		err = awaitCapture(context.Background(), c, io.Discard, func(context.Context) (io.Reader, func(), error) { return nil, nil, boom })
	}) || err != boom {
		t.Fatalf("awaitCapture with a child that did not start: %v", err)
	}
	// Mutant main.go:190, the context not cancelled on return: the store
	// watch outlives the capture. Mutant main.go:205-206, a capture that
	// does not verify reported as taken.
	var got context.Context
	err = awaitCapture(context.Background(), c, io.Discard, func(ctx context.Context) (io.Reader, func(), error) {
		got = ctx
		return strings.NewReader(""), func() {}, nil
	})
	if got == nil || got.Err() == nil {
		t.Fatal("the capture's context was still live after awaitCapture returned")
	}
	if err != errBadCapture {
		t.Fatalf("an empty capture: %v", err)
	}
	// Mutant main.go:201, a hello after the store reported as a failure:
	// it is ignored, and said so.
	if err := os.WriteFile(c.store, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	var said syncBuffer
	err = awaitCapture(context.Background(), c, &said, func(context.Context) (io.Reader, func(), error) {
		return bytes.NewReader(capture(t, newEdge(t))), func() {}, nil
	})
	if err != nil || !strings.Contains(said.String(), "this hello is ignored") {
		t.Fatalf("a hello after the store: %v, %q", err, said.String())
	}
}

func TestParseWritesNothingToStderr(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	old := os.Stderr
	os.Stderr = w
	_, perr := parse([]string{"-no-such-flag"})
	os.Stderr = old
	w.Close()
	b, _ := io.ReadAll(r)
	// Mutant main.go:69, the flag set's output left at stderr: its usage
	// text goes to the journal beside run's own error.
	// Mutant main.go:82, the parse error dropped: a later check's error
	// names some other fault.
	if perr == nil || !strings.Contains(perr.Error(), "no-such-flag") || len(b) != 0 {
		t.Fatalf("parse: %v, stderr %q", perr, b)
	}
}
