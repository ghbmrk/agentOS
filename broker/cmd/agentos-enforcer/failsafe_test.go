package main

// REQ: NET-2, KRN-12
// The daemon's fail-safes from #4754's Security and L3 reviews (#4755):
// lifecycle rows run from TestLifecycle (failSafeRows), plus the channel
// listener's Accept retry.

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/enforcer/channel"
	"github.com/ghbmrk/agentos/broker/enforcer/wire"
)

// silent opens a TLS connection to the channel and sends nothing.
func (x *box) silent(addr string) (*tls.Conn, error) {
	c, err := tls.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}, "tcp", addr, &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS13})
	if err == nil {
		// The handshake can finish at the client before the server sees a
		// refusal: a read tells a closed connection from an open one.
		c.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
		var b [1]byte
		if _, rerr := c.Read(b[:]); rerr != nil && !isTimeout(rerr) {
			c.Close()
			return nil, rerr
		}
		c.SetReadDeadline(time.Time{})
		x.t.Cleanup(func() { c.Close() })
	}
	return c, err
}

// logs counts the daemon's log lines that start with prefix; "cut: trip
// saved" is matched whole.
func (x *box) logs(prefix string) int {
	x.mu.Lock()
	defer x.mu.Unlock()
	n := 0
	for _, l := range x.log {
		if l == prefix || prefix != "cut: trip saved" && strings.HasPrefix(l, prefix) {
			n++
		}
	}
	return n
}

func isTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

// failSafeRows are the lifecycle rows for #4755.
func failSafeRows(t *testing.T) {
	// Trip not saved (item 1; KRN-12 Response): the disk refuses cut.json
	// at the trip. The core stays cut, the channel takes no connection,
	// each tick retries the write, and once it lands a restart finds the
	// core still cut.
	t.Run("trip not saved", func(t *testing.T) {
		x, _ := enrolled(t, true)
		addr := x.serve()
		c, _ := x.dial(addr, x.core)
		x.fail(fileCut, true)
		for range wire.Rate(wire.RateRead).Burst {
			c.read()
		}
		c.read() // past the rate: a burst
		waitFor(t, func() bool { return x.d.cut.Stage() == channel.Tripped })
		if !x.d.cut.Unsaved() {
			t.Fatal("a trip the disk refused counts as saved")
		}
		if n := x.logs("cut: trip not saved, "); n != 1 {
			t.Fatalf("the refused trip write logged %d times, want once", n)
		}
		if _, err := x.silent(addr); err == nil {
			t.Fatal("the channel took a connection while a trip was unsaved")
		}
		x.advance(time.Second)
		if !x.d.cut.Unsaved() || x.d.cut.Stage() != channel.Tripped {
			t.Fatal("a retry the disk refused counts as saved, or lifted the cut")
		}
		if x.logs("cut: trip still not saved: ") == 0 || x.logs("cut: trip saved") != 0 {
			t.Fatal("a retry the disk refused is not logged as refused, or is logged as saved")
		}
		x.fail(fileCut, false)
		x.advance(time.Second)
		if x.d.cut.Unsaved() {
			t.Fatal("the tick did not retry the unsaved trip")
		}
		x.advance(time.Second)
		if n := x.logs("cut: trip saved"); n != 1 {
			t.Fatalf("the trip's late write logged as saved %d times, want once: a saved trip is not written again", n)
		}
		x.restart()
		x.advance(time.Second)
		if x.d.cut.Stage() != channel.Tripped || x.page("Channel") != "paused" {
			t.Fatal("a restart after a trip the disk first refused lifted the cut")
		}
	})

	// Trip saved at close (item 1): the disk recovers and the daemon stops
	// before its next tick; Close writes the trip.
	t.Run("trip saved at close", func(t *testing.T) {
		x, _ := enrolled(t, true)
		x.fail(fileCut, true)
		x.d.cut.Trip("test trip")
		x.d.Close() // the disk still refuses: logged, and tried again below
		if n := x.logs("cut: trip not saved at close: "); n != 1 {
			t.Fatalf("a close that could not save the trip logged it %d times, want once", n)
		}
		x.fail(fileCut, false)
		x.restart()
		if x.d.cut.Stage() != channel.Tripped {
			t.Fatal("a trip unsaved at shutdown was lost though the disk took writes")
		}
	})

	// First firewall load refused (item 3; P4, P5): the box may have booted
	// with any ruleset, so a refused first load is a failed start that
	// serves no page and no channel; the service manager's restart serves
	// once a load succeeds.
	t.Run("first firewall load refused", func(t *testing.T) {
		x := newBox(t, true)
		x.d.Close()
		x.fire.mu.Lock()
		x.fire.fail = true
		x.fire.mu.Unlock()
		if d, err := x.open(); err == nil {
			d.Close()
			t.Fatal("the daemon started with its first firewall load refused")
		}
		x.start()
		if x.fire.last() == "" || x.d.Page() == nil {
			t.Fatal("the restart after a refused load serves nothing")
		}
	})

	// Silent connections (item 2; ENF-d-4, ENF-l-8): something on the
	// core's segment fills every slot with a TLS connection that never
	// sends its hello. The hello's deadline frees them, and the core
	// connects.
	t.Run("silent connections", func(t *testing.T) {
		x := newBox(t, true)
		x.waits.HelloWait, x.waits.IdleWait = 200*time.Millisecond, time.Hour
		x.restart()
		addr := x.serve()
		for range MaxCoreConns {
			if _, err := x.silent(addr); err != nil {
				t.Fatal(err)
			}
		}
		waitFor(t, func() bool { return x.d.conns.Load() == 0 })
		c, _ := x.dial(addr, x.core)
		if code := c.read(); code != wire.OK {
			t.Fatalf("the core after silent connections: %v", code)
		}
	})

	// Half-open sessions (item 4; ENF-l-8): the core authenticates twice
	// and both connections go dead (a power cut, a pulled cable). The idle
	// deadline frees both slots without counting the core as up, and the
	// core reconnects.
	t.Run("half-open sessions", func(t *testing.T) {
		x := newBox(t, true)
		x.waits.IdleWait = 300 * time.Millisecond
		x.restart()
		addr := x.serve()
		for range MaxCoreConns {
			c, _ := x.dial(addr, x.core)
			c.read()
		}
		waitFor(t, func() bool { return x.d.conns.Load() == 0 })
		x.mu.Lock()
		for _, l := range x.log {
			if strings.Contains(l, wire.ErrShort.Error()) {
				t.Errorf("an idle session's end was logged as the core's refused frame: %s", l)
			}
		}
		x.mu.Unlock()
		x.advance(Silence)
		if !x.d.alerts.Status().CoreDown {
			t.Fatal("an idle session's end counted the core as speaking")
		}
		c, _ := x.dial(addr, x.core)
		if code := c.read(); code != wire.OK {
			t.Fatalf("the core after half-open sessions: %v", code)
		}
	})

	// Firewall load hangs (item 8; KRN-12 Silence): a tick is stuck in a
	// hung nft when the core says hello and then falls silent. The load's
	// deadline frees the clock, and the core shows down though the hello
	// showed it up behind the tick's back.
	t.Run("firewall load hangs", func(t *testing.T) {
		x, _ := enrolled(t, true)
		x.waits.FireWait = time.Second
		x.restart()
		addr := x.serve()
		x.advance(time.Second)
		if !x.d.alerts.Status().CoreDown {
			t.Fatal("a core that never connected counts as up")
		}
		x.fire.mu.Lock()
		x.fire.stall = true
		x.fire.mu.Unlock()
		t.Cleanup(func() { x.fire.mu.Lock(); x.fire.stall = false; x.fire.mu.Unlock() })
		x.d.fwMu.Lock()
		x.d.loaded = "" // the next tick loads, as after a change
		x.d.fwMu.Unlock()
		done := make(chan struct{})
		go func() { x.d.Tick(context.Background()); close(done) }()
		c, _ := x.dial(addr, x.core)
		c.read()
		if x.d.alerts.Status().CoreDown {
			t.Fatal("the hello did not show the core up")
		}
		x.mu.Lock()
		x.now, x.el = x.now.Add(Silence+time.Second), x.el+Silence+time.Second // then silence
		x.mu.Unlock()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			t.Fatal("a hung firewall load stalled the clock")
		}
		if !x.d.alerts.Status().CoreDown {
			t.Fatal("a core silent past Silence shows up after a stalled tick")
		}
	})
}

// tempErr is an Accept error net/http would retry (EMFILE and the like).
type tempErr struct{}

func (tempErr) Error() string   { return "accept: too many open files" }
func (tempErr) Temporary() bool { return true }
func (tempErr) Timeout() bool   { return false }

// flakyListener fails its first n Accepts with err.
type flakyListener struct {
	net.Listener
	n   atomic.Int32
	err error
}

func (l *flakyListener) Accept() (net.Conn, error) {
	if l.n.Add(-1) >= 0 {
		return nil, l.err
	}
	return l.Listener.Accept()
}

// TestChannelListenerRetriesTemporaryErrors (#4755 item 5; NET-2 Channel
// availability): a temporary Accept error does not stop the channel
// listener, and the core still connects; any other error ends it, which
// stops the daemon (main.go) for the service manager to restart.
func TestChannelListenerRetriesTemporaryErrors(t *testing.T) {
	x := newBox(t, true)
	ln, err := net.Listen("tcp", netip.AddrPortFrom(coreAddr, 0).String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	fl := &flakyListener{Listener: ln, err: tempErr{}}
	fl.n.Store(3)
	stopped := make(chan error, 1)
	go func() { stopped <- x.d.ServeChannel(fl) }()
	c, _ := x.dial(ln.Addr().String(), x.core)
	if code := c.read(); code != wire.OK {
		t.Fatalf("the core after temporary accept errors: %v", code)
	}
	select {
	case err := <-stopped:
		t.Fatalf("the listener stopped: %v", err)
	default:
	}

	hard := errors.New("accept: listener broken")
	fl2 := &flakyListener{Listener: ln, err: hard}
	fl2.n.Store(1)
	if err := x.d.ServeChannel(fl2); !errors.Is(err, hard) {
		t.Fatalf("a permanent accept error: %v, want it returned", err)
	}
}

// scriptListener answers each Accept with the next of its steps, an error
// or a connection, and records when each Accept came.
type scriptListener struct {
	mu    sync.Mutex
	steps []any
	at    []time.Time
}

func (l *scriptListener) Accept() (net.Conn, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.at = append(l.at, time.Now())
	s := l.steps[0]
	l.steps = l.steps[1:]
	if c, ok := s.(net.Conn); ok {
		return c, nil
	}
	return nil, s.(error)
}

func (l *scriptListener) Close() error   { return nil }
func (l *scriptListener) Addr() net.Addr { return &net.TCPAddr{} }

// probeConn is an accepted connection that records whether it was read
// (a TLS handshake begun) or closed, and carries no bytes.
type probeConn struct {
	remote netip.AddrPort
	closed atomic.Bool
	read   chan struct{}
	once   sync.Once
}

func newProbeConn(a netip.Addr) *probeConn {
	return &probeConn{remote: netip.AddrPortFrom(a, 40000), read: make(chan struct{})}
}

func (c *probeConn) Read([]byte) (int, error) {
	c.once.Do(func() { close(c.read) })
	return 0, net.ErrClosed
}
func (c *probeConn) Write([]byte) (int, error)        { return 0, net.ErrClosed }
func (c *probeConn) Close() error                     { c.closed.Store(true); return nil }
func (c *probeConn) LocalAddr() net.Addr              { return &net.TCPAddr{} }
func (c *probeConn) RemoteAddr() net.Addr             { return net.TCPAddrFromAddrPort(c.remote) }
func (c *probeConn) SetDeadline(time.Time) error      { return nil }
func (c *probeConn) SetReadDeadline(time.Time) error  { return nil }
func (c *probeConn) SetWriteDeadline(time.Time) error { return nil }

// TestChannelAcceptBackoff (#4755 item 5; NET-2 Channel availability): a
// run of temporary Accept errors waits 5ms, then twice as long each time,
// and logs each wait; an accepted connection starts the next run at 5ms
// again.
func TestChannelAcceptBackoff(t *testing.T) {
	x := newBox(t, true)
	other := newProbeConn(netip.MustParseAddr("192.0.2.9")) // off the core's segment
	hard := errors.New("accept: listener broken")
	l := &scriptListener{steps: []any{tempErr{}, tempErr{}, tempErr{}, other, tempErr{}, hard}}
	if err := x.d.ServeChannel(l); !errors.Is(err, hard) {
		t.Fatalf("ServeChannel: %v, want the permanent error", err)
	}
	if !other.closed.Load() {
		t.Fatal("a connection off the core's segment was left open")
	}
	want := []time.Duration{5 * time.Millisecond, 10 * time.Millisecond, 20 * time.Millisecond, 5 * time.Millisecond}
	var got []string
	x.mu.Lock()
	for _, s := range x.log {
		if strings.HasPrefix(s, "channel: accept: ") {
			got = append(got, s)
		}
	}
	x.mu.Unlock()
	if len(got) != len(want) {
		t.Fatalf("accept retries logged: %q, want %d", got, len(want))
	}
	for i, w := range want {
		if !strings.HasSuffix(got[i], fmt.Sprintf("; retrying in %v", w)) {
			t.Errorf("retry %d logged %q, want a wait of %v", i, got[i], w)
		}
	}
	// Accepts 0-2 and 4 failed; each next Accept waited at least its backoff.
	for i, j := range []int{0, 1, 2, 4} {
		if gap := l.at[j+1].Sub(l.at[j]); gap < want[i] {
			t.Errorf("Accept %d came %v after a temporary error, want at least %v", j+1, gap, want[i])
		}
	}
}

// TestUnsavedTripRefusesUnread (#4755 item 1; KRN-12 Response): while a
// trip is not on disk, a connection from the core's own address is closed
// before any byte of it is read.
func TestUnsavedTripRefusesUnread(t *testing.T) {
	x := newBox(t, true)
	x.fail(fileCut, true)
	x.d.cut.Trip("test trip")
	if !x.d.cut.Unsaved() {
		t.Fatal("the refused trip write counts as saved")
	}
	c := newProbeConn(coreAddr)
	hard := errors.New("accept: listener broken")
	if err := x.d.ServeChannel(&scriptListener{steps: []any{c, hard}}); !errors.Is(err, hard) {
		t.Fatalf("ServeChannel: %v, want the permanent error", err)
	}
	if !c.closed.Load() {
		t.Fatal("a connection taken while a trip was unsaved was left open")
	}
	select {
	case <-c.read:
		t.Fatal("a connection taken while a trip was unsaved was read: a handshake began")
	case <-time.After(200 * time.Millisecond):
	}
}

// TestHandshakeDeadline (#4755 item 2; ENF-d-4): a connection that never
// sends its TLS ClientHello is dropped at the hello's deadline, so it
// cannot hold a slot.
func TestHandshakeDeadline(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	d := &Enforcer{dp: deps{HelloWait: 100 * time.Millisecond}}
	done := make(chan struct{})
	go func() { d.serveConn(tls.Server(a, &tls.Config{MinVersion: tls.VersionTLS13})); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("a connection that sent no ClientHello outlived the hello's deadline")
	}
}

// TestWriteDeadline (#4755 item 4; ENF-l-8): a session whose peer stops
// reading has each write bounded by the idle wait, so a dead core cannot
// hold the session's slot by never draining it.
func TestWriteDeadline(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	dc := &deadlineConn{Conn: a, idle: 100 * time.Millisecond}
	done := make(chan error, 1)
	go func() { _, err := dc.Write([]byte("summary")); done <- err }()
	select {
	case err := <-done:
		if !isTimeout(err) {
			t.Fatalf("a write nobody reads: %v, want its deadline", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("a write nobody reads outlived the idle wait")
	}
}

// TestFirewallLoadBounded (#4755 item 8; KRN-12 Silence): with no wait
// set, each firewall load runs under fireTimeout, and its context ends
// when the load returns rather than when the timer fires.
func TestFirewallLoadBounded(t *testing.T) {
	x := newBox(t, true) // x.waits is zero: the production waits
	x.fire.mu.Lock()
	defer x.fire.mu.Unlock()
	if len(x.fire.ctxs) == 0 {
		t.Fatal("the daemon started without a firewall load")
	}
	if left := x.fire.left[0]; left <= fireTimeout-5*time.Second || left > fireTimeout {
		t.Fatalf("the first load had %v left, want about fireTimeout (%v)", left, fireTimeout)
	}
	if x.fire.ctxs[0].Err() == nil {
		t.Fatal("a finished load's context is still live: its timer outlives the load")
	}
}

// TestCoreCALoaded: the core's page authority on disk is what the
// started daemon holds for the page (CH-9).
func TestCoreCALoaded(t *testing.T) {
	x := newBox(t, true)
	der := []byte("synthetic core CA, not a certificate")
	if err := (fileStore{path: filepath.Join(x.dir, fileCoreCA)}).Save(der); err != nil {
		t.Fatal(err)
	}
	x.restart()
	if !bytes.Equal(x.d.coreCA, der) {
		t.Fatalf("the started daemon holds core CA %q, want the one on disk", x.d.coreCA)
	}
}

// TestHandoverFailureReachesLog (HW-10, NET-4; ENF-c-f3 item 5, #4928): a
// policy hand-over that fails after the passkey is saved still enrols the
// owner and reaches the daemon's own log (Config.Logf), not the standard
// library's fallback that a nil Log would take. Catches a book wired with
// no Log.
func TestHandoverFailureReachesLog(t *testing.T) {
	x := newBox(t, false)
	x.failOn(fileEnrol, 2)                          // the passkey's save lands, the policy pointer's fails
	out := x.b.enrol(newAuthenticator(t), caseCode) // 200: the passkey is in force
	if out["recovery"] == nil {
		t.Fatalf("no recovery code after a hand-over failure: %v", out)
	}
	if n := x.logs("enrol: the passkey enrolled, but the policy hand-over failed"); n != 1 {
		t.Fatalf("hand-over failure reached the log %d times: %q", n, x.log)
	}
}
