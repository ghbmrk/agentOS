package main

// REQ: NET-2, KRN-12
// The daemon's fail-safes from #4754's Security and L3 reviews (#4755):
// lifecycle rows run from TestLifecycle (failSafeRows), plus the channel
// listener's Accept retry.

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/netip"
	"strings"
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
		if _, err := x.silent(addr); err == nil {
			t.Fatal("the channel took a connection while a trip was unsaved")
		}
		x.advance(time.Second)
		if !x.d.cut.Unsaved() || x.d.cut.Stage() != channel.Tripped {
			t.Fatal("a retry the disk refused counts as saved, or lifted the cut")
		}
		x.fail(fileCut, false)
		x.advance(time.Second)
		if x.d.cut.Unsaved() {
			t.Fatal("the tick did not retry the unsaved trip")
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
