package daemon

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/bridgeclient"
	"github.com/ghbmrk/agentos/broker/bridgeproto"
	"github.com/ghbmrk/agentos/broker/localapi"
	"github.com/ghbmrk/agentos/broker/modem"
	"github.com/ghbmrk/agentos/broker/modemlink"
	"github.com/ghbmrk/agentos/broker/sockets"
)

// REQ: CH-15, CH-7

// heldLine holds every text sent once armed until let is closed, telling
// entered of the first: an owner alert still in the modem.
type heldLine struct {
	modem.Modem
	armed   atomic.Bool
	once    sync.Once
	entered chan struct{}
	let     chan struct{}
}

func (m *heldLine) Send(to, text string) error {
	if m.armed.Load() {
		m.once.Do(func() { close(m.entered) })
		<-m.let
	}
	return m.Modem.Send(to, text)
}

// Owner O34: a text a page call started after its reply (here the
// wrong-code alert) is still being sent when agentosd is told to stop;
// Wait, after which agentosd exits, does not return until it is sent.
func TestShutdownWaitsForAPageTextInTheModem(t *testing.T) {
	dir := t.TempDir()
	line := &heldLine{Modem: modem.NewCarrier().Line("+15550000009"), entered: make(chan struct{}), let: make(chan struct{})}
	cancel, d := startWith(t, dir, func(c *Config) {
		c.Auth, c.OwnerState = nil, filepath.Join(dir, "owner.json")
		c.PageSocket = &PageSocket{UID: os.Getuid()}
		c.Modem = line
	})
	defer cancel()
	line.armed.Store(true)
	sock := filepath.Join(dir, "run", localapi.Socket)
	if r := send(t, sock, localapi.OpSignIn, localapi.SignIn{Code: "000000"}); !r.OK {
		t.Fatalf("sign-in: %+v", r)
	}
	select {
	case <-line.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("the wrong code was not texted")
	}
	cancel()
	waited := make(chan struct{})
	go func() { d.Wait(); close(waited) }()
	// This window shows only that Wait waits at all, not that it waits to
	// the bound (Security S3, Potency P5 on #1746): the bound is
	// TestShutdownDrainWaitsTheBoundWhenTheBridgeNeverPolls's.
	select {
	case <-waited:
		t.Fatal("Wait returned with the alert still in the modem")
	case <-time.After(300 * time.Millisecond):
	}
	close(line.let)
	select {
	case <-waited:
	case <-time.After(10 * time.Second):
		t.Fatal("Wait did not return after the alert was sent")
	}
}

// noticedLine tells text of the first text sent once armed, then passes
// it on to the shipped transport (a modemlink.Link).
type noticedLine struct {
	modem.Modem
	armed atomic.Bool
	once  sync.Once
	text  chan string
}

func (m *noticedLine) Send(to, text string) error {
	if m.armed.Load() {
		m.once.Do(func() { m.text <- text })
	}
	return m.Modem.Send(to, text)
}

// bridged is a daemon run as agentosd runs it with -modem-bridge, with a
// wrong-code alert queued for the bridge.
type bridged struct {
	dir    string
	cancel context.CancelFunc
	d      *Daemon
	link   *modemlink.Link
	bridge bridgeclient.Client
	alert  string
	// held is the ID of an earlier text the bridge took and has not
	// reported (busy), as while the modem is still sending it.
	held string
}

// earlier is the text a busy bridge holds.
const earlier = "Box: an earlier text."

// startBridged runs the daemon as agentosd runs it with -modem-bridge: the
// owner channel's modem is a modemlink.Link whose texts leave only when
// the bridge polls owner.sock, with a drain bound of drain. It reports the
// owner line ok as the bridge does, runs before (nil: nothing), starts a
// wrong-code alert from the page, and returns once the alert is queued for
// the bridge, which is not polling then.
func startBridged(t *testing.T, drain time.Duration, before func(*bridged)) *bridged {
	t.Helper()
	b := &bridged{dir: t.TempDir()}
	b.link = modemlink.New(modemlink.Config{Owner: owner, PollWait: 100 * time.Millisecond})
	line := &noticedLine{Modem: b.link, text: make(chan string, 1)}
	b.cancel, b.d = startWith(t, b.dir, func(c *Config) {
		c.Auth, c.OwnerState = nil, filepath.Join(b.dir, "owner.json")
		c.PageSocket = &PageSocket{UID: os.Getuid()}
		c.Modem, c.OwnerOps, c.BridgeOnly = line, b.link.Ops(), true
		c.OwnerDrainOps, c.OwnerDrainLive = modemlink.DrainOps(), b.link.Bridged
		c.SendDrain = drain
	})
	b.bridge = bridgeclient.Client{Path: filepath.Join(b.dir, "run", OwnerSocket)}
	if err := b.bridge.Call(context.Background(), bridgeproto.OpState, bridgeproto.State{OwnerLine: bridgeproto.StateOK}, nil); err != nil {
		t.Fatal(err)
	}
	if before != nil {
		before(b)
	}
	line.armed.Store(true)
	if r := send(t, filepath.Join(b.dir, "run", localapi.Socket), localapi.OpSignIn, localapi.SignIn{Code: "000000"}); !r.OK {
		t.Fatalf("sign-in: %+v", r)
	}
	select {
	case b.alert = <-line.text:
	case <-time.After(5 * time.Second):
		t.Fatal("the wrong code was not texted")
	}
	return b
}

// busy has the bridge take an earlier text and not report it yet, as while
// the modem is still sending it: the bridge is there, but not polling.
func busy(t *testing.T) func(*bridged) {
	return func(b *bridged) {
		go b.link.Send(owner, earlier)
		for b.held == "" {
			var r struct{ Item *bridgeproto.Item }
			if err := b.bridge.Call(context.Background(), bridgeproto.OpOutbox, struct{}{}, &r); err != nil {
				t.Fatal(err)
			}
			switch {
			case r.Item == nil:
			case r.Item.Text == earlier:
				b.held = r.Item.ID
			default: // a recovery text: sent
				if err := b.bridge.Call(context.Background(), bridgeproto.OpSent, bridgeproto.Sent{ID: r.Item.ID, Code: bridgeproto.CodeOK}, nil); err != nil {
					t.Fatal(err)
				}
			}
		}
	}
}

// waitFor returns a channel closed once d.Wait returns.
func waitFor(d *Daemon) chan struct{} {
	waited := make(chan struct{})
	go func() { d.Wait(); close(waited) }()
	return waited
}

// poll is the bridge's loop: it takes each item from the outbox and
// reports it sent, until owner.sock goes; each text taken is sent on got.
func poll(bridge bridgeclient.Client, got chan<- string) {
	for {
		var r struct{ Item *bridgeproto.Item }
		if err := bridge.Call(context.Background(), bridgeproto.OpOutbox, struct{}{}, &r); err != nil {
			if errors.Is(err, bridgeclient.ErrRefused) {
				continue
			}
			return
		}
		if r.Item == nil {
			continue
		}
		if bridge.Call(context.Background(), bridgeproto.OpSent, bridgeproto.Sent{ID: r.Item.ID, Code: bridgeproto.CodeOK}, nil) != nil {
			return
		}
		got <- r.Item.Text
	}
}

// Owner O34 with the shipped transport (Security S2, Potency P4, P7 on
// #1746): the bridge is still sending an earlier text when agentosd is
// told to stop, with an alert queued behind it. During the drain owner.sock
// hears the earlier text's result and hands the bridge the alert, and Wait
// returns as soon as the bridge reports it sent, well before the bound.
func TestShutdownDrainHandsAQueuedAlertToTheBridge(t *testing.T) {
	const bound = 10 * time.Second
	b := startBridged(t, bound, busy(t))
	stopped := time.Now()
	b.cancel()
	waited := waitFor(b.d)
	select {
	case <-waited:
		t.Fatal("Wait returned with the alert still queued for the bridge")
	case <-time.After(300 * time.Millisecond):
	}
	// The modem has sent the earlier text: the bridge reports it, then
	// polls on.
	if err := b.bridge.Call(context.Background(), bridgeproto.OpSent, bridgeproto.Sent{ID: b.held, Code: bridgeproto.CodeOK}, nil); err != nil {
		t.Fatalf("the bridge's result during the drain: %v", err)
	}
	got := make(chan string, 8)
	go poll(b.bridge, got)
	var delivered time.Time
	for delivered.IsZero() {
		select {
		case txt := <-got:
			if txt == b.alert {
				delivered = time.Now()
			}
		case <-waited:
			t.Fatal("Wait returned before the bridge took the alert")
		case <-time.After(bound):
			t.Fatal("the bridge was never handed the alert during the drain")
		}
	}
	select {
	case <-waited:
	case <-time.After(3 * time.Second):
		t.Fatal("Wait did not return once the alert was sent")
	}
	if took := time.Since(stopped); took >= bound {
		t.Fatalf("Wait took %v, the whole bound", took)
	}
	if _, err := os.Stat(b.bridge.Path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("owner.sock after Wait: %v", err)
	}
}

// During the drain the page starts nothing and the bridge's inbound text is
// refused, to be sent again to the next start, so no new owner text starts
// and none is taken in that nobody would read; but the bridge's state is
// still heard, so a SIM swapped during the drain stops the outbox handing
// the queued alert to the wrong SIM's line (S-B8; Security S7, Potency P7
// on #1746).
func TestShutdownDrainRefusesNewWorkButHearsTheBridgesState(t *testing.T) {
	const bound = 10 * time.Second
	b := startBridged(t, bound, busy(t))
	b.cancel()
	waited := waitFor(b.d)
	if r := send(t, filepath.Join(b.dir, "run", localapi.Socket), localapi.OpSignIn, localapi.SignIn{Code: "000000"}); r.OK || r.Error != string(errStopping) {
		t.Fatalf("page sign-in during the drain: %+v", r)
	}
	in := bridgeproto.Inbound{Line: bridgeproto.LineOwner, From: owner, Text: "STATUS", ID: "in-1"}
	if err := b.bridge.Call(context.Background(), bridgeproto.OpInbound, in, nil); err == nil || !bridgeproto.Retryable(err) {
		t.Fatalf("inbound during the drain: %v", err)
	}
	if err := b.bridge.Call(context.Background(), bridgeproto.OpState, bridgeproto.State{OwnerLine: bridgeproto.StateSwapped}, nil); err != nil {
		t.Fatalf("a swapped SIM reported during the drain: %v", err)
	}
	var r struct{ Item *bridgeproto.Item }
	if err := b.bridge.Call(context.Background(), bridgeproto.OpOutbox, struct{}{}, &r); err != nil || r.Item != nil {
		t.Fatalf("the outbox on a swapped SIM during the drain: %+v, %v", r.Item, err)
	}
	select {
	case <-waited:
		t.Fatal("Wait returned while the bridge held a text")
	default:
	}
	if err := b.bridge.Call(context.Background(), bridgeproto.OpSent, bridgeproto.Sent{ID: b.held, Code: bridgeproto.CodeOK}, nil); err != nil {
		t.Fatalf("the bridge's result during the drain: %v", err)
	}
	// The bridge holds nothing and polls no more: the drain ends.
	select {
	case <-waited:
	case <-time.After(modemlink.BridgeGap + 3*time.Second):
		t.Fatal("Wait did not return once the bridge was gone")
	}
}

// While the bridge holds a text and never reports it, the drain holds the
// stop for its whole bound (not less: Security S3, Potency P5 on #1746),
// then lets agentosd exit.
func TestShutdownDrainWaitsTheBoundWhileTheBridgeHoldsAText(t *testing.T) {
	const bound = time.Second
	b := startBridged(t, bound, busy(t))
	stopped := time.Now()
	b.cancel()
	select {
	case <-waitFor(b.d):
	case <-time.After(bound + 5*time.Second):
		t.Fatal("Wait did not return by the bound")
	}
	if took := time.Since(stopped); took < bound-50*time.Millisecond {
		t.Fatalf("Wait returned after %v, before the %v bound", took, bound)
	}
}

// With the shipped units systemd stops agentos-modem before agentosd
// (Security S5, Potency P6 on #1746): no bridge is on owner.sock when the
// drain starts, so nothing can take the alert, and the drain ends at once
// (within BridgeGap of the bridge's last poll) rather than hold the stop
// for its bound. The alert is lost, as before #1746 (owner O34).
func TestShutdownDrainEndsWhenNoBridgeIsConnected(t *testing.T) {
	const bound = 10 * time.Second
	for name, before := range map[string]func(*bridged){
		"never polled": nil,
		"polled, then stopped first": func(b *bridged) {
			var r struct{ Item *bridgeproto.Item }
			if err := b.bridge.Call(context.Background(), bridgeproto.OpOutbox, struct{}{}, &r); err != nil {
				t.Fatal(err)
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			b := startBridged(t, bound, before)
			stopped := time.Now()
			b.cancel()
			select {
			case <-waitFor(b.d):
			case <-time.After(modemlink.BridgeGap + 2*time.Second):
				t.Fatalf("Wait held the stop %v with no bridge connected", time.Since(stopped))
			}
		})
	}
}

// A call in flight at the stop has its context ended, so a long poll
// cannot hold the stop (Security S7, Potency P7 on #1746).
func TestShutdownEndsTheCallsInFlight(t *testing.T) {
	dir := t.TempDir()
	entered, ended, release := make(chan struct{}), make(chan error, 1), make(chan struct{})
	defer close(release)
	cancel, d := startWith(t, dir, func(c *Config) {
		c.OwnerOps = map[string]sockets.Handler{"hold": func(ctx context.Context, _ sockets.Peer, _ json.RawMessage) (any, error) {
			close(entered)
			select {
			case <-ctx.Done():
				ended <- ctx.Err()
				return nil, ctx.Err()
			case <-release:
				ended <- nil
				return struct{}{}, nil
			}
		}}
	})
	go bridgeclient.Client{Path: filepath.Join(dir, "run", OwnerSocket)}.Call(context.Background(), "hold", struct{}{}, nil)
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("the call did not start")
	}
	cancel()
	select {
	case err := <-ended:
		if err == nil {
			t.Fatal("the call in flight was not ended")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the call in flight at the stop did not end")
	}
	select {
	case <-waitFor(d):
	case <-time.After(5 * time.Second):
		t.Fatal("Wait did not return")
	}
}

// The drain starts only once the calls in flight at the stop have
// returned, so none can start a text the drain does not wait for (Security
// S7, Potency P7 on #1746).
func TestShutdownDrainStartsAfterTheCallsInFlight(t *testing.T) {
	dir := t.TempDir()
	entered, let := make(chan struct{}), make(chan struct{})
	var drained atomic.Bool
	cancel, d := startWith(t, dir, func(c *Config) {
		c.Auth, c.OwnerState = nil, filepath.Join(dir, "owner.json")
		c.OwnerDrainLive = func() bool { drained.Store(true); return true }
		c.OwnerOps = map[string]sockets.Handler{"hold": func(context.Context, sockets.Peer, json.RawMessage) (any, error) {
			close(entered)
			<-let // a handler that does not heed its context
			return struct{}{}, nil
		}}
	})
	var once sync.Once
	release := func() { once.Do(func() { close(let) }) }
	t.Cleanup(release) // before the stop startWith waits for
	go bridgeclient.Client{Path: filepath.Join(dir, "run", OwnerSocket)}.Call(context.Background(), "hold", struct{}{}, nil)
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("the call did not start")
	}
	cancel()
	time.Sleep(300 * time.Millisecond)
	if drained.Load() {
		t.Fatal("the drain started with a call in flight")
	}
	release()
	select {
	case <-waitFor(d):
	case <-time.After(5 * time.Second):
		t.Fatal("Wait did not return")
	}
	if !drained.Load() {
		t.Fatal("the drain never ran")
	}
}

// A call that arrives after the stop, before the stage is shut, is refused
// rather than run with an ended context (Security S6 on #1746).
func TestShutdownStageRefusesACallAfterTheStop(t *testing.T) {
	stop, cancel := context.WithCancel(context.Background())
	s := &stage{}
	var ran bool
	h := s.wrap(stop, func(context.Context, sockets.Peer, json.RawMessage) (any, error) {
		ran = true
		return struct{}{}, nil
	})
	if _, err := h(context.Background(), sockets.Peer{}, nil); err != nil || !ran {
		t.Fatalf("before the stop: ran %v, %v", ran, err)
	}
	ran = false
	cancel()
	if _, err := h(context.Background(), sockets.Peer{}, nil); err != errStopping || ran {
		t.Fatalf("after the stop: ran %v, %v", ran, err)
	}
}
