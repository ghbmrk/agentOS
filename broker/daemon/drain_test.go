package daemon

import (
	"context"
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

// startBridged runs the daemon as agentosd runs it with -modem-bridge: the
// owner channel's modem is a modemlink.Link whose texts leave only when
// the bridge polls owner.sock, with a drain bound of drain. It reports the
// owner line ok as the bridge does, starts a wrong-code alert from the
// page, and returns once the alert is queued for the bridge, which has not
// polled yet.
func startBridged(t *testing.T, drain time.Duration) (dir string, cancel context.CancelFunc, d *Daemon, bridge bridgeclient.Client, alert string) {
	t.Helper()
	dir = t.TempDir()
	link := modemlink.New(modemlink.Config{Owner: owner, PollWait: 100 * time.Millisecond})
	line := &noticedLine{Modem: link, text: make(chan string, 1)}
	cancel, d = startWith(t, dir, func(c *Config) {
		c.Auth, c.OwnerState = nil, filepath.Join(dir, "owner.json")
		c.PageSocket = &PageSocket{UID: os.Getuid()}
		c.Modem, c.OwnerOps, c.BridgeOnly, c.OwnerDrainOps = line, link.Ops(), true, modemlink.DrainOps()
		c.SendDrain = drain
	})
	bridge = bridgeclient.Client{Path: filepath.Join(dir, "run", OwnerSocket)}
	if err := bridge.Call(context.Background(), bridgeproto.OpState, bridgeproto.State{OwnerLine: bridgeproto.StateOK}, nil); err != nil {
		t.Fatal(err)
	}
	line.armed.Store(true)
	if r := send(t, filepath.Join(dir, "run", localapi.Socket), localapi.OpSignIn, localapi.SignIn{Code: "000000"}); !r.OK {
		t.Fatalf("sign-in: %+v", r)
	}
	select {
	case alert = <-line.text:
	case <-time.After(5 * time.Second):
		t.Fatal("the wrong code was not texted")
	}
	return dir, cancel, d, bridge, alert
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

// Owner O34 with the shipped transport (Security S2, Potency P4 on #1746):
// an alert still queued for the modem bridge when agentosd is told to stop
// is handed to the bridge through owner.sock during the drain, and Wait
// returns as soon as the bridge reports it sent, well before the bound.
// Meanwhile the page and the bridge's inbound refuse, so no new owner text
// starts and none is taken in that nobody would read.
func TestShutdownDrainHandsAQueuedAlertToTheBridge(t *testing.T) {
	const bound = 10 * time.Second
	dir, cancel, d, bridge, alert := startBridged(t, bound)
	stopped := time.Now()
	cancel()
	waited := make(chan struct{})
	go func() { d.Wait(); close(waited) }()
	// owner.sock is up and the page is still listening, but the page
	// starts nothing and the bridge's inbound text is refused, to be sent
	// again to the next start.
	if r := send(t, filepath.Join(dir, "run", localapi.Socket), localapi.OpSignIn, localapi.SignIn{Code: "000000"}); r.OK || r.Error != string(errStopping) {
		t.Fatalf("page sign-in during the drain: %+v", r)
	}
	in := bridgeproto.Inbound{Line: bridgeproto.LineOwner, From: owner, Text: "STATUS", ID: "in-1"}
	if err := bridge.Call(context.Background(), bridgeproto.OpInbound, in, nil); err == nil || !bridgeproto.Retryable(err) {
		t.Fatalf("inbound during the drain: %v", err)
	}
	select {
	case <-waited:
		t.Fatal("Wait returned with the alert still queued for the bridge")
	default:
	}
	got := make(chan string, 8)
	go poll(bridge, got)
	var delivered time.Time
	for delivered.IsZero() {
		select {
		case txt := <-got:
			if txt == alert {
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
	if _, err := os.Stat(bridge.Path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("owner.sock after Wait: %v", err)
	}
}

// With no bridge polling, the drain holds the stop for its whole bound (not
// less: Security S3, Potency P5 on #1746), then lets agentosd exit.
func TestShutdownDrainWaitsTheBoundWhenTheBridgeNeverPolls(t *testing.T) {
	const bound = time.Second
	_, cancel, d, _, _ := startBridged(t, bound)
	stopped := time.Now()
	cancel()
	waited := make(chan struct{})
	go func() { d.Wait(); close(waited) }()
	select {
	case <-waited:
	case <-time.After(bound + 5*time.Second):
		t.Fatal("Wait did not return by the bound")
	}
	if took := time.Since(stopped); took < bound-50*time.Millisecond {
		t.Fatalf("Wait returned after %v, before the %v bound", took, bound)
	}
}
