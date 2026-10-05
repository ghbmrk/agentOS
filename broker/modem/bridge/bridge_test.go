package bridge_test

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/bridgeclient"
	"github.com/ghbmrk/agentos/broker/bridgeproto"
	"github.com/ghbmrk/agentos/broker/modem"
	"github.com/ghbmrk/agentos/broker/modem/at"
	"github.com/ghbmrk/agentos/broker/modem/atsim"
	"github.com/ghbmrk/agentos/broker/modem/bridge"
	"github.com/ghbmrk/agentos/broker/modemlink"
	"github.com/ghbmrk/agentos/broker/sockets"
)

// REQ: CH-1, CH-2, ADP-12

const (
	ownerNum = "+15550000999"
	boxNum   = "+15550000100"
)

// rig runs agentosd's end (a modemlink.Link on a real owner socket) and
// the bridge over simulated modems on one carrier.
type rig struct {
	t       *testing.T
	carrier *modem.Carrier
	phone   *modem.Line
	link    *modemlink.Link
	mu      sync.Mutex
	devs    []*atsim.Device
	iccid   string
	openErr error
	cancel  context.CancelFunc
	done    chan error
}

func newRig(t *testing.T, iccid func(*atsim.Device) string) *rig {
	t.Helper()
	r := &rig{t: t, carrier: modem.NewCarrier(), done: make(chan error, 1)}
	r.phone = r.carrier.Line(ownerNum)
	r.link = modemlink.New(modemlink.Config{Owner: ownerNum, SendWait: 5 * time.Second, PollWait: 200 * time.Millisecond})
	dir := t.TempDir()
	ctx, cancel := context.WithCancel(context.Background())
	r.cancel = cancel
	srv := &sockets.Server{Dir: dir}
	if err := srv.Start(ctx, sockets.Endpoint{Name: "owner.sock", Peer: sockets.Peer{Kind: "owner"}, Ops: r.link.Ops(), MaxConns: 8}); err != nil {
		t.Fatal(err)
	}
	r.iccid = iccid(atsim.New(at.SIMCom, "SIMCOM_SIM7600G-H", modem.NewCarrier().Line(boxNum), time.Millisecond))
	cfg := bridge.Config{
		Agentosd: bridgeclient.Client{Path: filepath.Join(dir, "owner.sock")},
		OpenOwner: func(ctx context.Context) (bridge.Owner, error) {
			r.mu.Lock()
			err := r.openErr
			r.mu.Unlock()
			if err != nil {
				return nil, err
			}
			// Each open is a fresh port, as a reopened serial device is.
			dev := r.newDevice()
			return at.Open(ctx, at.Config{Profile: at.SIMCom, Port: dev.Port(), Number: boxNum, CountryCode: "1", Owner: ownerNum,
				Poll: 5 * time.Millisecond, Sweep: 20 * time.Millisecond})
		},
		OwnerICCID: func() string { r.mu.Lock(); defer r.mu.Unlock(); return r.iccid },
		Retry:      50 * time.Millisecond,
		StateEvery: 50 * time.Millisecond,
		Logf:       t.Logf,
	}
	go func() { r.done <- bridge.Run(ctx, cfg) }()
	t.Cleanup(func() {
		cancel()
		if err := <-r.done; err != nil && !errors.Is(err, context.Canceled) {
			t.Errorf("bridge: %v", err)
		}
		srv.Wait()
	})
	return r
}

func (r *rig) newDevice() *atsim.Device {
	dev := atsim.New(at.SIMCom, "SIMCOM_SIM7600G-H", r.carrier.Line(boxNum), time.Millisecond)
	r.mu.Lock()
	r.devs = append(r.devs, dev)
	r.mu.Unlock()
	return dev
}

func recorded(d *atsim.Device) string { return d.ICCID() }

// waitNote waits for the owner line's local-page note to satisfy ok.
func (r *rig) waitNote(ok func(string) bool) string {
	r.t.Helper()
	var n string
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
		if n = r.link.OwnerLineNote(); ok(n) {
			return n
		}
	}
	r.t.Fatalf("owner line note stayed %q", n)
	return n
}

func (r *rig) phoneGets() string {
	r.t.Helper()
	select {
	case m := <-r.phone.Inbox():
		return m.Text
	case <-time.After(5 * time.Second):
		r.t.Fatal("no text to the owner's phone")
	}
	return ""
}

// P2-3w part 1, end to end over the AT simulator and a real owner.sock:
// the owner's texts reach agentosd's owner channel, and its texts reach
// the owner's phone.
func TestOwnerTextsBothWays(t *testing.T) {
	r := newRig(t, recorded)
	r.waitNote(func(n string) bool { return n == "" })
	if err := r.phone.Send(boxNum, "STATUS"); err != nil {
		t.Fatal(err)
	}
	select {
	case m := <-r.link.Inbox():
		if m.From != ownerNum || m.Text != "STATUS" {
			t.Fatalf("delivered %+v", m)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the owner's text did not reach agentosd")
	}
	if err := r.link.Send(ownerNum, "Box: all well."); err != nil {
		t.Fatalf("send: %v", err)
	}
	if got := r.phoneGets(); got != "Box: all well." {
		t.Fatalf("phone got %q", got)
	}
}

// Security S-B8, UX U-B3: a SIM that is not the one recorded for the owner
// line is reported swapped, and no text passes either way; no recorded SIM
// is unbound.
func TestASwappedOrUnboundSIMStopsTheOwnerLine(t *testing.T) {
	r := newRig(t, func(*atsim.Device) string { return "89010000000000000000" })
	r.waitNote(func(n string) bool { return strings.HasPrefix(n, "The SIM in my phone modem changed.") })
	r.phone.Send(boxNum, "STOP")
	select {
	case m := <-r.link.Inbox():
		t.Fatalf("a text on a swapped SIM reached agentosd: %+v", m)
	case <-time.After(200 * time.Millisecond):
	}
	if err := r.link.Send(ownerNum, "hi"); !errors.Is(err, modem.ErrDown) {
		t.Fatalf("send on a swapped SIM: %v", err)
	}
	r.mu.Lock()
	r.iccid = ""
	r.mu.Unlock()
	r.waitNote(func(n string) bool {
		return strings.HasPrefix(n, "My phone modem has no SIM, or its number isn't set up.")
	})
	r.mu.Lock()
	r.iccid = r.devs[0].ICCID()
	r.mu.Unlock()
	r.waitNote(func(n string) bool { return n == "" })
	// The SIM is pulled: the modem restarts and opens without one.
	r.mu.Lock()
	r.openErr = &at.SIMError{Status: at.Status{SIM: at.SIMMissing}}
	dev := r.devs[len(r.devs)-1]
	r.mu.Unlock()
	dev.Unplug()
	r.waitNote(func(n string) bool { return strings.HasPrefix(n, "My phone modem has no SIM") })
}

// UX U-B1, U-B2: a modem that goes away reads as down; what could not be
// sent meanwhile is counted, and once it is back the owner gets one text
// with the count, nothing replayed.
func TestAnUnpluggedModemIsDownAndRecovers(t *testing.T) {
	r := newRig(t, recorded)
	r.waitNote(func(n string) bool { return n == "" })
	r.mu.Lock()
	r.openErr = errors.New("no modem")
	dev := r.devs[0]
	r.mu.Unlock()
	dev.Unplug()
	r.waitNote(func(n string) bool { return strings.HasPrefix(n, "I can't reach my phone modem.") })
	for i := 0; i < 2; i++ {
		if err := r.link.Send(ownerNum, "approve? code 123456"); !errors.Is(err, modem.ErrDown) {
			t.Fatalf("send while unplugged: %v", err)
		}
	}
	r.mu.Lock()
	r.openErr = nil
	r.mu.Unlock()
	r.waitNote(func(n string) bool { return n == "" })
	got := r.phoneGets()
	if !strings.HasPrefix(got, "I couldn't text you from ") || !strings.Contains(got, "2 texts weren't sent; see my Wi-Fi page.") {
		t.Fatalf("recovery text %q", got)
	}
	select {
	case m := <-r.phone.Inbox():
		t.Fatalf("replayed %q", m.Text)
	case <-time.After(200 * time.Millisecond):
	}
}

var _ = bridgeproto.OpState
