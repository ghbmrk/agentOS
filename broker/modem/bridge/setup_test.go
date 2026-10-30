package bridge_test

import (
	"context"
	"errors"
	"path/filepath"
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

// REQ: CH-1, CH-12

// P2-2w c4c, end to end over the AT simulator and a real owner.sock: on a
// box with no owner the bridge runs with no owner's number, setup binds
// the box's SIM, reads the box's number, gets a PAIR text from any phone
// and texts that phone back.
func TestSetupPairsOverTheBridge(t *testing.T) {
	carrier := modem.NewCarrier()
	phone := carrier.Line("+15550000101")
	dir := t.TempDir()
	var mu sync.Mutex
	recorded := ""
	line := modemlink.NewSetup(modemlink.SetupConfig{PollWait: 200 * time.Millisecond, SendWait: 5 * time.Second,
		Record: func(iccid string) error { mu.Lock(); defer mu.Unlock(); recorded = iccid; return nil }})
	sctx, sstop := context.WithCancel(context.Background())
	srv := &sockets.Server{Dir: dir}
	if err := srv.Start(sctx, sockets.Endpoint{Name: "owner.sock", Peer: sockets.Peer{Kind: "owner"}, Ops: line.Ops(), MaxConns: 8,
		HangupOps: map[string]bool{bridgeproto.OpOutbox: true}}); err != nil {
		t.Fatal(err)
	}
	var dev *atsim.Device
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- bridge.Run(ctx, bridge.Config{
			Agentosd: bridgeclient.Client{Path: filepath.Join(dir, "owner.sock")},
			OpenOwner: func(ctx context.Context, check func(string) error) (bridge.Owner, error) {
				mu.Lock()
				if dev == nil {
					dev = atsim.New(at.SIMCom, "SIMCOM_SIM7600G-H", carrier.Line(boxNum), time.Millisecond)
				} else {
					dev = dev.Reopen()
				}
				port := dev.Port()
				mu.Unlock()
				return at.Open(ctx, at.Config{Profile: at.SIMCom, Port: port, Number: boxNum, CountryCode: "1", CheckSIM: check, KeepUntilAck: true,
					Poll: 5 * time.Millisecond, Sweep: 20 * time.Millisecond})
			},
			OwnerICCID:   func() string { mu.Lock(); defer mu.Unlock(); return recorded },
			Retry:        50 * time.Millisecond,
			StateEvery:   time.Hour,
			InboundRetry: 10 * time.Millisecond,
			Logf:         t.Logf,
		})
	}()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil && !errors.Is(err, context.Canceled) {
			t.Errorf("bridge: %v", err)
		}
		sstop()
		srv.Wait()
	})
	deadline := time.Now().Add(5 * time.Second)
	for !line.Ready() {
		if time.Now().After(deadline) {
			t.Fatal("the setup line never became ready")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if line.Number() != boxNum {
		t.Fatalf("box number %q", line.Number())
	}
	mu.Lock()
	if recorded != dev.ICCID() {
		t.Errorf("recorded %q, SIM %q", recorded, dev.ICCID())
	}
	mu.Unlock()
	if err := phone.Send(boxNum, "hello"); err != nil {
		t.Fatal(err)
	}
	if err := phone.Send(boxNum, "PAIR 4821"); err != nil {
		t.Fatal(err)
	}
	nctx, ncancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer ncancel()
	from, text, ok := line.Next(nctx)
	if !ok || from != "+15550000101" || text != "PAIR 4821" {
		t.Fatalf("setup got %q %q %v", from, text, ok)
	}
	if err := line.Send(context.Background(), from, "agentOS is running on this PC. This is your box's number."); err != nil {
		t.Fatal(err)
	}
	select {
	case m := <-phone.Inbox():
		if m.From != boxNum {
			t.Fatalf("reply from %q", m.From)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no reply reached the phone")
	}
}
