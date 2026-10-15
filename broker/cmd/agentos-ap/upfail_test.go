package main

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/apnet"
	"github.com/ghbmrk/agentos/broker/durable"
)

// REQ: CH-12, REC-4, CH-7

// rotate writes a rotated password for the card's network, as agentosd's
// hand-off does, and returns it.
func (b *box) rotate(t *testing.T, password string) apnet.Network {
	t.Helper()
	n := apnet.Network{SSID: cardNet.SSID, Password: password}
	m, err := n.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if err := durable.WriteFile(b.cfg.APNet, m, 0o600); err != nil {
		t.Fatal(err)
	}
	return n
}

func (b *box) failures(t *testing.T) apnet.UpFailures {
	t.Helper()
	f, err := apnet.ReadUpFailures(b.cfg.APNet)
	if err != nil {
		t.Fatal(err)
	}
	return f
}

// #1525: when Up keeps failing for a rotated card network, each run (one
// per systemd restart) counts the failure against that network on disk,
// for agentosd to tell the owner past the bound, and serves only the
// rotated password: never the previous one. Once the network has served
// for a settled while the count is cleared.
func TestAFailingUpIsCountedAndNeverServesThePreviousNetwork(t *testing.T) {
	b := newBox(t, "wlan0")
	b.reportCardNet(t)
	os.WriteFile(b.cfg.Latch, []byte(`{"card_confirmed":true}`), 0o600)
	cancel, done := b.runAsync(t)
	waitFor(t, func() bool { return b.startedCount() == 1 })
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}

	rotated := b.rotate(t, "QRST-UVWX-YZ23-4567")
	id, err := apnet.NetworkID(b.cfg.APNet)
	if err != nil {
		t.Fatal(err)
	}
	b.ap.mu.Lock()
	b.ap.startErr = errors.New("hostapd: synthetic failure")
	b.ap.mu.Unlock()
	for i := 1; i <= apnet.UpFailureBound+1; i++ {
		if err := b.run(context.Background()); err == nil {
			t.Fatalf("run %d: a failing Up ended the run without an error", i)
		}
		if f := b.failures(t); f.Count != i || f.Network != id {
			t.Fatalf("after run %d: %+v, want %d failures of %s", i, f, i, id)
		}
	}
	for i := 1; i < b.startedCount(); i++ {
		if c := b.startedAt(i); c.Password != rotated.Password || c.SSID != rotated.SSID {
			t.Fatalf("attempt %d brought up %q without the rotated password", i, c.SSID)
		}
	}

	b.ap.mu.Lock()
	b.ap.startErr = nil
	b.ap.mu.Unlock()
	n := b.startedCount()
	cancel, done = b.runAsync(t)
	waitFor(t, func() bool { return b.startedCount() == n+1 })
	waitFor(t, func() bool { return b.failures(t) == apnet.UpFailures{} })
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if c := b.startedAt(n); c.Password != rotated.Password {
		t.Fatal("recovered without the rotated password")
	}
}

// #1525: a card network's child that dies before the network settles is
// a failed recovery too, and is counted; a cleared count is not cleared
// again before that.
func TestACardNetworkChildThatDiesIsCounted(t *testing.T) {
	b := newBox(t, "wlan0")
	b.reportCardNet(t)
	os.WriteFile(b.cfg.Latch, []byte(`{"card_confirmed":true}`), 0o600)
	b.cfg.Poll = time.Hour // nothing settles while the child runs
	cancel, done := b.runAsync(t)
	defer cancel()
	waitFor(t, func() bool { return b.startedCount() == 1 })
	b.ap.mu.Lock()
	close(b.ap.exited)
	b.ap.mu.Unlock()
	if err := <-done; err == nil {
		t.Fatal("a dead child ended the run without an error")
	}
	if f := b.failures(t); f.Count != 1 {
		t.Fatalf("%+v, want one failure", f)
	}
}

// #1525: only the card's network is counted; a failing setup network is
// not a rotation, and writes no record.
func TestASetupNetworkFailureIsNotCounted(t *testing.T) {
	b := newBox(t, "wlan0")
	b.reportCardNet(t)
	b.ap.startErr = errors.New("hostapd: synthetic failure")
	if err := b.run(context.Background()); err == nil {
		t.Fatal("a failing Up ended the run without an error")
	}
	if c := b.startedAt(0); c.SSID != b.net.SSID {
		t.Fatalf("brought up %q, want the setup network", c.SSID)
	}
	if _, err := os.Stat(apnet.UpFailuresPath(b.cfg.APNet)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("a setup network failure was recorded: %v", err)
	}
}
