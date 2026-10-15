package bridge_test

import (
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/modem"
	"github.com/ghbmrk/agentos/broker/modem/bridge"
)

// REQ: CH-15

// gated holds each owner-line send while r.gate is set and open.
type gated struct {
	bridge.Owner
	r *rig
}

func (g gated) Send(to, text string) error {
	g.r.mu.Lock()
	gate := g.r.gate
	g.r.mu.Unlock()
	if gate != nil {
		select {
		case <-gate:
		case <-g.Done():
			return modem.ErrDown
		}
	}
	return g.Owner.Send(to, text)
}

// sendAsync texts the owner through agentosd's Link, as an owner alert
// does, and returns its result on a channel.
func (r *rig) sendAsync(text string) chan error {
	res := make(chan error, 1)
	go func() { res <- r.link.Send(ownerNum, text) }()
	return res
}

// stopBridge sends the bridge its SIGTERM (its Run context ends) and
// returns a channel closed once Run has returned. The rig's cleanup still
// reads Run's error.
func (r *rig) stopBridge() chan struct{} {
	ran := make(chan struct{})
	r.cancel()
	go func() {
		err := <-r.done
		r.done <- err
		close(ran)
	}()
	return ran
}

// OWNER-ALERT-STOP-ORDER (#1772), owner O34, over the shipped transport (a
// modemlink.Link serving a real owner.sock as agentosd does, bridgeclient):
// the bridge is told to stop while the modem is still sending a text and
// an owner alert waits behind it, as when systemd stops agentos-modem
// before agentosd. agentosd is still up, so the bridge reports that text's
// result, takes the alert, sends it and reports it before it exits.
func TestAnAlertQueuedWhenTheBridgeStopsIsStillSent(t *testing.T) {
	r := newRig(t, recorded)
	r.waitNote(func(n string) bool { return n == "" })
	gate := make(chan struct{})
	r.mu.Lock()
	r.gate = gate
	r.mu.Unlock()
	first := r.sendAsync("Box: an earlier text.")
	time.Sleep(300 * time.Millisecond) // the bridge takes it and sends
	alert := r.sendAsync("Box: a wrong code was entered.")
	ran := r.stopBridge()
	time.Sleep(100 * time.Millisecond)
	close(gate) // the modem has sent the earlier text
	for _, want := range []string{"Box: an earlier text.", "Box: a wrong code was entered."} {
		if got := r.phoneGets(); got != want {
			t.Fatalf("the owner's phone got %q, want %q", got, want)
		}
	}
	for name, res := range map[string]chan error{"earlier text": first, "alert": alert} {
		select {
		case err := <-res:
			if err != nil {
				t.Fatalf("%s: %v", name, err)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("%s: no result reached agentosd", name)
		}
	}
	select {
	case <-ran:
	case <-time.After(3 * time.Second):
		t.Fatal("the bridge did not exit once its outbox was empty")
	}
}

// With nothing queued the bridge exits at its first empty poll, within one
// poll wait, not at its flush bound.
func TestAnIdleBridgeStopsAtItsFirstEmptyPoll(t *testing.T) {
	r := newRig(t, recorded)
	r.waitNote(func(n string) bool { return n == "" })
	stopped := time.Now()
	ran := r.stopBridge()
	select {
	case <-ran:
	case <-time.After(5 * time.Second):
		t.Fatal("the bridge did not exit")
	}
	if took := time.Since(stopped); took >= time.Second {
		t.Fatalf("the bridge took %v to exit with nothing queued", took)
	}
}

// The flush is bounded (FlushWait), so a send that never ends cannot hold
// the bridge past its unit's TimeoutStopSec: the bridge closes the modem
// and exits, and an inbound text that arrives meanwhile is not offered to
// agentosd but stays stored on the modem.
func TestTheFlushIsBounded(t *testing.T) {
	r := newRig(t, recorded)
	r.waitNote(func(n string) bool { return n == "" })
	r.mu.Lock()
	r.gate = make(chan struct{}) // never opened
	r.mu.Unlock()
	res := r.sendAsync("Box: an earlier text.")
	time.Sleep(300 * time.Millisecond) // the bridge takes it and sends
	stopped := time.Now()
	ran := r.stopBridge()
	if err := r.phone.Send(boxNum, "STOP"); err != nil {
		t.Fatal(err)
	}
	select {
	case <-ran:
	case <-time.After(10 * time.Second):
		t.Fatal("the bridge did not exit at its flush bound")
	}
	if took := time.Since(stopped); took < 2*time.Second || took > 5*time.Second {
		t.Fatalf("the bridge exited after %v, want its 2 s bound", took)
	}
	select {
	case m := <-r.link.Inbox():
		t.Fatalf("a text was offered while the bridge stopped: %+v", m)
	default:
	}
	if n := r.stored(); n != 1 {
		t.Fatalf("%d texts stored on the modem, want the STOP kept", n)
	}
	select {
	case err := <-res:
		if err == nil {
			t.Fatal("a text the bridge never sent was reported sent")
		}
	default: // still waiting for a result; agentosd's own drain bounds it
	}
}
