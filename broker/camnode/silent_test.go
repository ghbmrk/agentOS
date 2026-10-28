package camnode

import (
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/camwire"
)

// silentSource yields no frames: the stream is off, or the encoder is down.
type silentSource struct{ fakeSource }

func (s *silentSource) Read() (camwire.Frame, error) { select {} }

// REQ: NET-2

// TestSilentStreamFreesItsSlot (L3 on #3617, finding 1): a core stream
// that ends while no frame flows (the stream off, the encoder restarting)
// returns at once, so core reconnects cannot fill the connection cap and
// lock the enforcer out. Revert mutant: stream reading the source itself
// rather than selecting on its connection's end. Probe by the L3 review.
func TestSilentStreamFreesItsSlot(t *testing.T) {
	r := newRig(t, true)
	r.provision(3)
	r.node.cfg.Source = &silentSource{}
	for range maxConns {
		c, err := r.dial(r.core)
		if err != nil {
			t.Fatal(err)
		}
		c.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
		c.Read(make([]byte, 1)) // the handshake completes; no frame comes
		c.Close()               // the core gives up and reconnects
	}
	time.Sleep(200 * time.Millisecond)
	c, err := r.dial(r.enforcer)
	if err == nil {
		c.SetReadDeadline(time.Now().Add(2 * time.Second))
		_, err = readStatus(c)
	}
	if err != nil {
		t.Fatalf("enforcer locked out after %d core reconnects with no frames: %v", maxConns, err)
	}
}
