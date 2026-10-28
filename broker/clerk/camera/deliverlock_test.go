package camera

// REQ: DEV-7

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/camwire"
)

// gateSink blocks inside its third Frame until release is closed, and
// counts the frames it takes once returned is set.
type gateSink struct {
	in, release chan struct{}
	returned    atomic.Bool
	late, n     atomic.Int32
}

func (g *gateSink) Frame(string, camwire.Frame) error {
	if g.n.Add(1) == 3 {
		close(g.in)
		<-g.release
	}
	if g.returned.Load() {
		g.late.Add(1)
	}
	return nil
}

func (g *gateSink) Cut(string) {}

// TestDeliverLockHoldsOwnerChanges (#3602): a frame that has passed
// hand's re-check and is still inside the sink holds SetCapture(Off) and
// Repin until the sink returns, and no frame reaches the sink after they
// return. It fails if the delivery lock is dropped from hand or change.
func TestDeliverLockHoldsOwnerChanges(t *testing.T) {
	for name, change := range map[string]func(*Clerk) error{
		"capture off": func(c *Clerk) error { return c.SetCapture(testID, Off) },
		"re-pin":      func(c *Clerk) error { return c.Repin(testID, [32]byte{7}) },
	} {
		t.Run(name, func(t *testing.T) {
			g := &gateSink{in: make(chan struct{}), release: make(chan struct{})}
			r := newRig(t, func(c *Config, n *Node) { c.Frames = g; n.Interval = time.Hour })
			r.node.serve = func(_ int, c *tlsConn) {
				for camwire.WriteFrame(c, camwire.ToCore, lepton, video()) == nil {
				}
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			done := make(chan error, 1)
			go func() { done <- r.c.Run(ctx, testID) }()
			<-g.in
			changed := make(chan struct{})
			go func() {
				change(r.c)
				g.returned.Store(true)
				close(changed)
			}()
			select {
			case <-changed:
				t.Error("the change returned while a checked frame was still inside the sink")
			case <-time.After(100 * time.Millisecond):
			}
			close(g.release)
			<-changed
			cancel()
			<-done
			if n := g.late.Load(); n != 0 {
				t.Fatalf("%d frames reached the sink after the change returned", n)
			}
		})
	}
}
