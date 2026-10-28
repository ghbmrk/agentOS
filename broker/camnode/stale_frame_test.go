package camnode

// REQ: NET-2

// TestStaleFrameNeverCrossesBundles (L3 on #3617, delta finding 1): a frame
// the pump parked under one bundle is never delivered after later bundles
// turned the stream off and re-pinned the core. Revert mutant: stream
// without its epoch check. Probe by the delta L3 review.

import (
	"sync"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/camwire"
	"github.com/ghbmrk/agentos/broker/camwire/camwiretest"
)

type genSource struct {
	mu     sync.Mutex
	gen    byte
	stream bool
	last   byte // generation of the last frame read
}

func (s *genSource) Apply(st camwire.Settings) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.gen++
	s.stream = st.Stream
	return nil
}

func (s *genSource) Read() (camwire.Frame, error) {
	for {
		time.Sleep(5 * time.Millisecond)
		s.mu.Lock()
		on, g := s.stream, s.gen
		s.mu.Unlock()
		if on && g != s.last {
			// rpicam-vid takes a while to start after Apply
			time.Sleep(500 * time.Millisecond)
			s.last = g
		}
		if on {
			return camwire.Frame{Type: camwire.TypeVideo, Payload: []byte{0, 0, 0, 1, 0x65, g}}, nil
		}
	}
}

func TestStaleFrameNeverCrossesBundles(t *testing.T) {
	r := newRig(t, true)
	src := &genSource{}
	r.node.cfg.Source = src
	r.provision(3) // gen 1, stream on, core A
	a := r.streaming(r.core)
	a.Close() // core A drops off (network, restart); the pump parks a frame
	time.Sleep(100 * time.Millisecond)

	off := r.bundle(4)
	off.Settings.Stream = false // gen 2, nothing captured
	c, _ := r.dial(r.enforcer)
	if _, err := send(c, r.owner.SignBundle(t, off)); err != nil {
		t.Fatal(err)
	}

	on := r.bundle(5) // gen 3, stream on, a new core key
	newCore := camwiretest.NewKey(t)
	on.Core = camwiretest.Point(&newCore.PublicKey)
	c, _ = r.dial(r.enforcer)
	if _, err := send(c, r.owner.SignBundle(t, on)); err != nil {
		t.Fatal(err)
	}
	b, err := r.dial(newCore)
	if err != nil {
		t.Fatal(err)
	}
	f, err := camwire.ReadFrame(b, camwire.ToCore, camwire.Shape{})
	if err != nil {
		t.Fatal(err)
	}
	if g := f.Payload[len(f.Payload)-1]; g != 3 {
		t.Fatalf("new core's first frame was captured under settings generation %d (bundle for the old core), want 3", g)
	}
}
