package camera

// REQ: DEV-7, DEV-8

import (
	"context"
	"io"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/camwire"
	"github.com/ghbmrk/agentos/broker/cmd/agentos-camdecode/camdecode"
)

// gated is a sandbox that takes every thermal frame fed at once but
// decodes them only once release is closed, so frames sit inside it; it
// ends, as a killed sandbox does, when Stop closes its input.
func gated(release chan struct{}) func(io.Reader, io.Writer) {
	return func(in io.Reader, out io.Writer) {
		fed, gone := make(chan camwire.Frame, 64), make(chan struct{})
		go func() {
			defer close(gone)
			for {
				f, err := camwire.ReadFrame(in, camwire.ToCore, lepton)
				if err != nil {
					return
				}
				fed <- f
			}
		}()
		for {
			var f camwire.Frame
			select {
			case f = <-fed:
			case <-gone:
				return
			}
			select {
			case <-release:
			case <-gone:
				return
			}
			th, _ := camwire.ParseThermal(f.Payload, lepton)
			out.Write(camdecode.AppendHeader(nil, outThermal, lepton, th.Counter))
			out.Write(th.Samples)
		}
	}
}

// TestDecoderCutDropsQueuedAndInFlight (#3614 item 1): once Cut returns,
// no frame fed before it reaches Out, whether it was queued or inside the
// sandbox; the sandbox is stopped, the camera's shapes stay, and a later
// frame starts a fresh sandbox whose output does reach Out.
func TestDecoderCutDropsQueuedAndInFlight(t *testing.T) {
	release := make(chan struct{})
	var cut atomic.Bool
	var late atomic.Int32
	r := newDecRig(t, func(c *DecodeConfig) {
		out := c.Out
		c.Out = func(d Decoded) {
			if cut.Load() {
				late.Add(1)
			}
			out(d)
		}
	}, gated(release), decodes)
	for i := uint32(1); i <= 4; i++ {
		r.d.Frame(testID, thermalN(i))
	}
	waitFor(t, "the sandbox", func() bool { return r.st.n() == 1 })
	r.d.Cut(testID)
	cut.Store(true)
	close(release)
	select {
	case <-r.st.procs[0].done:
	default:
		t.Error("sandbox still running after Cut")
	}
	time.Sleep(50 * time.Millisecond)
	if n := late.Load(); n != 0 {
		t.Fatalf("%d frames fed before Cut reached Out after it", n)
	}
	cut.Store(false)
	if err := r.d.Frame(testID, thermalN(9)); err != nil {
		t.Fatalf("frame after Cut: %v", err)
	}
	waitFor(t, "a frame from a fresh sandbox", func() bool { return len(r.out.all()) == 1 })
	if got := r.out.all()[0].Counter; got != 9 || r.st.n() != 2 {
		t.Errorf("after Cut: counter %d from start %d, want 9 from start 2", got, r.st.n())
	}
	r.d.Cut("other") // an unknown camera is a no-op
}

// TestClerkCutsDecoderOnOwnerChange (#3614 item 1): revoke, capture off
// and re-pin each cut the decoder, so a frame already handed to it does
// not come out after the change returns.
func TestClerkCutsDecoderOnOwnerChange(t *testing.T) {
	for name, change := range map[string]func(*Clerk) error{
		"capture off": func(c *Clerk) error { return c.SetCapture(testID, Off) },
		"re-pin":      func(c *Clerk) error { return c.Repin(testID, [32]byte{7}) },
		"revoke":      func(c *Clerk) error { c.Remove(testID); return nil },
	} {
		t.Run(name, func(t *testing.T) {
			release := make(chan struct{})
			var changed atomic.Bool
			var late atomic.Int32
			var d *Decoder
			var st *starts
			rig := newRig(t, func(c *Config, n *Node) {
				n.Interval = time.Hour
				st = &starts{runs: []func(io.Reader, io.Writer){gated(release)}}
				var err error
				d, err = NewDecoder(DecodeConfig{Start: st.start, Root: "/r", Cgroup: "/c",
					Out: func(Decoded) {
						if changed.Load() {
							late.Add(1)
						}
					},
					Report: func(string, Kind) {}})
				if err != nil {
					t.Fatal(err)
				}
				c.Frames = d
			})
			defer d.Close()
			if err := d.Add(testID, picture, lepton); err != nil {
				t.Fatal(err)
			}
			rig.node.serve = func(_ int, c *tlsConn) { write(c, thermal(), thermal()); hold(c) }
			stop := rig.start(func(ctx context.Context) error { return rig.c.Run(ctx, testID) })
			defer stop()
			waitFor(t, "frames in the sandbox", func() bool { return st.n() == 1 })
			if err := change(rig.c); err != nil {
				t.Fatal(err)
			}
			changed.Store(true)
			close(release)
			time.Sleep(50 * time.Millisecond)
			if n := late.Load(); n != 0 {
				t.Fatalf("%d frames reached Out after the change returned", n)
			}
		})
	}
	// The sink is cut on every change, by camera.
	f := &frames{}
	rig := newRig(t, func(c *Config, _ *Node) { c.Frames = f })
	rig.c.SetCapture(testID, Off)
	rig.c.Repin(testID, [32]byte{7})
	rig.c.Remove(testID)
	if len(f.cuts) != 3 || f.cuts[0] != testID || f.cuts[2] != testID {
		t.Errorf("cuts %q, want three of %s", f.cuts, testID)
	}
}

// TestDecoderThermalCounterChecked (#3614 item 2): each thermal frame out
// must carry the counter of the next thermal frame fed, so a sandbox that
// invents, reorders or skips frames, or holds a thermal frame back behind
// pictures, is stopped as a fault before the frame reaches Out.
func TestDecoderThermalCounterChecked(t *testing.T) {
	emit := func(out io.Writer, n uint32) {
		h := camdecode.AppendHeader(nil, outThermal, lepton, n)
		out.Write(h)
		out.Write(make([]byte, outLen(outThermal, lepton)))
	}
	for name, c := range map[string]struct {
		feed []uint32
		run  func(io.Reader, io.Writer)
		want int
	}{
		"invented": {[]uint32{1}, liar(func(out io.Writer, _ camwire.Frame) { emit(out, 999) }), 0},
		"reordered": {[]uint32{1, 2}, func(in io.Reader, out io.Writer) {
			for range 2 {
				camwire.ReadFrame(in, camwire.ToCore, lepton)
			}
			emit(out, 2)
			emit(out, 1)
			io.Copy(io.Discard, in)
		}, 0},
		"skipped": {[]uint32{1, 2, 3}, func(in io.Reader, out io.Writer) {
			for range 3 {
				camwire.ReadFrame(in, camwire.ToCore, lepton)
			}
			emit(out, 1)
			emit(out, 3)
			io.Copy(io.Discard, in)
		}, 1},
	} {
		t.Run(name, func(t *testing.T) {
			r := newDecRig(t, func(c *DecodeConfig) { c.Backoff = Backoff{Min: time.Hour, Max: time.Hour} }, c.run)
			for _, n := range c.feed {
				r.d.Frame(testID, thermalN(n))
			}
			waitFor(t, "a fault", func() bool { return r.rep.count(DecoderFault) == 1 })
			if n := len(r.out.all()); n != c.want {
				t.Errorf("%d frames reached Out, want %d", n, c.want)
			}
		})
	}
	// In order, every counter passes and comes out as fed.
	r := newDecRig(t, nil, decodes)
	for _, n := range []uint32{5, 6, 40} {
		r.d.Frame(testID, thermalN(n))
	}
	waitFor(t, "three frames", func() bool { return len(r.out.all()) == 3 })
	for i, want := range []uint32{5, 6, 40} {
		if got := r.out.all()[i].Counter; got != want {
			t.Errorf("frame %d counter %d, want %d", i, got, want)
		}
	}
	if r.rep.count(DecoderFault) != 0 {
		t.Error("a faithful decoder faulted")
	}
}

// TestDecoderThermalHeldBehindPicturesStalls: a sandbox that answers every
// picture but holds a thermal frame back is stopped once that frame has
// waited past the stall deadline, though output never stops.
func TestDecoderThermalHeldBehindPicturesStalls(t *testing.T) {
	r := newDecRig(t, func(c *DecodeConfig) { c.Backoff = Backoff{Min: time.Hour, Max: time.Hour} },
		liar(func(out io.Writer, f camwire.Frame) {
			if f.Type == camwire.TypeVideo {
				out.Write(camdecode.AppendHeader(nil, outVideo, picture, 0))
				out.Write(make([]byte, outLen(outVideo, picture)))
			}
		}))
	r.d.Frame(testID, thermalN(1))
	start := time.Now()
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		for {
			select {
			case <-stop:
				return
			case <-time.After(20 * time.Millisecond):
				r.d.Frame(testID, video())
			}
		}
	}()
	waitFor(t, "a fault", func() bool { return r.rep.count(DecoderFault) == 1 })
	if el := time.Since(start); el < 200*time.Millisecond {
		t.Errorf("stopped after %v, before the 200ms deadline", el)
	}
	for _, d := range r.out.all() {
		if d.Thermal {
			t.Error("a thermal frame reached Out")
		}
	}
}
