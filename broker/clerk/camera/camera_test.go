package camera

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/camwire"
	"github.com/ghbmrk/agentos/broker/kernel/key"
	"github.com/ghbmrk/agentos/broker/netguard"
)

// REQ: DEV-3, DEV-7, KRN-7

// TestSpoofedNodeRefused: a node with another key is refused at the
// handshake, before any frame is read and before the client key signs
// anything; the node is off with a KRN-7 line and one tamper event, and is
// not dialed again until the owner re-pins it. Revert mutant: dial skipping
// the SPKI comparison streams the spoofer's frame.
func TestSpoofedNodeRefused(t *testing.T) {
	r := newRig(t)
	_, other := newCert(t)
	if err := r.c.Repin(testID, other); err != nil { // the pin is now another node's key
		t.Fatal(err)
	}
	r.node.serve = func(_ int, c *tlsConn) { write(c, video()); hold(c) }
	signed := r.store.lends.Load()

	if err := r.c.Run(bounded(t), testID); !errors.Is(err, ErrOff) {
		t.Fatalf("Run = %v, want ErrOff", err)
	}
	if r.fr.len() != 0 {
		t.Fatal("a frame from the spoofed node reached the decoder")
	}
	if got := r.store.lends.Load(); got != signed {
		t.Fatalf("the client key was lent %d times for a spoofed node", got-signed)
	}
	if ev := r.ev.of(KeyRefused); len(ev) != 1 || !ev[0].Verified || ev[0].Camera != testID || ev[0].Label != Label {
		t.Fatalf("tamper events = %+v, want one verified key-refused", ev)
	}
	if !strings.Contains(r.log.all(), "off: its key does not match the pin") || !strings.Contains(r.log.all(), "KRN-7") {
		t.Fatalf("no KRN-7 line in the log:\n%s", r.log.all())
	}
	if st := r.c.Status(); len(st) != 1 || !strings.Contains(st[0], "off") {
		t.Fatalf("STATUS = %q", st)
	}
	dials := r.node.dials.Load()
	if err := r.c.Run(bounded(t), testID); !errors.Is(err, ErrOff) {
		t.Fatalf("second Run = %v, want ErrOff", err)
	}
	if r.node.dials.Load() != dials {
		t.Fatal("an off node was dialed again")
	}

	// The owner re-pins the real key: it streams again.
	if err := r.c.Repin(testID, r.node.pin); err != nil {
		t.Fatal(err)
	}
	stop := r.start(func(ctx context.Context) error { return r.c.Run(ctx, testID) })
	waitFor(t, "a frame after the re-pin", func() bool { return r.fr.len() > 0 })
	stop()
}

// REQ: DEV-7, DEV-10

// TestNoStreamBeforeTurnOn: with capture off no connection is opened; a
// continuous camera opens none for a step; an on-request camera opens one
// only for a read step of a task naming it, and only until the task ends.
// Revert mutant: Run ignoring the mode dials an off camera.
func TestNoStreamBeforeTurnOn(t *testing.T) {
	r := newRig(t, func(_ *Config, n *Node) { n.Capture = Off })
	r.node.serve = func(_ int, c *tlsConn) { write(c, video(), thermal(), status()); hold(c) }
	step := Step{Task: "task-1", Camera: testID, Verb: key.Read}
	if err := r.c.Run(bounded(t), testID); !errors.Is(err, ErrCaptureOff) {
		t.Fatalf("Run with capture off = %v", err)
	}
	if err := r.c.Capture(bounded(t), step); !errors.Is(err, ErrCaptureOff) {
		t.Fatalf("Capture with capture off = %v", err)
	}
	r.c.SetCapture(testID, Continuous)
	if err := r.c.Capture(bounded(t), step); !errors.Is(err, ErrCaptureOff) {
		t.Fatalf("Capture of a continuous camera = %v", err)
	}
	r.c.SetCapture(testID, OnRequest)
	if err := r.c.Run(bounded(t), testID); !errors.Is(err, ErrCaptureOff) {
		t.Fatalf("Run of an on-request camera = %v", err)
	}
	for _, s := range []Step{
		{Task: "task-1", Camera: "garden", Verb: key.Read},
		{Task: "task-1", Camera: testID, Verb: key.Actuate},
		{Task: "", Camera: testID, Verb: key.Read},
	} {
		err := r.c.Capture(bounded(t), s)
		if !errors.Is(err, ErrStep) && !errors.Is(err, ErrUnknown) {
			t.Fatalf("Capture(%+v) = %v", s, err)
		}
	}
	if n := r.node.dials.Load(); n != 0 {
		t.Fatalf("%d connections opened before a step allowed one", n)
	}

	stop := r.start(func(ctx context.Context) error { return r.c.Capture(ctx, step) })
	waitFor(t, "the step's frames", func() bool { return r.fr.len() == 2 })
	if err := stop(); !errors.Is(err, context.Canceled) {
		t.Fatalf("Capture at task end = %v", err)
	}
	if st, ok := r.c.LastStatus(testID); !ok || st.Uptime != 42 {
		t.Fatalf("status = %+v, %v", st, ok)
	}
	if r.fr.f[0].Type != camwire.TypeVideo || r.fr.f[1].Type != camwire.TypeThermal {
		t.Fatalf("frames = %v, %v", r.fr.f[0].Type, r.fr.f[1].Type)
	}

	// Turning capture off ends a running stream at once.
	r.c.SetCapture(testID, Continuous)
	done := make(chan error, 1)
	go func() { done <- r.c.Run(context.Background(), testID) }()
	waitFor(t, "streaming", func() bool { return r.fr.len() >= 4 })
	r.c.SetCapture(testID, Off)
	select {
	case err := <-done:
		if !errors.Is(err, ErrCaptureOff) {
			t.Fatalf("Run after turn-off = %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("turning capture off did not end the stream")
	}
}

// REQ: CLK-1, A16

// TestClientKeyNeverLeaves: the canary client key appears in no log line,
// error, event, frame or STATUS line, and no value prints it; the node sees
// only its public certificate.
func TestClientKeyNeverLeaves(t *testing.T) {
	r := newRig(t)
	r.node.serve = func(n int, c *tlsConn) {
		switch n {
		case 1:
			write(c, video(), status())
			c.Write([]byte{9, 0, 0, 0, 1, 0}) // a fault
		default:
			hold(c) // silence
		}
	}
	stop := r.start(func(ctx context.Context) error { return r.c.Run(ctx, testID) })
	waitFor(t, "a fault and silence", func() bool { return len(r.ev.of(StreamFault)) > 0 && len(r.ev.of(Silent)) > 0 })
	stop()
	_, other := newCert(t)
	r.c.Repin(testID, other)
	r.c.Run(bounded(t), testID)
	if r.node.wrong.Load() != 0 {
		t.Fatal("the node was shown a key other than the core's point")
	}

	var all bytes.Buffer
	fmt.Fprintf(&all, "%s\n%q\n%+v\n%#v\n%v\n%+v\n%#v\n", r.log.all(), r.c.Status(), r.ev.ev, r.ev.ev, r.c, r.c, r.c.cfg.Key)
	for _, err := range r.errs {
		fmt.Fprintf(&all, "%v\n", err)
	}
	for _, f := range r.fr.f {
		all.Write(f.Payload)
	}
	raw := r.store.raw
	for _, form := range [][]byte{raw, []byte(hex.EncodeToString(raw)), []byte(base64.StdEncoding.EncodeToString(raw)), []byte(base64.RawURLEncoding.EncodeToString(raw))} {
		if bytes.Contains(all.Bytes(), form) {
			t.Fatal("the client key appears in the clerk's output")
		}
	}
	if s := fmt.Sprintf("%v %+v %#v %s", r.c.cfg.Key, r.c.cfg.Key, r.c.cfg.Key, r.c.cfg.Key); strings.Contains(s, "D:") || strings.Count(s, "camera.ClientKey{}") != 4 {
		t.Fatalf("the key prints as %q", s)
	}
}

// REQ: DEV-1, DEV-2

// TestOnlyPinnedAddressDialed: an address off the home network is refused
// at Add, a home address the host did not pin is refused by the guard
// before any connection, and a pinned node is dialed at exactly its pin.
func TestOnlyPinnedAddressDialed(t *testing.T) {
	r := newRig(t)
	for _, a := range []string{"8.8.8.8:8443", "[2001:db8::1]:8443", "127.0.0.1:8443", "[::1]:8443", "192.168.1.255:8443",
		"224.0.0.1:8443", "0.0.0.0:8443", "192.168.1.61:0", "[fe80::1%eth0]:8443"} {
		n := Node{ID: "other", Addr: netip.MustParseAddrPort(a), Key: r.node.pin, Capture: Continuous}
		if err := r.c.Add(n); !errors.Is(err, ErrAddress) {
			t.Errorf("Add(%s) = %v, want ErrAddress", a, err)
		}
	}
	unpinned := Node{ID: "garden", Addr: netip.MustParseAddrPort("192.168.1.61:8443"), Key: r.node.pin, Capture: Continuous, Interval: time.Hour}
	if err := r.c.Add(unpinned); err != nil {
		t.Fatal(err)
	}
	stop := r.start(func(ctx context.Context) error { return r.c.Run(ctx, "garden") })
	waitFor(t, "a refused dial", func() bool { return strings.Contains(r.log.all(), "camera garden: dial refused") })
	stop()
	if r.node.dials.Load() != 0 {
		t.Fatal("the guard let an unpinned address connect")
	}

	r.node.serve = func(_ int, c *tlsConn) { write(c, video()); hold(c) }
	stop = r.start(func(ctx context.Context) error { return r.c.Run(ctx, testID) })
	waitFor(t, "a frame", func() bool { return r.fr.len() > 0 })
	stop()
	for _, a := range r.node.dialed() {
		if a != testAddr.String() {
			t.Fatalf("dialed %s, pinned %s", a, testAddr)
		}
	}

	// A pin of another kind (a backup target) does not admit a device dial.
	r.guard.SetPins([]netguard.Pin{{Kind: netguard.PinBackup, Addr: testAddr, Key: r.node.pin}})
	before := r.node.dials.Load()
	stop = r.start(func(ctx context.Context) error { return r.c.Run(ctx, testID) })
	time.Sleep(30 * time.Millisecond)
	stop()
	if r.node.dials.Load() != before {
		t.Fatal("a non-device pin admitted the camera's dial")
	}
}

// REQ: DEV-8

// TestSilenceRaisesEvent: a node that stops sending past its interval
// raises one silent event and is redialed; frames again raise a recovery.
func TestSilenceRaisesEvent(t *testing.T) {
	r := newRig(t, func(c *Config, _ *Node) { c.Now = time.Now })
	r.node.serve = func(n int, c *tlsConn) {
		if len(r.ev.of(Silent)) == 0 {
			if n == 1 {
				write(c, video())
			}
			return // the node hangs up at once: silent once its interval passes
		}
		write(c, video())
		hold(c)
	}
	stop := r.start(func(ctx context.Context) error { return r.c.Run(ctx, testID) })
	waitFor(t, "recovery", func() bool { return len(r.ev.of(Recovered)) == 1 })
	if st := r.c.Status(); !strings.Contains(st[0], "streaming") {
		t.Fatalf("STATUS after recovery = %q", st)
	}
	stop()
	if s := r.ev.of(Silent); len(s) != 1 || !s[0].Verified {
		t.Fatalf("silent events = %+v, want one verified", s)
	}

	// A node that keeps its connection open but sends nothing is silent
	// at its read deadline.
	r2 := newRig(t)
	r2.node.serve = func(n int, c *tlsConn) {
		if n == 1 {
			write(c, video())
		}
		hold(c)
	}
	stop = r2.start(func(ctx context.Context) error { return r2.c.Run(ctx, testID) })
	waitFor(t, "a stall", func() bool { return len(r2.ev.of(Silent)) == 1 })
	if st := r2.c.Status(); st[0] != "camera porch: silent" {
		t.Fatalf("STATUS while silent = %q", st)
	}
	stop()
}

// TestEventsRateLimited: a flapping node's faults coalesce to Burst events
// and one counted event per window, while another kind still passes.
// Revert mutant: emit without the limit sends every fault.
func TestEventsRateLimited(t *testing.T) {
	r := newRig(t, func(c *Config, _ *Node) { c.Limit = Limit{Burst: 1, Window: time.Minute} })
	r.node.serve = func(_ int, c *tlsConn) {
		write(c, video())
		c.Write([]byte{byte(camwire.TypeBundle), 0, 0, 0, 1, 0})
	}
	stop := r.start(func(ctx context.Context) error { return r.c.Run(ctx, testID) })
	waitFor(t, "a flapping node", func() bool { return r.node.dials.Load() >= 6 })
	stop()
	faults := int(r.node.dials.Load()) // each connection ends in one fault
	if n := len(r.ev.of(StreamFault)); n != 1 {
		t.Fatalf("%d fault events inside the window, want 1", n)
	}
	_, other := newCert(t)
	r.c.Repin(testID, other)
	r.c.Run(bounded(t), testID)
	if len(r.ev.of(KeyRefused)) != 1 {
		t.Fatal("the key change was hidden by the fault flood")
	}
	r.clock.add(time.Minute)
	if err := r.c.Flush(); err != nil {
		t.Fatal(err)
	}
	ev := r.ev.of(StreamFault)
	if len(ev) != 2 || ev[1].Coalesced < faults-2 || ev[1].Coalesced > faults-1 {
		t.Fatalf("coalesced = %+v after %d faults", ev, faults)
	}
}

// REQ: NET-2

// TestFrameHeaderFaultsEndConnection: an unknown type, an over-cap length
// and a settings-type frame from the node each end the connection in the
// clerk, with a fault event; nothing after them is read.
func TestFrameHeaderFaultsEndConnection(t *testing.T) {
	for name, bad := range map[string][]byte{
		"unknown type":   {9, 0, 0, 0, 1, 0},
		"over cap":       {byte(camwire.TypeVideo), 0, 0x40, 0, 0},
		"settings frame": {byte(camwire.TypeBundle), 0, 0, 0, 1, 0},
		"manifest frame": {byte(camwire.TypeManifest), 0, 0, 0, 1, 0},
		"status length":  {byte(camwire.TypeStatus), 0, 0, 0, 1, 0},
		"thermal shape":  {byte(camwire.TypeThermal), 0, 0, 0, 1, 0},
		"not annex b":    {byte(camwire.TypeVideo), 0, 0, 0, 5, 1, 2, 3, 4, 5},
	} {
		t.Run(name, func(t *testing.T) {
			r := newRig(t)
			after := make(chan error, 1)
			r.node.serve = func(n int, c *tlsConn) {
				if n > 1 {
					hold(c)
					return
				}
				write(c, video())
				c.Write(bad)
				// The clerk has hung up: this frame is never read.
				after <- camwire.WriteFrame(c, camwire.ToCore, lepton, video())
			}
			stop := r.start(func(ctx context.Context) error { return r.c.Run(ctx, testID) })
			waitFor(t, "the fault", func() bool { return len(r.ev.of(StreamFault)) == 1 })
			select {
			case <-after:
			case <-time.After(5 * time.Second):
				t.Fatal("the connection was not closed")
			}
			stop()
			if r.fr.len() != 1 {
				t.Fatalf("%d frames reached the decoder, want the one before the fault", r.fr.len())
			}
		})
	}
}

// REQ: DEV-7, LOG-4

// TestCaptureNotInLogOrEvents: after a run with faults and silence, no
// payload byte (the stream's marker) is in the log, events, STATUS or an
// error, while the decoder got it; and the package links no recall or log
// store, so capture has no path there.
func TestCaptureNotInLogOrEvents(t *testing.T) {
	r := newRig(t)
	r.node.serve = func(n int, c *tlsConn) {
		write(c, video(), thermal(), status())
		if n == 1 {
			c.Write(append([]byte{9, 0, 0, 0, byte(len(marker))}, marker...))
			return
		}
		hold(c)
	}
	stop := r.start(func(ctx context.Context) error { return r.c.Run(ctx, testID) })
	waitFor(t, "fault, frames and silence", func() bool {
		return len(r.ev.of(StreamFault)) == 1 && len(r.ev.of(Silent)) == 1 && r.fr.len() >= 4
	})
	stop()
	got := false
	for _, f := range r.fr.f {
		got = got || bytes.Contains(f.Payload, marker)
	}
	if !got {
		t.Fatal("control: the decoder never got the marker")
	}
	out := fmt.Sprintf("%s\n%q\n%+v\n%v", r.log.all(), r.c.Status(), r.ev.ev, r.errs)
	if strings.Contains(out, string(marker)) || strings.Contains(out, hex.EncodeToString(marker)) {
		t.Fatalf("capture bytes reached the log, events or STATUS:\n%s", out)
	}

	deps, err := exec.Command("go", "list", "-deps", ".").CombinedOutput()
	if err != nil {
		t.Fatalf("go list: %v\n%s", err, deps)
	}
	for _, p := range strings.Fields(string(deps)) {
		for _, banned := range []string{"/broker/recall", "/broker/journal", "/broker/kernel/log", "/broker/events"} {
			if strings.HasSuffix(p, banned) || strings.Contains(p, banned+"/") {
				t.Errorf("the camera clerk links %s", p)
			}
		}
	}
}

// TestConfigAndAdmission: a config missing a part is refused, and a camera
// admission refuses is not added and is logged (RES-2); one stream per
// camera.
func TestConfigAndAdmission(t *testing.T) {
	if _, err := New(Config{}); !errors.Is(err, ErrConfig) {
		t.Fatalf("New(empty) = %v", err)
	}
	r := newRig(t, func(c *Config, _ *Node) {
		c.Admit = func(id string) bool { return id != "garden" }
	})
	if err := r.c.Add(Node{ID: "garden", Addr: netip.MustParseAddrPort("192.168.1.61:8443"), Key: r.node.pin}); !errors.Is(err, ErrAdmission) {
		t.Fatalf("Add past admission = %v", err)
	}
	if !strings.Contains(r.log.all(), "camera garden: not admitted (RES-2)") {
		t.Fatal("refusal not logged")
	}
	for _, n := range []Node{
		{ID: "Porch!", Addr: testAddr, Key: r.node.pin},
		{ID: "back", Addr: testAddr},
		{ID: testID, Addr: testAddr, Key: r.node.pin},
	} {
		if err := r.c.Add(n); !errors.Is(err, ErrNode) {
			t.Errorf("Add(%+v) = %v", n.ID, err)
		}
	}
	r.node.serve = func(_ int, c *tlsConn) { write(c, video()); hold(c) }
	stop := r.start(func(ctx context.Context) error { return r.c.Run(ctx, testID) })
	waitFor(t, "a frame", func() bool { return r.fr.len() > 0 })
	if err := r.c.Run(bounded(t), testID); !errors.Is(err, ErrBusy) {
		t.Fatalf("second stream = %v", err)
	}
	if st := r.c.Status(); !strings.HasPrefix(st[0], "camera porch: streaming") {
		t.Fatalf("STATUS = %q", st)
	}
	r.c.Remove(testID)
	if err := stop(); !errors.Is(err, context.Canceled) && !errors.Is(err, ErrUnknown) {
		t.Fatalf("Run after Remove = %v", err)
	}
}

var _ net.Conn = (*tlsConn)(nil)
