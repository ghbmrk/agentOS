package camera

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"os/exec"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/camwire"
	"github.com/ghbmrk/agentos/broker/clerk/devhost"
	"github.com/ghbmrk/agentos/broker/kernel/key"
	"github.com/ghbmrk/agentos/broker/netguard"
)

// REQ: DEV-2, DEV-3, DEV-7, DEV-8, DEV-10, CLK-1, KRN-7, NET-2, LOG-4, A16

func readStep(cam, task string) key.Step {
	return key.Step{Verb: key.Read, Clerk: ClerkName, Task: task, Args: map[string]key.Arg{CameraArg: {Value: cam}}}
}

// TestSpoofedNodeRefused: a node with another key is refused at the
// handshake, nothing is read, the node is off, a KRN-7 line and one tamper
// event are emitted, and it is not dialed again until re-pinned. Revert
// mutant: dropping the pin check in VerifyConnection streams the marker.
func TestSpoofedNodeRefused(t *testing.T) {
	real := newNode(t, send(video(0)))
	e := newEnv(t, real, Continuous)
	spoof := newNode(t, send(video(1), video(2)))
	e.mu.Lock()
	e.nodes[testAddr] = spoof
	e.mu.Unlock()

	err := e.c.Run(context.Background(), e.cam.ID)
	if !errors.Is(err, ErrSpoofed) {
		t.Fatalf("Run = %v, want ErrSpoofed", err)
	}
	if e.nframes() != 0 || spoof.conns.Load() != 0 {
		t.Fatalf("a spoofed node got %d frames read and %d sessions", e.nframes(), spoof.conns.Load())
	}
	if !e.c.Off(e.cam.ID) {
		t.Fatal("node not off")
	}
	if len(e.losses) != 1 || e.losses[0] != (Loss{Camera: "porch", Reason: ReasonKey}) {
		t.Fatalf("losses = %+v, want one KRN-7 line", e.losses)
	}
	if n, _ := e.count(KindKey); n != 1 || len(e.events) != 1 {
		t.Fatalf("events = %+v, want one key event", e.events)
	}
	ev := e.events[0]
	if ev.Device != "porch" || ev.Label != "private" || ev.Unverified {
		t.Fatalf("event = %+v, want private and verified for porch", ev)
	}

	dials := e.dials.Load()
	if err := e.c.Run(context.Background(), e.cam.ID); !errors.Is(err, ErrOff) {
		t.Fatalf("second Run = %v, want ErrOff", err)
	}
	if e.dials.Load() != dials {
		t.Fatal("an off node was dialed again")
	}

	// Re-pin to the new key (tier 4): it streams; the old key is refused.
	cm := e.cam
	cm.Key = spoof.point
	e.pin(cm)
	if err := e.c.Repin(cm.ID, spoof.point); err != nil {
		t.Fatal(err)
	}
	stop := e.run()
	waitFor(t, "frames after re-pin", func() bool { return e.nframes() == 2 })
	stop()
	e.mu.Lock()
	e.nodes[testAddr] = real
	e.mu.Unlock()
	e.pin(e.cam)
	if err := e.c.Run(context.Background(), e.cam.ID); !errors.Is(err, ErrSpoofed) {
		t.Fatalf("old key after re-pin: Run = %v, want ErrSpoofed", err)
	}
}

// TestNoStreamBeforeTurnOn: with capture off no connection is opened; on
// request opens one only within a task whose read step names the camera,
// and ends it at the task's end.
func TestNoStreamBeforeTurnOn(t *testing.T) {
	n := newNode(t, send(video(0)))
	e := newEnv(t, n, CaptureOff)
	ctx := context.Background()
	if err := e.c.Run(ctx, "porch"); !errors.Is(err, ErrCapture) {
		t.Fatalf("Run with capture off = %v", err)
	}
	if err := e.c.Capture(ctx, "porch", readStep("porch", "t1")); !errors.Is(err, ErrCapture) {
		t.Fatalf("Capture with capture off = %v", err)
	}

	cm := e.cam
	cm.Capture = OnRequest
	if err := e.c.Set(cm); err != nil {
		t.Fatal(err)
	}
	if err := e.c.Run(ctx, "porch"); !errors.Is(err, ErrCapture) {
		t.Fatalf("Run on request = %v, want ErrCapture", err)
	}
	bad := []key.Step{
		readStep("garage", "t1"),
		readStep("porch", ""),
		{Verb: key.Actuate, Clerk: ClerkName, Task: "t1", Args: map[string]key.Arg{CameraArg: {Value: "porch"}}},
		{Verb: key.Read, Clerk: "mail", Task: "t1", Args: map[string]key.Arg{CameraArg: {Value: "porch"}}},
	}
	for i, s := range bad {
		if err := e.c.Capture(ctx, "porch", s); !errors.Is(err, ErrStep) {
			t.Fatalf("step %d: Capture = %v, want ErrStep", i, err)
		}
	}
	if e.dials.Load() != 0 {
		t.Fatalf("%d dials before a turned-on stream", e.dials.Load())
	}

	done := make(chan error, 1)
	go func() { done <- e.c.Capture(ctx, "porch", readStep("porch", "t1")) }()
	waitFor(t, "a frame in the task", func() bool { return e.nframes() == 1 })
	e.c.EndTask("t2")
	select {
	case err := <-done:
		t.Fatalf("another task's end stopped the stream: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	e.c.EndTask("t1")
	select {
	case err := <-done:
		if !errors.Is(err, ErrRemoved) {
			t.Fatalf("Capture after task end = %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("task end did not close the stream")
	}

	// Turning capture off ends a continuous stream.
	cm.Capture = Continuous
	if err := e.c.Set(cm); err != nil {
		t.Fatal(err)
	}
	go func() { done <- e.c.Run(ctx, "porch") }()
	waitFor(t, "a continuous frame", func() bool { return e.nframes() == 2 })
	cm.Capture = CaptureOff
	if err := e.c.Set(cm); err != nil {
		t.Fatal(err)
	}
	if err := <-done; !errors.Is(err, ErrRemoved) {
		t.Fatalf("Run after turn-off = %v", err)
	}
}

// TestClientKeyNeverLeaves: the canary client key appears in no log line,
// error, event or frame (A16), and the node saw the key's public half, so
// the key was used.
func TestClientKeyNeverLeaves(t *testing.T) {
	n := newNode(t, send(status(), video(0)))
	e := newEnv(t, n, Continuous)
	stop := e.run()
	waitFor(t, "a frame", func() bool { return e.nframes() == 1 })
	runErr := stop()

	spoof := newNode(t, nil)
	e.mu.Lock()
	e.nodes[testAddr] = spoof
	e.mu.Unlock()
	spoofErr := e.c.Run(context.Background(), "porch")

	want, err := ClientPoint(lendCanary)
	if err != nil {
		t.Fatal(err)
	}
	n.mu.Lock()
	seen := n.clients
	n.mu.Unlock()
	if len(seen) == 0 || seen[0] != want {
		t.Fatal("node did not see the core's client key")
	}

	all := e.everything(runErr, spoofErr)
	all = append(all, fmt.Sprintf("%v %+v %#v %s", e.c, e.c, e.c, e.c))
	for _, f := range e.frames {
		all = append(all, string(f.Payload))
	}
	forms := []string{string(canaryKey), hex.EncodeToString(canaryKey), base64.StdEncoding.EncodeToString(canaryKey), "canary"}
	for _, s := range all {
		for _, f := range forms {
			if strings.Contains(s, f) {
				t.Fatalf("client key leaked in %q", s)
			}
		}
	}
}

// TestOnlyPinnedAddressDialed: addresses off the home network are refused
// before a dial, and an address the guard has not pinned is refused by it.
func TestOnlyPinnedAddressDialed(t *testing.T) {
	n := newNode(t, send(video(0)))
	e := newEnv(t, n, Continuous)
	for _, a := range []string{"8.8.8.8:7443", "127.0.0.1:7443", "[::1]:7443", "[2001:db8::1]:7443", "192.168.1.255:7443", "0.0.0.0:7443", "224.0.0.1:7443", "192.168.1.21:0"} {
		cm := e.cam
		cm.ID = "other"
		cm.Addr = netip.MustParseAddrPort(a)
		if err := e.c.Set(cm); !errors.Is(err, ErrAddress) {
			t.Fatalf("Set(%s) = %v, want ErrAddress", a, err)
		}
	}

	// A home address the guard holds no device pin for is refused by the
	// guard, so nothing connects.
	cm := e.cam
	cm.ID = "shed"
	cm.Addr = netip.MustParseAddrPort("192.168.1.30:7443")
	if err := e.c.Set(cm); err != nil {
		t.Fatal(err)
	}
	if _, err := e.c.dial(context.Background(), cm); !errors.Is(err, netguard.ErrDenied) {
		t.Fatalf("dial unpinned = %v, want ErrDenied", err)
	}
	// Pinned with another kind (a backup target), still refused.
	p, _ := cm.GuardPin()
	p.Kind = netguard.PinBackup
	if err := e.guard.SetPins([]netguard.Pin{p}); err != nil {
		t.Fatal(err)
	}
	if _, err := e.c.dial(context.Background(), cm); !errors.Is(err, netguard.ErrDenied) {
		t.Fatalf("dial backup-pinned = %v, want ErrDenied", err)
	}
	if e.dials.Load() != 0 {
		t.Fatalf("%d connections opened", e.dials.Load())
	}
}

// TestSilenceRaisesEvent: a node that stops sending past its interval
// raises one silent event; the clerk redials, and the next frame raises
// one recovered event.
func TestSilenceRaisesEvent(t *testing.T) {
	n := newNode(t, func(i int, c *tls.Conn) {
		if i == 0 {
			camwire.WriteFrame(c, camwire.ToCore, camwire.Shape{}, video(0))
			hold(c) // silent: ends when the clerk gives up on it
			return
		}
		send(video(i))(i, c)
	})
	e := newEnv(t, n, Continuous)
	cm := e.cam
	cm.Silence = 60 * time.Millisecond
	if err := e.c.Set(cm); err != nil {
		t.Fatal(err)
	}
	stop := e.run()
	waitFor(t, "recovery", func() bool { r, _ := e.count(KindRecovered); return r == 1 })
	stop()
	if s, _ := e.count(KindSilent); s != 1 {
		t.Fatalf("silent events = %d, want 1", s)
	}
	if n.conns.Load() < 2 {
		t.Fatal("no redial after silence")
	}
	if e.events[0].Reading.Kind != KindSilent || e.events[1].Reading.Kind != KindRecovered {
		t.Fatalf("events = %+v, want silent then recovered", e.events)
	}
}

// TestEventsRateLimited: a flapping node coalesces to one counted event per
// window and kind.
func TestEventsRateLimited(t *testing.T) {
	n := newNode(t, func(i int, c *tls.Conn) {
		camwire.WriteFrame(c, camwire.ToCore, camwire.Shape{}, video(i))
		hold(c)
	})
	e := newEnv(t, n, Continuous, func(c *Config) { c.Limit = devhost.Limit{Burst: 1, Window: time.Hour} })
	cm := e.cam
	cm.Silence = 30 * time.Millisecond
	if err := e.c.Set(cm); err != nil {
		t.Fatal(err)
	}
	stop := e.run()
	waitFor(t, "several flaps", func() bool { return n.conns.Load() >= 5 })
	stop()
	s, _ := e.count(KindSilent)
	r, _ := e.count(KindRecovered)
	if s != 1 || r != 1 {
		t.Fatalf("within one window: %d silent and %d recovered events, want 1 each", s, r)
	}
	e.skew.Store(int64(2 * time.Hour))
	if err := e.c.Flush(); err != nil {
		t.Fatal(err)
	}
	s2, sc := e.count(KindSilent)
	r2, rc := e.count(KindRecovered)
	if s2 != 2 || r2 != 2 || sc < 2 || rc < 2 {
		t.Fatalf("after the window: silent %d (coalesced %d), recovered %d (coalesced %d)", s2, sc, r2, rc)
	}
	if err := e.c.Flush(); err != nil {
		t.Fatal(err)
	}
	if s3, _ := e.count(KindSilent); s3 != 2 {
		t.Fatal("a window was flushed twice")
	}
}

// TestFrameHeaderFaultsEndConnection: an unknown type, an over-cap length
// and a settings-type frame from the node each end the connection in the
// clerk, raise a fault event, and deliver nothing after them.
func TestFrameHeaderFaultsEndConnection(t *testing.T) {
	header := func(typ byte, n uint32) []byte {
		return binary.BigEndian.AppendUint32([]byte{typ}, n)
	}
	cases := map[string][]byte{
		"unknown type":   append(header(9, 4), 0, 0, 0, 1),
		"over cap":       header(byte(camwire.TypeVideo), camwire.MaxVideo+1),
		"settings frame": append(header(byte(camwire.TypeBundle), 4), 1, 2, 3, 4),
		"thermal undeclared": append(header(byte(camwire.TypeThermal), 10),
			make([]byte, 10)...),
		"status short": append(header(byte(camwire.TypeStatus), 4), 0, 0, 0, 0),
	}
	for name, bad := range cases {
		t.Run(name, func(t *testing.T) {
			ended := make(chan struct{}, 8)
			n := newNode(t, func(i int, c *tls.Conn) {
				camwire.WriteFrame(c, camwire.ToCore, camwire.Shape{}, video(i))
				c.Write(bad)
				c.Write(append(append([]byte{}, header(byte(camwire.TypeVideo), 8)...), 0, 0, 0, 1, 'a', 'f', 't', 'r'))
				hold(c)
				ended <- struct{}{}
			})
			e := newEnv(t, n, Continuous)
			stop := e.run()
			select {
			case <-ended:
			case <-time.After(5 * time.Second):
				t.Fatal("connection not ended by the clerk")
			}
			waitFor(t, "fault event", func() bool { f, _ := e.count(KindFault); return f >= 1 })
			stop()
			e.mu.Lock()
			defer e.mu.Unlock()
			for _, f := range e.frames {
				if bytes.Contains(f.Payload, []byte("aftr")) {
					t.Fatal("a frame after the fault was delivered")
				}
			}
		})
	}
}

// TestCaptureNotInLogOrEvents: after a run that ends in a fault, silence
// and a spoof, no payload byte (the marker) is in the log, events, losses,
// errors or STATUS; frames went only to Frames. The package links no
// recall or log writer, so it has no path into recall (LOG-4).
func TestCaptureNotInLogOrEvents(t *testing.T) {
	n := newNode(t, func(i int, c *tls.Conn) {
		camwire.WriteFrame(c, camwire.ToCore, camwire.Shape{}, status())
		camwire.WriteFrame(c, camwire.ToCore, camwire.Shape{}, video(i))
		if i == 0 {
			c.Write([]byte{9, 0, 0, 0, 4, 'M', 'A', 'R', 'K'})
		}
		hold(c)
	})
	e := newEnv(t, n, Continuous)
	cm := e.cam
	cm.Silence = 40 * time.Millisecond
	if err := e.c.Set(cm); err != nil {
		t.Fatal(err)
	}
	stop := e.run()
	waitFor(t, "fault and silence", func() bool {
		f, _ := e.count(KindFault)
		s, _ := e.count(KindSilent)
		return f >= 1 && s >= 1
	})
	runErr := stop()
	st, ok := e.c.Status("porch")
	if !ok || st.Uptime != 7 || st.Temperature != 4100 {
		t.Fatalf("status = %+v, %v", st, ok)
	}
	e.mu.Lock()
	e.nodes[testAddr] = newNode(t, nil)
	e.mu.Unlock()
	spoofErr := e.c.Run(context.Background(), "porch")

	if e.nframes() == 0 || !bytes.Contains(e.frames[0].Payload, []byte(marker)) {
		t.Fatal("frames did not reach Frames")
	}
	all := e.everything(runErr, spoofErr)
	all = append(all, fmt.Sprintf("%+v", st))
	for _, s := range all {
		if strings.Contains(s, marker) || strings.Contains(s, "MARK") {
			t.Fatalf("payload in %q", s)
		}
	}

	out, err := exec.Command("go", "list", "-deps", ".").CombinedOutput()
	if err != nil {
		t.Fatalf("go list: %v\n%s", err, out)
	}
	for _, p := range strings.Fields(string(out)) {
		for _, banned := range []string{"/broker/recall", "/broker/journal", "/broker/events", "/broker/kernel/proc"} {
			if strings.HasSuffix(p, banned) || strings.Contains(p, banned+"/") {
				t.Errorf("camera links %s", p)
			}
		}
	}
}

// TestAdmissionRefusesNewCamera: RES-2 admission saying no refuses a new
// camera and logs it; a refused camera is never dialed.
func TestAdmissionRefusesNewCamera(t *testing.T) {
	n := newNode(t, nil)
	e := newEnv(t, n, Continuous)
	e.mu.Lock()
	e.admit = false
	e.mu.Unlock()
	cm := e.cam
	cm.ID = "gate"
	cm.Addr = netip.MustParseAddrPort("192.168.1.31:7443")
	if err := e.c.Set(cm); !errors.Is(err, ErrAdmission) {
		t.Fatalf("Set = %v, want ErrAdmission", err)
	}
	if err := e.c.Run(context.Background(), "gate"); !errors.Is(err, ErrUnknown) {
		t.Fatalf("Run = %v, want ErrUnknown", err)
	}
	if !strings.Contains(strings.Join(e.everything(), "\n"), "admission refused a camera: gate") {
		t.Fatal("refusal not logged")
	}
}

// TestOneStreamPerCamera: a second stream for a streaming camera is
// refused, and a camera's key changes only by Repin.
func TestOneStreamPerCamera(t *testing.T) {
	n := newNode(t, send(video(0)))
	e := newEnv(t, n, Continuous)
	stop := e.run()
	waitFor(t, "a frame", func() bool { return e.nframes() == 1 })
	if err := e.c.Run(context.Background(), "porch"); !errors.Is(err, ErrBusy) {
		t.Fatalf("second Run = %v, want ErrBusy", err)
	}
	stop()
	cm := e.cam
	cm.Key = newNode(t, nil).point
	if err := e.c.Set(cm); !errors.Is(err, ErrCamera) {
		t.Fatalf("Set with another key = %v, want ErrCamera", err)
	}
	e.c.Remove("porch")
	if err := e.c.Run(context.Background(), "porch"); !errors.Is(err, ErrUnknown) {
		t.Fatalf("Run after disconnect = %v", err)
	}
}

// TestNoFrameAfterStop: once EndTask, Set (capture off) or Remove returns,
// no frame or status reaches the consumer, even from bytes already
// buffered (Security on #3600, point 1). Revert mutant: delivering without
// the slot's stopped check gets late frames in most runs.
func TestNoFrameAfterStop(t *testing.T) {
	flood := func(i int, c *tls.Conn) {
		for j := 0; ; j++ {
			f := video(j)
			if j%7 == 0 {
				f = status()
			}
			if camwire.WriteFrame(c, camwire.ToCore, camwire.Shape{}, f) != nil {
				return
			}
		}
	}
	stops := map[string]func(e *env){
		"end task": func(e *env) { e.c.EndTask("t1") },
		"capture off": func(e *env) {
			cm := e.cam
			cm.Capture = CaptureOff
			if err := e.c.Set(cm); err != nil {
				t.Fatal(err)
			}
		},
		"remove": func(e *env) { e.c.Remove("porch") },
	}
	for name, stop := range stops {
		t.Run(name, func(t *testing.T) {
			for range 20 {
				n := newNode(t, flood)
				e := newEnv(t, n, OnRequest)
				var late atomic.Int32
				var stopped atomic.Bool
				e.c.cfg.Frames = func(string, camwire.Frame) {
					if stopped.Load() {
						late.Add(1)
					}
				}
				done := make(chan error, 1)
				go func() { done <- e.c.Capture(context.Background(), "porch", readStep("porch", "t1")) }()
				waitFor(t, "a status", func() bool { _, ok := e.c.Status("porch"); return ok || n.conns.Load() > 0 })
				time.Sleep(5 * time.Millisecond)
				stop(e)
				stopped.Store(true)
				if err := <-done; !errors.Is(err, ErrRemoved) {
					t.Fatalf("Capture = %v, want ErrRemoved", err)
				}
				time.Sleep(10 * time.Millisecond)
				if late.Load() != 0 {
					t.Fatalf("%d frames delivered after the stop returned", late.Load())
				}
			}
		})
	}
}
