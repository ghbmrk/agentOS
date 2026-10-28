package camnode

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"reflect"
	"slices"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/camwire"
	"github.com/ghbmrk/agentos/broker/camwire/camwiretest"
)

// REQ: NET-2, DEV-2, KRN-2

// refused reports whether a connection made with key is refused: at the
// handshake, or on the first read (where a TLS 1.3 client sees its
// certificate refused).
func refused(r *rig, key *ecdsaKey) bool {
	c, err := r.dial(key)
	if err != nil {
		return true
	}
	var b [1]byte
	_, err = c.Read(b[:])
	return err != nil
}

// TestOnlyPinnedClients: the port admits the bundle's core key to the
// stream only and its enforcer key to the settings channel only; a client
// with no certificate or an unknown key is refused at the handshake, and
// the core key on the settings channel cannot send a bundle. Revert
// mutant: roleLocked admitting any key as core streams to a stranger.
func TestOnlyPinnedClients(t *testing.T) {
	r := newRig(t, true)
	r.provision(8)

	if !refused(r, nil) {
		t.Error("a client with no certificate was admitted")
	}
	if !refused(r, camwiretest.NewKey(t)) {
		t.Error("a client with an unknown key was admitted")
	}

	core, err := r.dial(r.core)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		f, err := camwire.ReadFrame(core, camwire.ToCore, camwire.Shape{})
		if err != nil || f.Type != camwire.TypeVideo {
			t.Fatalf("core: frame %d: %v %v", i, f.Type, err)
		}
	}
	// The core sends nothing on the stream: a bundle from it ends the
	// connection and is not applied.
	camwire.WriteFrame(core, camwire.FromEnforcer, camwire.Shape{}, camwire.Frame{Type: camwire.TypeBundle, Payload: r.owner.SignBundle(t, r.bundle(9))})
	if _, err := io.Copy(io.Discard, core); err != nil && !errors.Is(err, io.EOF) && !isClosed(err) {
		t.Logf("core connection ended: %v", err)
	}
	if c, _, _ := r.el.Settings(); c != 8 {
		t.Errorf("a bundle sent on the stream moved the counter to %d", c)
	}

	// The enforcer gets the status record and the settings channel, never
	// video: its reader refuses a video type outright.
	enf, err := r.dial(r.enforcer)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := readStatus(enf); err != nil {
		t.Fatalf("enforcer status: %v", err)
	}
	enf.SetReadDeadline(deadline(200))
	if f, err := camwire.ReadFrame(enf, camwire.ToEnforcer, camwire.Shape{}); err == nil {
		t.Errorf("enforcer was sent an unasked frame of type %d", f.Type)
	}
	// With the stream turned off, the core key is refused too.
	off := r.bundle(9)
	off.Settings.Stream = false
	enf2, _ := r.dial(r.enforcer)
	if _, err := send(enf2, r.owner.SignBundle(t, off)); err != nil {
		t.Fatal(err)
	}
	if !refused(r, r.core) {
		t.Error("core admitted with the stream off")
	}
}

// TestFirstBundleNeedsButton: without the button no client is admitted
// and no bundle is taken; with it, exactly one bundle is taken, it must
// name its sender as the enforcer, and the window then closes. Revert
// mutant: New opening the window without Button.
func TestFirstBundleNeedsButton(t *testing.T) {
	r := newRig(t, false)
	if !refused(r, r.enforcer) {
		t.Error("an unprovisioned node admitted a client without the button")
	}
	if c, d, _ := r.el.Settings(); c != 0 || d != ([32]byte{}) {
		t.Errorf("unprovisioned node committed counter %d", c)
	}

	r.boot(true)
	// A stranger may reach the window but cannot provision with a bundle
	// that names another enforcer.
	stranger := camwiretest.NewKey(t)
	c, err := r.dial(stranger)
	if err != nil {
		t.Fatal(err)
	}
	// Nothing is sent before a bundle applies (#3588 item 3).
	c.SetReadDeadline(deadline(300))
	if _, err := readStatus(c); err == nil {
		t.Error("status sent to a client in the open window")
	}
	c.SetDeadline(deadline(5000))
	if _, err := sendMore(c, r.owner.SignBundle(t, r.bundle(3))); err == nil {
		t.Error("a first bundle naming another enforcer was taken")
	}
	r.provision(3)
	if !refused(r, stranger) {
		t.Error("window still open after the first bundle")
	}
	// A second owner's first bundle is refused: the window took one.
	other := camwiretest.NewPasskey(t)
	b := r.bundle(4)
	b.Owner = other.Owner()
	c, err = r.dial(r.enforcer)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := send(c, other.SignBundle(t, b)); err == nil {
		t.Error("a second owner's bundle was taken")
	}
	if got, _, _ := r.el.Settings(); got != 3 {
		t.Errorf("counter %d after one first bundle, want 3", got)
	}
}

// TestReplayedBundleRefused: an equal or lower counter is refused, the
// settings stay those of the newest bundle, and a restart keeps the bundle,
// the key and the counter. Revert mutant: apply passing counter-1 to
// VerifyBundle takes the replay.
func TestReplayedBundleRefused(t *testing.T) {
	r := newRig(t, true)
	r.provision(8)
	nine := r.bundle(9)
	nine.Settings.FPS = 15
	c, _ := r.dial(r.enforcer)
	if _, err := send(c, r.owner.SignBundle(t, nine)); err != nil {
		t.Fatal(err)
	}
	for _, n := range []uint64{8, 9} {
		c, _ := r.dial(r.enforcer)
		if _, err := send(c, r.owner.SignBundle(t, r.bundle(n))); err == nil {
			t.Errorf("bundle at counter %d taken after 9", n)
		}
	}
	if st, _ := r.src.last(); st.FPS != 15 {
		t.Errorf("source has %d fps, want bundle 9's 15", st.FPS)
	}
	// The node refuses the replay itself; the element's refusal is a
	// second wall, not the first.
	if r.el.nonRising != 0 {
		t.Errorf("node asked the element to commit %d non-rising counters", r.el.nonRising)
	}

	fp := r.node.Fingerprint()
	if err := r.boot(false); err != nil {
		t.Fatalf("restart: %v", err)
	}
	if r.node.Fingerprint() != fp {
		t.Error("device key changed across a restart")
	}
	if st, _ := r.src.last(); st.FPS != 15 {
		t.Error("restart did not apply the stored bundle")
	}
	c, _ = r.dial(r.enforcer)
	if _, err := send(c, r.owner.SignBundle(t, r.bundle(9))); err == nil {
		t.Error("replay taken after a restart")
	}
	if !readable(r, r.core) {
		t.Error("core not streamed to after a restart")
	}
}

func readable(r *rig, k *ecdsaKey) bool {
	c, err := r.dial(k)
	if err != nil {
		return false
	}
	_, err = camwire.ReadFrame(c, camwire.ToCore, camwire.Shape{})
	return err == nil
}

// TestSettingsWithinDeclaredRanges: an owner-signed bundle outside the
// node's declared ranges is refused before it reaches the source or the
// element's counter. Revert mutant: apply skipping Ranges.check.
func TestSettingsWithinDeclaredRanges(t *testing.T) {
	r := newRig(t, true)
	r.provision(8)
	_, applied := r.src.last()
	for name, bend := range map[string]func(*camwire.Settings){
		"bitrate over":         func(s *camwire.Settings) { s.BitrateKbps = testRanges.MaxKbps + 1 },
		"bitrate under":        func(s *camwire.Settings) { s.BitrateKbps = testRanges.MinKbps - 1 },
		"frame rate over":      func(s *camwire.Settings) { s.FPS = testRanges.MaxFPS + 1 },
		"undeclared size":      func(s *camwire.Settings) { s.Width, s.Height = 3840, 2160 },
		"thermal, none fitted": func(s *camwire.Settings) { s.Thermal = true },
	} {
		b := r.bundle(9)
		bend(&b.Settings)
		c, _ := r.dial(r.enforcer)
		if _, err := send(c, r.owner.SignBundle(t, b)); err == nil {
			t.Errorf("%s: taken", name)
		}
	}
	if _, n := r.src.last(); n != applied {
		t.Errorf("an out-of-range bundle reached the source")
	}
	if c, _, _ := r.el.Settings(); c != 8 {
		t.Errorf("an out-of-range bundle moved the counter to %d", c)
	}
	if err := (Ranges{Resolutions: testRanges.Resolutions, MaxFPS: 30, MinKbps: 1, MaxKbps: 9}).check(camwire.Settings{Width: 1920, Height: 1080, FPS: 1, BitrateKbps: 5, IR: camwire.IROn}, camwire.Shape{}); !errors.Is(err, ErrRange) {
		t.Error("IR taken on a node with no illuminator")
	}
}

// TestDeviceKeyNeverExported (A16): the element interface has no method
// that could return key material, and the canary device key's private
// scalar appears in no log line, error or byte the node sends. Revert
// mutant: an Export method on Element, or logging the signer.
func TestDeviceKeyNeverExported(t *testing.T) {
	want := []string{"ClearBundle", "CommitBundle", "Image", "Public", "RaiseImage", "Settings", "Sign"}
	var got []string
	et := reflect.TypeOf((*Element)(nil)).Elem()
	for i := 0; i < et.NumMethod(); i++ {
		got = append(got, et.Method(i).Name)
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("Element methods %v, want exactly %v", got, want)
	}

	r := newRig(t, true)
	r.provision(8)
	var wire bytes.Buffer
	c, _ := r.dial(r.core)
	for i := 0; i < 3; i++ {
		f, _ := camwire.ReadFrame(c, camwire.ToCore, camwire.Shape{})
		wire.Write(f.Payload)
	}
	c, _ = r.dial(r.enforcer)
	st, _ := readStatus(c)
	wire.Write(camwire.AppendStatus(nil, st))
	_, err := sendMore(c, []byte("not a bundle"))
	r.boot(false)
	r.store.Put([]byte("x"))
	os.WriteFile(r.store.path([32]byte{1}), []byte("y"), 0o600)
	r.el.record = [32]byte{1}
	err2 := r.boot(false)

	d := r.el.key.D.FillBytes(make([]byte, 32))
	canaries := [][]byte{d, []byte(hex.EncodeToString(d)), []byte(base64.StdEncoding.EncodeToString(d)), []byte(r.el.key.D.String())}
	var out bytes.Buffer
	out.Write(wire.Bytes())
	for _, l := range r.logs.lines {
		out.WriteString(l)
	}
	fmt.Fprintf(&out, "%v %v %v %+v %#v", err, err2, r.errs, r.node, r.node)
	for _, c := range canaries {
		if bytes.Contains(out.Bytes(), c) {
			t.Fatal("the device key's private scalar left the element")
		}
	}
	if !errors.Is(err2, ErrAltered) {
		t.Errorf("a stored bundle not matching the element's record: %v", err2)
	}
}

// TestRestartCompletesCommit: a power cut between the element's record and
// its counter leaves the record raised; the next start completes the
// raise, so the bundle stays the node's and its replay stays refused.
func TestRestartCompletesCommit(t *testing.T) {
	r := newRig(t, true)
	r.provision(8)
	r.el.failRaise = true
	c, _ := r.dial(r.enforcer)
	if _, err := send(c, r.owner.SignBundle(t, r.bundle(9))); err == nil {
		t.Fatal("a failed commit reported success")
	}
	r.el.failRaise = false
	if err := r.boot(false); err != nil {
		t.Fatalf("restart after the cut: %v", err)
	}
	if got, _, _ := r.el.Settings(); got != 9 {
		t.Errorf("counter %d after restart, want 9", got)
	}
}

// TestButtonResetKeepsKey: the button on a provisioned node erases the
// bundle and reopens the window; the device key and the counter are kept.
func TestButtonResetKeepsKey(t *testing.T) {
	r := newRig(t, true)
	r.provision(8)
	fp := r.node.Fingerprint()
	r.boot(true)
	if r.node.Fingerprint() != fp {
		t.Error("device key changed on reset")
	}
	if c, d, _ := r.el.Settings(); c != 8 || d != ([32]byte{}) {
		t.Errorf("after reset: counter %d, record kept %v", c, d != [32]byte{})
	}
	r.provision(9)
	c, _ := r.dial(r.enforcer)
	if _, err := send(c, r.owner.SignBundle(t, r.bundle(9))); err == nil {
		t.Error("a reset let an old counter back in")
	}
}

// TestLiveStreamRevoked (L3 on #3586, finding 1): a bundle that turns the
// stream off, or names another core key, ends the stream already running,
// not only the next dial; and a second core connection ends the first.
// Revert mutants: apply keeping the connections it should close, or handle
// not replacing the older stream.
func TestLiveStreamRevoked(t *testing.T) {
	r := newRig(t, true)
	r.provision(8)

	first := r.streaming(r.core)
	second := r.streaming(r.core)
	if !ends(first) {
		t.Error("a second core stream left the first running")
	}

	off := r.bundle(9)
	off.Settings.Stream = false
	c, _ := r.dial(r.enforcer)
	if _, err := send(c, r.owner.SignBundle(t, off)); err != nil {
		t.Fatal(err)
	}
	if !ends(second) {
		t.Error("a live stream outlived the bundle that turned the stream off")
	}

	c, _ = r.dial(r.enforcer)
	if _, err := send(c, r.owner.SignBundle(t, r.bundle(10))); err != nil {
		t.Fatal(err)
	}
	live := r.streaming(r.core)
	moved := r.bundle(11)
	newCore := camwiretest.NewKey(t)
	moved.Core = camwiretest.Point(&newCore.PublicKey)
	c, _ = r.dial(r.enforcer)
	if _, err := send(c, r.owner.SignBundle(t, moved)); err != nil {
		t.Fatal(err)
	}
	if !ends(live) {
		t.Error("a live stream outlived the bundle that replaced the core key")
	}
	if !readable(r, newCore) {
		t.Error("the new core key is not streamed to")
	}
}

// TestStartRefusesCounterAboveBundle: an element counter above the stored
// bundle's (the store rolled back under a moved counter) refuses start.
// Revert mutant: load skipping the counter > b.Counter check.
func TestStartRefusesCounterAboveBundle(t *testing.T) {
	r := newRig(t, true)
	r.provision(8)
	r.el.settings = 9
	if err := r.boot(false); !errors.Is(err, ErrState) {
		t.Errorf("start with the element's counter above the bundle's: %v", err)
	}
}

// TestFirstBundleWindowCloses (Security on #3586, finding 1): the window a
// button start opens closes after Config.Window, so a reset node left
// unprovisioned cannot be claimed later. Revert mutant: windowOpen
// ignoring windowEnd.
func TestFirstBundleWindowCloses(t *testing.T) {
	r := newRig(t, false)
	r.window = 100 * time.Millisecond
	r.boot(true)
	time.Sleep(200 * time.Millisecond)
	if !refused(r, r.enforcer) {
		t.Error("a client was admitted after the window closed")
	}
	if err := r.node.apply(r.owner.SignBundle(t, r.bundle(1)), camwiretest.Point(&r.enforcer.PublicKey), true); !errors.Is(err, ErrWindow) {
		t.Errorf("a first bundle after the window: %v", err)
	}
	if c, _, _ := r.el.Settings(); c != 0 {
		t.Errorf("counter %d after the window closed", c)
	}
}

// TestSourceFailureAfterCommit (L3 on #3586, finding 2): a bundle the
// element committed but the source would not take is reported as committed:
// the enforcer gets a status with the new counter and the log says so,
// not "bundle refused".
func TestSourceFailureAfterCommit(t *testing.T) {
	r := newRig(t, true)
	r.provision(8)
	r.src.mu.Lock()
	r.src.fail = true
	r.src.mu.Unlock()
	c, _ := r.dial(r.enforcer)
	st, err := send(c, r.owner.SignBundle(t, r.bundle(9)))
	if err != nil || st.Settings != 9 {
		t.Fatalf("status after a committed bundle: counter %d, %v", st.Settings, err)
	}
	r.logs.mu.Lock()
	defer r.logs.mu.Unlock()
	if !slices.Contains(r.logs.lines, "bundle committed, source failed") || slices.Contains(r.logs.lines, "bundle refused") {
		t.Errorf("log %q", r.logs.lines)
	}
}

// TestConnectionCap (#3588 item 2): connections past maxConns are closed
// before their handshake, so a LAN host holding idle handshakes cannot
// make the node sign without bound; once they go, the core connects again.
// Revert mutant: Serve without its token.
func TestConnectionCap(t *testing.T) {
	r := newRig(t, true)
	r.provision(3)
	// provision's handler gives its token back after its connection
	// closes; until then an idle dial below could be refused in its place.
	waitFor(t, func() bool { return len(r.node.slots) == 0 })
	var idle []net.Conn
	for range maxConns {
		c, err := net.Dial("tcp", r.addr)
		if err != nil {
			t.Fatal(err)
		}
		idle = append(idle, c)
	}
	waitFor(t, func() bool { return len(r.node.slots) == maxConns })
	if c, err := r.dial(r.core); err == nil {
		c.SetReadDeadline(deadline(1000))
		if _, err := camwire.ReadFrame(c, camwire.ToCore, camwire.Shape{}); err == nil {
			t.Fatal("a connection past the cap was served")
		}
	}
	for _, c := range idle {
		c.Close()
	}
	waitFor(t, func() bool {
		c, err := r.dial(r.core)
		if err != nil {
			return false
		}
		defer c.Close()
		c.SetReadDeadline(deadline(1000))
		_, err = camwire.ReadFrame(c, camwire.ToCore, camwire.Shape{})
		return err == nil
	})
}
