package camnode

import (
	"crypto/ecdsa"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/camwire"
)

// REQ: DEV-2, DEV-3, NET-2, NET-4, KRN-2

// readsNothing reports whether the connection ends, or stays silent past
// a short wait, without a byte. In TLS 1.3 the client finishes its side
// before the node checks the client's certificate, so a refusal shows on
// the client's first read.
func readsNothing(t *testing.T, c interface {
	SetReadDeadline(time.Time) error
	Read([]byte) (int, error)
}) bool {
	t.Helper()
	c.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	var b [1]byte
	n, _ := c.Read(b[:])
	return n == 0
}

// TestOnlyPinnedClients: a client with no certificate or an unknown key
// gets nothing; the enforcer's key gets the settings channel and never a
// frame of the stream; the core's key gets the status record, then video
// and thermal frames, and the stream ends on any byte from the core.
// Revert mutant: role returning Core for any key.
func TestOnlyPinnedClients(t *testing.T) {
	n := newNode(t)
	n.provision()

	for name, key := range map[string]*ecdsa.PrivateKey{"no certificate": nil, "unknown key": newKey(t)} {
		c, err := n.dial(key)
		if err == nil && !readsNothing(t, c) {
			t.Fatalf("%s got a byte from the node", name)
		}
	}

	// The enforcer is not streamed to.
	c, err := n.dial(n.enforcer)
	if err != nil {
		t.Fatal(err)
	}
	if !readsNothing(t, c) {
		t.Fatal("the enforcer's key got stream bytes")
	}
	// The enforcer's channel takes a bundle and answers with status.
	if st, err := n.send(n.enforcer, n.owner.sign(t, n.bundle(2, goodSettings))); err != nil || st.Settings != 2 {
		t.Fatalf("enforcer bundle: %v %+v", err, st)
	}

	// The core gets status, then frames.
	c, err = n.dial(n.core)
	if err != nil {
		t.Fatal(err)
	}
	f, err := camwire.ReadFrame(c, camwire.ToCore, testRanges.Thermal)
	if err != nil || f.Type != camwire.TypeStatus {
		t.Fatalf("first frame: %v %v", f.Type, err)
	}
	st, _ := camwire.ParseStatus(f.Payload)
	if st.Settings != 2 {
		t.Fatalf("status counter %d, want 2", st.Settings)
	}
	seen := map[camwire.Type]bool{}
	for range 6 {
		f, err := camwire.ReadFrame(c, camwire.ToCore, testRanges.Thermal)
		if err != nil {
			t.Fatal(err)
		}
		seen[f.Type] = true
	}
	if !seen[camwire.TypeVideo] || !seen[camwire.TypeThermal] {
		t.Fatalf("frames seen: %v", seen)
	}
	// A byte from the core ends the stream.
	c.Write([]byte{0})
	c.SetReadDeadline(time.Now().Add(2 * time.Second))
	for {
		if _, err := camwire.ReadFrame(c, camwire.ToCore, testRanges.Thermal); err != nil {
			break
		}
	}

	// The core's key on the settings channel: it is on the stream, so its
	// bundle ends the stream and is not taken.
	st, err = n.send(n.core, n.owner.sign(t, n.bundle(3, goodSettings)))
	if err == nil && st.Settings != 2 {
		t.Fatalf("the core's key got status %+v", st)
	}
	if n.counter() != 2 {
		t.Fatalf("counter %d after the core's bundle", n.counter())
	}
}

// TestFirstBundleNeedsButton: without the button no bundle is taken and
// every client is refused; with it, exactly one first bundle is taken,
// from the key it names as the enforcer's, within the window.
// Revert mutant: role returning Provisioner without the window.
func TestFirstBundleNeedsButton(t *testing.T) {
	n := newNode(t)
	n.boot(false)
	if _, err := n.send(n.enforcer, n.owner.sign(t, n.bundle(1, goodSettings))); err == nil {
		t.Fatal("bundle taken without the button")
	}
	if _, ok, _ := n.el.OwnerPin(); ok || n.counter() != 0 {
		t.Fatal("state changed without the button")
	}
	waitLog(t, n, "handshake refused")

	n.boot(true)
	// A first bundle from a key it does not name as the enforcer's.
	if _, err := n.send(newKey(t), n.owner.sign(t, n.bundle(1, goodSettings))); err == nil {
		t.Fatal("first bundle taken from a key it does not name")
	}
	if st, err := n.send(n.enforcer, n.owner.sign(t, n.bundle(1, goodSettings))); err != nil || st.Settings != 1 {
		t.Fatalf("first bundle refused: %v", err)
	}
	// The window is closed: another owner's first bundle is refused.
	other := passkey{newKey(t)}
	b := n.bundle(5, goodSettings)
	b.Owner = other.owner()
	if _, err := n.send(n.enforcer, other.sign(t, b)); err == nil {
		t.Fatal("a second first bundle was taken")
	}
	if pin, _, _ := n.el.OwnerPin(); pin != OwnerDigest(n.owner.owner()) {
		t.Fatal("owner pin moved")
	}

	// The window closes by time too.
	m := newNode(t)
	m.boot(true)
	m.advance(ProvisionWindow)
	if _, err := m.send(m.enforcer, m.owner.sign(t, m.bundle(1, goodSettings))); err == nil {
		t.Fatal("first bundle taken after the window")
	}
	waitLog(t, m, "handshake refused")
}

// waitLog waits for the server to log line: a refusal at the handshake is
// logged after the client's side has finished.
func waitLog(t *testing.T, n *node, line string) {
	t.Helper()
	for range 200 {
		if strings.Contains(n.logs.all(), line) {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("no %q in the log:\n%s", line, n.logs.all())
}

// TestReplayedBundleRefused: once a bundle is in force, it, an older one
// and a bundle for another node are refused and the settings stay; the
// counter survives a restart, so the replay stays refused after one.
func TestReplayedBundleRefused(t *testing.T) {
	n := newNode(t)
	first := n.provision()
	s2 := goodSettings
	s2.FPS = 15
	second := n.owner.sign(t, n.bundle(2, s2))
	if _, err := n.send(n.enforcer, second); err != nil {
		t.Fatal(err)
	}
	for name, p := range map[string][]byte{
		"replay": second,
		"older":  n.owner.sign(t, first),
	} {
		if _, err := n.send(n.enforcer, p); err == nil {
			t.Fatalf("%s bundle taken", name)
		}
	}
	other := n.bundle(3, goodSettings)
	other.Node[0] ^= 1
	if _, err := n.send(n.enforcer, n.owner.sign(t, other)); err == nil {
		t.Fatal("bundle for another node taken")
	}
	n.boot(false)
	if got := n.src.Applied(); len(got) != 1 || got[0] != s2 {
		t.Fatalf("settings after restart: %+v", got)
	}
	if _, err := n.send(n.enforcer, second); err == nil {
		t.Fatal("replay taken after a restart")
	}
	if n.counter() != 2 {
		t.Fatalf("counter %d", n.counter())
	}
}

// TestSettingsWithinDeclaredRanges: an out-of-range bitrate, frame rate,
// resolution, IR or thermal setting is refused before it reaches the
// source or moves the counter.
// Revert mutant: apply without Ranges.Check.
func TestSettingsWithinDeclaredRanges(t *testing.T) {
	n := newNode(t)
	n.provision()
	before := len(n.src.Applied())
	bad := map[string]func(*camwire.Settings){
		"bitrate":    func(s *camwire.Settings) { s.BitrateKbps = 9000 },
		"low rate":   func(s *camwire.Settings) { s.BitrateKbps = 100 },
		"frame rate": func(s *camwire.Settings) { s.FPS = 31 },
		"resolution": func(s *camwire.Settings) { s.Width = 3840 },
	}
	for name, bend := range bad {
		s := goodSettings
		bend(&s)
		if _, err := n.send(n.enforcer, n.owner.sign(t, n.bundle(2, s))); err == nil {
			t.Fatalf("%s out of range taken", name)
		}
	}
	if n.counter() != 1 || len(n.src.Applied()) != before {
		t.Fatalf("counter %d, applies %d: an out-of-range bundle moved state", n.counter(), len(n.src.Applied()))
	}
	noIR := testRanges
	noIR.IR, noIR.Thermal = false, camwire.Shape{}
	for _, s := range []camwire.Settings{
		{Width: 1280, Height: 720, FPS: 60, BitrateKbps: 500, IR: camwire.IROn},
		{Width: 1280, Height: 720, FPS: 60, BitrateKbps: 500, Thermal: true},
	} {
		if noIR.Check(s) == nil {
			t.Fatalf("%+v passed a node without IR or thermal", s)
		}
	}
	if testRanges.Check(camwire.Settings{Width: 1280, Height: 720, FPS: 60, BitrateKbps: 8000}) != nil {
		t.Fatal("in-range settings refused")
	}
}

// TestRestartKeepsBundle: a restart keeps the bundle and counter and
// streams again; a stored bundle altered offline, or one an apply left
// pending, is verified again: the altered one admits no client, the
// pending one is finished.
func TestRestartKeepsBundle(t *testing.T) {
	n := newNode(t)
	n.provision()
	if _, err := n.dial(n.core); err != nil {
		t.Fatal(err)
	}

	// Cut an apply short after its pending write: the restart finishes it.
	s3 := goodSettings
	s3.BitrateKbps = 3000
	p := n.owner.sign(t, n.bundle(3, s3))
	if err := n.dir.Write(pendingName, p); err != nil {
		t.Fatal(err)
	}
	n.boot(false)
	if n.counter() != 3 {
		t.Fatalf("pending bundle not finished: counter %d", n.counter())
	}
	if got := n.src.Applied(); len(got) != 1 || got[0] != s3 {
		t.Fatalf("applied %+v", got)
	}

	// A pending bundle the owner did not sign is dropped.
	forged := passkey{newKey(t)}.sign(t, n.bundle(4, goodSettings))
	n.dir.Write(pendingName, forged)
	n.boot(false)
	if n.counter() != 3 {
		t.Fatal("forged pending bundle applied")
	}

	// The stored bundle altered offline: nothing is admitted.
	cur, _ := n.dir.Read(currentName)
	cur[len(cur)-1] ^= 1
	n.dir.Write(currentName, cur)
	n.boot(false)
	for _, k := range []*ecdsa.PrivateKey{n.core, n.enforcer} {
		c, err := n.dial(k)
		if err == nil && !readsNothing(t, c) {
			t.Fatal("a client was admitted on an altered bundle")
		}
	}
}

// TestButtonReset: a button boot of a provisioned node erases the bundle
// and the owner pin, keeps the device key and both counters, and opens
// the window for a new owner above the old counter.
func TestButtonReset(t *testing.T) {
	n := newNode(t)
	n.provision()
	fp := n.fingerprint()
	n.boot(true)
	if _, ok, _ := n.el.OwnerPin(); ok {
		t.Fatal("pin survived the reset")
	}
	if _, err := n.dir.Read(currentName); err == nil {
		t.Fatal("bundle survived the reset")
	}
	if n.fingerprint() != fp || n.counter() != 1 {
		t.Fatal("device key or counter changed")
	}
	n.owner = passkey{newKey(t)}
	if _, err := n.send(n.enforcer, n.owner.sign(t, n.bundle(1, goodSettings))); err == nil {
		t.Fatal("first bundle at the old counter taken")
	}
	if _, err := n.send(n.enforcer, n.owner.sign(t, n.bundle(2, goodSettings))); err != nil {
		t.Fatalf("new owner's first bundle: %v", err)
	}
	if pin, _, _ := n.el.OwnerPin(); pin != OwnerDigest(n.owner.owner()) {
		t.Fatal("new owner not pinned")
	}
}

// TestBundleMovesKeys: a bundle that moves the core key ends the old
// core's stream, and a bundle that turns the stream off refuses the core.
func TestBundleMovesKeys(t *testing.T) {
	n := newNode(t)
	n.provision()
	c, err := n.dial(n.core)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := camwire.ReadFrame(c, camwire.ToCore, testRanges.Thermal); err != nil {
		t.Fatal(err)
	}
	oldCore := n.core
	n.core = newKey(t)
	if _, err := n.send(n.enforcer, n.owner.sign(t, n.bundle(2, goodSettings))); err != nil {
		t.Fatal(err)
	}
	c.SetReadDeadline(time.Now().Add(2 * time.Second))
	for {
		if _, err := camwire.ReadFrame(c, camwire.ToCore, testRanges.Thermal); err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				t.Fatal("old core still streamed")
			}
			break
		}
	}
	if c, err := n.dial(oldCore); err == nil && !readsNothing(t, c) {
		t.Fatal("old core key still admitted")
	}
	off := goodSettings
	off.Stream = false
	if _, err := n.send(n.enforcer, n.owner.sign(t, n.bundle(3, off))); err != nil {
		t.Fatal(err)
	}
	if c, err := n.dial(n.core); err == nil && !readsNothing(t, c) {
		t.Fatal("core streamed with the stream off")
	}
}
