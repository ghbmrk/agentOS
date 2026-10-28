package camnode

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/camwire"
	"github.com/ghbmrk/agentos/broker/camwire/camwiretest"
)

// REQ: NET-4, NET-7, DEV-3

// fakeSlots is the board's A/B slots in memory.
type fakeSlots struct {
	mu       sync.Mutex
	staged   bytes.Buffer
	armed    []byte // the manifest Arm stored; nil: nothing armed
	arms     int
	aborts   int
	good     int // MarkGood calls
	reboots  int
	failGood bool
}

type fakeStaged struct{ s *fakeSlots }

func (s *fakeSlots) Stage(size uint64) (Staged, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.staged.Reset()
	s.armed = nil
	return fakeStaged{s}, nil
}

func (s *fakeSlots) MarkGood() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.failGood {
		return errors.New("fake slots: boot partition not written")
	}
	s.good++
	return nil
}

func (s *fakeSlots) Reboot() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.reboots++
	return nil
}

func (s *fakeSlots) state() (staged []byte, armed []byte, aborts, good, reboots int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return bytes.Clone(s.staged.Bytes()), s.armed, s.aborts, s.good, s.reboots
}

func (f fakeStaged) Write(p []byte) (int, error) {
	f.s.mu.Lock()
	defer f.s.mu.Unlock()
	return f.s.staged.Write(p)
}

func (f fakeStaged) Arm(m []byte) error {
	f.s.mu.Lock()
	defer f.s.mu.Unlock()
	f.s.armed = bytes.Clone(m)
	f.s.arms++
	return nil
}

func (f fakeStaged) Abort() error {
	f.s.mu.Lock()
	defer f.s.mu.Unlock()
	f.s.staged.Reset()
	f.s.aborts++
	return nil
}

// signManifest is the release signer's and owner's signed manifest for img
// at counter, naming the rig's node.
func (r *rig) signManifest(img []byte, counter uint64, owner camwiretest.Passkey, rel ed25519.PrivateKey) []byte {
	r.t.Helper()
	m := camwire.Manifest{Image: sha256.Sum256(img), Size: uint64(len(img)), Version: 7, Counter: counter, Nodes: [][32]byte{r.node.Fingerprint()}}
	enc, err := m.Encode()
	if err != nil {
		r.t.Fatal(err)
	}
	var sm camwire.SignedManifest
	sm.Manifest = enc
	copy(sm.Release[:], ed25519.Sign(rel, enc))
	sm.Assertion = owner.Assert(r.t, enc)
	out, err := sm.Encode()
	if err != nil {
		r.t.Fatal(err)
	}
	return out
}

// push sends a manifest and the image in chunks on a fresh enforcer
// connection, after its opening status, and reports the status the node
// sends once the image is armed.
func (r *rig) push(p, img []byte, chunk int) (camwire.Status, error) {
	r.t.Helper()
	c, err := r.dial(r.enforcer)
	if err != nil {
		r.t.Fatal(err)
	}
	if _, err := readStatus(c); err != nil {
		return camwire.Status{}, err
	}
	w := func(t camwire.Type, b []byte) error {
		return camwire.WriteFrame(c, camwire.FromEnforcer, camwire.Shape{}, camwire.Frame{Type: t, Payload: b})
	}
	if err := w(camwire.TypeManifest, p); err != nil {
		return camwire.Status{}, err
	}
	for len(img) > 0 {
		n := min(chunk, len(img))
		if err := w(camwire.TypeImage, img[:n]); err != nil {
			return camwire.Status{}, err
		}
		img = img[n:]
	}
	return readStatus(c)
}

// image is generated image bytes, a little over two chunks.
func testImage() []byte {
	img := make([]byte, 2*camwire.MaxImage+123)
	rand.Read(img)
	return img
}

// TestUpdateStagesAndRollsBack (brief design point 3; NET-7, DEV-3): a
// manifest signed by the release key and approved by the owner stages its
// image to the inactive slot, arms it for one boot and restarts; the trial
// boot marks it good and raises the image counter only once Serve starts.
// A trial that fails to start, an image older than the counter, one the
// owner did not approve, one that does not hash to its manifest, and a
// chunk past the manifest's size never mark good or raise. Revert mutants:
// settleImage in New instead of Serve; the counter check dropped from
// image(); the hash check dropped from update.
func TestUpdateStagesAndRollsBack(t *testing.T) {
	r := newRig(t, true)
	r.provision(5)
	img := testImage()
	p := r.signManifest(img, 3, r.owner, r.release)

	if _, err := r.push(p, img, camwire.MaxImage); err != nil {
		t.Fatalf("update not staged: %v", err)
	}
	staged, armed, _, good, reboots := r.slots.state()
	if !bytes.Equal(staged, img) || !bytes.Equal(armed, p) || reboots != 1 || good != 0 {
		t.Fatalf("staging: image ok %v, armed %v, reboots %d, good %d", bytes.Equal(staged, img), armed != nil, reboots, good)
	}
	if c, _ := r.el.Image(); c != 0 {
		t.Fatalf("image counter raised to %d before the trial boot", c)
	}

	// The trial boot: nothing is marked good until Serve starts.
	r.manifest, r.trial, r.image, r.serve = p, true, sha256.Sum256(img), make(chan struct{})
	if err := r.boot(false); err != nil {
		t.Fatal(err)
	}
	if _, _, _, good, _ := r.slots.state(); good != 0 {
		t.Fatal("marked good before the server started")
	}
	if c, _ := r.el.Image(); c != 0 {
		t.Fatal("counter raised before the server started")
	}
	close(r.serve)
	waitFor(t, func() bool { c, _ := r.el.Image(); return c == 3 })
	if _, _, _, good, _ := r.slots.state(); good != 1 {
		t.Fatalf("marked good %d times, want 1", good)
	}
	if !readable(r, r.core) {
		t.Fatal("updated node does not stream")
	}

	// The settled image starts again without a trial, needing no owner.
	r.trial, r.serve = false, nil
	if err := r.boot(false); err != nil {
		t.Fatalf("settled image: %v", err)
	}
	if _, _, _, good, _ := r.slots.state(); good != 1 {
		t.Fatal("a settled image marked good again")
	}

	// A trial whose start fails is never marked good: the board's one-shot
	// boot returns to the old slot.
	r.slots.failGood = true
	newer := testImage()
	q := r.signManifest(newer, 4, r.owner, r.release)
	r.manifest, r.trial, r.image = q, true, sha256.Sum256(newer)
	if err := r.boot(false); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-r.served:
		if !errors.Is(err, ErrUpdate) {
			t.Fatalf("Serve after a failed mark-good: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Serve kept serving a trial it could not mark good")
	}
	if c, _ := r.el.Image(); c != 3 {
		t.Fatalf("failed trial raised the counter to %d", c)
	}
	r.slots.failGood = false

	// Refused at boot: a trial of an image other than the one running, a
	// trial the owner did not approve, and an image older than the counter.
	for name, cfg := range map[string]struct {
		m     []byte
		image [32]byte
		trial bool
		want  error
	}{
		"other image": {q, sha256.Sum256(img), true, ErrUpdate},
		"no owner":    {r.signManifest(newer, 4, camwiretest.NewPasskey(t), r.release), sha256.Sum256(newer), true, camwire.ErrAssertion},
		"older":       {r.signManifest(newer, 2, r.owner, r.release), sha256.Sum256(newer), false, ErrRollback},
		"factory":     {nil, sha256.Sum256(newer), false, ErrRollback},
		"other key":   {r.signManifest(newer, 3, r.owner, ed25519.NewKeyFromSeed(make([]byte, 32))), sha256.Sum256(newer), false, camwire.ErrRelease},
		// The boot partition edited offline to make an unapproved slot the
		// default: not a trial, but the owner is still required.
		"default slot": {r.signManifest(newer, 4, camwiretest.NewPasskey(t), r.release), sha256.Sum256(newer), false, camwire.ErrAssertion},
	} {
		r.manifest, r.image, r.trial = cfg.m, cfg.image, cfg.trial
		if err := r.boot(false); !errors.Is(err, cfg.want) {
			t.Errorf("%s: boot %v, want %v", name, err, cfg.want)
		}
	}
	if _, _, _, good, _ := r.slots.state(); good != 1 {
		t.Fatal("a refused trial was marked good")
	}

	// Refused at staging: an older or equal counter, an image that does
	// not hash to its manifest, a chunk past its size, and an image the
	// owner did not approve. None arms or restarts.
	r.manifest, r.image, r.trial = p, sha256.Sum256(img), false
	if err := r.boot(false); err != nil {
		t.Fatal(err)
	}
	bad := bytes.Clone(newer)
	bad[0] ^= 1
	long := append(bytes.Clone(newer), 0)
	for name, c := range map[string]struct{ p, img []byte }{
		"equal counter": {r.signManifest(newer, 3, r.owner, r.release), newer},
		"altered image": {q, bad},
		"past its size": {q, long},
		"not approved":  {r.signManifest(newer, 4, camwiretest.NewPasskey(t), r.release), newer},
	} {
		if _, err := r.push(c.p, c.img, camwire.MaxImage); err == nil {
			t.Errorf("%s: update staged", name)
		}
	}
	r.slots.mu.Lock()
	arms, reboots, aborts := r.slots.arms, r.slots.reboots, r.slots.aborts
	r.slots.mu.Unlock()
	if arms != 1 || reboots != 1 || aborts != 2 {
		t.Fatalf("refused updates: %d arms, %d restarts, %d aborts; want 1, 1, 2", arms, reboots, aborts)
	}
}

// TestRaiseCompletesAfterMarkGood: a power cut between mark-good and the
// raise boots the new image as the default; that start verifies the
// manifest with the loaded owner and raises the counter without marking
// good again. On a button start no owner is loaded, so the raise needs the
// release signature alone, within camwire.MaxCounterStep. Revert mutant:
// the release-only arm taken while a bundle is loaded (Security on #3617,
// finding 1).
func TestRaiseCompletesAfterMarkGood(t *testing.T) {
	r := newRig(t, true)
	r.provision(5)
	img := testImage()
	r.manifest, r.image = r.signManifest(img, 2, r.owner, r.release), sha256.Sum256(img)
	if err := r.boot(false); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool { c, _ := r.el.Image(); return c == 2 })
	if _, _, _, good, _ := r.slots.state(); good != 0 {
		t.Fatal("a non-trial boot marked good")
	}

	// A button start with a manifest another owner approved: no owner is
	// loaded, the button is presence, and raising only tightens.
	other := camwiretest.NewPasskey(t)
	r.manifest = r.signManifest(img, 3, other, r.release)
	if err := r.boot(true); err != nil {
		t.Fatalf("button start: %v", err)
	}
	waitFor(t, func() bool { c, _ := r.el.Image(); return c == 3 })
	// Past the counter step it is refused even then.
	r.manifest = r.signManifest(img, 3+camwire.MaxCounterStep+1, other, r.release)
	if err := r.boot(true); !errors.Is(err, camwire.ErrCounter) {
		t.Fatalf("button start past the step: %v", err)
	}
}

func waitFor(t *testing.T, ok func() bool) {
	t.Helper()
	for end := time.Now().Add(5 * time.Second); time.Now().Before(end); time.Sleep(10 * time.Millisecond) {
		if ok() {
			return
		}
	}
	t.Fatal("condition not reached in 5 s")
}
