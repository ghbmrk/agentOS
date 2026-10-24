package kernel_test

// REQ: KEY-4, LOG-2

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"testing"

	"github.com/ghbmrk/agentos/broker/kernel"
	"github.com/ghbmrk/agentos/broker/kernel/key"
)

// setupRig is a box enrolled with no anchors in its store: the kernel boots
// with none, as a setup-only start does (#2905 open point 2).
type setupRig struct {
	*rig
}

func newSetupRig(t *testing.T) setupRig {
	r := &rig{t: t, owner: gen(1), spare: gen(12), holder: gen(2), head: gen(3), store: &kernel.MemStore{}, anchor: &flakyAnchor{MemAnchor: &kernel.MemAnchor{}}}
	s := setupRig{r}
	s.reboot()
	return s
}

func (s setupRig) reboot() {
	l, err := kernel.Open(cfg(s.rig))
	must(s.t, err)
	s.k, err = kernel.Boot(l, nil, nil, 0)
	must(s.t, err)
}

func (s setupRig) first() kernel.FirstAnchors {
	return kernel.SignSetup(s.k.Box(), s.owner.priv, s.spare.priv)
}

// A box with no anchors authorizes nothing, takes the owner's two hardware
// keys once as its log's first entry, keeps them across a restart, and never
// takes setup again.
func TestSetupTakesTheTwoHardwareKeysOnce(t *testing.T) {
	s := newSetupRig(t)
	if !s.k.State().SetupOpen() || len(s.k.State().Anchors) != 0 {
		t.Fatal("a box with no anchors is not open for setup")
	}
	root := key.Issue(s.owner.priv, key.Root{Clerk: "mail", Verbs: []key.Verb{key.Trash}, Serial: "r"})
	if err := s.k.Issue(0, approve([]key.Key{root}, s.owner, s.spare), root); err == nil {
		t.Fatal("a grant was issued before setup")
	}
	must(t, s.k.Setup(1, s.first()))
	es := s.k.Log().Entries()
	if len(es) != 1 || es[0].Type != kernel.TAnchorsSet || !key.In(s.k.State().Anchors, s.owner.pub) || !key.In(s.k.State().Anchors, s.spare.pub) {
		t.Fatalf("setup logged %v, anchors %v", es, s.k.State().Anchors)
	}
	if err := s.k.Setup(2, s.first()); !errors.Is(err, kernel.ErrSetupClosed) {
		t.Fatalf("a second setup: got %v, want ErrSetupClosed", err)
	}
	if err := s.k.Issue(3, approve([]key.Key{root}, s.owner, s.spare), root); err != nil {
		t.Fatalf("a grant after setup: %v", err)
	}
	s.reboot()
	if len(s.k.State().Anchors) != 2 || s.k.State().SetupOpen() {
		t.Fatalf("after a restart: anchors %v, open %v", s.k.State().Anchors, s.k.State().SetupOpen())
	}
}

// Setup is the owner's two distinct hardware keys, each signing over this
// box's head key; anything else is refused and logs nothing.
func TestSetupRefusesAnythingButTwoSigningKeys(t *testing.T) {
	s := newSetupRig(t)
	box, other := s.k.Box(), gen(9)
	swapped := s.first()
	swapped.Sigs[0], swapped.Sigs[1] = swapped.Sigs[1], swapped.Sigs[0]
	short := s.first()
	short.Sigs = short.Sigs[:1]
	for name, f := range map[string]kernel.FirstAnchors{
		"one key":     kernel.SignSetup(box, s.owner.priv),
		"three keys":  kernel.SignSetup(box, s.owner.priv, s.spare.priv, other.priv),
		"a duplicate": kernel.SignSetup(box, s.owner.priv, s.owner.priv),
		"another box": kernel.SignSetup(other.pub, s.owner.priv, s.spare.priv),
		"swapped":     swapped,
		"one sig":     short,
		"none":        {},
	} {
		if err := s.k.Setup(1, f); !errors.Is(err, kernel.ErrSetupKeys) {
			t.Errorf("%s: got %v, want ErrSetupKeys", name, err)
		}
	}
	if n := len(s.k.Log().Entries()); n != 0 {
		t.Fatalf("refused setups logged %d entries", n)
	}
}

// A box whose store gave anchors, or whose log holds anything, is never
// open for setup.
func TestSetupIsClosedOnAnyOtherBox(t *testing.T) {
	r := newRig(t) // anchors from the store, and a grant in the log
	if r.k.State().SetupOpen() {
		t.Fatal("a box with anchors is open for setup")
	}
	if err := r.k.Setup(1, kernel.SignSetup(r.k.Box(), r.owner.priv, r.spare.priv)); !errors.Is(err, kernel.ErrSetupClosed) {
		t.Fatalf("got %v, want ErrSetupClosed", err)
	}
	s := newSetupRig(t)
	must(t, s.k.Stop(1)) // any entry before setup shuts it; the process serves none (proc)
	if err := s.k.Setup(2, s.first()); !errors.Is(err, kernel.ErrSetupClosed) {
		t.Fatalf("setup after another entry: got %v, want ErrSetupClosed", err)
	}
}

// LOG-2, KRN-7: setup is a widening. One no anchor confirmed is dropped at
// the next open, so the box is open for setup again, never half set up.
func TestAnUnconfirmedSetupIsDropped(t *testing.T) {
	s := newSetupRig(t)
	s.anchor.down = true
	if err := s.k.Setup(1, s.first()); err == nil {
		t.Fatal("setup returned nil with its anchor down")
	}
	s.anchor.down = false
	s.reboot()
	if !s.k.State().SetupOpen() || len(s.k.Log().Entries()) != 0 {
		t.Fatal("an unconfirmed setup survived the restart")
	}
	must(t, s.k.Setup(2, s.first()))
}

// A setup entry anywhere but first, or on a box whose store gave anchors,
// is not this box's log: the replay refuses it.
func TestASetupEntryOutOfPlaceIsCorrupt(t *testing.T) {
	s := newSetupRig(t)
	f := s.first()
	setup := kernel.Entry{Seq: 1, Type: kernel.TAnchorsSet, V: 1, Body: mustJSON(t, f)}
	if _, err := kernel.Replay([]ed25519.PublicKey{s.owner.pub}, []kernel.Entry{setup}); !errors.Is(err, kernel.ErrCorrupt) {
		t.Fatalf("setup over the store's anchors: got %v, want ErrCorrupt", err)
	}
	st, err := kernel.Replay(nil, []kernel.Entry{setup})
	if err != nil || len(st.Anchors) != 2 {
		t.Fatalf("setup first: %v %v", st, err)
	}
	if err := st.Apply(kernel.Entry{Seq: 2, Type: kernel.TAnchorsSet, V: 1, Body: mustJSON(t, f)}); !errors.Is(err, kernel.ErrCorrupt) {
		t.Fatalf("setup second: got %v, want ErrCorrupt", err)
	}
	one := kernel.SignSetup(s.k.Box(), s.owner.priv)
	if _, err := kernel.Replay(nil, []kernel.Entry{{Seq: 1, Type: kernel.TAnchorsSet, V: 1, Body: mustJSON(t, one)}}); !errors.Is(err, kernel.ErrCorrupt) {
		t.Fatalf("setup of one key: got %v, want ErrCorrupt", err)
	}
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	must(t, err)
	return b
}
