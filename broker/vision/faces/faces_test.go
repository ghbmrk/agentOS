package faces

// REQ: DEV-7, LOG-4

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/clerk"
	"github.com/ghbmrk/agentos/broker/kernel/key"
	"github.com/ghbmrk/agentos/broker/vision"
)

// memContent is a content seam that never erases: enough for the checks
// here (the kernel's own erase is tested in cmd/agentos-vision).
type memContent struct {
	items map[Hash][]byte
	reads []string
}

func (m *memContent) OpenSubject() (string, error) { return "0123456789abcdef0123456789abcdef", nil }
func (m *memContent) Seal(_, _ string, d []byte) (Hash, error) {
	h := Hash{byte(len(m.items) + 1)}
	m.items[h] = bytes.Clone(d)
	return h, nil
}
func (m *memContent) ReadFor(h Hash, lineage string) ([]byte, error) {
	m.reads = append(m.reads, lineage)
	return bytes.Clone(m.items[h]), nil
}

// control records each lend and answers enrol with tpl.
type control struct {
	tpl    []byte
	lends  [][]vision.Template
	fail   error
	enrols int
}

func (c *control) Enrol(context.Context, vision.Frame) ([]byte, error) {
	c.enrols++
	return bytes.Clone(c.tpl), nil
}
func (c *control) Lend(_ context.Context, ts []vision.Template) error {
	var cp []vision.Template
	for _, t := range ts {
		cp = append(cp, vision.Template{ID: t.ID, Vec: bytes.Clone(t.Vec)})
	}
	c.lends = append(c.lends, cp)
	return c.fail
}

// anchor is the test's one anchor passkey.
var anchor = key.Ed25519Signer(ed25519.NewKeyFromSeed(bytes.Repeat([]byte{9}, 32)))

func newFaces(t *testing.T) (*Faces, *control, *memContent) {
	s, err := clerk.NewAESSealer(bytes.Repeat([]byte{1}, 32))
	if err != nil {
		t.Fatal(err)
	}
	c := &control{tpl: []byte{0, 0, 128, 63, 0, 0, 0, 64}}
	m := &memContent{items: map[Hash][]byte{}}
	anchors := func() []key.PublicKey { return []key.PublicKey{anchor.Public()} }
	return &Faces{Slots: slotsOf(clerk.NewSecrets(s, nil)), Content: m, Control: c, Anchors: anchors}, c, m
}

// enrol is the owner's step: Begin, the anchor's tap, Enrol.
func enrol(ctx context.Context, f *Faces, id string, fr vision.Frame) error {
	what, err := f.Begin(id, "", fr)
	if err != nil {
		return err
	}
	return f.Enrol(ctx, id, "", fr, what, key.Approve(anchor, what))
}

// Enrolment takes a valid, new id, up to MaxEnrolled; every wrap-key read
// is logged under svc-vision; the lend carries the template; and Enrolled
// follows the lends, never the service: after a failed lend it keeps only
// ids both sets hold.
func TestEnrolChecksAndLends(t *testing.T) {
	ctx := context.Background()
	f, c, m := newFaces(t)
	fr := vision.Frame{Format: vision.FormatGray8, Width: 2, Height: 2, Data: make([]byte, 4)}
	if err := f.Enrol(ctx, "Alice", "", fr, [32]byte{}, key.Cosign{}); !errors.Is(err, ErrID) {
		t.Fatalf("a bad id: %v", err)
	}
	if err := enrol(ctx, f, "alice", fr); err != nil {
		t.Fatal(err)
	}
	if err := enrol(ctx, f, "alice", fr); !errors.Is(err, ErrEnrolled) {
		t.Fatalf("a second enrolment: %v", err)
	}
	if len(c.lends) != 1 || len(c.lends[0]) != 1 || c.lends[0][0].ID != "alice" || !bytes.Equal(c.lends[0][0].Vec, c.tpl) {
		t.Fatalf("lends: %+v", c.lends)
	}
	for _, l := range m.reads {
		if l != Lineage {
			t.Fatalf("a wrap key read for %q", l)
		}
	}
	if !f.Enrolled("alice") || f.Enrolled("bob") {
		t.Fatal("Enrolled does not follow the lend")
	}
	c.fail = errors.New("service down")
	if err := f.Unenrol(ctx, "alice"); err == nil {
		t.Fatal("a failed lend was not returned")
	}
	if f.Enrolled("alice") {
		t.Fatal("after a failed lend an un-enrolled id is still accepted")
	}
	if err := enrol(ctx, f, "bob", fr); err == nil || f.Enrolled("bob") {
		t.Fatalf("an id a failed lend carried is accepted: %v", err)
	}
	c.fail = nil
	if err := f.Sync(ctx); err != nil || !f.Enrolled("bob") {
		t.Fatalf("a lend that lands: %v", err)
	}
	for i := range vision.MaxEnrolled - 1 { // bob holds one slot
		id := "p" + string(rune('a'+i%26)) + string(rune('a'+i/26))
		if err := enrol(ctx, f, id, fr); err != nil {
			t.Fatalf("enrolment %d: %v", i, err)
		}
	}
	if err := enrol(ctx, f, "one-more", fr); !errors.Is(err, ErrFull) {
		t.Fatalf("over MaxEnrolled: %v", err)
	}
}

// Enrol makes a template only on an anchor's co-signature over the one
// change Begin named, used once and within ApprovalTTL: not without one,
// not a passkey that is no anchor, not over another id, subject, frame or
// notice, not a second time, and not late. A refused enrolment asks the
// service for nothing and writes no slot (DEV-7, CH-3).
func TestEnrolNeedsTheAnchorsApproval(t *testing.T) {
	ctx := context.Background()
	f, c, _ := newFaces(t)
	now := time.Unix(1_800_000_000, 0)
	f.Now = func() time.Time { return now }
	fr := vision.Frame{Format: vision.FormatGray8, Width: 2, Height: 2, Data: []byte{1, 2, 3, 4}}
	other := vision.Frame{Format: vision.FormatGray8, Width: 2, Height: 2, Data: []byte{1, 2, 3, 5}}
	stranger := key.Ed25519Signer(ed25519.NewKeyFromSeed(bytes.Repeat([]byte{8}, 32)))
	begin := func(id string) [32]byte {
		t.Helper()
		w, err := f.Begin(id, "", fr)
		if err != nil {
			t.Fatal(err)
		}
		return w
	}
	var nonce [16]byte
	unbegun := EnrolHash(nonce, "alice", "", FrameDigest(fr))
	w0, w1, w2, w3 := begin("alice"), begin("alice"), begin("alice"), begin("alice")
	for _, tc := range []struct {
		name  string
		id    string
		frame vision.Frame
		what  [32]byte
		c     key.Cosign
	}{
		{"no signature", "alice", fr, w0, key.Cosign{}},
		{"not an anchor", "alice", fr, w1, key.Approve(stranger, w1)},
		{"another id", "bob", fr, w2, key.Approve(anchor, w2)},
		{"another frame", "alice", other, w3, key.Approve(anchor, w3)},
		{"never begun", "alice", fr, unbegun, key.Approve(anchor, unbegun)},
	} {
		if err := f.Enrol(ctx, tc.id, "", tc.frame, tc.what, tc.c); !errors.Is(err, ErrApproval) {
			t.Errorf("%s: %v", tc.name, err)
		}
	}
	// A refusal used its change up: the right signature over it now fails.
	if err := f.Enrol(ctx, "alice", "", fr, w0, key.Approve(anchor, w0)); !errors.Is(err, ErrApproval) {
		t.Errorf("a change a refusal used: %v", err)
	}
	w := begin("alice")
	// A signature over another change (as a page with other notice
	// words would get) is refused.
	if err := f.Enrol(ctx, "alice", "", fr, w, key.Approve(anchor, [32]byte{1})); !errors.Is(err, ErrApproval) {
		t.Errorf("a signature over another change: %v", err)
	}
	// Late.
	w = begin("alice")
	now = now.Add(ApprovalTTL)
	if err := f.Enrol(ctx, "alice", "", fr, w, key.Approve(anchor, w)); !errors.Is(err, ErrApproval) {
		t.Errorf("late: %v", err)
	}
	if c.enrols != 0 || len(f.Slots.Names()) != 0 {
		t.Fatalf("a refused enrolment asked the service %d times, slots %v", c.enrols, f.Slots.Names())
	}
	// The right one, once.
	w = begin("alice")
	if err := f.Enrol(ctx, "alice", "", fr, w, key.Approve(anchor, w)); err != nil {
		t.Fatal(err)
	}
	if err := f.Unenrol(ctx, "alice"); err != nil {
		t.Fatal(err)
	}
	if err := f.Enrol(ctx, "alice", "", fr, w, key.Approve(anchor, w)); !errors.Is(err, ErrApproval) {
		t.Errorf("a used approval: %v", err)
	}
	// No anchors: nothing is approved.
	f.Anchors = nil
	w = begin("alice")
	if err := f.Enrol(ctx, "alice", "", fr, w, key.Approve(anchor, w)); !errors.Is(err, ErrApproval) {
		t.Errorf("no anchors: %v", err)
	}
	if c.enrols != 1 {
		t.Fatalf("%d enrol calls", c.enrols)
	}
}

// EnrolHash names one enrolment: any other nonce, id, subject or frame is
// another change, and an id and subject cannot trade bytes.
func TestEnrolHashNamesOneEnrolment(t *testing.T) {
	var n, n2 [16]byte
	n2[0] = 1
	fr := [32]byte{1}
	base := EnrolHash(n, "alice", "s", fr)
	for name, h := range map[string][32]byte{
		"nonce":   EnrolHash(n2, "alice", "s", fr),
		"id":      EnrolHash(n, "alicf", "s", fr),
		"subject": EnrolHash(n, "alice", "t", fr),
		"frame":   EnrolHash(n, "alice", "s", [32]byte{2}),
		"split":   EnrolHash(n, "alices", "", fr),
	} {
		if h == base {
			t.Errorf("another %s names the same change", name)
		}
	}
}

// Begin keeps at most MaxPending changes, dropping the oldest, and refuses
// what Enrol would before any tap.
func TestBeginBounds(t *testing.T) {
	f, _, _ := newFaces(t)
	now := time.Unix(1_800_000_000, 0)
	f.Now = func() time.Time { now = now.Add(time.Second); return now }
	fr := vision.Frame{Format: vision.FormatGray8, Width: 2, Height: 2, Data: make([]byte, 4)}
	first, _ := f.Begin("alice", "", fr)
	for range MaxPending {
		if _, err := f.Begin("alice", "", fr); err != nil {
			t.Fatal(err)
		}
	}
	if len(f.pending) != MaxPending {
		t.Fatalf("%d pending", len(f.pending))
	}
	if _, ok := f.pending[first]; ok {
		t.Fatal("the oldest change was kept")
	}
	if _, err := f.Begin("Alice", "", fr); !errors.Is(err, ErrID) {
		t.Fatalf("a bad id: %v", err)
	}
	f.Content = nil
	if _, err := f.Begin("alice", "", fr); !errors.Is(err, ErrNoErase) {
		t.Fatalf("no erase: %v", err)
	}
}

// slotsOf is the wiring's Slots over a clerk.Secrets store.
func slotsOf(s *clerk.Secrets) Slots {
	return Slots{
		Names:  func() []string { return s.Names(clerk.VisionTemplateSlots) },
		Put:    func(slot string, rec []byte) error { return s.Put(slot, clerk.KindStatic, rec) },
		Remove: s.Remove,
		Lend:   s.VisionTemplate,
	}
}

// SlotPrefix is the clerk's own prefix, so the wiring's Lend opens these
// slots and no other.
func TestSlotPrefixIsTheClerks(t *testing.T) {
	if SlotPrefix != clerk.VisionTemplateSlots {
		t.Fatal("the slot prefixes differ")
	}
}
