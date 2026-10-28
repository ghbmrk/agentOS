package faces

// REQ: DEV-7, LOG-4

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/ghbmrk/agentos/broker/clerk"
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
	tpl   []byte
	lends [][]vision.Template
	fail  error
}

func (c *control) Enrol(context.Context, vision.Frame) ([]byte, error) {
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

func newFaces(t *testing.T) (*Faces, *control, *memContent) {
	s, err := clerk.NewAESSealer(bytes.Repeat([]byte{1}, 32))
	if err != nil {
		t.Fatal(err)
	}
	c := &control{tpl: []byte{0, 0, 128, 63, 0, 0, 0, 64}}
	m := &memContent{items: map[Hash][]byte{}}
	return &Faces{Slots: slotsOf(clerk.NewSecrets(s, nil)), Content: m, Control: c}, c, m
}

// Enrolment takes a valid, new id, up to MaxEnrolled; every wrap-key read
// is logged under svc-vision; the lend carries the template; and Enrolled
// follows the last lend that landed, never the service.
func TestEnrolChecksAndLends(t *testing.T) {
	ctx := context.Background()
	f, c, m := newFaces(t)
	fr := vision.Frame{Format: vision.FormatGray8, Width: 2, Height: 2, Data: make([]byte, 4)}
	if err := f.Enrol(ctx, "Alice", "", fr); !errors.Is(err, ErrID) {
		t.Fatalf("a bad id: %v", err)
	}
	if err := f.Enrol(ctx, "alice", "", fr); err != nil {
		t.Fatal(err)
	}
	if err := f.Enrol(ctx, "alice", "", fr); !errors.Is(err, ErrEnrolled) {
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
	if !f.Enrolled("alice") {
		t.Fatal("a failed lend changed the list the service may still answer from")
	}
	c.fail = nil
	for i := range vision.MaxEnrolled {
		id := "p" + string(rune('a'+i%26)) + string(rune('a'+i/26))
		if err := f.Enrol(ctx, id, "", fr); err != nil {
			t.Fatalf("enrolment %d: %v", i, err)
		}
	}
	if err := f.Enrol(ctx, "one-more", "", fr); !errors.Is(err, ErrFull) {
		t.Fatalf("over MaxEnrolled: %v", err)
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
