package kernel_test

// REQ: BAK-1, HW-16, HW-17, LOG-1, LOG-4, LOG-5

import (
	"bytes"
	"errors"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/ghbmrk/agentos/broker/kernel"
	"github.com/ghbmrk/agentos/broker/kernel/key"
)

func drive(name string) kernel.BackupTarget {
	return kernel.BackupTarget{Name: name, Kind: kernel.KindDir, Locator: "/mnt/" + name, AppendOnly: true}
}

// target signs t as the next target with by.
func target(r *rig, by pair, t kernel.BackupTarget) key.Cosign {
	return key.Approve(by.pass, kernel.BackupTargetHash(r.k.State().TargetsAdded(), t))
}

func listed(s *kernel.State) map[string]kernel.KeptTarget {
	out := map[string]kernel.KeptTarget{}
	for _, t := range s.BackupTargets() {
		out[t.Name] = t
	}
	return out
}

// A destination is where the box may connect (HW-16, HW-17), so adding one
// is a widening only a hardware key signs: a phone passkey's, a stale or
// another target's signature, or none, refuses and logs nothing. An anchor's
// logs it, anchored. Catches an owner side widening egress alone.
func TestBackupTargetNeedsAnAnchor(t *testing.T) {
	r := newRig(t)
	phone, stranger := gen(8), gen(9)
	must(t, r.k.Enroll(0, key.Enroll(r.owner.pass, phone.pk)))
	d := drive("usb")
	moved := d
	moved.Locator = "/mnt/elsewhere"
	rw := d
	rw.AppendOnly = false
	n := r.k.State().TargetsAdded()
	for name, c := range map[string]key.Cosign{
		"none":             {},
		"anchor, no sig":   {By: r.owner.pk},
		"phone passkey":    target(r, phone, d),
		"stranger":         target(r, stranger, d),
		"stale count":      key.Approve(r.owner.pass, kernel.BackupTargetHash(n+1, d)),
		"another locator":  target(r, r.owner, moved),
		"append-only lost": target(r, r.owner, rw),
		"line domain":      key.Approve(r.owner.pass, kernel.LineHash(n, 300)),
		"by forged":        {By: r.owner.pk, Sig: phone.pass.Sign(key.CosignMsg(kernel.BackupTargetHash(n, d)))},
	} {
		before := r.k.Log().Len()
		if err := r.k.BackupTarget(1, d, c); !errors.Is(err, kernel.ErrTargetSig) {
			t.Fatalf("%s: %v", name, err)
		}
		if r.k.Log().Len() != before || len(r.k.State().BackupTargets()) != 0 {
			t.Fatalf("%s: a refused target logged or took effect", name)
		}
	}

	must(t, r.k.BackupTarget(1, d, target(r, r.spare, d)))
	es := r.k.Log().Entries()
	if last := es[len(es)-1]; last.Type != kernel.TBackupTarget || !kernel.Widening(last.Type) {
		t.Fatalf("logged %s, want a widening %s", last.Type, kernel.TBackupTarget)
	}
	if h, ok := r.anchor.Latest(); !ok || h.Seq != uint64(len(es)) {
		t.Fatal("an added target is not anchored at once")
	}
	got := listed(r.k.State())["usb"]
	if got.BackupTarget != d || got.Removed {
		t.Fatalf("listed %+v, want %+v", got, d)
	}
	// The same signature again, or the same name newly signed, adds nothing.
	if err := r.k.BackupTarget(2, d, key.Approve(r.spare.pass, kernel.BackupTargetHash(n, d))); !errors.Is(err, kernel.ErrTargetSig) {
		t.Fatalf("a replayed signature: %v", err)
	}
	if err := r.k.BackupTarget(2, moved, target(r, r.owner, moved)); !errors.Is(err, kernel.ErrTargetExists) {
		t.Fatalf("a second target under one name: %v", err)
	}
}

// Removing a target only narrows, so it needs no signature; the target stays
// listed as removed, since its backups keep their erase reach (LOG-4, D-168).
func TestUntargetIsANarrowingAndKeepsTheTarget(t *testing.T) {
	r := newRig(t)
	d := drive("usb")
	must(t, r.k.BackupTarget(1, d, target(r, r.owner, d)))
	if err := r.k.Untarget(2, "nas"); !errors.Is(err, kernel.ErrNoTarget) {
		t.Fatalf("removing an unknown target: %v", err)
	}
	r.anchor.down = true // a narrowing stands without its anchor
	if err := r.k.Untarget(2, "usb"); err == nil {
		t.Fatal("an unanchored removal must report the anchor")
	}
	es := r.k.Log().Entries()
	if last := es[len(es)-1]; last.Type != kernel.TBackupUntarget || kernel.Widening(last.Type) {
		t.Fatalf("logged %s, want a narrowing %s", last.Type, kernel.TBackupUntarget)
	}
	r.anchor.down = false
	r.boot(3)
	got, ok := listed(r.k.State())["usb"]
	if !ok || !got.Removed || got.BackupTarget != d {
		t.Fatalf("after removal and restart: %+v, %v", got, ok)
	}
	if err := r.k.Untarget(4, "usb"); !errors.Is(err, kernel.ErrNoTarget) {
		t.Fatalf("removing a removed target: %v", err)
	}
	if err := r.k.BackupTarget(4, d, target(r, r.owner, d)); !errors.Is(err, kernel.ErrTargetExists) {
		t.Fatalf("a removed target's name reused: %v", err)
	}
}

// Targets and removals survive a replay, in the order they were added; an
// unconfirmed add is dropped at restart; a shape the kernel cannot carry
// refuses, and one written to the log anyway folds to nothing.
func TestTargetsReplay(t *testing.T) {
	r := newRig(t)
	a, b, c := drive("usb"), drive("nas"), drive("spare")
	b.AppendOnly = false
	must(t, r.k.BackupTarget(1, a, target(r, r.owner, a)))
	must(t, r.k.BackupTarget(2, b, target(r, r.spare, b)))
	must(t, r.k.Untarget(3, "usb"))
	r.anchor.down = true
	if err := r.k.BackupTarget(4, c, target(r, r.owner, c)); err == nil {
		t.Fatal("an add the anchor cannot confirm must report it")
	}
	r.anchor.down = false
	r.boot(5)
	got := r.k.State().BackupTargets()
	if len(got) != 2 || got[0].BackupTarget != a || !got[0].Removed || got[1].BackupTarget != b || got[1].Removed {
		t.Fatalf("after replay: %+v", got)
	}
	if r.k.State().TargetsAdded() != 2 {
		t.Fatalf("targets added %d, want 2", r.k.State().TargetsAdded())
	}
	re, err := kernel.Replay(r.anchors(), r.k.Log().Entries())
	must(t, err)
	if len(re.BackupTargets()) != 2 {
		t.Fatal("a fresh replay differs from the booted state")
	}

	bad := map[string]kernel.BackupTarget{
		"unknown kind":      {Name: "s3", Kind: "s3", Locator: "/mnt/s3"},
		"oversized locator": {Name: "big", Kind: kernel.KindDir, Locator: "/" + strings.Repeat("a", kernel.MaxLocator)},
		"relative dir":      {Name: "rel", Kind: kernel.KindDir, Locator: "mnt/rel"},
		"unclean dir":       {Name: "up", Kind: kernel.KindDir, Locator: "/mnt/../etc"},
		"no name":           {Kind: kernel.KindDir, Locator: "/mnt/x"},
		"long name":         {Name: strings.Repeat("n", kernel.MaxTargetName+1), Kind: kernel.KindDir, Locator: "/mnt/x"},
		"name with slash":   {Name: "a/b", Kind: kernel.KindDir, Locator: "/mnt/x"},
		"control in path":   {Name: "ctl", Kind: kernel.KindDir, Locator: "/mnt/x\n"},
		"not text":          {Name: "bin", Kind: kernel.KindDir, Locator: "/mnt/\xff"},
		"bidi override":     {Name: "bidi", Kind: kernel.KindDir, Locator: "/mnt/\u202ekcab"},
		"zero-width":        {Name: "zw", Kind: kernel.KindDir, Locator: "/mnt/us\u200bb"},
		"byte order mark":   {Name: "bom", Kind: kernel.KindDir, Locator: "/mnt/\ufeffusb"},
		"line separator":    {Name: "ls", Kind: kernel.KindDir, Locator: "/mnt/usb\u2028x"},
		"para separator":    {Name: "ps", Kind: kernel.KindDir, Locator: "/mnt/usb\u2029x"},
		"grapheme joiner":   {Name: "cgj", Kind: kernel.KindDir, Locator: "/mnt/us\u034fb"},
		"selector 16":       {Name: "vs16", Kind: kernel.KindDir, Locator: "/mnt/us\ufe0fb"},
		"selector 17":       {Name: "vs17", Kind: kernel.KindDir, Locator: "/mnt/us\U000E0100b"},
		"hangul filler":     {Name: "hf", Kind: kernel.KindDir, Locator: "/mnt/usb\u3164"},
		"choseong filler":   {Name: "chf", Kind: kernel.KindDir, Locator: "/mnt/usb\u115f"},
		"halfwidth filler":  {Name: "hwf", Kind: kernel.KindDir, Locator: "/mnt/usb\uffa0"},
		"khmer vowel":       {Name: "km", Kind: kernel.KindDir, Locator: "/mnt/usb\u17b4"},
		"dot name":          {Name: ".", Kind: kernel.KindDir, Locator: "/mnt/x"},
		"dot-dot name":      {Name: "..", Kind: kernel.KindDir, Locator: "/mnt/x"},
		"dot-led name":      {Name: ".hidden", Kind: kernel.KindDir, Locator: "/mnt/x"},
	}
	for name, bt := range bad {
		n := r.k.Log().Len()
		if err := r.k.BackupTarget(6, bt, target(r, r.owner, bt)); !errors.Is(err, kernel.ErrTarget) {
			t.Fatalf("%s: %v", name, err)
		}
		if r.k.Log().Len() != n {
			t.Fatalf("%s: a refused target logged", name)
		}
	}

	// A log holding an unsigned or misshapen add, written past the kernel,
	// gains no target on replay: an audit trusts no writer for it.
	type body struct {
		Target kernel.BackupTarget
		Cosign key.Cosign
	}
	unk := bad["unknown kind"]
	for _, w := range []body{{Target: c}, {Target: c, Cosign: key.Approve(gen(8).pass, kernel.BackupTargetHash(2, c))}, {Target: unk, Cosign: target(r, r.owner, unk)}} {
		_, err := r.k.Log().Append(7, kernel.TBackupTarget, 1, w)
		must(t, err)
	}
	re, err = kernel.Replay(r.anchors(), r.k.Log().Entries())
	must(t, err)
	if len(re.BackupTargets()) != 2 || re.TargetsAdded() != 2 {
		t.Fatalf("a logged unsigned or misshapen target took effect: %+v", re.BackupTargets())
	}
}

// taken is a well-formed backup.taken of id at target, recipient fill.
func taken(id, target string, fill byte, upto uint64) kernel.BackupTaken {
	return kernel.BackupTaken{BackupID: id, Target: target, Created: 5, Upto: upto, Recipient: kernel.BackupRecipient{
		X: bytes.Repeat([]byte{fill}, kernel.RecipientXLen), EK: bytes.Repeat([]byte{fill}, kernel.RecipientEKLen)}}
}

func bid(c string) string { return strings.Repeat(c, 32) }

// LOG-5: backup.taken is a known type at version 1 and not a widening, so
// Open keeps it unanchored; it is logged and anchored at once. An unknown
// target, a duplicate or malformed ID, short recipient keys and a snapshot
// not before the entry are each refused live, and fold to nothing when
// written past the kernel.
func TestBackupTakenIsKnownAndNotWidening(t *testing.T) {
	r := newRig(t)
	if !kernel.Known(kernel.TBackupTaken, 1) || kernel.Known(kernel.TBackupTaken, 2) || kernel.Widening(kernel.TBackupTaken) {
		t.Fatal("backup.taken must be known at v1 only, and not a widening")
	}
	d := drive("usb")
	must(t, r.k.BackupTarget(1, d, target(r, r.owner, d)))
	head := uint64(r.k.Log().Len())
	b1 := taken(bid("a"), "usb", 1, head)
	must(t, r.k.BackupTaken(2, b1))
	es := r.k.Log().Entries()
	if last := es[len(es)-1]; last.Type != kernel.TBackupTaken || last.V != 1 {
		t.Fatalf("logged %s v%d", last.Type, last.V)
	}
	if h, ok := r.anchor.Latest(); !ok || h.Seq != uint64(len(es)) {
		t.Fatal("a logged backup is not anchored at once")
	}

	short := taken(bid("c"), "usb", 1, head)
	short.Recipient.EK = short.Recipient.EK[:100]
	shortX := taken(bid("d"), "usb", 1, head)
	shortX.Recipient.X = nil
	bad := map[string]kernel.BackupTaken{
		"unknown target": taken(bid("b"), "nas", 1, head),
		"duplicate id":   taken(bid("a"), "usb", 2, head),
		"malformed id":   taken("not-a-backup-id", "usb", 1, head),
		"uppercase id":   taken(bid("A"), "usb", 1, head),
		"short ek":       short,
		"short x":        shortX,
		"snapshot ahead": taken(bid("e"), "usb", 1, uint64(r.k.Log().Len())+1),
	}
	for name, b := range bad {
		n := r.k.Log().Len()
		if err := r.k.BackupTaken(3, b); !errors.Is(err, kernel.ErrBackupTaken) {
			t.Fatalf("%s: %v", name, err)
		}
		if r.k.Log().Len() != n {
			t.Fatalf("%s: a refused backup logged", name)
		}
	}
	// Written past the kernel, each folds to nothing.
	for name, b := range bad {
		if name == "snapshot ahead" {
			b.Upto = uint64(r.k.Log().Len()) + 1 // its own sequence number
		}
		_, err := r.k.Log().Append(4, kernel.TBackupTaken, 1, b)
		must(t, err)
	}
	re, err := kernel.Replay(r.anchors(), r.k.Log().Entries())
	must(t, err)
	if got := re.BackupsTaken(); len(got) != 1 || !reflect.DeepEqual(got[0], b1) {
		t.Fatalf("after replay: %d backups taken, want only %s", len(got), b1.BackupID)
	}

	// Unanchored, it survives Open: a crash after the write keeps it.
	r.anchor.down = true
	b2 := taken(bid("f"), "usb", 3, uint64(r.k.Log().Len()))
	if err := r.k.BackupTaken(5, b2); err == nil {
		t.Fatal("an unanchored backup.taken must report the anchor")
	}
	r.anchor.down = false
	r.boot(6)
	if got := r.k.State().BackupsTaken(); len(got) != 2 || got[1].BackupID != b2.BackupID {
		t.Fatalf("an unanchored backup.taken dropped at restart: %d taken", len(got))
	}
	if _, err := kernel.Rederive(r.anchors(), r.head.pub, r.k.Log().Entries()); err != nil {
		t.Fatalf("rederive: %v", err)
	}
}

// LOG-1: the logged backups and the subjects opened at or below a sequence
// number are a projection of the log: a replay from empty equals the live
// state, at a removed target too.
func TestBackupsTakenRebuildFromEmpty(t *testing.T) {
	r := newRig(t)
	_, err := r.k.OpenContent(kernel.NewMemKeys(), map[string]kernel.ContentStore{}, 1)
	must(t, err)
	a, b := drive("usb"), drive("nas")
	must(t, r.k.BackupTarget(1, a, target(r, r.owner, a)))
	must(t, r.k.BackupTarget(1, b, target(r, r.owner, b)))
	s1, err := r.k.OpenSubject(2)
	must(t, err)
	upto := uint64(r.k.Log().Len())
	must(t, r.k.BackupTaken(3, taken(bid("1"), "nas", 1, upto)))
	must(t, r.k.BackupTaken(3, taken(bid("2"), "usb", 1, upto)))
	s2, err := r.k.OpenSubject(4)
	must(t, err)
	must(t, r.k.Untarget(5, "usb"))
	must(t, r.k.BackupTaken(6, taken(bid("3"), "usb", 2, uint64(r.k.Log().Len()))))
	if got := r.k.State().SubjectsUpto(upto); !reflect.DeepEqual(got, []string{s1}) {
		t.Fatalf("subjects at or below %d: %v, want only %s", upto, got, s1)
	}
	if got := r.k.State().SubjectsUpto(uint64(r.k.Log().Len())); len(got) != 2 || !slices.Contains(got, s2) {
		t.Fatalf("subjects at the head: %v", got)
	}
	live := r.k.State().BackupsTaken()
	if len(live) != 3 {
		t.Fatalf("live backups taken: %d, want 3", len(live))
	}
	re, err := kernel.Replay(r.anchors(), r.k.Log().Entries())
	must(t, err)
	if !reflect.DeepEqual(re.BackupsTaken(), live) || !reflect.DeepEqual(re.SubjectsUpto(upto), r.k.State().SubjectsUpto(upto)) {
		t.Fatal("a replay from empty differs from the live state")
	}
}
