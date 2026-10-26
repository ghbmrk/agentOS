package kernel_test

// REQ: BAK-1, HW-16, HW-17

import (
	"errors"
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
