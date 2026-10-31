package kernel_test

// REQ: REC-4, BAK-1, LOG-1, LOG-5

import (
	"errors"
	"strings"
	"testing"

	"github.com/ghbmrk/agentos/broker/kernel"
	"github.com/ghbmrk/agentos/broker/kernel/key"
)

var (
	ridOld  = strings.Repeat("0a", 16)
	ridNext = strings.Repeat("1b", 16)
)

// MIG-4-recovery-r1 (#3391): only a hardware key approves a recovery-key
// rotation. A phone passkey's, a missing, a stranger's or another
// rotation's signature refuses and logs nothing; an anchor's logs one
// widening entry, anchored, that replays and rederives. Catches an owner
// side approving a rotation alone.
func TestRecoveryRotateNeedsAnAnchor(t *testing.T) {
	r := newRig(t)
	phone, stranger := gen(8), gen(9)
	must(t, r.k.Enroll(0, key.Enroll(r.owner.pass, phone.pk)))
	h := kernel.RecoveryRotateHash(ridOld, ridNext)
	for name, c := range map[string]key.Cosign{
		"none":           {},
		"anchor, no sig": {By: r.owner.pk},
		"phone passkey":  key.Approve(phone.pass, h),
		"stranger":       key.Approve(stranger.pass, h),
		"another next":   key.Approve(r.owner.pass, kernel.RecoveryRotateHash(ridOld, strings.Repeat("2c", 16))),
		"another old":    key.Approve(r.owner.pass, kernel.RecoveryRotateHash("", ridNext)),
		"lost-card hash": key.Approve(r.owner.pass, kernel.RecoveryRotateHash(ridOld, "")),
		"swapped":        key.Approve(r.owner.pass, kernel.RecoveryRotateHash(ridNext, ridOld)),
		"target domain":  key.Approve(r.owner.pass, kernel.BackupTargetHash(0, drive("usb"))),
		"by forged":      {By: r.owner.pk, Sig: phone.pass.Sign(key.CosignMsg(h))},
	} {
		before := r.k.Log().Len()
		if err := r.k.RecoveryRotate(1, ridOld, ridNext, c); !errors.Is(err, kernel.ErrRotateSig) {
			t.Fatalf("%s: %v", name, err)
		}
		if r.k.Log().Len() != before {
			t.Fatalf("%s: a refused rotation logged", name)
		}
	}
	// Out of shape refuses before any signature is looked at.
	for name, ids := range map[string][2]string{
		"next is old":    {ridOld, ridOld},
		"old not an ID":  {"OLD", ridNext},
		"next not an ID": {ridOld, strings.ToUpper(ridNext)},
		"next too long":  {ridOld, ridNext + "00"},
	} {
		c := key.Approve(r.owner.pass, kernel.RecoveryRotateHash(ids[0], ids[1]))
		if err := r.k.RecoveryRotate(1, ids[0], ids[1], c); !errors.Is(err, kernel.ErrRotate) {
			t.Fatalf("%s: %v", name, err)
		}
	}

	must(t, r.k.RecoveryRotate(2, ridOld, ridNext, key.Approve(r.spare.pass, h)))
	// The lost-card route names no next; a store enrolled before e1 no old.
	must(t, r.k.RecoveryRotate(3, ridOld, "", key.Approve(r.owner.pass, kernel.RecoveryRotateHash(ridOld, ""))))
	must(t, r.k.RecoveryRotate(4, "", ridNext, key.Approve(r.owner.pass, kernel.RecoveryRotateHash("", ridNext))))
	es := r.k.Log().Entries()
	n := 0
	for _, e := range es {
		if e.Type == kernel.TRecoveryRotate {
			n++
		}
	}
	if last := es[len(es)-1]; n != 3 || last.Type != kernel.TRecoveryRotate || !kernel.Widening(last.Type) {
		t.Fatalf("logged %d rotations, last %s; want 3, a widening", n, last.Type)
	}
	if h, ok := r.anchor.Latest(); !ok || h.Seq != uint64(len(es)) {
		t.Fatal("a rotation is not anchored at once")
	}
	// An approval is signed only once its entry is anchored: with the
	// anchor down, the call fails.
	r.anchor.down = true
	if err := r.k.RecoveryRotate(5, ridOld, ridNext, key.Approve(r.owner.pass, h)); err == nil {
		t.Fatal("a rotation whose anchor failed reported success")
	}
	r.anchor.down = false
	r.boot(6)
	r.replays()
}

// LOG-5: recovery.rotate is known at version 1 only and folded as given.
func TestRecoveryRotateIsKnown(t *testing.T) {
	if !kernel.Known(kernel.TRecoveryRotate, 1) || kernel.Known(kernel.TRecoveryRotate, 2) {
		t.Fatal("recovery.rotate must be known at version 1 only")
	}
	r := newRig(t)
	must(t, r.k.RecoveryRotate(1, "", ridNext, key.Approve(r.owner.pass, kernel.RecoveryRotateHash("", ridNext))))
	got, err := kernel.Rederive(r.anchors(), r.k.Box(), r.k.Log().Entries())
	must(t, err)
	if got.Recorded[kernel.TRecoveryRotate] != 1 {
		t.Fatalf("rederive %+v", got)
	}
}

// MIG-4-recovery-r4c (#4128): only a hardware key's tap over the card's
// own ID shows the lost-card route's new card. A phone passkey's, a
// stranger's, another card's or a rotation's signature refuses, as does an
// ID out of shape; none logs. Catches an owner-page session signed in with
// the phone passkey alone reading the only recovery key that opens the
// store.
func TestRecoveryCardTapNeedsAnAnchor(t *testing.T) {
	r := newRig(t)
	phone, stranger := gen(8), gen(9)
	must(t, r.k.Enroll(0, key.Enroll(r.owner.pass, phone.pk)))
	h := kernel.RecoveryCardHash(ridNext)
	before := r.k.Log().Len()
	for name, c := range map[string]key.Cosign{
		"none":          {},
		"phone passkey": key.Approve(phone.pass, h),
		"stranger":      key.Approve(stranger.pass, h),
		"another card":  key.Approve(r.owner.pass, kernel.RecoveryCardHash(ridOld)),
		"rotation":      key.Approve(r.owner.pass, kernel.RecoveryRotateHash(ridOld, "")),
	} {
		if err := r.k.RecoveryCardTap(ridNext, c); !errors.Is(err, kernel.ErrRotateSig) {
			t.Fatalf("%s: %v", name, err)
		}
	}
	if err := r.k.RecoveryCardTap("NEXT", key.Approve(r.owner.pass, kernel.RecoveryCardHash("NEXT"))); !errors.Is(err, kernel.ErrRotateSig) {
		t.Fatalf("an ID out of shape: %v", err)
	}
	must(t, r.k.RecoveryCardTap(ridNext, key.Approve(r.spare.pass, h)))
	if r.k.Log().Len() != before {
		t.Fatal("a card tap logged")
	}
}
