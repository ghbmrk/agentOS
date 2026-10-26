package kernel_test

// REQ: KEY-3, OWN-9, CLK-2, D-146

import (
	"testing"

	"github.com/ghbmrk/agentos/broker/kernel"
	"github.com/ghbmrk/agentos/broker/kernel/key"
)

// A passkey narrowing the clerk's key for the clerk itself is the owner's
// approval of exactly that: live at once, since it hands out nothing the
// clerk lacked, and its use cap counts the approval alone (OWN-9, D-146).
func TestAPasskeyNarrowsAClerkKeyAtOnce(t *testing.T) {
	r := newRig(t)
	phone := gen(8)
	must(t, r.k.Enroll(0, key.Enroll(r.owner.pass, phone.pk)))
	ok, err := key.Narrow(r.ck, phone.pass, key.LimitUses(1), key.LimitExpires(hour))
	must(t, err)
	v, err := key.Chain(ok, r.k.State().Passkeys())
	must(t, err)
	if !v.ByOwner || len(v.Narrowers) != 1 {
		t.Fatal("a passkey's narrowing must read as the owner's")
	}
	if v, err := key.Chain(r.derive(key.LimitUses(1)), r.k.State().Passkeys()); err != nil || v.ByOwner {
		t.Fatal("the clerk's own narrowing must not read as the owner's")
	}
	r.plan("p1", ok, st(key.Trash, "m1"))
	must(t, r.tick(10))
	if r.status("p1") != kernel.SDone {
		t.Fatalf("an approval waits no hold: %s", r.status("p1"))
	}
	r.plan("p2", ok, st(key.Trash, "m2"))
	r.plan("p3", r.ck, st(key.Trash, "m3"))
	must(t, r.tick(20))
	if r.status("p2") != kernel.SRejected || r.status("p3") != kernel.SDone {
		t.Fatalf("the approval's cap must count it alone: %s %s", r.status("p2"), r.status("p3"))
	}
}

// A passkey cannot hand the clerk's power to anyone else without a grant, and
// a cut-off passkey's approvals stop.
func TestAPasskeysNarrowingKeepsItsHolderAndEndsAtCutOff(t *testing.T) {
	r := newRig(t)
	phone := gen(8)
	must(t, r.k.Enroll(0, key.Enroll(r.owner.pass, phone.pk)))
	other := key.Extend(r.ck, phone.priv, key.Link{Caveats: []key.Caveat{key.LimitUses(1)}, Holder: gen(9).pub})
	if _, err := key.Chain(other, r.k.State().Passkeys()); err == nil {
		t.Fatal("a passkey's link to another holder is a grant, not a narrowing")
	}
	ok, err := key.Narrow(r.ck, phone.pass, key.LimitUses(1))
	must(t, err)
	below, err := key.Derive(ok, r.holder.priv, r.holder.pub, key.LimitUses(1))
	must(t, err)
	must(t, r.k.Unenroll(1, key.Unenroll(r.owner.pass, phone.pk)))
	for _, k := range []key.Key{ok, below} {
		p := r.sign(kernel.Plan{ID: "p1", Key: k, Steps: []kernel.PlanStep{st(key.Trash, "m1")}})
		if _, _, rf := kernel.Admit(r.k.State(), p, 2); rf == nil || rf.Code != kernel.CCutOff {
			t.Fatalf("a cut-off passkey's approval, and a key derived below it, must stop: %v", rf)
		}
	}
	r.plan("p2", r.ck, st(key.Trash, "m2"))
	must(t, r.tick(10))
	if r.status("p2") != kernel.SDone {
		t.Fatalf("the clerk's own key stands: %s", r.status("p2"))
	}
}
