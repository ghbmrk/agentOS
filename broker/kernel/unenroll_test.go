package kernel_test

// REQ: KEY-4

import (
	"errors"
	"testing"

	"github.com/ghbmrk/agentos/broker/kernel"
	"github.com/ghbmrk/agentos/broker/kernel/key"
)

// Only a hardware key's signature cuts a phone passkey off (#3209, #3176
// option B): a cut-off with no signature, the phone's own, one over the
// enrolment domain, one over another key, or a stranger's is refused and
// logs nothing; the anchor's cuts the phone off and cancels its held grants.
func TestOnlyAHardwareKeyCutsAPhoneOff(t *testing.T) {
	r := newRig(t) // the rig's owner is the anchor, the hardware key
	phone, other, stranger := gen(8), gen(9), gen(10)
	must(t, r.k.Enroll(0, key.Enroll(r.owner.pass, phone.pk)))
	must(t, r.k.Enroll(0, key.Enroll(r.owner.pass, other.pk)))
	root := trashRoot(r, "ph", phone)
	ck, err := key.ClerkKey(root, phone.pass, r.holder.pub, 1, 10)
	must(t, err)
	must(t, r.issue(1, root, ck))

	overOther := key.Unenroll(r.owner.pass, other.pk)
	overOther.Passkey = phone.pk
	for name, u := range map[string]key.Unenrollment{
		"no signature":   {Passkey: phone.pk},
		"anchor, no sig": {Passkey: phone.pk, By: r.owner.pk},
		"phone passkey":  key.Unenroll(phone.pass, phone.pk),
		"other phone":    key.Unenroll(other.pass, phone.pk),
		"stranger":       key.Unenroll(stranger.pass, phone.pk),
		"wrong domain":   {Passkey: phone.pk, By: r.owner.pk, Sig: r.owner.pass.Sign(key.EnrollMsg(phone.pk))},
		"another key":    overOther,
		"by forged":      {Passkey: phone.pk, By: r.owner.pk, Sig: phone.pass.Sign(key.UnenrollMsg(phone.pk))},
	} {
		n := len(r.k.Log().Entries())
		if err := r.k.Unenroll(2, u); !errors.Is(err, kernel.ErrNotUnenrolled) {
			t.Fatalf("%s: %v", name, err)
		}
		if len(r.k.Log().Entries()) != n || !key.In(r.k.State().Passkeys(), phone.pk) {
			t.Fatalf("%s: a refused cut-off logged or took effect", name)
		}
	}
	if got := r.k.State().Pending(2); len(got) == 0 {
		t.Fatalf("the phone's held grant before a signed cut-off: %d", len(got))
	}

	must(t, r.k.Unenroll(2, key.Unenroll(r.owner.pass, phone.pk)))
	if key.In(r.k.State().Passkeys(), phone.pk) || !key.In(r.k.State().Passkeys(), other.pk) {
		t.Fatal("the hardware key's cut-off: the phone stays, or the other phone went")
	}
	if got := r.k.State().Pending(3); len(got) != 0 {
		t.Fatalf("a cut-off phone's grants still pending: %d", len(got))
	}
	p := r.sign(kernel.Plan{ID: "p1", Key: ck, Steps: []kernel.PlanStep{st(key.Trash, "m1")}})
	if c := admits(r, p, 3*kernel.GrantHold); c == "" {
		t.Fatal("a cut-off phone's held grant came live")
	}
}

// A logged cut-off no hardware key signed changes nothing on replay, so an
// audit of the log trusts no writer for it (#3209).
func TestAnUnsignedLoggedCutOffChangesNothing(t *testing.T) {
	r := newRig(t)
	phone := gen(8)
	must(t, r.k.Enroll(0, key.Enroll(r.owner.pass, phone.pk)))
	for _, u := range []key.Unenrollment{{Passkey: phone.pk}, key.Unenroll(phone.pass, phone.pk)} {
		_, err := r.k.Log().Append(2, kernel.TUnenrolled, 1, struct{ key.Unenrollment }{u})
		must(t, err)
	}
	re, err := kernel.Replay(r.anchors(), r.k.Log().Entries())
	must(t, err)
	if !key.In(re.Passkeys(), phone.pk) {
		t.Fatal("an unsigned logged cut-off took effect")
	}
}
