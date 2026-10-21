package kernel_test

// REQ: KEY-1, KEY-4, KEY-6, KRN-7, CLK-2

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/ghbmrk/agentos/broker/kernel"
	"github.com/ghbmrk/agentos/broker/kernel/key"
)

// admits reports the refusal code Admit gives p at now, "" when it admits it.
func admits(r *rig, p kernel.Plan, now int64) string {
	if _, _, rf := kernel.Admit(r.k.State(), p, now); rf != nil {
		return rf.Code
	}
	return ""
}

func trashRoot(r *rig, serial string, by pair) key.Key {
	return key.Issue(by.priv, key.Root{Clerk: "mail", Verbs: []key.Verb{key.Trash}, Serial: serial})
}

// A grant waits GrantHold, listed for the owner's notice, and a revoke during
// the hold cancels it for good (D-146).
func TestGrantWaitsItsHoldAndARevokeCancelsIt(t *testing.T) {
	r := newRig(t)
	root := trashRoot(r, "r2", r.owner)
	ck, err := key.ClerkKey(root, r.owner.priv, r.holder.pub, 0, 10)
	must(t, err)
	must(t, r.k.Issue(0, root, ck)) // one batch: one hold, one entry
	p := r.sign(kernel.Plan{ID: "p1", Key: ck, Steps: []kernel.PlanStep{st(key.Trash, "m1")}})
	if c := admits(r, p, kernel.GrantHold-1); c != kernel.CGrantHeld {
		t.Fatalf("a plan under a grant in its hold: %q", c)
	}
	if got := r.k.State().Pending(1); len(got) != 2 {
		t.Fatalf("pending grants for the owner's notice: %d", len(got))
	}
	if c := admits(r, p, kernel.GrantHold); c != "" {
		t.Fatalf("a plan once the hold has run: %q", c)
	}
	other := trashRoot(r, "r3", r.owner)
	must(t, r.k.Issue(0, other))
	must(t, r.k.Revoke(1, other.Tip())) // the owner cancels it
	if got := r.k.State().Pending(1); len(got) != 2 {
		t.Fatalf("a cancelled grant is not pending: %d", len(got))
	}
	ock, err := key.ClerkKey(other, r.owner.priv, r.holder.pub, 0, 10)
	must(t, err)
	must(t, r.k.Issue(1, ock))
	q := r.sign(kernel.Plan{ID: "p2", Key: ock, Steps: []kernel.PlanStep{st(key.Trash, "m1")}})
	if c := admits(r, q, 3*kernel.GrantHold); c != key.RRevoked {
		t.Fatalf("a cancelled grant after its hold: %q", c)
	}
	if !kernel.Widening(kernel.TKeyIssued) {
		t.Fatal("a grant is a widening: it anchors")
	}
}

// Only a renewal of a live clerk key, same root, holder and limits, with a
// later expiry within ClerkLife, skips the hold (D-146).
func TestOnlyASameLimitRenewalIsLiveAtOnce(t *testing.T) {
	r := newRig(t)
	at := 10 * hour
	renew := func(name string, holder pair, spendDay, life int64, c ...key.Caveat) key.Key {
		t.Helper()
		k, err := key.Derive(key.Key{Root: r.ck.Root}, r.owner.priv, holder.pub,
			append([]key.Caveat{key.LimitExpires(at + life), key.LimitSpendDay(spendDay)}, c...)...)
		must(t, err)
		must(t, r.k.Issue(at, k))
		return k
	}
	cases := []struct {
		name string
		k    key.Key
		live bool
	}{
		{"same limits", renew("same", r.holder, 1<<40, key.ClerkLife), true},
		{"a wider cap", renew("wider", r.holder, 1<<41, key.ClerkLife), false},
		{"a narrower cap", renew("narrower", r.holder, 5, key.ClerkLife), false},
		{"an added limit", renew("added", r.holder, 1<<40, key.ClerkLife, key.LimitUses(3)), false},
		{"past ClerkLife", renew("long", r.holder, 1<<40, key.ClerkLife+1), false},
		{"another holder", renew("other", gen(7), 1<<40, key.ClerkLife), false},
	}
	for _, c := range cases {
		from, ok := r.k.State().Granted(c.k.Tip())
		if !ok || (from == at) != c.live {
			t.Fatalf("%s: live from %d (granted %v), want live at once %v", c.name, from, ok, c.live)
		}
	}
	// A renewal of a grant still in its hold is not live at once either.
	root := trashRoot(r, "r2", r.owner)
	ck, err := key.ClerkKey(root, r.owner.priv, r.holder.pub, at, 10)
	must(t, err)
	must(t, r.k.Issue(at, root, ck))
	again, err := key.ClerkKey(root, r.owner.priv, r.holder.pub, at+1, 10)
	must(t, err)
	must(t, r.k.Issue(at+1, again))
	if from, _ := r.k.State().Granted(again.Tip()); from < at+kernel.GrantHold {
		t.Fatalf("a renewal of a pending grant is live at %d", from)
	}
}

// The bare root is the passkey's alone: its own tap is a one-off under it,
// and the home clerk's signature under it confers nothing (D-146).
func TestBareRootIsUsedOnlyByThePasskey(t *testing.T) {
	r := newRig(t)
	bare := key.Key{Root: r.ck.Root}
	steps := []kernel.PlanStep{st(key.Trash, "m1")}
	if c := admits(r, kernel.SignPlan(kernel.Plan{ID: "p1", Key: bare, Steps: steps}, r.holder.priv), 0); c != kernel.CKey {
		t.Fatalf("the home clerk under the bare root: %q", c)
	}
	if c := admits(r, kernel.SignPlan(kernel.Plan{ID: "p1", Key: bare, Steps: steps}, r.owner.priv), 0); c != "" {
		t.Fatalf("the passkey's one-off under the bare root: %q", c)
	}
	if _, err := key.Derive(bare, r.holder.priv, r.holder.pub, key.LimitExpires(1), key.LimitSpendDay(1)); !errors.Is(err, key.ErrNotHolder) {
		t.Fatalf("the home clerk derives off the root: %v", err)
	}
}

// Only an anchor enrolls a passkey, at once; a revoked one signs no new grant
// and no one-off, while keys under its earlier grants run until they lapse
// (D-146).
func TestAnAnchorEnrollsAPhoneAndARevokeCutsItOff(t *testing.T) {
	r := newRig(t) // the rig's owner is the anchor, the hardware key
	phone, stranger := gen(8), gen(9)
	if err := r.k.Enroll(0, key.Enroll(stranger.priv, phone.pub)); !errors.Is(err, kernel.ErrNotEnrolled) {
		t.Fatalf("an enrollment no anchor signed: %v", err)
	}
	if err := r.k.Issue(0, trashRoot(r, "early", phone)); err == nil {
		t.Fatal("a passkey not yet enrolled grants nothing")
	}
	must(t, r.k.Enroll(0, key.Enroll(r.owner.priv, phone.pub)))
	root := trashRoot(r, "phone", phone)
	ck, err := key.ClerkKey(root, phone.priv, r.holder.pub, 0, 10)
	must(t, err)
	must(t, r.k.Issue(0, root, ck))
	p := r.sign(kernel.Plan{ID: "p1", Key: ck, Steps: []kernel.PlanStep{st(key.Trash, "m1")}})
	oneOff := kernel.SignPlan(kernel.Plan{ID: "p2", Key: root, Steps: p.Steps}, phone.priv)
	at := kernel.GrantHold
	if c, d := admits(r, p, at), admits(r, oneOff, at); c != "" || d != "" {
		t.Fatalf("the enrolled phone's grant %q and one-off %q", c, d)
	}
	must(t, r.k.Unenroll(at, phone.pub)) // the phone is lost
	if c := admits(r, p, at); c != "" {
		t.Fatalf("a key under the lost phone's earlier grant runs until it lapses: %q", c)
	}
	if c := admits(r, oneOff, at); c != kernel.CKey {
		t.Fatalf("the lost phone's one-off: %q", c)
	}
	renewal, err := key.ClerkKey(root, phone.priv, r.holder.pub, at, 10)
	must(t, err)
	if err := r.k.Issue(at, renewal); err == nil {
		t.Fatal("the lost phone renews nothing")
	}
	if err := r.k.Enroll(at, key.Enroll(r.owner.priv, phone.pub)); !errors.Is(err, kernel.ErrNotEnrolled) ||
		key.In(r.k.State().Passkeys(), phone.pub) {
		t.Fatalf("a revoked passkey never comes back: %v", err)
	}
	if !kernel.Widening(kernel.TEnrolled) || kernel.Widening(kernel.TUnenrolled) {
		t.Fatal("an enrollment widens and anchors; a revoke narrows")
	}
}

// An enrollment the anchor never confirmed does not survive a reboot (KRN-7).
func TestUnanchoredEnrollmentDoesNotSurviveReboot(t *testing.T) {
	r := newRig(t)
	phone := gen(8)
	r.anchor.down = true
	if err := r.k.Enroll(1, key.Enroll(r.owner.priv, phone.pub)); err == nil {
		t.Fatal("an unconfirmed enrollment must report it")
	}
	r.anchor.down = false
	r.boot(2)
	if key.In(r.k.State().Passkeys(), phone.pub) {
		t.Fatal("an unconfirmed enrollment survived a reboot")
	}
}

// The clerk judges a grant's hold on its own clock: a kernel clock that runs
// ahead admits the plan, and the clerk still refuses it (CLK-2, D-146).
func TestClerkKeepsTheGrantHoldWhenTheKernelClockRunsAhead(t *testing.T) {
	r := newRig(t)
	root := trashRoot(r, "r2", r.owner)
	ck, err := key.ClerkKey(root, r.owner.priv, r.holder.pub, 0, 10)
	must(t, err)
	must(t, r.k.Issue(0, root, ck))
	ahead := kernel.GrantHold + 1
	must(t, r.k.Submit(ahead, r.sign(kernel.Plan{ID: "p1", Key: ck, Steps: []kernel.PlanStep{st(key.Trash, "m1")}})))
	r.now = hour // the clerk's clock: still in the hold
	must(t, r.k.Tick(ahead))
	if len(r.mail.Effects()) != 0 || r.status("p1") != kernel.SFailed {
		t.Fatalf("status %s, %d effects: the clerk let a grant go live on the kernel's clock", r.status("p1"), len(r.mail.Effects()))
	}
	if d := r.k.State().Plans["p1"].Steps[0].Detail; d != kernel.CGrantHeld {
		t.Fatalf("detail %q, want %q", d, kernel.CGrantHeld)
	}
}

// A first link is a grant of its own: one under a granted root, never
// granted itself, confers nothing (D-146, KEY-1).
func TestAFirstLinkNotGrantedConfersNothing(t *testing.T) {
	r := newRig(t)
	ck, err := key.ClerkKey(key.Key{Root: r.ck.Root}, r.owner.priv, r.holder.pub, 0, 1<<39)
	must(t, err)
	if c := admits(r, r.sign(kernel.Plan{ID: "p1", Key: ck, Steps: []kernel.PlanStep{st(key.Trash, "m1")}}), 0); c != kernel.CUngranted {
		t.Fatalf("an ungranted first link: %q", c)
	}
}

// A first link is never live before its root, whatever time its entry
// carries (a kernel clock set back, KRN-7).
func TestAFirstLinkIsNeverLiveBeforeItsRoot(t *testing.T) {
	r := newRig(t)
	root := trashRoot(r, "r2", r.owner)
	must(t, r.k.Issue(10*hour, root))
	ck, err := key.ClerkKey(root, r.owner.priv, r.holder.pub, 0, 10)
	must(t, err)
	must(t, r.k.Issue(0, ck))
	rf, _ := r.k.State().Granted(root.Tip())
	if from, _ := r.k.State().Granted(ck.Tip()); from < rf {
		t.Fatalf("first link live at %d, its root at %d", from, rf)
	}
}

// The fold, not only Issue, checks a grant against the passkeys in the set at
// its entry: a log that carries a cut-off phone's grant does not grant it.
func TestReplayGrantsNothingFromACutOffPasskey(t *testing.T) {
	r := newRig(t)
	phone := gen(8)
	must(t, r.k.Enroll(0, key.Enroll(r.owner.priv, phone.pub)))
	root := trashRoot(r, "phone", phone)
	ck, err := key.ClerkKey(root, phone.priv, r.holder.pub, 0, 10)
	must(t, err)
	must(t, r.k.Issue(0, root, ck))
	must(t, r.k.Unenroll(1, phone.pub))
	again, err := key.ClerkKey(root, phone.priv, r.holder.pub, 2, 10)
	must(t, err)
	es := r.k.Log().Entries()
	body, _ := json.Marshal(struct{ Keys []key.Key }{[]key.Key{again}})
	es = append(es, kernel.Entry{Seq: uint64(len(es) + 1), At: 2, Type: kernel.TKeyIssued, V: 1, Body: body})
	s, err := kernel.Replay(r.anchors(), es)
	must(t, err)
	if _, ok := s.Granted(again.Tip()); ok {
		t.Fatal("a cut-off passkey's grant folded in")
	}
	if _, ok := s.Granted(ck.Tip()); !ok {
		t.Fatal("its earlier grant stands")
	}
}
