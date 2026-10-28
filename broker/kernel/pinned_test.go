package kernel_test

// REQ: KRN-1, KRN-4, KEY-1, KEY-4, UPD-3

import (
	"errors"
	"reflect"
	"testing"

	"github.com/ghbmrk/agentos/broker/clerk/check"
	"github.com/ghbmrk/agentos/broker/kernel"
	"github.com/ghbmrk/agentos/broker/kernel/key"
)

// updateClerk stands in for broker/apply's update clerk: it checks each
// request against the pinned root alone, as that clerk does, and acts.
type updateClerk struct {
	pinned key.PublicKey
	now    *int64
	done   int
}

func (c *updateClerk) facts(st key.Step) (string, []string, int64) {
	return st.Content, st.Labels, st.Amount
}

func (c *updateClerk) Do(r kernel.Request, v kernel.View) kernel.Result {
	if rf := check.Check([]key.PublicKey{c.pinned}, "update", c.facts, *c.now, r, v); rf != nil {
		return kernel.Result{Outcome: "failed", Detail: rf.Code}
	}
	c.done++
	return kernel.Result{Outcome: "ok"}
}

func (c *updateClerk) Probe(kernel.Request, kernel.View) kernel.Result {
	return kernel.Result{Outcome: "unknown"}
}

// pinRig is the kernel rig with the image-pinned update root: a standing
// root for clerk update, change-account only, owned by a key the image
// carries with its holder (Mark's card
// cmsg_01R91wiieBzMSvPKFsAJVvuKUCsPpUiKJNwvXkmXsdfr63, #3677).
type pinRig struct {
	*rig
	image pair    // the pinned key: its private half ships in the image
	up    key.Key // the pinned root
	clerk *updateClerk
}

func newPinRig(t *testing.T) *pinRig {
	r := &pinRig{rig: newRig(t), image: gen(40)}
	r.up = key.Issue(r.image.pass, key.Root{Clerk: "update", Verbs: []key.Verb{key.ChangeAccount}, Serial: "image"})
	r.clerk = &updateClerk{pinned: r.image.pk, now: &r.now}
	r.reboot(0)
	return r
}

// reboot starts the kernel over the rig's log with the pinned root, as
// the kernel process does at every start.
func (r *pinRig) reboot(now int64) {
	l, err := kernel.Open(cfg(r.rig))
	must(r.t, err)
	r.k, err = kernel.Boot(l, r.anchors(), map[string]kernel.Clerk{"mail": r.mail, "update": r.clerk}, now, r.up)
	must(r.t, err)
}

func (r *pinRig) replays() {
	r.t.Helper()
	re, err := kernel.Replay(r.anchors(), r.k.Log().Entries(), r.up)
	must(r.t, err)
	if !reflect.DeepEqual(re, r.k.State()) {
		r.t.Fatal("replay differs from the live state (KRN-1)")
	}
	_, err = kernel.Rederive(r.anchors(), r.k.Box(), r.k.Log().Entries(), r.up)
	must(r.t, err)
}

func activate(id string) kernel.PlanStep {
	return kernel.PlanStep{Verb: key.ChangeAccount, Clerk: "update", Args: map[string]string{"target": "usr-" + id, "value": "entry-" + id}}
}

// submit has the image's holder sign plan id under k with steps.
func (r *pinRig) submit(id string, k key.Key, at int64, steps ...kernel.PlanStep) string {
	r.t.Helper()
	must(r.t, r.k.Submit(at, kernel.SignPlan(kernel.Plan{ID: id, Key: k, Steps: steps}, r.image.priv)))
	return r.status(id)
}

// The pinned root runs its one verb at its one clerk with no owner Issue:
// the box activates a release before any owner exists (UPD-3), and the
// clerk's own check against the pinned root alone passes (CLK-2).
func TestPinnedRootActivatesWithNoGrant(t *testing.T) {
	r := newPinRig(t)
	if _, ok := r.k.State().Grants[r.up.Tip()]; ok {
		t.Fatal("the pinned root is in the log's grants")
	}
	if got := r.submit("a1", r.up, 1, activate("a1")); got != kernel.SActive {
		t.Fatalf("pinned activate: %s %s", got, r.k.State().Plans["a1"].Reject)
	}
	must(t, r.tick(2))
	if r.status("a1") != kernel.SDone || r.clerk.done != 1 {
		t.Fatalf("pinned activate ran %d times, status %s", r.clerk.done, r.status("a1"))
	}
	r.replays()
	r.reboot(3)
	if r.status("a1") != kernel.SDone {
		t.Fatal("a reboot with the same pinned root changed the plan")
	}

	// Booted without it, the same root is ungranted: the image is its only source.
	l, err := kernel.Open(cfg(r.rig))
	must(t, err)
	bare, err := kernel.Boot(l, r.anchors(), nil, 4)
	must(t, err)
	p := kernel.SignPlan(kernel.Plan{ID: "a2", Key: r.up, Steps: []kernel.PlanStep{activate("a2")}}, r.image.priv)
	if _, _, rf := kernel.Admit(bare.State(), p, 4); rf == nil || rf.Code != kernel.CKey {
		t.Fatalf("unpinned kernel admitted the update root: %v", rf)
	}

	// A revoke of the pinned root's ID still stops it.
	must(t, r.k.Revoke(5, r.up.Tip()))
	if got := r.submit("a3", r.up, 6, activate("a3")); got != kernel.SRejected {
		t.Fatalf("revoked pinned root: %s", got)
	}
}

// The pinned key is never an anchor or a passkey (#3677): anyone holding the
// image holds it, so it enrolls, cuts off, grants, co-signs and anchors
// nothing, and signs no plan under any root but its own exact one.
func TestPinnedKeyCannotEnrollOrAnchor(t *testing.T) {
	r := newPinRig(t)
	s := r.k.State()
	if key.In(s.Anchors, r.image.pk) || key.In(s.Passkeys(), r.image.pk) {
		t.Error("the pinned key is among the owner's passkeys")
	}
	attacker := gen(41)

	// Enroll a passkey of the attacker's into the owner's set.
	if err := r.k.Enroll(1, key.Enroll(r.image.pass, attacker.pk)); !errors.Is(err, kernel.ErrNotEnrolled) {
		t.Fatalf("pinned-key enrollment: %v", err)
	}
	// Enroll itself, then use it.
	if err := r.k.Enroll(1, key.Enroll(r.image.pass, r.image.pk)); !errors.Is(err, kernel.ErrNotEnrolled) {
		t.Fatalf("pinned-key self-enrollment: %v", err)
	}
	// Cut the owner's phone off.
	phone := gen(42)
	must(t, r.k.Enroll(1, key.Enroll(r.owner.pass, phone.pk)))
	if err := r.k.Unenroll(2, key.Unenroll(r.image.pass, phone.pk)); !errors.Is(err, kernel.ErrNotUnenrolled) {
		t.Fatalf("pinned-key cut-off: %v", err)
	}
	// Grant a root of its own at another clerk, or a wider one at update.
	for _, root := range []key.Key{
		key.Issue(r.image.pass, key.Root{Clerk: "mail", Verbs: []key.Verb{key.Send}, Serial: "x"}),
		key.Issue(r.image.pass, key.Root{Clerk: "update", Verbs: []key.Verb{key.ChangeAccount, key.Send}, Serial: "x"}),
	} {
		if err := r.k.Issue(3, approve([]key.Key{root}, r.image, r.owner), root); err == nil {
			t.Fatalf("pinned key granted root %v", root.Root.Verbs)
		}
	}
	// Grant a clerk key off its own root, so a link outlives the image.
	ck, err := key.ClerkKey(r.up, r.image.pass, attacker.pub, 3, 1<<20)
	must(t, err)
	if err := r.k.Issue(3, nil, ck); err == nil {
		t.Fatal("pinned key granted a link off the pinned root")
	}
	// Co-sign the owner's big grant as its second passkey.
	big := key.Issue(r.owner.pass, key.Root{Clerk: "mail", Verbs: []key.Verb{key.Send}, Serial: "big"})
	if err := r.k.Issue(4, approve([]key.Key{big}, r.owner, r.image), big); !errors.Is(err, kernel.ErrNeedsCosign) {
		t.Fatalf("pinned key co-signed a big grant: %v", err)
	}
	// Raise the owner's line.
	if err := r.k.SetLine(4, 90, key.Approve(r.owner.pass, kernel.LineHash(s.LineChanges(), 90)), key.Approve(r.image.pass, kernel.LineHash(s.LineChanges(), 90))); err == nil {
		t.Fatal("pinned key co-signed a raised line")
	}

	// Plans: only the exact pinned root, only its verb, only its clerk.
	other := key.Issue(r.image.pass, key.Root{Clerk: "update", Verbs: []key.Verb{key.ChangeAccount}, Serial: "other"})
	mail := key.Issue(r.image.pass, key.Root{Clerk: "mail", Verbs: []key.Verb{key.Trash}, Serial: "m"})
	ownerRoot := key.Issue(r.owner.pass, key.Root{Clerk: "update", Verbs: []key.Verb{key.ChangeAccount}, Serial: "o"})
	for name, c := range map[string]struct {
		k  key.Key
		st kernel.PlanStep
	}{
		"another root it signed":    {other, activate("p1")},
		"a root at another clerk":   {mail, st(key.Trash, "m1")},
		"the owner's root":          {ownerRoot, activate("p3")},
		"its link off the pinned":   {ck, activate("p4")},
		"another verb at update":    {r.up, kernel.PlanStep{Verb: key.Trash, Clerk: "update", Args: map[string]string{"message": "x"}}},
		"its verb at another clerk": {r.up, kernel.PlanStep{Verb: key.ChangeAccount, Clerk: "mail", Args: map[string]string{"target": "t", "value": "v"}}},
	} {
		if got := r.submit(name, c.k, 5, c.st); got != kernel.SRejected {
			t.Errorf("%s: %s", name, got)
		}
	}
	// The owner's passkeys sign nothing under the pinned root either.
	p := kernel.SignPlan(kernel.Plan{ID: "o1", Key: r.up, Steps: []kernel.PlanStep{activate("o1")}}, r.owner.priv)
	must(t, r.k.Submit(5, p))
	if r.status("o1") != kernel.SRejected {
		t.Fatalf("owner-signed plan under the pinned root: %s", r.status("o1"))
	}

	if s := r.k.State(); key.In(s.Passkeys(), attacker.pk) || key.In(s.Passkeys(), r.image.pk) || len(s.Enrolled) != 1 {
		t.Fatalf("the owner's set changed: %d enrolled", len(s.Enrolled))
	}
	r.replays()
}

// A pinned root must be a bare root its own owner signed, and no anchor's:
// the kernel refuses to boot on anything else.
func TestPinRefusesAnythingButABareSelfSignedRoot(t *testing.T) {
	r := newPinRig(t)
	ck, err := key.ClerkKey(r.up, r.image.pass, gen(41).pub, 0, 1<<20)
	must(t, err)
	forged := r.up
	forged.Root.Sig = append([]byte(nil), forged.Root.Sig...)
	forged.Root.Sig[0] ^= 1
	byAnchor := key.Issue(r.owner.pass, key.Root{Clerk: "update", Verbs: []key.Verb{key.ChangeAccount}, Serial: "image"})
	for name, k := range map[string]key.Key{"a link": ck, "a bad signature": forged, "an anchor's root": byAnchor} {
		l, err := kernel.Open(cfg(r.rig))
		must(t, err)
		if _, err := kernel.Boot(l, r.anchors(), nil, 1, k); !errors.Is(err, kernel.ErrPinned) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// On a first boot there are no anchors to check the pinned key against, so
// setup refuses to take it as one, live and when the log is read back: else
// anyone with the image could anchor the box and enroll a passkey (#3701).
func TestSetupRefusesThePinnedKey(t *testing.T) {
	owner, image := gen(1), gen(40)
	up := key.Issue(image.pass, key.Root{Clerk: "update", Verbs: []key.Verb{key.ChangeAccount}, Serial: "image"})
	r := &rig{t: t, head: gen(3), store: &kernel.MemStore{}, anchor: &flakyAnchor{MemAnchor: &kernel.MemAnchor{}}}
	boot := func(pinned ...key.Key) (*kernel.Kernel, error) {
		l, err := kernel.Open(cfg(r))
		must(t, err)
		return kernel.Boot(l, nil, nil, 0, pinned...)
	}
	k, err := boot(up)
	must(t, err)
	if err := k.Setup(1, kernel.SignSetup(k.Box(), image.pass, owner.pass)); !errors.Is(err, kernel.ErrPinned) {
		t.Fatalf("setup anchored the pinned key: %v", err)
	}
	if k.Log().Len() != 0 || !k.State().SetupOpen() {
		t.Fatal("a refused setup logged something")
	}

	// A log whose setup anchored the image's key, written by a kernel booted
	// without the pin, does not boot with it.
	k, err = boot()
	must(t, err)
	must(t, k.Setup(1, kernel.SignSetup(k.Box(), image.pass, owner.pass)))
	if _, err := boot(up); !errors.Is(err, kernel.ErrPinned) {
		t.Fatalf("booted a log that anchors the pinned key: %v", err)
	}
	if _, err := kernel.Replay(nil, k.Log().Entries(), up); !errors.Is(err, kernel.ErrPinned) {
		t.Fatalf("replayed a log that anchors the pinned key: %v", err)
	}
}
