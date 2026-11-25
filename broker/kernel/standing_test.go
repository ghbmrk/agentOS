package kernel_test

// REQ: CH-3, KEY-2

import (
	"errors"
	"fmt"
	"testing"

	"github.com/ghbmrk/agentos/broker/kernel"
	"github.com/ghbmrk/agentos/broker/kernel/key"
)

// standing issues a mail root and its clerk key as standing keys stamped at
// rung, the clerk key asking for P3 (KEY-5's first-approval key), a hold
// before the test so both are live. It returns the root too.
func standing(r *rig, serial string, rung key.Proof) (key.Key, key.Key, error) {
	r.t.Helper()
	root := key.Issue(r.owner.pass, key.Root{Clerk: "mail", Verbs: []key.Verb{key.Trash}, Serial: serial})
	ck, err := key.ClerkKey(root, r.owner.pass, r.holder.pub, 0, 1<<40, key.LimitRung(key.P3))
	must(r.t, err)
	return ck, root, r.k.IssueStanding(-kernel.GrantHold, rung, approve([]key.Key{root, ck}, r.owner, r.spare), root, ck)
}

// A step under a standing key is checked at the rung of the owner event that
// derived the key, recorded on its grant, not P0 (KEY-2 rung clause, KEY-5,
// D-311): with no task, and in a run's task the kernel opens at P0. The same
// key issued as an ordinary grant carries no such rung, and a stamp no
// signature behind the key reaches is refused.
func TestStandingKeyStepRunsAtItsDerivingRung(t *testing.T) {
	r := newRig(t)
	sk, sroot, err := standing(r, "s1", key.P3)
	must(t, err)
	// A clerk key issued later by plain Issue under the standing root takes
	// its own grant's P0, not the root's stamp.
	later, err := key.ClerkKey(sroot, r.owner.pass, r.holder.pub, 0, 1<<39, key.LimitRung(key.P3))
	must(t, err)
	must(t, r.issue(-kernel.GrantHold, later))
	if got := r.k.State().Rung("", later, false); got != key.P0 {
		t.Fatalf("a plain clerk key under a standing root at %v, want P0", got)
	}
	root := key.Issue(r.owner.pass, key.Root{Clerk: "mail", Verbs: []key.Verb{key.Trash}, Serial: "o1"})
	plain, err := key.ClerkKey(root, r.owner.pass, r.holder.pub, 0, 1<<40, key.LimitRung(key.P3))
	must(t, err)
	must(t, r.issue(-kernel.GrantHold, root, plain))
	if got := r.k.State().Rung("", sk, false); got != key.P3 {
		t.Fatalf("a standing key's step at %v, want its deriving P3", got)
	}
	r.plan("later", sk, st(key.Trash, "m1"))
	must(t, r.k.OpenTask(0, "run", key.P0))
	run, err := key.Derive(sk, r.holder.priv, r.holder.pub, key.LimitTask("run"))
	must(t, err)
	r.plan("run", run, st(key.Trash, "m2"))

	r.plan("inherited", later, st(key.Trash, "m9"))
	if p := r.k.State().Plans["inherited"]; p.Status != kernel.SRejected || p.Reject != key.RRung {
		t.Fatalf("a plain clerk key under a standing root: %s %s", p.Status, p.Reject)
	}
	r.plan("plain", plain, st(key.Trash, "m3"))
	if p := r.k.State().Plans["plain"]; p.Status != kernel.SRejected || p.Reject != key.RRung {
		t.Fatalf("an ordinary grant's step under a P3 key: %s %s", p.Status, p.Reject)
	}
	must(t, r.tick(1))
	for _, id := range []string{"later", "run"} {
		if r.status(id) != kernel.SDone {
			t.Fatalf("%s under the standing key: %s %s", id, r.status(id), r.k.State().Plans[id].Reject)
		}
	}
	// A renewal of a live grant keeps its stamp: it never raises one.
	if err := r.k.IssueStanding(2, key.P3, approve([]key.Key{root, plain}, r.owner, r.spare), root, plain); err != nil {
		t.Fatal(err)
	}
	if got := r.k.State().Rung("", plain, false); got != key.P0 {
		t.Fatalf("a re-issue stamped an ordinary grant %v", got)
	}

	for _, bad := range []key.Proof{key.PRecovery, 255} {
		if _, _, err := standing(r, "bad", bad); !errors.Is(err, kernel.ErrStandingRung) {
			t.Fatalf("a standing key stamped %v: %v", bad, err)
		}
	}
	phone := gen(8)
	must(t, r.k.Enroll(0, key.Enroll(r.owner.pass, phone.pk)))
	proot := key.Issue(phone.pass, key.Root{Clerk: "mail", Verbs: []key.Verb{key.Trash}, Serial: "p1"})
	if err := r.k.IssueStanding(3, key.P4, approve([]key.Key{proot}, r.owner, r.spare), proot); !errors.Is(err, kernel.ErrStandingRung) {
		t.Fatalf("a phone passkey's root stamped P4: %v", err)
	}
	r.replays()
}

// A metered call is checked at its plan's rung (LOG-7, CH-3): a P3-rung key
// funds no call for a task opened at P1, though its held step was admitted
// on the code approval it waits for, and funds one for a task opened at P3.
func TestSpendRefusesBelowTheKeyRung(t *testing.T) {
	r := newRig(t)
	must(t, r.k.OpenTask(0, "t1", key.P1))
	must(t, r.k.OpenTask(0, "t3", key.P3))
	c := []key.Caveat{key.LimitRung(key.P3), key.LimitHold(hour, hour), key.LimitSpendTask(100)}
	r.plan("low", r.serve("t1", c...), st(key.Unsubscribe, "list-a"))
	r.plan("high", r.serve("t3", c...), st(key.Unsubscribe, "list-b"))
	if r.status("low") != kernel.SActive {
		t.Fatalf("the held step's plan: %s", r.status("low"))
	}
	if rf := r.admit(1, "low", 1); rf == nil || rf.Code() != key.RRung {
		t.Fatalf("a P1 task's metered call under a P3 key: %v", rf)
	}
	if rf := r.admit(1, "high", 1); rf != nil {
		t.Fatalf("a P3 task's metered call: %v", rf)
	}
	r.replays()
}

// A standing stamp is refused above P4, and above P3Local unless an anchor
// owns the root; P4 under an anchor's root and P3Local under a phone's are
// taken (KEY-4). The fold refuses a logged stamp no signature reaches, as
// IssueStanding does.
func TestAStandingStampIsBoundedByItsRootsOwner(t *testing.T) {
	r := newRig(t)
	if _, _, err := standing(r, "top", key.P4); err != nil {
		t.Fatalf("P4 under an anchor's root: %v", err)
	}
	phone := gen(8)
	must(t, r.k.Enroll(0, key.Enroll(r.owner.pass, phone.pk)))
	proot := key.Issue(phone.pass, key.Root{Clerk: "mail", Verbs: []key.Verb{key.Trash}, Serial: "p2"})
	if err := r.k.IssueStanding(0, key.P3Local, approve([]key.Key{proot}, r.owner, r.spare), proot); err != nil {
		t.Fatalf("P3Local under a phone's root: %v", err)
	}

	var cks []key.Key
	for i, rung := range []key.Proof{255, key.P3} {
		root := key.Issue(r.owner.pass, key.Root{Clerk: "mail", Verbs: []key.Verb{key.Trash}, Serial: fmt.Sprint("logged", i)})
		ck, err := key.ClerkKey(root, r.owner.pass, r.holder.pub, 0, 1<<40)
		must(t, err)
		keys := []key.Key{root, ck}
		_, err = r.k.Log().Append(1, kernel.TKeyIssued, 2, map[string]any{"Keys": keys, "Cosigns": approve(keys, r.owner, r.spare), "Rung": rung})
		must(t, err)
		cks = append(cks, ck)
	}
	s, err := kernel.Replay(r.anchors(), r.k.Log().Entries())
	must(t, err)
	if _, ok := s.Grants[cks[0].Tip()]; ok {
		t.Fatal("the fold granted a key stamped past P4")
	}
	if g, ok := s.Grants[cks[1].Tip()]; !ok || g.Rung != key.P3 {
		t.Fatalf("a logged P3 stamp: %v %v", ok, g.Rung)
	}
}

// A step's rung is raised for its hold only when it has one: an irreversible
// step under a one-use key the owner made, which has no hold, runs at its
// task's rung (CH-3, CH-10).
func TestAStepWithNoHoldIsNotRaised(t *testing.T) {
	r := newRig(t)
	root := key.Issue(r.owner.pass, key.Root{Clerk: "mail", Verbs: []key.Verb{key.Unsubscribe}, Serial: "once"})
	once, err := key.ClerkKey(root, r.owner.pass, r.holder.pub, 0, 1<<40, key.LimitUses(1), key.LimitRung(key.P3), key.LimitTask("t1"))
	must(t, err)
	must(t, r.issue(-kernel.GrantHold, root, once))
	must(t, r.k.OpenTask(0, "t1", key.P1))
	must(t, r.k.Submit(0, r.sign(kernel.Plan{ID: "p", Key: once, Steps: []kernel.PlanStep{st(key.Unsubscribe, "list-a")}})))
	if p := r.k.State().Plans["p"]; p.Status != kernel.SRejected || p.Reject != key.RRung {
		t.Fatalf("a P3 key's unheld step in a P1 task: %s %s", p.Status, p.Reject)
	}
}

// A metered call is checked at its plan's rung both while calls are still
// in flight and when the owner extends the held plan, and a plan whose own
// key was revoked funds nothing through its extension (LOG-7, CH-3, KEY-6).
func TestSpendInFlightAndExtensionKeepThePlansRung(t *testing.T) {
	r := newRig(t)
	env := envelope(r, 500, 800)
	must(t, r.k.OpenTask(0, "t3", key.P3))
	k := r.serve("t3", key.LimitRung(key.P3), key.LimitHold(hour, hour), key.LimitSpendTask(100))
	r.plan("p", k, st(key.Unsubscribe, "list-a"))
	a, rf := r.k.AdmitSpend(1, "p", 60)
	if rf != nil {
		t.Fatal(rf)
	}
	if _, rf := r.k.AdmitSpend(1, "p", 50); rf == nil || rf.Code() != kernel.CInFlight {
		t.Fatalf("a call over the cap only while one is in flight: %v", rf)
	}
	must(t, r.k.Meter(1, a, "api", 100, "provider"))
	_, rf = r.k.AdmitSpend(2, "p", 1)
	if rf == nil {
		t.Fatal("the plan should be exhausted")
	}
	must(t, r.k.Hold(2, "p", rf))
	must(t, r.k.Extend(3, extension(r, env, key.LimitSpendTask(300), key.LimitRung(key.P3)), "p"))
	must(t, r.k.Revoke(4, k.Tip()))
	if _, rf := r.k.AdmitSpend(5, "p", 1); rf == nil || rf.Code() != key.RRevoked {
		t.Fatalf("an extended plan whose own key was revoked: %v", rf)
	}
}
