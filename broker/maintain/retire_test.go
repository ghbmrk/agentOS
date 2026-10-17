package maintain

// REQ: OSS-9, UPD-5, UPD-8, CH-12
// SR3-6-f6 (Security points 1-3 and L3 points 1-2 on #620): a narrowing
// retires a claim an ordinary release was proposed on, as it does a
// security fix's, and a restarted Loop 3 retires a claim it holds no
// release for.

import (
	"strings"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/change"
	"github.com/ghbmrk/agentos/broker/update"
)

// soakAndAttest publishes ordinary release 2, lets it soak, and attests
// it from the rig's listed attestor, so the next tick proposes it on that
// pass.
func soakAndAttest(r *rig) {
	r.t.Helper()
	r.release(2, nil)
	for i := 0; i < 8; i++ {
		r.tick()
		r.clk.add(24 * time.Hour)
		r.refresh()
	}
	r.attest()
}

// T1: an ordinary release proposed on a listed attestor's pass loses its
// claim when the owner removes that attestor: STATUS and the digest stop
// saying it is ready or who checked it, Evidence goes, and a check
// decides it again under the current list.
func TestNarrowingRetiresOrdinaryReleaseClaim(t *testing.T) {
	const checked = "Checked by 1 independent builder"
	r := newRig(t)
	r.followAs("Acme")
	soakAndAttest(r)
	r.tick()
	if len(r.p.proposed()) != 1 || r.l.st.Evidence[2][0] != 1 {
		t.Fatalf("not proposed on the pass: %d proposals, evidence %v", len(r.p.proposed()), r.l.st.Evidence)
	}
	if line := r.l.Status().Line; !strings.Contains(line, checked) {
		t.Fatalf("status before the narrowing: %q", line)
	}
	r.allow = nil
	r.must(r.l.AttestorsChanged())
	if _, ok := r.l.st.Evidence[2]; ok {
		t.Fatalf("Evidence kept the retired claim: %v", r.l.st.Evidence)
	}
	if line := r.l.Status().Line; strings.Contains(line, checked) {
		t.Fatalf("status still says the removed attestor checked it: %q", line)
	}
	if d := r.digest(); strings.Contains(d, checked) {
		t.Fatalf("digest still says the removed attestor checked it: %q", d)
	}
	r.tick()
	if n := len(r.p.proposed()); n != 2 {
		t.Fatalf("the release was not decided again: %d proposals", n)
	}
	if ev := r.l.st.Evidence[2]; ev[0] != 0 {
		t.Fatalf("the re-decided release counts a removed attestor: %v", ev)
	}

	// Adopted: "ready" goes too.
	a := newRig(t)
	a.p.state = change.StateAdopted
	soakAndAttest(a)
	a.tick()
	const ready = "Update 2 is ready and installs at the next quiet time."
	if line := a.l.Status().Line; line != ready {
		t.Fatalf("status before the narrowing: %q", line)
	}
	a.p.state = ""
	a.allow = nil
	a.must(a.l.AttestorsChanged())
	if line := a.l.Status().Line; strings.Contains(line, "ready") {
		t.Fatalf("status after the narrowing: %q", line)
	}
	if d := a.digest(); strings.Contains(d, "ready") {
		t.Fatalf("digest after the narrowing: %q", d)
	}
}

// T2: a claim the change did not touch stands. An unchanged list keeps an
// ordinary release's attested claim, and a release proposed on no pass
// keeps its claim when an attestor is listed: it never rested on the
// policy, so retiring on !Security() (false for every ordinary release)
// would be wrong.
func TestOrdinaryClaimSurvivesWhenPolicyStillHolds(t *testing.T) {
	r := newRig(t)
	soakAndAttest(r)
	r.tick()
	if len(r.p.proposed()) != 1 {
		t.Fatal("not proposed")
	}
	r.must(r.l.AttestorsChanged())
	if _, ok := r.l.st.Proposed[2]; !ok || r.l.st.Evidence[2][0] != 1 {
		t.Fatalf("an unchanged list retired the claim: proposed %v, evidence %v", r.l.st.Proposed, r.l.st.Evidence)
	}

	u := newRig(t)
	u.allow = nil
	u.l = u.newLoop()
	u.release(2, nil)
	for i := 0; i < 8 && len(u.p.proposed()) == 0; i++ {
		u.tick()
		u.clk.add(24 * time.Hour)
		u.refresh()
	}
	if len(u.p.proposed()) != 1 {
		t.Fatal("not proposed with no attestor listed")
	}
	u.allow = r.allow
	u.must(u.l.AttestorsChanged())
	if _, ok := u.l.st.Proposed[2]; !ok {
		t.Fatalf("a claim that never rested on a pass was retired: %v", u.l.st.Proposed)
	}
}

// T4: a Loop 3 rebuilt from saved state holds no release, so a claim it
// cannot judge is retired, not kept: the security claim and the ordinary
// one alike.
func TestRestartedLoop3RetiresClaimOnNarrowing(t *testing.T) {
	r := newRig(t)
	r.p.state = change.StateAdopted
	r.release(2, func(m *update.Manifest) { m.Security = true })
	r.attest()
	r.tick()
	if r.l.st.TestedBy[2] == "" {
		t.Fatalf("no claim recorded: %v", r.l.st.TestedBy)
	}
	r.l = r.newLoop()
	if r.l.st.TestedBy[2] == "" {
		t.Fatal("the claim was not saved")
	}
	r.allow = nil
	r.must(r.l.AttestorsChanged())
	if _, ok := r.l.st.TestedBy[2]; ok {
		t.Fatalf("the restarted loop kept a claim it holds no release for: %v", r.l.st.TestedBy)
	}
	if line := r.l.Status().Line; strings.Contains(line, "passed") || strings.Contains(line, "ready") {
		t.Fatalf("status: %q", line)
	}

	// New forgets a request still awaiting the owner, so the saved
	// ordinary claim is an adopted one.
	o := newRig(t)
	o.p.state = change.StateAdopted
	soakAndAttest(o)
	o.tick()
	o.l = o.newLoop()
	if o.l.st.Evidence[2][0] != 1 {
		t.Fatalf("the claim was not saved: %v", o.l.st.Evidence)
	}
	o.allow = nil
	o.must(o.l.AttestorsChanged())
	if _, ok := o.l.st.Evidence[2]; ok {
		t.Fatalf("the restarted loop kept an ordinary claim it holds no release for: %v", o.l.st.Evidence)
	}
}
