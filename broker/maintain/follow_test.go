package maintain

// REQ: OSS-10, OSS-9, UPD-8

import (
	"crypto/ed25519"
	"strings"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/update"
)

// followAs switches the box to the rig's own root under the owner's name
// for it, as the tier-4 page does for a fork ("" switches back). The fork
// here is the rig's repository itself: what Loop 3 says depends on the
// store's record, not on whose keys signed.
func (r *rig) followAs(name string) update.Followed {
	r.t.Helper()
	o := update.Options{Now: r.clk.now}
	sum, err := update.DescribeRoot(r.rootJSON, o)
	r.must(err)
	r.must(r.store.FollowRoot(r.rootJSON, sum.Digest, name, o))
	src, err := r.store.Following()
	r.must(err)
	return src
}

// Security C7 and C5: while on a fork, STATUS names it with its root key's
// fingerprint, and up to date reads as the fork having nothing newer; the
// digest says the switch once. Switching back says so once too.
func TestOSS10StatusAndDigestNameTheFork(t *testing.T) {
	r := newRig(t)
	src := r.followAs("Acme Fork")
	r.tick()
	want := "Updates: Acme Fork has no release newer than yours yet (checked Mon 5 Oct 03:00). Following: Acme Fork (" + src.Fingerprint[:8] + ")."
	if st := r.l.Status(); !st.Current || st.Line != want {
		t.Fatalf("status %+v\nwant %q", st, want)
	}
	d := r.l.Digest()
	if !contains(d, "Updates now come from Acme Fork, chosen by you on Mon 5 Oct. You can switch back on my Wi-Fi page.") || !contains(d, want) {
		t.Fatalf("digest %q", d)
	}
	if d := r.l.Digest(); contains(d, "Updates now come from Acme Fork, chosen by you on Mon 5 Oct. You can switch back on my Wi-Fi page.") {
		t.Fatalf("the switch was said twice: %q", d)
	}
	r.followAs("")
	r.clk.add(time.Hour)
	if st := r.l.Status(); strings.Contains(st.Line, "Following") || strings.Contains(st.Line, "Acme") {
		t.Fatalf("still names the fork: %q", st.Line)
	}
	if d := r.l.Digest(); !contains(d, "Updates now come from the AgentOS project again, chosen by you.") {
		t.Fatalf("switching back not said: %q", d)
	}
	if d := r.l.Digest(); contains(d, "Updates now come from the AgentOS project again, chosen by you.") {
		t.Fatalf("switching back said twice: %q", d)
	}
}

func contains(lines []string, s string) bool {
	for _, l := range lines {
		if l == s {
			return true
		}
	}
	return false
}

// Potency C1 (binding): while no attestor is listed, each fork security
// fix is asked of the owner once, and STATUS says why. Once one is listed,
// a fix with its report stages on its own.
func TestOSS9ForkSecurityFixesAskUntilAnAttestorIsListed(t *testing.T) {
	if forkAsks != "Security fixes: you approve each one, since no attestor is listed for the fork you follow." {
		t.Fatalf("wording: %q", forkAsks)
	}
	r := newRig(t)
	r.allow = nil
	r.l = r.newLoop()
	src := r.followAs("Acme")
	r.release(2, func(m *update.Manifest) { m.Security = true })
	r.tick()
	r.clk.add(25 * time.Hour)
	r.refresh()
	r.tick()
	got := r.p.proposed()
	if len(got) != 1 || got[0].Security() {
		t.Fatalf("want one ask, not staged: %+v", got)
	}
	line := r.l.Status().Line
	if !strings.Contains(line, forkAsks) || !strings.Contains(line, "Following: Acme ("+src.Fingerprint[:8]+").") ||
		!strings.Contains(line, "Security update 2 needs your approval") || !strings.Contains(line, "No independent check yet; only Acme's own.") {
		t.Fatalf("status %q", line)
	}
	if d := r.l.Digest(); !contains(d, line) {
		t.Fatalf("the ask is not in the digest: %q", d)
	}

	listed := newRig(t)
	listed.followAs("Acme")
	listed.release(2, func(m *update.Manifest) { m.Security = true })
	listed.attest()
	listed.tick()
	if got := listed.p.proposed(); len(got) != 1 || !got[0].Security() {
		t.Fatalf("a fix with a listed attestor's report did not stage on its own: %+v", got)
	}
	if strings.Contains(listed.l.Status().Line, forkAsks) {
		t.Fatal("the no-attestor line shows with an attestor listed")
	}
	// On the project's own chain the line never shows.
	own := newRig(t)
	own.allow = nil
	own.l = own.newLoop()
	own.release(2, func(m *update.Manifest) { m.Security = true })
	own.tick()
	if strings.Contains(own.l.Status().Line, forkAsks) || strings.Contains(own.l.Status().Line, "Following") {
		t.Fatalf("project box: %q", own.l.Status().Line)
	}
}

// A switch forgets what Loop 3 knew of the old chain's releases, so a
// fork release with a version the old chain already proposed is still
// asked about.
func TestOSS10SwitchForgetsTheOldChainsProposals(t *testing.T) {
	r := newRig(t)
	r.allow = nil
	r.l = r.newLoop()
	r.release(2, func(m *update.Manifest) { m.Security = true })
	r.tick()
	if len(r.p.proposed()) != 1 {
		t.Fatal("project release not asked")
	}
	r.followAs("Acme")
	r.clk.add(25 * time.Hour)
	r.refresh()
	r.tick()
	if n := len(r.p.proposed()); n != 2 {
		t.Fatalf("the fork's release 2 was not asked: %d proposals", n)
	}
}

// UX wording for the page, the alert and the evidence (OSS-9 Q-C).
func TestOSS9FollowWording(t *testing.T) {
	at := time.Date(2026, 10, 5, 13, 52, 0, 0, time.UTC)
	for got, want := range map[string]string{
		FollowPrompt("Acme", "AgentOS"):   "Follow Acme? After this, Acme decides what software I install, instead of AgentOS. Do this only if you trust Acme and got these details from them directly.",
		FollowCheckHeading("Acme"):        "Check these match what Acme published.",
		FollowNameLabel:                   "the name you gave it",
		FollowAlert("Acme", at):           "Updates now come from Acme, set on my Wi-Fi page at 13:52. Not you? Switch back there and change your codes.",
		EvidenceLine("Acme", 2, 1, true):  "Checked by 2 independent builders, by Acme, and rebuilt here to the same result.",
		EvidenceLine("Acme", 1, 0, false): "Checked by 1 independent builder.",
		EvidenceLine("Acme", 1, 0, true):  "Checked by 1 independent builder and rebuilt here to the same result.",
		EvidenceLine("Acme", 0, 1, true):  "No independent check yet; only Acme's own. Rebuilt here to the same result.",
		EvidenceLine("Acme", 0, 3, false): "No independent check yet; only Acme's own.",
		EvidenceLine("Acme", 0, 0, false): "No independent check yet; only Acme's own.",
	} {
		if got != want {
			t.Errorf("got  %q\nwant %q", got, want)
		}
	}
}

// On a fork, an ordinary release waiting for the owner says who checked
// it, counting only listed attestors (OSS-9, Q-A).
func TestOSS9ForkApprovalSaysWhoChecked(t *testing.T) {
	r := newRig(t)
	_, box, _ := ed25519.GenerateKey(nil) // the image-pinned test box
	r.interim = []ed25519.PublicKey{box.Public().(ed25519.PublicKey)}
	r.l = r.newLoop()
	src := r.followAs("Acme")
	r.release(2, nil)
	for i := 0; i < 8; i++ {
		r.tick()
		r.clk.add(24 * time.Hour)
		r.refresh()
	}
	r.attest()
	_, stranger, _ := ed25519.GenerateKey(nil)
	r.attestWith(stranger)
	r.attestWith(box)
	r.tick()
	if len(r.p.proposed()) != 1 {
		t.Fatal("not proposed")
	}
	want := "Update 2 has been waiting for your approval since Tue 13 Oct. Checked by 1 independent builder, by Acme. Following: Acme (" + src.Fingerprint[:8] + ")."
	if line := r.l.Status().Line; line != want {
		t.Fatalf("status %q\nwant %q", line, want)
	}
}
