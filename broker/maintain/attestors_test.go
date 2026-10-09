package maintain

// REQ: UPD-8, SR3-6f-1a, SR3-6f-1b, SR3-6-f4b, SR3-6-f4c
// SR3-6f-1 (Security 4a S1 on #430): one attestor source, read once at the
// start of each check and by AttestorsChanged, so an owner's narrowing is
// not undone by the next check.

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/change"
	"github.com/ghbmrk/agentos/broker/update"
)

// countSource counts mirror opens, so a test can tell that no Check ran.
type countSource struct {
	update.Source
	n *atomic.Int32
}

func (c countSource) Open(p string) (io.ReadCloser, error) { c.n.Add(1); return c.Source.Open(p) }

// twoAttestors lists a second attestor b beside the rig's a, and attests
// security fix 2 from both.
func twoAttestors(r *rig) {
	r.t.Helper()
	_, b, _ := ed25519.GenerateKey(rand.Reader)
	r.allow = append(r.allow, b.Public().(ed25519.PublicKey))
	r.release(2, func(m *update.Manifest) { m.Security = true })
	r.attest()
	r.attestWith(b)
}

func TestOwnerNarrowingSurvivesTheNextCheck(t *testing.T) {
	r := newRig(t)
	twoAttestors(r)
	r.tick()
	got := r.p.proposed()
	if len(got) != 1 || !got[0].Security() {
		t.Fatalf("not proposed as attested security: %+v", got)
	}
	old := got[0]

	// The owner removes a; b's report alone still passes, but the release
	// checked under {a, b} loses its authority.
	r.allow = r.allow[1:]
	r.must(r.l.AttestorsChanged())
	if old.Security() {
		t.Fatal("AttestorsChanged did not retire the authority granted under {a, b}")
	}
	r.clk.add(time.Hour)
	r.l.st.Next = time.Time{}
	r.tick()
	if old.Security() {
		t.Fatal("the next Loop 3 check restored the authority the owner's narrowing retired")
	}
	// The narrowing retired the claim (SR3-6-f4b), so the check decided
	// the fix again: b's report may stage it, a's never counts.
	again := r.p.proposed()[1:]
	if len(again) == 0 {
		t.Fatal("the retired claim was not decided again")
	}
	for _, v := range again {
		if n := v.IndependentPasses(r.atts[:1], r.l.cfg.OwnKey); n != 0 {
			t.Fatalf("Loop 3 counted the removed attestor's report after the narrowing: %d", n)
		}
	}
}

func TestAttestorSourceErrorFailsClosed(t *testing.T) {
	r := newRig(t)
	twoAttestors(r)
	var n atomic.Int32
	r.mirrors = []update.Source{countSource{update.DirSource(r.repo.Dir), &n}}
	r.attErr = errors.New("settings unreadable")
	r.tick()
	if n.Load() != 0 {
		t.Fatalf("Store.Check ran %d mirror reads with no attestor list", n.Load())
	}
	if got := r.p.proposed(); len(got) != 0 {
		t.Fatalf("scheduled %+v without an attestor list", got)
	}
	if st := r.l.Status(); st.Current || !strings.Contains(st.Line, "could not check: my list of trusted testers could not be read") {
		t.Fatalf("status: %q", st.Line)
	}
	if !r.l.Urgent() {
		t.Fatal("a failed attestor read is not retried as a failed check")
	}

	// Once readable, the check runs and the fix stages on its reports.
	r.attErr = nil
	r.clk.add(time.Hour)
	r.tick()
	if got := r.p.proposed(); len(got) != 1 || !got[0].Security() {
		t.Fatalf("after recovery: %+v", got)
	}
}

func TestAttestorSourceErrorKeepsOlderAuthorityRetired(t *testing.T) {
	r := newRig(t)
	twoAttestors(r)
	r.tick()
	old := r.p.proposed()[0]
	r.allow = r.allow[1:]
	r.must(r.l.AttestorsChanged())
	// A failed read neither checks nor notes a list, so nothing widens.
	r.allow = append(r.allow, r.attestor.Public().(ed25519.PublicKey))
	r.attErr = errors.New("settings unreadable")
	r.clk.add(time.Hour)
	r.l.st.Next = time.Time{}
	r.tick()
	if err := r.l.AttestorsChanged(); err == nil {
		t.Fatal("AttestorsChanged hid the read error")
	}
	if old.Security() {
		t.Fatal("a failed attestor read restored retired authority")
	}
}

func TestAttestorsChangedNotesThePolicy(t *testing.T) {
	r := newRig(t)
	twoAttestors(r)
	r.tick()
	old := r.p.proposed()[0]
	if !old.Security() {
		t.Fatal("not proposed as attested security")
	}
	r.allow = r.allow[:1]
	r.must(r.l.AttestorsChanged())
	if old.Security() {
		t.Fatal("a narrowed list noted by AttestorsChanged left the old release its authority")
	}
}

func TestAttestorsChangedReadErrorNarrows(t *testing.T) {
	// A read error at a change notes no attestor at all: it can only
	// narrow, never keep a list the owner may have just removed.
	r := newRig(t)
	twoAttestors(r)
	r.tick()
	old := r.p.proposed()[0]
	r.attErr = errors.New("settings unreadable")
	if err := r.l.AttestorsChanged(); err == nil {
		t.Fatal("AttestorsChanged hid the read error")
	}
	if old.Security() {
		t.Fatal("a failed read at a change kept the old authority")
	}
}

func TestNoAttestorSourceOnlyNarrows(t *testing.T) {
	// No source: today's no-attestor behaviour, the owner's path.
	r := newRig(t)
	r.noSource = true
	r.l = r.newLoop()
	r.release(2, func(m *update.Manifest) { m.Security = true })
	r.attest()
	r.tick()
	got := r.p.proposed()
	if len(got) != 1 || got[0].Security() {
		t.Fatalf("proposed %+v", got)
	}
	r.must(r.l.AttestorsChanged())
}

func TestNarrowingDuringACheckIsNotUndone(t *testing.T) {
	// The owner narrows while a check, which read {a, b}, is between its
	// read and its Store.Check calls: the check must not write {a, b}
	// back over the narrowing.
	r := newRig(t)
	twoAttestors(r)
	r.tick()
	old := r.p.proposed()[0]

	entered, release := make(chan struct{}), make(chan struct{})
	var once atomic.Bool
	mirrors := r.mirrors
	r.l.cfg.Mirrors = func() []update.Source {
		if once.CompareAndSwap(false, true) {
			close(entered)
			<-release
		}
		return mirrors
	}
	r.clk.add(time.Hour)
	r.l.st.Next = time.Time{}
	job, ok := r.l.Next(context.Background(), true)
	if !ok {
		t.Fatal("no check offered")
	}
	checked := make(chan struct{})
	go func() { job.Run(context.Background()); close(checked) }()
	<-entered

	r.allow = r.allow[1:]
	changed := make(chan error, 1)
	go func() { changed <- r.l.AttestorsChanged() }()
	select {
	case err := <-changed: // not serialized with the check
		changed <- err
	case <-time.After(200 * time.Millisecond):
	}
	close(release)
	<-checked
	r.must(<-changed)
	if old.Security() {
		t.Fatal("a check that read the list before the owner's narrowing undid it")
	}
}

// SR3-6-f4b (UX and Potency lens on #595, point 1): a narrowing makes the
// next check due at once and retires the adopted claim that rested on the
// removed attestor, so STATUS stops saying an independent tester passed.
func TestNarrowingRetiresTheAdoptedClaim(t *testing.T) {
	r := newRig(t)
	r.p.state = change.StateAdopted
	r.release(2, func(m *update.Manifest) { m.Security = true })
	r.attest()
	r.tick()
	const passed = "An independent tester's report passed."
	if line := r.l.Status().Line; line != "Security update 2 is ready and installs at the next quiet time. "+passed {
		t.Fatalf("status before the narrowing: %q", line)
	}

	r.p.state = ""
	r.allow = nil
	r.must(r.l.AttestorsChanged())
	if !r.l.Urgent() {
		t.Fatal("a narrowing did not make a check urgent")
	}
	if _, ok := r.l.Next(context.Background(), true); !ok {
		t.Fatal("a narrowing did not make a check due")
	}
	r.tick()
	if line := r.l.Status().Line; strings.Contains(line, passed) {
		t.Fatalf("status after the narrowing still claims the removed tester's pass: %q", line)
	}
	if _, ok := r.l.st.TestedBy[2]; ok {
		t.Fatalf("TestedBy kept the retired claim: %v", r.l.st.TestedBy)
	}
	if r.l.Urgent() {
		t.Fatal("still urgent after the check that followed the narrowing")
	}
}

// SR3-6-f4c (Security point 3 and L3 point 1 on #595): an unreadable list
// reads as none listed in STATUS, so on a fork the owner is told each
// security fix is theirs to approve. Kills listed()'s fail-open mutant.
func TestAttestorSourceErrorStatusReadsAsNoneListed(t *testing.T) {
	r := newRig(t)
	r.followAs("Acme")
	r.attErr = errors.New("settings unreadable")
	r.tick()
	if line := r.l.Status().Line; !strings.Contains(line, forkAsks) {
		t.Fatalf("an unreadable attestor list read as listed: %q", line)
	}
	if d := r.digest(); !strings.Contains(d, forkAsks) {
		t.Fatalf("digest: %q", d)
	}
}

// SR3-6-f4b: a narrowing that lands after a check read the list, before
// it records anything, leaves the next check due, so what that check
// decides under the old list is judged again under the narrowed one.
func TestNarrowingAfterTheReadKeepsTheRecheckDue(t *testing.T) {
	r := newRig(t)
	r.release(2, func(m *update.Manifest) { m.Security = true })
	r.attest()
	job, ok := r.l.Next(context.Background(), true)
	if !ok {
		t.Fatal("no check offered")
	}
	// Block the check at its first clock read outside the policy lock:
	// after its attestor read and Store.Check calls, before it records.
	entered, release := make(chan struct{}), make(chan struct{})
	var once atomic.Bool
	r.l.cfg.Now = func() time.Time {
		if r.l.policy.TryLock() {
			r.l.policy.Unlock()
			if once.CompareAndSwap(false, true) {
				close(entered)
				<-release
			}
		}
		return r.clk.now()
	}
	checked := make(chan struct{})
	go func() { job.Run(context.Background()); close(checked) }()
	<-entered
	r.allow = nil
	r.must(r.l.AttestorsChanged())
	close(release)
	<-checked
	if !r.l.Urgent() {
		t.Fatal("a check that read the list before a narrowing cleared the recheck it asked for")
	}
	if _, ok := r.l.Next(context.Background(), true); !ok {
		t.Fatal("no check due after a narrowing during a check")
	}
}
