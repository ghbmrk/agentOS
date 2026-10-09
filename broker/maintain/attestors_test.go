package maintain

// REQ: UPD-8, SR3-6f-1a, SR3-6f-1b
// SR3-6f-1 (Security 4a S1 on #430): one attestor source, read once at the
// start of each check and by AttestorsChanged, so an owner's narrowing is
// not undone by the next check.

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"
	"strings"
	"sync/atomic"
	"testing"
	"time"

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
	for _, v := range r.p.proposed()[1:] {
		if v.Security() {
			t.Fatal("Loop 3 scheduled a release as security under the old list")
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
