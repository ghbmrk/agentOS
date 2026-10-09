package maintain

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/change"
	"github.com/ghbmrk/agentos/broker/update"
)

// REQ: UPD-1, UPD-5, UPD-8, CH-12, SR3-4f-2-r1a, SR3-4f-2-r1b, SR3-4f-2-r1c, SR3-4f-2-r1d

// adoptedFast has release 2 on the fast channel adopted by the pipeline
// as c1 at the first check.
func adoptedFast(t *testing.T) *rig {
	t.Helper()
	r := newRig(t)
	r.p.state = change.StateAdopted
	r.settings.Updates.Channel = update.ChannelFast
	r.release(2, func(m *update.Manifest) { m.Channel = update.ChannelFast })
	r.tick()
	if n := len(r.p.proposed()); n != 1 {
		t.Fatalf("proposed %d times", n)
	}
	return r
}

// nextCheck runs the next daily check.
func (r *rig) nextCheck() {
	r.clk.add(24 * time.Hour)
	r.refresh()
	r.tick()
}

func dropped(a *change.Adoption) { a.Staged, a.Reverted = false, change.WhyDropped }

// A staged adoption the applier dropped (a narrowing, a supersede, a
// refusal, a restart) is offered again at the next check, under a new ID.
func TestDroppedAdoptionReofferedAtNextCheck(t *testing.T) {
	r := adoptedFast(t)
	r.p.adopt("c1", dropped)
	r.nextCheck()
	if n := len(r.p.proposed()); n != 2 {
		t.Fatalf("dropped release proposed %d times", n)
	}
	r.p.adopt("c2", nil)
	r.nextCheck()
	if n := len(r.p.proposed()); n != 2 {
		t.Fatalf("staged re-offer proposed again: %d times", n)
	}
	if st := r.l.Status(); !strings.Contains(st.Line, "Update 2 is ready and installs at the next quiet time.") {
		t.Fatalf("status after the re-offer: %q", st.Line)
	}
}

func TestDroppedSecurityFixReofferedAtNextCheck(t *testing.T) {
	r := newRig(t)
	r.p.state = change.StateAdopted
	r.release(2, func(m *update.Manifest) { m.Security = true })
	r.attest()
	r.tick()
	r.p.adopt("c1", dropped)
	r.nextCheck()
	got := r.p.proposed()
	if len(got) != 2 || !got[1].Security() {
		t.Fatalf("dropped security fix: proposed %d times", len(got))
	}
}

// Only a drop is offered again: not an adoption the owner undid, Recheck
// reverted or that fell back, and not one still staged or confirmed.
func TestRevertedNotDroppedIsNotReoffered(t *testing.T) {
	for name, f := range map[string]func(*change.Adoption){
		"owner":      func(a *change.Adoption) { a.Staged, a.Reverted = false, change.WhyOwner },
		"security":   func(a *change.Adoption) { a.Staged, a.Reverted = false, change.WhySecurity },
		"regression": func(a *change.Adoption) { a.Staged, a.Reverted = false, change.WhyRegression },
		"fallback":   func(a *change.Adoption) { a.Staged, a.Reverted = false, change.WhyFallback },
		"staged":     nil,
		"confirmed":  func(a *change.Adoption) { a.Staged, a.Confirmed = false, true },
	} {
		r := adoptedFast(t)
		r.p.adopt("c1", f)
		r.nextCheck()
		if n := len(r.p.proposed()); n != 1 {
			t.Fatalf("%s: proposed %d times", name, n)
		}
		if st := r.l.Status(); strings.Contains(st.Line, "offer it again") {
			t.Fatalf("%s: status %q", name, st.Line)
		}
	}
}

// The drop is matched by the saved proposal ID: the old c1 still reads
// dropped after the re-offer c2 is staged, and offers nothing more.
func TestStaleDropIsNotReofferedAgain(t *testing.T) {
	r := adoptedFast(t)
	r.p.adopt("c1", dropped)
	r.nextCheck()
	r.p.adopt("c2", nil)
	for d := 0; d < 2; d++ {
		r.nextCheck()
	}
	if n := len(r.p.proposed()); n != 2 {
		t.Fatalf("a stale drop re-offered: proposed %d times", n)
	}
}

// The re-offer's authority is decided afresh: with no attestor listed
// now, the security fix goes to the owner, and nothing of the dropped
// adoption's record carries over into the line.
func TestDroppedSecurityFixGoesToTheOwnerWithoutAnAttestor(t *testing.T) {
	r := newRig(t)
	r.p.state = change.StateAdopted
	r.release(2, func(m *update.Manifest) { m.Security = true })
	r.attest()
	r.tick()
	r.p.adopt("c1", dropped)
	r.allow = nil
	r.p.state = change.StateAwaitingOwner
	r.nextCheck()
	got := r.p.proposed()
	if len(got) != 2 || got[1].Security() {
		t.Fatalf("re-offer: %d proposals, security authority %v", len(got), len(got) == 2 && got[1].Security())
	}
	want := "Security update 2 needs your approval: no trusted independent test report yet. Asked " + r.clk.now().Format("Mon 2 Jan")
	if st := r.l.Status(); !strings.Contains(st.Line, want) {
		t.Fatalf("status %q, want %q", st.Line, want)
	}
}

// Between the drop and the next check, the owner is told the release was
// not installed and will be offered again; no check comes before the
// daily one.
func TestDroppedReleaseLine(t *testing.T) {
	r := adoptedFast(t)
	r.p.adopt("c1", dropped)
	const want = "Update 2 was not installed; I will offer it again."
	if st := r.l.Status(); st.Line != want {
		t.Fatalf("status %q, want %q", st.Line, want)
	}
	if d := r.digest(); !strings.Contains(d, want) || strings.Contains(d, "ready and installs") {
		t.Fatalf("digest %q", d)
	}
	r.clk.add(time.Hour)
	if _, ok := r.l.Next(context.Background(), true); ok {
		t.Fatal("a check before the daily one")
	}
	if n := len(r.p.proposed()); n != 1 {
		t.Fatalf("proposed %d times", n)
	}
}
