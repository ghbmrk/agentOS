package localsrv

import (
	"strings"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/localapi"
	"github.com/ghbmrk/agentos/broker/owner"
)

// REQ: CH-1, CH-7, CH-19

const simTag = "0123456789abcdef"

func (r *rig) adopt(tok, sim, c string) (localapi.Answered, error) {
	r.t.Helper()
	out, err := r.call(localapi.OpSIM, localapi.AdoptSIM{Token: tok, SIM: sim, Code: c})
	if err != nil {
		return localapi.Answered{}, err
	}
	return out.(localapi.Answered), nil
}

// P2-2w d2b, CH-19: adopting a SIM re-opens the owner channel on its line,
// so it always takes a code-generator code or the grid cell, even just
// after signing in: a SIM swapper, or anyone holding a stolen session,
// holds no such code. A wrong code counts toward the socket's limit and
// the day's tries, as any code does.
func TestAdoptingASIMAlwaysTakesACode(t *testing.T) {
	r := newRig(t)
	tok := r.signIn()
	signIns := r.own.signIns
	if a, err := r.adopt(tok, simTag, ""); err != nil || a.Refusal != localapi.RefusedCodeNeeded || len(r.adopted) != 0 || r.own.signIns != signIns {
		t.Fatalf("no code, fresh session: %+v %v", a, err)
	}
	for i := 0; i < WrongPerMinute; i++ {
		if a, err := r.adopt(tok, simTag, "000000"); err != nil || a.Refusal != localapi.RefusedWrongCode || len(r.adopted) != 0 {
			t.Fatalf("wrong code %d: %+v %v", i, a, err)
		}
	}
	if _, err := r.adopt(tok, simTag, good); code(err) != localapi.ErrLimited || len(r.adopted) != 0 {
		t.Fatalf("past the limit: %v", err)
	}
	r.now = r.now.Add(time.Minute)
	a, err := r.adopt(tok, simTag, good)
	if err != nil || a.Refusal != "" || len(r.adopted) != 1 || r.adopted[0] != simTag {
		t.Fatalf("good code: %+v %v %v", a, err, r.adopted)
	}
	if a.Text != "Done. I'll use that SIM for my number. Texts with you start again within a minute." {
		t.Fatalf("reply: %q", a.Text)
	}
}

// The vault unlock's sign-in proof is not a code the owner holds in hand
// (it passes through the page), so it cannot adopt a SIM.
func TestAnUnlockProofCannotAdoptASIM(t *testing.T) {
	r := newRig(t)
	tok := r.signIn()
	signIns := r.own.signIns
	if _, err := r.adopt(tok, simTag, owner.UnlockProofPrefix+"ticket"); code(err) != localapi.ErrBadArgs || len(r.adopted) != 0 || r.own.signIns != signIns {
		t.Fatalf("unlock proof: %v", err)
	}
}

// A SIM changed since the page showed it, or a tag that is not one, is
// refused; the good code is still spent as a sign-in.
func TestAStaleOrBadSIMTagIsRefused(t *testing.T) {
	r := newRig(t)
	tok := r.signIn()
	if a, err := r.adopt(tok, "fedcba9876543210", good); err != nil || a.Refusal != localapi.RefusedChanged || len(r.adopted) != 0 {
		t.Fatalf("stale tag: %+v %v", a, err)
	}
	for _, bad := range []string{"", "0123456789ABCDEF", "0123", strings.Repeat("0", localapi.SIMLen+1)} {
		if _, err := r.adopt(tok, bad, good); code(err) != localapi.ErrBadArgs {
			t.Errorf("tag %q: %v", bad, err)
		}
	}
	if _, err := r.adopt(tok, simTag, strings.Repeat("1", localapi.MaxCode+1)); code(err) != localapi.ErrBadArgs {
		t.Fatalf("long code: %v", err)
	}
	// No modem bridge: nothing to adopt with.
	r.srv.cfg.AdoptSIM = nil
	if _, err := r.adopt(tok, simTag, good); code(err) != localapi.ErrFailed {
		t.Fatalf("no bridge: %v", err)
	}
}

// Security D1: the SIM to adopt goes only to a signed-in page.
func TestTheSIMToAdoptNeedsAToken(t *testing.T) {
	r := newRig(t)
	r.srv.cfg.Line = func() localapi.Line { return localapi.Line{Note: "n", SIM: simTag, SIMEnds: "2345"} }
	out, err := r.call(localapi.OpStatus, struct{}{})
	if err != nil {
		t.Fatal(err)
	}
	if st := out.(localapi.Status); st.LineNote != "n" {
		t.Fatalf("status: %+v", st)
	}
	out, err = r.call(localapi.OpLine, localapi.Auth{Token: r.signIn()})
	if err != nil || out.(localapi.Line).SIMEnds != "2345" {
		t.Fatalf("line: %+v %v", out, err)
	}
}
