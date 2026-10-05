package maintain

import (
	"strings"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/loops"
	"github.com/ghbmrk/agentos/broker/update"
)

// REQ: UPD-4, UPD-5
//
// Loop 3 reads the owner's update channel and cadence from the loop
// settings (UPD-c): the channel, the stable soak, and whether security
// fixes go to the owner.

func TestChannelNamesMatchUpdate(t *testing.T) {
	if loops.ChannelStable != update.ChannelStable || loops.ChannelFast != update.ChannelFast || ChannelPinned != loops.ChannelPinned {
		t.Fatal("loops and update name the channels differently")
	}
}

func TestOwnerSoakIsRead(t *testing.T) {
	r := newRig(t)
	r.settings.Updates.SoakDays = 14
	r.release(2, nil)
	r.attest()
	r.tick()
	for i := 0; i < 7; i++ {
		r.clk.add(24 * time.Hour)
		r.refresh()
		r.tick()
	}
	if len(r.p.proposed()) != 0 {
		t.Fatal("proposed after 7 days with a 14-day soak")
	}
	if d := r.digest(); !strings.Contains(d, "Update 2") || !strings.Contains(d, "Mon 19 Oct") {
		t.Fatalf("digest: %q", d)
	}
	for i := 0; i < 7; i++ {
		r.clk.add(24 * time.Hour)
		r.refresh()
		r.tick()
	}
	if got := r.p.proposed(); len(got) != 1 || got[0].Version() != "2" {
		t.Fatalf("after 14 days: %+v", got)
	}
}

func TestChannelChangeTakesEffectAtTheNextCheck(t *testing.T) {
	r := newRig(t)
	r.settings.Updates.Channel = loops.ChannelPinned
	r.release(2, func(m *update.Manifest) { m.Channel = update.ChannelFast })
	r.tick()
	if len(r.p.proposed()) != 0 {
		t.Fatal("pinned box proposed")
	}
	r.settings.Updates.Channel = loops.ChannelFast
	r.clk.add(25 * time.Hour)
	r.refresh()
	r.tick()
	if got := r.p.proposed(); len(got) != 1 || got[0].Version() != "2" {
		t.Fatalf("after UPDATES FAST: %+v", got)
	}
}

// SECURITY UPDATES ASK: an attested security fix goes to the owner at
// once, without staging on its own and without waiting for a report.
func TestSecurityAskSendsSecurityFixesToTheOwner(t *testing.T) {
	for name, attested := range map[string]bool{"attested": true, "unattested": false} {
		r := newRig(t)
		r.settings.Updates.SecurityAsk = true
		r.release(2, func(m *update.Manifest) { m.Security = true })
		if attested {
			r.attest()
		}
		r.tick()
		got := r.p.proposed()
		if len(got) != 1 || got[0].Version() != "2" || got[0].Security() {
			t.Fatalf("%s: proposed %+v", name, got)
		}
		if st := r.l.Status(); st.Current || !strings.Contains(st.Line, "Security update 2 needs your approval") {
			t.Fatalf("%s: status %q", name, st.Line)
		}
	}
}

// A pinned box's notice says how to take the fix.
func TestPinnedNoticeSaysHowToTakeUpdates(t *testing.T) {
	r := newRig(t)
	r.settings.Updates.Channel = loops.ChannelPinned
	r.release(2, func(m *update.Manifest) { m.Security = true })
	r.tick()
	if d := r.digest(); !strings.Contains(d, "Reply UPDATES STABLE to take it and later tested releases") {
		t.Fatalf("digest: %q", d)
	}
	if st := r.l.Status(); !strings.Contains(st.Line, "Reply UPDATES STABLE") {
		t.Fatalf("status: %q", st.Line)
	}
}
