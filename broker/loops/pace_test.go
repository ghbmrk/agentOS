package loops

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/change"
	"github.com/ghbmrk/agentos/broker/journal"
	"github.com/ghbmrk/agentos/broker/modem"
	ownerch "github.com/ghbmrk/agentos/broker/owner"
)

// paceEngine is the least control.Engine an owner channel needs.
type paceEngine struct{}

func (paceEngine) Stop(context.Context) (journal.StopReport, error) {
	return journal.StopReport{}, nil
}
func (paceEngine) Resume() error          { return nil }
func (paceEngine) Stopped() bool          { return false }
func (paceEngine) List() []journal.Status { return nil }

// pacedGuard is a guard rig whose texts go through a real owner channel
// with quiet hours 22 to 7, wired as agentosd wires it: urgent texts as
// security, the rest as updates, "Cleared" texts with their keys and the
// guard's Current as the hold's hook.
func pacedGuard(t *testing.T, b *box) (*guardRig, *ownerch.Channel, func() []string) {
	t.Helper()
	r := &guardRig{b: b, p: newPipe(t), c: &contain{}, store: &change.MemStore{}, now: t0}
	carrier := modem.NewCarrier()
	carrier.SetClock(func() time.Time { return r.now })
	phone := carrier.Line("+15550000001")
	st := &ownerch.MemStore{}
	if err := st.Save(ownerch.State{Pacing: ownerch.Pacing{QuietFrom: 22 * 60, QuietTo: 7 * 60}}); err != nil {
		t.Fatal(err)
	}
	ch, err := ownerch.New(ownerch.Config{
		Owner: "+15550000001", Modem: carrier.Line("+15550000100"), Engine: paceEngine{}, Store: st,
		Secrets:  ownerch.Secrets{TOTPSeed: []byte("12345678901234567890"), GridSeed: []byte("synthetic-grid-seed")},
		Location: time.UTC, Now: func() time.Time { return r.now },
	})
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	sent := func() []string {
		for {
			select {
			case m := <-phone.Inbox():
				got = append(got, m.Text)
			default:
				return got
			}
		}
	}
	r.notifyTo = func(text string, urgent bool) {
		class := ownerch.ClassUpdate
		if urgent {
			class = ownerch.ClassSecurity
		}
		r.texts, r.urgent = append(r.texts, text), append(r.urgent, urgent)
		must(t, ch.Post(class, text))
	}
	r.clearTo = func(text string, keys []string) {
		r.texts, r.urgent = append(r.texts, text), append(r.urgent, false)
		must(t, ch.PostAbout(ownerch.ClassUpdate, text, keys))
	}
	r.reopen(t)
	ch.SetCurrent(r.g.Current)
	return r, ch, sent
}

// REQ: OWN-4, CH-15 (PACE-1 PC-4, PC-5)
func TestStaleClearedNeverFollowsTheReturnAlert(t *testing.T) {
	// 03:00, inside quiet hours: alerts go at once, "Cleared" waits.
	b := cleanBox()
	b.live["config/quiet.json"] = "edited"
	r, ch, sent := pacedGuard(t, b)
	r.pass(t)
	b.live["config/quiet.json"] = "c1"
	r.pass(t)
	b.live["config/quiet.json"] = "edited"
	r.pass(t)
	got := sent()
	if len(got) != 2 || !strings.Contains(got[0], "Setting file config/quiet.json") || !strings.Contains(got[1], "It is back: ") {
		t.Fatalf("owner got %q, want the alert and the return, at once", got)
	}
	// Quiet hours end with the finding still open: the held "Cleared"
	// is no longer true and is never sent.
	r.now = r.now.Add(4*time.Hour + time.Minute) // 07:01
	must(t, ch.Release())
	if got := sent(); len(got) != 2 {
		t.Fatalf("owner got %q after the hold released, want no stale Cleared", got)
	}
	// It clears again: that "Cleared" is true and goes, so the owner's
	// last text is not "it is back" (PC-5).
	b.live["config/quiet.json"] = "c1"
	r.pass(t)
	got = sent()
	if len(got) != 3 || !strings.Contains(got[2], "Cleared: config/quiet.json.") {
		t.Fatalf("owner got %q, want the second Cleared last", got)
	}
}

// REQ: OWN-4 (PACE-1 PC-7)
func TestClearedGoesApartFromOtherNotices(t *testing.T) {
	b := cleanBox()
	b.expiries = []Expiry{{Name: "mail-oauth", NotAfter: t0.Add(-time.Hour)}}
	r := newGuardRig(t, b)
	var clears []string
	var keys [][]string
	r.clearTo = func(text string, k []string) { clears, keys = append(clears, text), append(keys, k) }
	r.reopen(t)
	r.pass(t)
	if len(r.texts) != 1 || r.urgent[0] || !strings.Contains(r.texts[0], "mail-oauth") {
		t.Fatalf("texts %q urgent %v, want one non-urgent expiry alert", r.texts, r.urgent)
	}
	// In one pass mail-oauth is renewed and another credential
	// expires: the alert goes as before, the "Cleared" apart with its key,
	// so the hold dropping it can never drop the alert.
	b.expiries = []Expiry{{Name: "mail-oauth", NotAfter: t0.Add(90 * 24 * time.Hour)}, {Name: "vpn-cert", NotAfter: t0.Add(-time.Hour)}}
	r.pass(t)
	if len(r.texts) != 2 || r.urgent[1] || !strings.Contains(r.texts[1], "vpn-cert") || strings.Contains(r.texts[1], "Cleared") {
		t.Fatalf("texts %q, want the vpn-cert alert alone", r.texts)
	}
	if len(clears) != 1 || !strings.Contains(clears[0], "Cleared: mail-oauth") || len(keys[0]) != 1 {
		t.Fatalf("clears %q keys %q, want mail-oauth's with its one key", clears, keys)
	}
	if r.g.Current(keys[0]) != true {
		t.Fatal("a closed key reads as not current")
	}
	b.expiries[0].NotAfter = t0.Add(-time.Hour)
	r.pass(t)
	if r.g.Current(keys[0]) {
		t.Fatal("a reopened key reads as current")
	}
}
