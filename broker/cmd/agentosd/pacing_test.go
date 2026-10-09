package main

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/grants"
	"github.com/ghbmrk/agentos/broker/journal"
	"github.com/ghbmrk/agentos/broker/modem"
	ownerch "github.com/ghbmrk/agentos/broker/owner"
)

// pacingEngine is the least control.Engine an owner channel needs.
type pacingEngine struct{}

func (pacingEngine) Stop(context.Context) (journal.StopReport, error) {
	return journal.StopReport{}, nil
}
func (pacingEngine) Resume() error          { return nil }
func (pacingEngine) Stopped() bool          { return false }
func (pacingEngine) List() []journal.Status { return nil }

// pacedOwnerRig is a real owner channel with a pacing setting saved, on a
// fake carrier and a clock the test moves.
type pacedOwnerRig struct {
	t     *testing.T
	mu    sync.Mutex
	now   time.Time
	phone *modem.Line
	ch    *ownerch.Channel
}

func pacedOwner(t *testing.T, p ownerch.Pacing, now time.Time) *pacedOwnerRig {
	t.Helper()
	r := &pacedOwnerRig{t: t, now: now}
	carrier := modem.NewCarrier()
	carrier.SetClock(r.clock)
	box := carrier.Line("+15550000100")
	r.phone = carrier.Line(ownerNum)
	st := &ownerch.MemStore{}
	if err := st.Save(ownerch.State{Pacing: p}); err != nil {
		t.Fatal(err)
	}
	ch, err := ownerch.New(ownerch.Config{
		Owner: ownerNum, Modem: box, Engine: pacingEngine{}, Store: st,
		Secrets:  ownerch.Secrets{TOTPSeed: []byte("12345678901234567890"), GridSeed: []byte("synthetic-grid-seed")},
		Location: time.UTC, Now: r.clock,
	})
	if err != nil {
		t.Fatal(err)
	}
	r.ch = ch
	return r
}

func (r *pacedOwnerRig) clock() time.Time { r.mu.Lock(); defer r.mu.Unlock(); return r.now }

func (r *pacedOwnerRig) set(t time.Time) { r.mu.Lock(); r.now = t; r.mu.Unlock() }

// sent drains the texts the owner's phone has received so far.
func (r *pacedOwnerRig) sent() []string {
	var out []string
	for {
		select {
		case m := <-r.phone.Inbox():
			out = append(out, m.Text)
		default:
			return out
		}
	}
}

// pacer is the agentosd pacer over this channel, as main attaches it.
func (r *pacedOwnerRig) pacer() *ownerPacer {
	p := &ownerPacer{}
	p.ch.Store(r.ch)
	return p
}

// at23 is 23:00 on day0, inside quiet22to7.
var at23 = day0.Add(23 * time.Hour)

func quiet22to7(urgent ...ownerch.Class) ownerch.Pacing {
	return ownerch.Pacing{QuietFrom: 22 * 60, QuietTo: 7 * 60, Urgent: urgent}
}

// REQ: CH-15 (W5-Dc-r1b QH-8)

// TestGrantsWiringReadsTheOwner: the grants Config agentosd builds reads
// the owner channel's own setting and its one hourly budget; until the
// channel is attached, nothing paced goes.
func TestGrantsWiringReadsTheOwner(t *testing.T) {
	p := &ownerPacer{}
	var cfg grants.Config
	p.wire(&cfg)
	if cfg.Quiet == nil || cfg.Urgent == nil || cfg.Allowance == nil {
		t.Fatal("grants hooks not wired")
	}
	if cfg.Allowance(at23) != 0 || cfg.Urgent(ownerch.Item{}) {
		t.Fatal("before attach: paced texts may go")
	}
	r := pacedOwner(t, quiet22to7(), at23)
	p.ch.Store(r.ch)
	if !cfg.Quiet(at23) || cfg.Quiet(at23.Add(8*time.Hour)) {
		t.Fatal("Quiet does not read the owner's quiet hours")
	}
	if cfg.Urgent(ownerch.Item{}) {
		t.Fatal("approval urgent by default")
	}
	day := at23.Add(10 * time.Hour)
	r.set(day)
	if got := cfg.Allowance(day); got != 3 {
		t.Fatalf("allowance %d, want the owner's 3", got)
	}
	if err := r.ch.Inform("Update."); err != nil {
		t.Fatal(err)
	}
	if got := cfg.Allowance(day); got != 2 {
		t.Fatalf("allowance after an update %d, want 2: one budget", got)
	}
	u := pacedOwner(t, quiet22to7(ownerch.ClassApproval), at23)
	p.ch.Store(u.ch)
	if !cfg.Urgent(ownerch.Item{}) {
		t.Fatal("URGENT approval ON not read")
	}
}

// REQ: CH-15 (W5-Dc-r1b QH-9)

// TestCallersUseTheirClass: in quiet hours, a loops urgent security text
// and a fork-switch alert go at once; a loops report, a forget done text,
// an agent reply and a recall take-back notice are held, the last two
// unless the owner made their class urgent.
func TestCallersUseTheirClass(t *testing.T) {
	r := pacedOwner(t, quiet22to7(), at23)
	var ln loop2Notify
	ln.ch.Store(r.ch)
	ln.send("Security checks: a machine is contained.", true)
	if got := r.sent(); len(got) != 1 || !strings.Contains(got[0], "contained") {
		t.Fatalf("loops urgent security text: %q", got)
	}
	fs := &followSetting{}
	fs.owner.Store(r.ch)
	if err := fs.alert(context.Background(), "Updates now come from another source. Not you? Switch back there and change your codes."); err != nil {
		t.Fatal(err)
	}
	if got := r.sent(); len(got) != 1 || !strings.Contains(got[0], "Not you?") {
		t.Fatalf("fork-switch alert: %q", got)
	}
	ln.send("Weekly report: nothing new.", false)
	if err := ln.try("Forget done."); err != nil {
		t.Fatal(err)
	}
	ev := &evidence{notify: r.ch.Notify, logf: t.Logf} // as evidence.attach wires it
	ev.send("agent", "Your invoice is drafted.")
	notice := recallNotify(func() *ownerch.Channel { return r.ch })
	if err := notice("Taken back: the agent's work since Monday."); err != nil {
		t.Fatal(err)
	}
	if got := r.sent(); len(got) != 0 {
		t.Fatalf("paced texts sent in quiet hours: %q", got)
	}

	// The owner's urgent classes let agent replies and recall notices
	// through, with the agent prefix.
	u := pacedOwner(t, quiet22to7(ownerch.ClassAgent, ownerch.ClassApproval), at23)
	ev = &evidence{notify: u.ch.Notify, logf: t.Logf}
	ev.send("agent", "Your invoice is drafted.")
	if err := recallNotify(func() *ownerch.Channel { return u.ch })("Taken back: the agent's work since Monday."); err != nil {
		t.Fatal(err)
	}
	got := u.sent()
	if len(got) != 2 || !strings.HasPrefix(got[0], ownerch.AgentPrefix) || !strings.HasPrefix(got[1], ownerch.AgentPrefix) {
		t.Fatalf("urgent agent and approval texts: %q", got)
	}
	// Without approval urgent, the recall notice is held even with agent
	// urgent: it is approval class, not agent.
	a := pacedOwner(t, quiet22to7(ownerch.ClassAgent), at23)
	if err := recallNotify(func() *ownerch.Channel { return a.ch })("Taken back."); err != nil {
		t.Fatal(err)
	}
	if got := a.sent(); len(got) != 0 {
		t.Fatalf("recall notice sent as agent class: %q", got)
	}
}

// REQ: CH-15 (W5-Dc-r1b QH-10)

// TestTickReleasesAndStatusSaysHeld: in quiet hours two updates are held
// and STATUS says so; at 07:00 the tick sends them as one text and the
// line is gone. Held past the allowance, the line names the rate; past
// the hold's cap, the drops.
func TestTickReleasesAndStatusSaysHeld(t *testing.T) {
	r := pacedOwner(t, quiet22to7(), at23)
	p := r.pacer()
	if l := p.note(); l != "" {
		t.Fatalf("STATUS line with nothing held: %q", l)
	}
	for _, s := range []string{"Update one.", "Update two."} {
		if err := r.ch.Inform(s); err != nil {
			t.Fatal(err)
		}
	}
	if l := p.note(); l != "2 texts held until 07:00 (quiet hours)." {
		t.Fatalf("STATUS line in quiet hours: %q", l)
	}
	p.tick()
	if got := r.sent(); len(got) != 0 {
		t.Fatalf("released in quiet hours: %q", got)
	}
	r.set(day0.AddDate(0, 0, 1).Add(7 * time.Hour))
	p.tick()
	got := r.sent()
	if len(got) != 1 || !strings.Contains(got[0], "Update one.") || !strings.Contains(got[0], "Update two.") ||
		strings.Index(got[0], "one") > strings.Index(got[0], "two") {
		t.Fatalf("released at 07:00: %q", got)
	}
	if l := p.note(); l != "" {
		t.Fatalf("STATUS line after release: %q", l)
	}

	// Held past the allowance, outside quiet hours.
	for _, s := range []string{"A.", "B.", "C."} {
		if err := r.ch.Inform(s); err != nil {
			t.Fatal(err)
		}
	}
	if l := p.note(); l != "1 text held: 3 an hour." {
		t.Fatalf("STATUS line past the allowance: %q", l)
	}

	// Past the hold's cap: the drops are said.
	d := pacedOwner(t, quiet22to7(), at23)
	for range ownerch.MaxHeld + 2 {
		if err := d.ch.Inform("Update."); err != nil {
			t.Fatal(err)
		}
	}
	if l := d.pacer().note(); l != "32 texts held until 07:00 (quiet hours). 2 earlier texts were dropped." {
		t.Fatalf("STATUS line past the cap: %q", l)
	}
}
