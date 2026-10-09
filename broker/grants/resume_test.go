package grants

import (
	"context"
	"errors"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/journal"
	"github.com/ghbmrk/agentos/broker/modem"
	"github.com/ghbmrk/agentos/broker/owner"
)

// REQ: CH-3, CH-10, OP-5, LOOP-9

// W5a-resume (Security R2 on #169): a paused grant is resumed only from
// the box's Wi-Fi page, with a fresh code-generator code bound to that
// grant and to the pause the page showed.

// pausedRule makes a pre-allowance and pauses it from Loop 2's origin, as
// agentosd's containment does; it returns the grant and the pause.
func pausedRule(r *rig, pause string) string {
	r.t.Helper()
	rule := r.grant(Spec{Account: "mail", Rule: &Rule{Action: "invoice.send", AmountCap: 15000, PerRecord: 5, PerDay: 50}})
	r.pause(rule, pause)
	return rule
}

func (r *rig) pause(id, pause string) {
	r.t.Helper()
	if st := r.submit(journal.Intent{ID: pause, Origin: OriginLoop2, Account: journal.BrokerAccount,
		Action: journal.ActionGrantPause, GrantRef: id, Executor: ExecutorName,
		Params: map[string]any{"finding": "advisory:f1"}}); st.State != journal.Succeeded {
		r.t.Fatalf("pause %s: %s", id, st.State)
	}
}

func (r *rig) paused(id string) bool {
	for _, gr := range r.g.Grants() {
		if gr.ID == id {
			return gr.Paused
		}
	}
	return false
}

func TestThePageListsPausedGrantsAndWhoPausedThem(t *testing.T) {
	r := newRig(t, nil)
	r.grant(mailGrant())
	rule := pausedRule(r, "loop2/pause/a1")
	if got := r.g.Narrow("PAUSE", "G1"); !strings.HasPrefix(got, "Paused G1.") {
		t.Fatal(got)
	}
	ps := r.g.Paused()
	if len(ps) != 2 || ps[0].ID != "G1" || ps[1].ID != rule {
		t.Fatalf("paused %+v", ps)
	}
	if ps[0].By != "you" || !strings.HasPrefix(ps[0].Pause, "owner/pause/G1/") || !strings.HasPrefix(ps[0].What, "Connect account mail") {
		t.Fatalf("owner's pause %+v", ps[0])
	}
	if ps[1].By != "Loop 2" || ps[1].Pause != "loop2/pause/a1" || !strings.Contains(ps[1].What, "invoice.send on mail") {
		t.Fatalf("Loop 2's pause %+v", ps[1])
	}
	r.open() // the pause and who made it survive a restart
	if ps2 := r.g.Paused(); len(ps2) != 2 || ps2[1] != ps[1] || ps2[0] != ps[0] {
		t.Fatalf("after restart %+v", ps2)
	}
}

// The page asks; the request names the grant, what it allows and the
// pause, so its sum binds the code to them; one page code resumes it.
func TestAResumeIsAskedOnThePageAndBoundToItsPause(t *testing.T) {
	var ended []string
	r := newRig(t, func(c *Config) { c.Unpaused = func(id string) { ended = append(ended, id) } })
	r.grant(mailGrant())
	rule := pausedRule(r, "loop2/pause/a1")
	id, err := r.g.AskResume(context.Background(), rule, "loop2/pause/a1")
	if err != nil {
		t.Fatal(err)
	}
	if st := r.state(id); st.State != journal.Pending || st.Intent.Origin != originLocal {
		t.Fatalf("ask: %s from %q", st.State, st.Intent.Origin)
	}
	// Asked again before it is answered: the same request, not another.
	if again, err := r.g.AskResume(context.Background(), rule, "loop2/pause/a1"); err != nil || again != id {
		t.Fatalf("second ask %q %v", again, err)
	}
	r.g.Flush()
	_, items := r.own.last(t)
	if len(items) != 1 || items[0].Object != "resume "+rule || !strings.Contains(items[0].Detail, "invoice.send on mail") ||
		!strings.Contains(items[0].Detail, "Paused by Loop 2 (loop2/pause/a1).") {
		t.Fatalf("asked %+v", items)
	}
	r.pageDecide("")
	if st := r.state(id); st.State != journal.Succeeded || r.paused(rule) || len(ended) != 1 || ended[0] != rule {
		t.Fatalf("resume: %s paused=%v ended=%v", st.State, r.paused(rule), ended)
	}
	if ps := r.g.Paused(); len(ps) != 0 {
		t.Fatalf("still listed %+v", ps)
	}
	// Not paused any more: nothing to ask.
	if _, err := r.g.AskResume(context.Background(), rule, "loop2/pause/a1"); !errors.Is(err, ErrPauseChanged) {
		t.Fatalf("ask on a live grant: %v", err)
	}
}

// A page approval carrying another grant's request as shown does not
// resume this one.
func TestAResumeCodeForAnotherGrantIsRefused(t *testing.T) {
	r := newRig(t, nil)
	r.grant(mailGrant())
	g2 := pausedRule(r, "loop2/pause/a1")
	g3 := pausedRule(r, "loop2/pause/a2")
	id2, err := r.g.AskResume(context.Background(), g2, "loop2/pause/a1")
	if err != nil {
		t.Fatal(err)
	}
	r.g.Flush()
	_, items := r.own.last(t)
	sum2 := owner.ItemSum(items[0])
	id3, err := r.g.AskResume(context.Background(), g3, "loop2/pause/a2")
	if err != nil {
		t.Fatal(err)
	}
	r.g.Flush()
	r.pageDecide(sum2) // G3's request, answered with G2's as shown
	if st := r.state(id3); st.State == journal.Succeeded || !r.paused(g3) {
		t.Fatalf("G3 resumed on G2's approval: %s", st.State)
	}
	if st := r.state(id2); st.State != journal.Pending || !r.paused(g2) {
		t.Fatalf("G2: %s", st.State)
	}
}

// Paused again since the page showed it: the old ask cannot end the new
// pause, and asking with the old pause is refused.
func TestAResumeDoesNotEndALaterPause(t *testing.T) {
	r := newRig(t, nil)
	r.grant(mailGrant())
	rule := pausedRule(r, "loop2/pause/a1")
	id, err := r.g.AskResume(context.Background(), rule, "loop2/pause/a1")
	if err != nil {
		t.Fatal(err)
	}
	r.g.Flush()
	r.pause(rule, "loop2/pause/a2")
	r.pageDecide("")
	if st := r.state(id); st.State == journal.Succeeded || !r.paused(rule) {
		t.Fatalf("an old ask ended a newer pause: %s", st.State)
	}
	if _, err := r.g.AskResume(context.Background(), rule, "loop2/pause/a1"); !errors.Is(err, ErrPauseChanged) {
		t.Fatalf("ask with a stale pause: %v", err)
	}
	if _, err := r.g.AskResume(context.Background(), "G9", "loop2/pause/a1"); !errors.Is(err, ErrPauseChanged) {
		t.Fatalf("ask for no grant: %v", err)
	}
}

// A resume comes only from the page and names the pause it ends.
func TestAResumeComesOnlyFromThePageNamingItsPause(t *testing.T) {
	r := newRig(t, nil)
	r.grant(mailGrant())
	rule := pausedRule(r, "loop2/pause/a1")
	for i, x := range []struct {
		origin string
		s      Spec
	}{
		{"local", Spec{Resume: rule}},                              // no pause named
		{OriginOwner, Spec{Resume: rule, Pause: "loop2/pause/a1"}}, // not the page
		{OriginLoop2, Spec{Resume: rule, Pause: "loop2/pause/a1"}},
		{"guest:agent", Spec{Resume: rule, Pause: "loop2/pause/a1"}},
		{"local", Spec{Resume: rule, Pause: "loop2/pause/zz"}}, // not its pause
		{"local", Spec{Account: "mail", Executor: "mail", Ops: mailOps(), Pause: "loop2/pause/a1"}},
	} {
		in := journal.Intent{ID: "x/" + string(rune('a'+i)), Origin: x.origin, Account: journal.BrokerAccount,
			Action: journal.ActionGrantChange, Params: specParams(x.s), Executor: ExecutorName}
		if st := r.submit(in); st.State != journal.Denied {
			t.Errorf("%d: %s from %s: %s", i, Describe(x.s), x.origin, st.State)
		}
	}
	if !r.paused(rule) {
		t.Fatal("resumed")
	}
}

// End to end with the real owner channel: the page's code is a fresh
// code-generator code, spent once across page and texts, and the
// answer is texted to the owner.
func TestAResumeTakesAFreshPageCode(t *testing.T) {
	const ownerNum, boxNum = "+15550000001", "+15550000002"
	seed := []byte("synthetic-totp-seed-0003") // synthetic canary, not a credential
	r := newRig(t, nil)
	carrier := modem.NewCarrier()
	carrier.SetClock(r.now)
	box, phone := carrier.Line(boxNum), carrier.Line(ownerNum)
	ch, err := owner.New(owner.Config{
		Owner: ownerNum, Modem: box, Engine: r.eng, Secrets: owner.Secrets{TOTPSeed: seed}, Store: unpaced(),
		Limits: owner.Limits{AmountLimit: 50000}, Location: time.UTC, Now: r.now,
		Decide: r.g.Decide, Narrow: r.g.Narrow,
	})
	if err != nil {
		t.Fatal(err)
	}
	r.g.Attach(r.eng, ch)
	ctx := context.Background()
	text := func() string {
		t.Helper()
		select {
		case m := <-phone.Inbox():
			return m.Text
		case <-time.After(2 * time.Second):
			t.Fatal("no text to the owner")
		}
		return ""
	}
	say := func(msg string) string { return strings.Join(ch.Handle(ctx, ownerNum, msg), " | ") }
	r.grant2(ch, text, say, seed, mailGrant(), true)
	r.grant2(ch, text, say, seed, Spec{Account: "mail", Rule: &Rule{Action: "invoice.send", AmountCap: 15000, PerRecord: 5, PerDay: 50}}, false)
	r.grant2(ch, text, say, seed, Spec{Account: "mail", Rule: &Rule{Action: "message.send", PerRecord: 3, PerDay: 10, Reply: true}}, false)
	r.pause("G2", "loop2/pause/a1")
	r.pause("G3", "loop2/pause/a2")

	ask := func(g, pause string) (req, sum string) {
		t.Helper()
		if _, err := r.g.AskResume(ctx, g, pause); err != nil {
			t.Fatal(err)
		}
		r.g.Flush()
		m := regexp.MustCompile(`^([A-Z][0-9]{1,2}):`).FindStringSubmatch(text())
		if m == nil {
			t.Fatal("no page notice")
		}
		for _, rq := range ch.LocalRequests() {
			if rq.ID == m[1] {
				return rq.ID, rq.Sum
			}
		}
		t.Fatalf("%s is not on the page", m[1])
		return "", ""
	}
	req2, sum2 := ask("G2", "loop2/pause/a1")
	req3, sum3 := ask("G3", "loop2/pause/a2")
	r.advance(30 * time.Second)
	code := totp(seed, r.now())

	// No code: refused, and nothing resumes.
	if _, err := ch.LocalAnswer(req2, sum2, true, ""); !errors.Is(err, owner.ErrWrongCode) {
		t.Fatalf("no code: %v", err)
	}
	// G2's request answered as G3's was shown: refused.
	if _, err := ch.LocalAnswer(req2, sum3, true, code); !errors.Is(err, owner.ErrChanged) {
		t.Fatalf("another grant's request: %v", err)
	}
	r.g.Wait()
	if !r.paused("G2") || !r.paused("G3") {
		t.Fatal("resumed without its own code")
	}
	// The code resumes G2, and the answer is texted.
	if got, err := ch.LocalAnswer(req2, sum2, true, code); err != nil || !strings.HasPrefix(got, "Approved") {
		t.Fatalf("resume G2: %q %v", got, err)
	}
	r.g.Wait()
	if r.paused("G2") {
		t.Fatal("G2 still paused")
	}
	pageTexts(text, "Resumed G2", false)
	// The same code again, for G3: spent.
	if _, err := ch.LocalAnswer(req3, sum3, true, code); !errors.Is(err, owner.ErrWrongCode) {
		t.Fatalf("reused code: %v", err)
	}
	r.g.Wait()
	if !r.paused("G3") {
		t.Fatal("G3 resumed with a spent code")
	}
	r.advance(30 * time.Second)
	if got, err := ch.LocalAnswer(req3, sum3, true, totp(seed, r.now())); err != nil || !strings.HasPrefix(got, "Approved") {
		t.Fatalf("resume G3: %q %v", got, err)
	}
	r.g.Wait()
	if r.paused("G3") {
		t.Fatal("G3 still paused")
	}
	// Both page answers reach the owner by text, coalesced.
	r.advance(owner.SignInAlertEvery)
	ch.Tick()
	for m := text(); !strings.Contains(m, "On my Wi-Fi page:") ||
		!strings.Contains(m, "Approved "+req2+" at") || !strings.Contains(m, "Approved "+req3+" at"); m = text() {
	}
}

// resume resumes a paused grant the way the owner does: asked on the
// page, approved there with one code.
func (r *rig) resume(id string) {
	r.t.Helper()
	var pause string
	for _, p := range r.g.Paused() {
		if p.ID == id {
			pause = p.Pause
		}
	}
	iid, err := r.g.AskResume(context.Background(), id, pause)
	if err != nil {
		r.t.Fatal(err)
	}
	r.g.Flush()
	r.pageDecide("")
	if st := r.state(iid); st.State != journal.Succeeded {
		r.t.Fatalf("resume %s: %s %q", id, st.State, st.Permission.Reason)
	}
}
