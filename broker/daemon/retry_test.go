package daemon

import (
	"context"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/journal"
	"github.com/ghbmrk/agentos/broker/modem"
	ownerch "github.com/ghbmrk/agentos/broker/owner"
)

// REQ: OP-2, CH-11

var retryCodeRe = regexp.MustCompile(`YES ([A-Z][0-9]{1,2}) ([0-9]{6})`)

func waitParked(t *testing.T, d *Daemon) []journal.ParkedIntent {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		if ps := d.Engine().Parked(); len(ps) > 0 {
			return ps
		}
		if time.Now().After(deadline) {
			t.Fatal("nothing parked")
		}
		time.Sleep(time.Millisecond)
	}
}

// A restart leaves LOOPS OFF unclear and no check settles it: agentosd
// parks it without running it again, lifting the fence, and runs it a
// second time only when the owner texts RETRY and approves with the texted
// code the request carries. The request says it may happen twice and when
// it was first tried. A declined, expired or restart-dropped retry runs
// nothing. The owner is texted how the retry ended, and a refused retry is
// listed again.
func TestOP2UnclearEffectIsParkedAndRetriedOnlyOnTheOwnersWord(t *testing.T) {
	fastSettle(t)
	crashed := crashMidLoopsOff(t)
	dir := t.TempDir()
	carrier := modem.NewCarrier()
	phone := carrier.Line(owner)
	f := &crashLoops{uncertain: true}
	cfg := loopsCfg(dir, crashed, f)
	cfg.Auth, cfg.OwnerState, cfg.Modem = nil, dir+"/owner.json", carrier.Line("+15550000009")
	ctx, cancel := context.WithCancel(context.Background())
	d, err := Run(ctx, cfg)
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	defer func() { cancel(); d.Wait() }()

	ps := waitParked(t, d)
	if len(ps) != 1 || ps[0].Intent.ID != "loops:off:1" || ps[0].Attempt != 1 {
		t.Fatalf("parked %+v", ps)
	}
	waitUnfenced(t, d)
	f.mu.Lock()
	ran := len(f.ran)
	f.mu.Unlock()
	if ran != 0 {
		t.Fatal("an unclear effect ran again without the owner")
	}

	// Every answer but an approval leaves the effect parked: a NO, an
	// expiry, a wrong code, an item left out of a partial YES, and the
	// decisions a restart reports (Boot: Approved false, Why "restart").
	for _, why := range []string{"owner", "expired", "void", "not chosen", "restart"} {
		d.retry.items()
		d.retry.decide(func(ownerch.Decision) { t.Fatal("a retry decision went to the gate") })(
			ownerch.Decision{Request: "A1", Item: 1, Ref: retryRef(ps[0]), Approved: false, Why: why})
		d.retry.running.Wait()
		f.mu.Lock()
		ran := len(f.ran)
		f.mu.Unlock()
		if ran != 0 || len(d.Engine().Parked()) != 1 {
			t.Fatalf("a retry the owner did not approve (%s) ran: ran %d, parked %+v", why, ran, d.Engine().Parked())
		}
	}

	if got := d.Owner().Handle(ctx, owner, "RETRY"); len(got) != 0 {
		t.Fatalf("RETRY replies %q", got)
	}
	var req string
	select {
	case m := <-phone.Inbox():
		req = m.Text
	case <-time.After(5 * time.Second):
		t.Fatal("no retry request texted")
	}
	m := retryCodeRe.FindStringSubmatch(req)
	first := ps[0].Dispatched.In(time.Local).Format("15:04 Jan 2")
	if m == nil || !strings.Contains(req, "a setting change") || !strings.Contains(req, "may go twice, first tried "+first) ||
		strings.Contains(strings.ToLower(req), "for all") {
		t.Fatalf("request %q", req)
	}
	if got := d.Owner().Handle(ctx, owner, "YES "+m[1]+" "+m[2]); len(got) != 1 || got[0] != "Approved "+m[1]+"." {
		t.Fatalf("approve: %q", got)
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		st, err := d.Engine().Get("loops:off:1")
		if err == nil && st.State == journal.Succeeded && len(st.Attempts) == 2 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("after approval: %+v %v", st, err)
		}
		time.Sleep(time.Millisecond)
	}
	d.retry.running.Wait()
	if got := nextText(t, phone); got != "Retry "+m[1]+": a setting change went through." {
		t.Fatalf("outcome %q", got)
	}
	f.mu.Lock()
	if len(f.ran) != 1 || f.ran[0] != "loops:off:1" {
		t.Fatalf("ran %q", f.ran)
	}
	f.mu.Unlock()

	// A retry the engine refuses (here: the attempt is no longer parked)
	// is texted as refused and listed again in the digest.
	relisted := 0
	d.OnRetryRefused(func() { relisted++ })
	line := d.retry.gate.RetryItem(ctx, ps[0], EffectWord("loops"))
	d.retry.run("B2", "loops:off:1", 1, line, false)
	if got := nextText(t, phone); relisted != 1 || !strings.HasPrefix(got, "Retry B2 refused: it is no longer waiting for a retry.") {
		t.Fatalf("refused retry: relisted %d, text %q", relisted, got)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.ran) != 1 {
		t.Fatalf("ran %q", f.ran)
	}
}

func nextText(t *testing.T, phone *modem.Line) string {
	t.Helper()
	select {
	case m := <-phone.Inbox():
		return m.Text
	case <-time.After(5 * time.Second):
		t.Fatal("nothing texted")
		return ""
	}
}

// Retry refs name the attempt asked about, and only an approved one runs.
func TestOP2RetryRefsRoundTrip(t *testing.T) {
	p := journal.ParkedIntent{Intent: journal.Intent{ID: "m1/r:7"}, Attempt: 3}
	id, n, ok := parseRetryRef(retryRef(p))
	if !ok || id != "m1/r:7" || n != 3 {
		t.Fatalf("%q %d %v", id, n, ok)
	}
	for _, bad := range []string{"m1/r", "retry:", "retry:a", "retry::1", "retry:a:0", "retry:a:x"} {
		if _, _, ok := parseRetryRef(bad); ok {
			t.Fatalf("%q parsed", bad)
		}
	}
}
