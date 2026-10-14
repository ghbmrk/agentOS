package daemon

import (
	"context"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/grants"
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
		ref := d.retry.items()[0].Ref
		d.retry.decide(func(ownerch.Decision) { t.Fatal("a retry decision went to the gate") })(
			ownerch.Decision{Request: "A1", Item: 1, Ref: ref, Approved: false, Why: why})
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
	d.retry.run("B2", retryAsk{id: "loops:off:1", attempt: 1, line: line}, false)
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

// Retry refs name the attempt asked about and are new for every ask.
func TestOP2RetryRefsRoundTrip(t *testing.T) {
	p := journal.ParkedIntent{Intent: journal.Intent{ID: "m1/r:7"}, Attempt: 3}
	ref := retryRef(p, newNonce())
	id, n, ok := parseRetryRef(ref)
	if !ok || id != "m1/r:7" || n != 3 {
		t.Fatalf("%q %d %v", id, n, ok)
	}
	if again := retryRef(p, newNonce()); again == ref {
		t.Fatalf("two asks share the ref %q", ref)
	}
	for _, bad := range []string{"m1/r", "retry:", "retry:a", "retry::1", "retry:a:0", "retry:a:x", "retry:a:1", "retry:a:1:", "retry::1:n", "retry:a:0:n", "retry:a:x:n"} {
		if _, _, ok := parseRetryRef(bad); ok {
			t.Fatalf("%q parsed", bad)
		}
	}
}

// startParked runs agentosd over a journal in which LOOPS OFF was left
// unclear by a crash and is parked.
func startParked(t *testing.T) (context.Context, *Daemon, *modem.Line, *crashLoops) {
	t.Helper()
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
	t.Cleanup(func() { cancel(); d.Wait() })
	waitParked(t, d)
	return ctx, d, phone, f
}

func noGate(t *testing.T) func(ownerch.Decision) {
	return func(ownerch.Decision) { t.Error("a retry decision went to the gate") }
}

// B3 (CH-12, OP-3): an approval runs the line the approved request showed.
// The owner texts RETRY and is asked about a payment of $120; the source
// changes to $9,000 and a second RETRY asks about that. Approving the
// first request runs the $120 line (which the gate's recheck then refuses,
// as the source no longer gives it), never the $9,000 one; the second
// request still runs its own line.
func TestOP2RetryApprovalRunsTheLineItsRequestShowed(t *testing.T) {
	_, d, _, _ := startParked(t)
	var mu sync.Mutex
	amount, ran := "$120.00", []string{}
	d.retry.line = func(context.Context, journal.ParkedIntent, string) grants.RetryLine {
		mu.Lock()
		defer mu.Unlock()
		it := ownerch.Item{Object: "invoice 1042", Amount: amount, Facts: ownerch.Facts{Verb: "pay", HasAmount: true}}
		return grants.RetryLine{Shown: it, Base: it}
	}
	d.retry.send = func(_ context.Context, a retryAsk, _ bool) (journal.Status, error) {
		mu.Lock()
		defer mu.Unlock()
		ran = append(ran, a.line.Shown.Amount)
		return journal.Status{State: journal.Succeeded}, nil
	}
	first := d.retry.items()
	mu.Lock()
	amount = "$9,000.00"
	mu.Unlock()
	second := d.retry.items()
	if len(first) != 1 || len(second) != 1 || first[0].Ref == second[0].Ref || second[0].Amount != "$9,000.00" {
		t.Fatalf("asks %+v then %+v", first, second)
	}
	decide := d.retry.decide(noGate(t))
	approve := func(req, ref string) {
		decide(ownerch.Decision{Request: req, Item: 1, Ref: ref, Approved: true, Why: "owner"})
		d.retry.running.Wait()
	}
	approve("A1", first[0].Ref)
	approve("A1", first[0].Ref) // answered once; a repeat runs nothing
	mu.Lock()
	got := strings.Join(ran, ",")
	mu.Unlock()
	if got != "$120.00" {
		t.Fatalf("approving the $120 request ran %q", got)
	}
	approve("B2", second[0].Ref)
	mu.Lock()
	defer mu.Unlock()
	if got := strings.Join(ran, ","); got != "$120.00,$9,000.00" {
		t.Fatalf("ran %q", got)
	}
}

// B3 (CH-12, OP-3): the owner texts RETRY twice; the older request
// expires, or the owner says NO to it, and the newer one is approved. The
// effect runs once, from the newer request: the older one's ending does
// not drop the newer one's line.
func TestOP2OlderRetryRequestEndingLeavesTheNewerOne(t *testing.T) {
	for _, why := range []string{"expired", "owner", "void"} {
		t.Run(why, func(t *testing.T) {
			_, d, phone, f := startParked(t)
			first, second := d.retry.items(), d.retry.items()
			if len(first) != 1 || len(second) != 1 || first[0].Ref == second[0].Ref {
				t.Fatalf("asks %+v then %+v", first, second)
			}
			decide := d.retry.decide(noGate(t))
			decide(ownerch.Decision{Request: "A1", Item: 1, Ref: first[0].Ref, Approved: false, Why: why})
			decide(ownerch.Decision{Request: "B2", Item: 1, Ref: second[0].Ref, Approved: true, Why: "owner"})
			d.retry.running.Wait()
			if got := nextText(t, phone); got != "Retry B2: a setting change went through." {
				t.Fatalf("outcome %q", got)
			}
			f.mu.Lock()
			defer f.mu.Unlock()
			if len(f.ran) != 1 || f.ran[0] != "loops:off:1" {
				t.Fatalf("ran %q", f.ran)
			}
		})
	}
}

// crashMidLoopsOnStopped leaves a journal in which LOOPS ON was
// dispatched, STOP was sent while it ran, and the broker died before its
// outcome was recorded.
func crashMidLoopsOnStopped(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	f := &crashLoops{entered: make(chan struct{}), release: make(chan struct{})}
	ctx, cancel := context.WithCancel(context.Background())
	d, err := Run(ctx, loopsCfg(dir, filepath.Join(dir, "journal.log"), f))
	if err != nil {
		t.Fatal(err)
	}
	in := loopsIntent("loops:on:1", actionLoopsOn)
	if _, err := d.Gate().Submit(in); err != nil {
		t.Fatal(err)
	}
	if st, err := d.Gate().Authorize(ctx, in.ID); err != nil || st.State != journal.Authorized {
		t.Fatalf("authorize: %s %v", st.State, err)
	}
	go d.Gate().Dispatch(ctx, in.ID)
	<-f.entered
	if _, err := d.Engine().Stop(ctx); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(dir, "journal.log"))
	if err != nil {
		t.Fatal(err)
	}
	crashed := filepath.Join(t.TempDir(), "journal.log")
	if err := os.WriteFile(crashed, data, 0o600); err != nil {
		t.Fatal(err)
	}
	close(f.release)
	cancel()
	d.Wait()
	return crashed
}

// R4, P1b (OP-2): after a restart the check proves LOOPS ON did not go,
// and its resend is refused (STOP is on). It is not dropped: RETRY offers
// it as an ordinary ask, without "may go twice", since it cannot go twice,
// and once STOP is lifted the owner's approval sends it once.
func TestOP2RefusedResendIsOfferedByRetry(t *testing.T) {
	fastSettle(t)
	crashed := crashMidLoopsOnStopped(t)
	dir := t.TempDir()
	carrier := modem.NewCarrier()
	phone := carrier.Line(owner)
	f := &crashLoops{saved: map[string]bool{}}
	cfg := loopsCfg(dir, crashed, f)
	cfg.Auth, cfg.OwnerState, cfg.Modem = nil, dir+"/owner.json", carrier.Line("+15550000009")
	ctx, cancel := context.WithCancel(context.Background())
	d, err := Run(ctx, cfg)
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	defer func() { cancel(); d.Wait() }()
	deadline := time.Now().Add(5 * time.Second)
	for len(d.Engine().NotResent()) == 0 {
		if time.Now().After(deadline) {
			st, err := d.Engine().Get("loops:on:1")
			t.Fatalf("not listed: %+v %v", st, err)
		}
		time.Sleep(time.Millisecond)
	}
	f.mu.Lock()
	ran := len(f.ran)
	f.mu.Unlock()
	if ran != 0 || len(d.Engine().Parked()) != 0 {
		t.Fatalf("ran %d, parked %+v", ran, d.Engine().Parked())
	}
	// The digest names what RETRY offers.
	if w := d.RetryWaiting(); len(w) != 1 || w[0].Intent.ID != "loops:on:1" || !w[0].NotDone {
		t.Fatalf("waiting %+v", w)
	}
	if err := d.Engine().Resume(); err != nil {
		t.Fatal(err)
	}

	if got := d.Owner().Handle(ctx, owner, "RETRY"); len(got) != 0 {
		t.Fatalf("RETRY replies %q", got)
	}
	req := nextText(t, phone)
	m := retryCodeRe.FindStringSubmatch(req)
	if m == nil || !strings.Contains(req, "a setting change") || strings.Contains(req, "twice") {
		t.Fatalf("request %q", req)
	}
	if got := d.Owner().Handle(ctx, owner, "YES "+m[1]+" "+m[2]); len(got) != 1 || got[0] != "Approved "+m[1]+"." {
		t.Fatalf("approve: %q", got)
	}
	d.retry.running.Wait()
	if got := nextText(t, phone); got != "Retry "+m[1]+": a setting change went through." {
		t.Fatalf("outcome %q", got)
	}
	if st, err := d.Engine().Get("loops:on:1"); err != nil || st.State != journal.Succeeded || len(st.Attempts) != 2 {
		t.Fatalf("after approval: %+v %v", st, err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.ran) != 1 || f.ran[0] != "loops:on:1" || len(d.Engine().NotResent()) != 0 {
		t.Fatalf("ran %q, not resent %+v", f.ran, d.Engine().NotResent())
	}
}

// A RETRY refused because the same effect went, or waits to go, as
// another request (journal.SupersededError) says so in plain words: it
// does not tell the owner to text RETRY later, and the effect is not
// listed again.
func TestOP2SupersededRetrySaysTheEffectWentAnotherWay(t *testing.T) {
	var got string
	relisted := 0
	r := &retrier{
		ctx:   context.Background(),
		lines: map[string]retryAsk{},
		send: func(context.Context, retryAsk, bool) (journal.Status, error) {
			return journal.Status{}, &journal.SupersededError{ID: "agent/s1", By: "agent/s2"}
		},
		inform:    func(s string) error { got = s; return nil },
		onRefused: func() { relisted++ },
	}
	r.run("B3", retryAsk{id: "agent/s1", attempt: 1, notDone: true,
		line: grants.RetryLine{Shown: ownerch.Item{Object: "invoice 1042"}}}, false)
	want := "Retry B3: nothing was sent. Invoice 1042 already went, or is waiting to go, as another request, so it was not sent again."
	if got != want || relisted != 0 {
		t.Fatalf("text %q, relisted %d", got, relisted)
	}
	if strings.Contains(got, "RETRY later") || strings.Contains(got, "agent/") {
		t.Fatalf("text %q", got)
	}
}
