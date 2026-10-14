package daemon

import (
	"context"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/journal"
	"github.com/ghbmrk/agentos/broker/modem"
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
// code the request carries. The request says it may happen twice.
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
	if m == nil || !strings.Contains(req, "a setting change") || !strings.Contains(req, "may go twice") {
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
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.ran) != 1 || f.ran[0] != "loops:off:1" {
		t.Fatalf("ran %q", f.ran)
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
