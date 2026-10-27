package localui

// REQ: HW-10, K9

import (
	"context"
	"net/http"
	"net/url"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/claim"
)

// slowClaim is a claim whose tries block until gate closes, as Argon2id
// derivations under a flood; calls counts them.
type slowClaim struct {
	gate  chan struct{}
	calls atomic.Int32
}

func (c *slowClaim) Status() claim.Status { return claim.Status{TriesLeft: 5} }
func (c *slowClaim) Claim(string) (string, error) {
	c.calls.Add(1)
	<-c.gate
	return "", claim.ErrWrongCode
}
func (c *slowClaim) Claimant(string) bool { return false }

func newFloodRig(t *testing.T) (*rig, *slowClaim) {
	t.Helper()
	r := newRig(t)
	c := &slowClaim{gate: make(chan struct{})}
	s, err := New(Config{Page: testPage(), Hooks: r.hooks, SetupSecret: r.card.SetupSecret, Store: &MemStore{},
		Claim: c, Now: r.clock, Rand: r.srv.cfg.Rand})
	if err != nil {
		t.Fatal(err)
	}
	r.srv = s
	return r, c
}

// until polls cond for up to five seconds.
func until(t *testing.T, cond func() bool) {
	t.Helper()
	for end := time.Now().Add(5 * time.Second); !cond(); time.Sleep(time.Millisecond) {
		if time.Now().After(end) {
			t.Fatal("timed out")
		}
	}
}

var wrongCode = url.Values{"code": {"WRON-GCOD-EWRO-NGCO"}}

// Brief test 6: 32 posts at once against a claim that blocks run Claim at
// most claimQueue+1 times; the rest are answered busy (503) at once.
func TestAClaimFloodIsAnsweredBusy(t *testing.T) {
	r, c := newFloodRig(t)
	var busy atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if r.do("POST", "/claim", wrongCode).Code == http.StatusServiceUnavailable {
				busy.Add(1)
			}
		}()
	}
	until(t, func() bool { return busy.Load() == 32-(claimQueue+1) })
	close(c.gate)
	wg.Wait()
	if n := c.calls.Load(); n != claimQueue+1 || busy.Load() != 32-(claimQueue+1) {
		t.Fatalf("%d Claim calls, %d busy", n, busy.Load())
	}
}

// A post whose request already ended never runs Claim, and neither does
// one whose request ends while it waits: both are answered busy.
func TestAClaimForAGonePhoneIsNotTried(t *testing.T) {
	r, c := newFloodRig(t)
	gone, cancel := context.WithCancel(context.Background())
	cancel()
	withCtx := func(ctx context.Context) func(*http.Request) {
		return func(req *http.Request) { *req = *req.WithContext(ctx) }
	}
	for i := 0; i < 20; i++ { // claimTurn's select picks at random
		if rec := r.do("POST", "/claim", wrongCode, withCtx(gone)); rec.Code != http.StatusServiceUnavailable {
			t.Fatalf("done request: %d", rec.Code)
		}
	}
	if n := c.calls.Load(); n != 0 {
		t.Fatalf("Claim ran %d times for a done request", n)
	}

	done := make(chan struct{})
	go func() { r.do("POST", "/claim", wrongCode); close(done) }()
	until(t, func() bool { return c.calls.Load() == 1 })
	leaving, leave := context.WithCancel(context.Background())
	code := make(chan int, 1)
	go func() { code <- r.do("POST", "/claim", wrongCode, withCtx(leaving)).Code }()
	until(t, func() bool { return len(r.srv.claimWait) == 2 })
	leave()
	if got := <-code; got != http.StatusServiceUnavailable {
		t.Fatalf("a request that ended while waiting: %d", got)
	}
	close(c.gate)
	<-done
	if n := c.calls.Load(); n != 1 {
		t.Fatalf("Claim ran %d times", n)
	}
}
