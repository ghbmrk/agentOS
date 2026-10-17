package grants

import (
	"sync"
	"testing"
	"time"
)

// spender stands in for the owner channel's Spend and Refund: left texts
// in the hour, counted at grant time.
type spender struct {
	mu      sync.Mutex
	left    int
	spends  int
	refunds int
}

func (s *spender) spend(paced bool) (time.Time, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if paced && s.left <= 0 {
		return time.Time{}, false
	}
	s.left--
	s.spends++
	return time.Unix(int64(s.spends), 0), true
}

// refund returns a spend: the fake channel sends no request on one.
func (s *spender) refund(time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.left++
	s.refunds++
}

func spendRig(t *testing.T) (*rig, *spender) {
	sp := &spender{left: 100}
	r := newRig(t, func(c *Config) {
		c.Verifiers = nil
		c.Allowance = func(time.Time) int { return 1 } // stale: never read to grant
		c.Spend, c.Refund = sp.spend, sp.refund
	})
	r.grant(mailGrant())
	r.own.local, r.own.localCalls = nil, 0
	return r, sp
}

func (r *rig) batched() int {
	r.g.mu.Lock()
	defer r.g.mu.Unlock()
	return len(r.g.batch)
}

// REQ: CH-15 (#1685)
// With an allowance of 1 and a page of 3, the gate spends each request
// at grant time, before it checks the next, so exactly one request is
// asked and the other two wait in the batch; the spend the channel did
// not use is refunded once the call returns.
func TestPageSpendsEachRequestBeforeTheNext(t *testing.T) {
	r, sp := spendRig(t)
	many := []string{"mom@example.com", "dad@example.com", "sis@example.com", "bro@example.com", "gran@example.com", "x@attacker.example"}
	for _, id := range []string{"agent/p1", "agent/p2", "agent/p3"} {
		r.effect(id, "message.send", map[string]any{"body": "hi"}, many...)
	}
	sp.mu.Lock()
	sp.left, sp.spends, sp.refunds = 1, 0, 0
	sp.mu.Unlock()
	r.g.flush(true)
	r.own.mu.Lock()
	local := len(r.own.local)
	r.own.mu.Unlock()
	if local != 1 || r.batched() != 2 {
		t.Fatalf("asked %d and batched %d with an allowance of 1, want 1 and 2", local, r.batched())
	}
	if sp.spends != 1 || sp.refunds != 1 {
		t.Fatalf("spends %d, refunds %d, want 1 and 1", sp.spends, sp.refunds)
	}
}

// REQ: CH-15 (#1685)
// The gate grants on Spend, not on an allowance it read earlier: with the
// hour spent by a NotifyNow after that read, the paced request is not
// sent and waits in the batch, though the read said 1 was left.
func TestStaleAllowanceGrantsNothing(t *testing.T) {
	r, sp := spendRig(t)
	x := sam()
	x.Record = "a"
	r.ver.set("a", x)
	base := r.own.count()
	sp.mu.Lock()
	sp.left = 0 // a NotifyNow spent the hour after the gate's read
	sp.mu.Unlock()
	r.effect("agent/a", "invoice.send", map[string]any{"record": "a"}, "sam@example.com")
	r.g.flush(true)
	if n := r.own.count() - base; n != 0 || r.batched() != 1 {
		t.Fatalf("sent %d, batched %d past a spent hour, want 0 and 1", n, r.batched())
	}
}
