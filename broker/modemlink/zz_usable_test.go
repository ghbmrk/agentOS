package modemlink_test

import (
	"sync"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/bridgeproto"
	"github.com/ghbmrk/agentos/broker/modemlink"
)

// usableClock is the test's clock.
type usableClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *usableClock) now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *usableClock) add(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// REQ: CH-12. #6292: Usable says whether the owner line can carry a text
// now, as a send would find it, but opens no outage and counts nothing,
// so a sender holding a refused text can ask before trying again. New's
// defaults stand when the config leaves them unset.
func TestUsableAsksWithoutCounting(t *testing.T) {
	clk := &usableClock{t: time.Date(2026, 10, 5, 13, 5, 0, 0, time.UTC)}
	l := modemlink.New(modemlink.Config{Owner: "+15550000999", Now: clk.now})
	if c := modemlink.ConfigForTest(l); c.SendWait != modemlink.SendWait || c.PollWait != bridgeproto.OutboxWait {
		t.Fatalf("defaults %v %v, want %v %v", c.SendWait, c.PollWait, modemlink.SendWait, bridgeproto.OutboxWait)
	}
	if l.Usable() {
		t.Fatal("a line the bridge never reported reads as usable")
	}
	modemlink.SetLineForTest(l, bridgeproto.StateOK, clk.now())
	if !l.Usable() {
		t.Fatal("a line reported ok just now reads as unusable")
	}
	clk.add(modemlink.Silent)
	if !l.Usable() {
		t.Fatal("a line heard exactly Silent ago reads as unusable")
	}
	clk.add(time.Nanosecond)
	if l.Usable() {
		t.Fatal("a line silent past Silent reads as usable")
	}
	if modemlink.OutageOpenForTest(l) {
		t.Fatal("asking opened an outage")
	}
}
