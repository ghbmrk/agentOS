package modemlink

import (
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/bridgeproto"
)

// REQ: CH-12. #6292: Usable says whether the owner line can carry a text
// now, as a send would find it, but opens no outage and counts nothing,
// so a sender holding a refused text can ask before trying again. New's
// defaults stand when the config leaves them unset.
func TestUsableAsksWithoutCounting(t *testing.T) {
	clk := &clock{t: time.Date(2026, 10, 5, 13, 5, 0, 0, time.UTC)}
	l := New(Config{Owner: ownerNum, Now: clk.now})
	if l.cfg.SendWait != SendWait || l.cfg.PollWait != bridgeproto.OutboxWait {
		t.Fatalf("defaults %v %v, want %v %v", l.cfg.SendWait, l.cfg.PollWait, SendWait, bridgeproto.OutboxWait)
	}
	if l.Usable() {
		t.Fatal("a line the bridge never reported reads as usable")
	}
	l.state, l.seen = bridgeproto.StateOK, clk.now()
	if !l.Usable() {
		t.Fatal("a line reported ok just now reads as unusable")
	}
	clk.add(Silent)
	if !l.Usable() {
		t.Fatal("a line heard exactly Silent ago reads as unusable")
	}
	clk.add(time.Nanosecond)
	if l.Usable() {
		t.Fatal("a line silent past Silent reads as usable")
	}
	if l.outage != nil {
		t.Fatalf("asking opened an outage: %+v", *l.outage)
	}
}
