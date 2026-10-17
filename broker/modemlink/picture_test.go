package modemlink

import (
	"sync"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/bridgeproto"
)

// REQ: CH-12, CH12-mms-c

// A picture texted to the owner line is counted apart for the owner and
// for others, told to Config.Picture once per ID, never put in the inbox,
// and never spends the owner's rate limit.
func TestPicturesAreCountedAndJournaledNeverInboxed(t *testing.T) {
	clk := &clock{t: time.Date(2026, 10, 17, 9, 0, 0, 0, time.UTC)}
	var mu sync.Mutex
	var told []bool
	var l *Link
	l = New(Config{Owner: ownerNum, Now: clk.now, SendWait: 2 * time.Second, PollWait: 200 * time.Millisecond,
		Picture: func(owner bool) {
			// Called outside the lock: the Link answers meanwhile.
			_ = l.Others()
			mu.Lock()
			told = append(told, owner)
			mu.Unlock()
		}})
	call(t, l, bridgeproto.OpState, bridgeproto.State{OwnerLine: bridgeproto.StateOK}, nil)
	if got := l.PictureNote(); got != "" {
		t.Fatalf("note before any picture: %q", got)
	}
	pic := func(from, id string, named bool) {
		t.Helper()
		if err := call(t, l, bridgeproto.OpInbound, bridgeproto.Inbound{Line: bridgeproto.LineOwner, From: from, Named: named, ID: id, Picture: true}, nil); err != nil {
			t.Fatalf("picture %s refused: %v", id, err)
		}
	}
	pic(ownerNum, "a", false)
	pic(ownerNum, "a", false) // a try whose answer was lost
	pic("+15550000777", "b", false)
	pic(ownerNum, "c", true) // a sender name spelling the owner's number
	for i := 0; i < InboundPerMinute; i++ {
		pic(ownerNum, "flood"+string(rune('A'+i)), false)
	}
	mu.Lock()
	n, first := len(told), append([]bool(nil), told[:3]...)
	mu.Unlock()
	if n != InboundPerMinute || first[0] != true || first[1] != false || first[2] != false {
		t.Fatalf("told %d, first %v", n, first)
	}
	want := "Pictures by text: 21 from you, 2 from others. Not opened yet."
	if got := l.PictureNote(); got != want {
		t.Fatalf("note %q, want %q", got, want)
	}
	if l.Others() != 0 {
		t.Fatalf("others %d: pictures are counted apart", l.Others())
	}
	select {
	case m := <-l.Inbox():
		t.Fatalf("inboxed %+v", m)
	default:
	}
	// The owner's texts still pass: pictures spent none of the limit.
	if err := call(t, l, bridgeproto.OpInbound, bridgeproto.Inbound{Line: bridgeproto.LineOwner, From: ownerNum, Text: "STATUS", ID: "t"}, nil); err != nil {
		t.Fatal(err)
	}
	if m := <-l.Inbox(); m.Text != "STATUS" {
		t.Fatalf("inbox %+v", m)
	}
	// A minute later pictures are told again.
	clk.add(time.Minute)
	pic(ownerNum, "d", false)
	mu.Lock()
	n = len(told)
	mu.Unlock()
	if n != InboundPerMinute+1 {
		t.Fatalf("told %d after a minute", n)
	}
}
