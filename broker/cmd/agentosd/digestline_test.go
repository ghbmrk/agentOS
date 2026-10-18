package main

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/bridgeproto"
	"github.com/ghbmrk/agentos/broker/change"
	"github.com/ghbmrk/agentos/broker/digestqueue"
	"github.com/ghbmrk/agentos/broker/modemlink"
	"github.com/ghbmrk/agentos/broker/sockets"
)

// REQ: CH-15, CH-1 (#1291, #2170)

// TestDigestWaitsForTheOwnerLine: a digest due while the owner line is
// down is not handed to the transport; it stays Ready, costing no
// attempt, and goes at the first step after the line is back, once.
func TestDigestWaitsForTheOwnerLine(t *testing.T) {
	r := newDigestRig(t, &change.MemStore{}, nil)
	// The line comes back at 08:41, between two 30-minute retries: the
	// first step after it sends, not the next retry.
	up := day0.Add(8*time.Hour + 41*time.Minute)
	r.down = func() bool { return r.now.Before(up) }
	r.at(0, 8, 0)
	r.at(0, 8, 30)
	r.at(0, 8, 40)
	if got := r.tr.sent(); len(got) != 0 {
		t.Fatalf("sent with the line down: %q", got)
	}
	if bs := r.batches(); len(bs) != 1 || bs[0].State != digestqueue.Ready || bs[0].Attempts != 0 {
		t.Fatalf("batches with the line down: %+v", bs)
	}
	r.at(0, 8, 41)
	if got := r.tr.sent(); len(got) != 1 || !strings.HasPrefix(got[0], fmt.Sprintf(digestHead, "Mon 5 Oct")) {
		t.Fatalf("once the line is back: %q", got)
	}
	r.at(0, 8, 42)
	r.at(0, 12, 0)
	if got := r.tr.sent(); len(got) != 1 {
		t.Fatalf("sent again: %q", got)
	}
}

// TestDigestAtBootLeavesNoRecoveryNotice: over a real modem link, as main
// wires it, a digest due before the bridge's first state report is not
// counted as a missed text, so the line's first OK report queues no
// recovery notice (#1291's acceptance via #2170: a phone-control run after
// setup passes over none). Without LineDown the same boot queues one,
// which is what main's image runs showed (texts=1, via the digest sender).
func TestDigestAtBootLeavesNoRecoveryNotice(t *testing.T) {
	for _, wired := range []bool{true, false} {
		t.Run(fmt.Sprintf("wired=%v", wired), func(t *testing.T) {
			link := modemlink.New(modemlink.Config{Owner: "+15550100001", SendWait: 50 * time.Millisecond})
			r := &digestRig{t: t, now: day0.Add(7 * time.Hour), queue: &change.MemStore{}, state: &change.MemStore{}, tr: &fakeDigestTransport{}}
			r.make(nil)
			r.d.cfg.Transport = newDigestTransport(link, "+15550100001")
			if wired {
				r.d.cfg.LineDown = digestLineDown(link)
			}
			r.d.open(context.Background())
			r.at(0, 8, 0) // due at boot, the bridge not yet reporting
			report(t, link, bridgeproto.StateOK)
			want := 0
			if !wired {
				want = 1
			}
			if got := link.Queued(); got != want {
				t.Fatalf("queued after the first OK report: %d, want %d", got, want)
			}
		})
	}
}

// TestDigestLineDownFollowsTheLink: the digest reads the line as down
// before any report, up once the bridge reports OK, and down again on any
// other state.
func TestDigestLineDownFollowsTheLink(t *testing.T) {
	link := modemlink.New(modemlink.Config{Owner: "+15550100001"})
	down := digestLineDown(link)
	if !down() {
		t.Fatal("up before the bridge's first state report")
	}
	report(t, link, bridgeproto.StateOK)
	if down() {
		t.Fatal("down after an OK report")
	}
	for _, st := range []string{bridgeproto.StateDown, bridgeproto.StateSwapped, bridgeproto.StateUnbound} {
		report(t, link, st)
		if !down() {
			t.Errorf("up after a %s report", st)
		}
		report(t, link, bridgeproto.StateOK)
	}
}

// report sends link a state report as the bridge does.
func report(t *testing.T, link *modemlink.Link, st string) {
	t.Helper()
	args, err := json.Marshal(bridgeproto.State{OwnerLine: st})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := link.Ops()[bridgeproto.OpState](context.Background(), sockets.Peer{}, args); err != nil {
		t.Fatalf("state %s: %v", st, err)
	}
}
