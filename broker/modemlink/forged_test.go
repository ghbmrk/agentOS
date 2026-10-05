package modemlink_test

import (
	"context"
	"regexp"
	"sync"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/bridgeproto"
	"github.com/ghbmrk/agentos/broker/daemon"
	"github.com/ghbmrk/agentos/broker/journal"
	"github.com/ghbmrk/agentos/broker/modemlink"
	"github.com/ghbmrk/agentos/broker/owner"
)

// REQ: CH-1, CH-10

type engine struct{}

func (engine) Stop(context.Context) (journal.StopReport, error) { return journal.StopReport{}, nil }
func (engine) Resume() error                                    { return nil }
func (engine) Stopped() bool                                    { return false }
func (engine) List() []journal.Status                           { return nil }

var _ = daemon.OwnerSocket // the daemon serves Link.Ops on this socket

// Security S-B1 on the P2-3w design: a compromised bridge is an attacker
// on the cellular path. It reads every text to the owner and can forge any
// text from the owner's number, yet it cannot approve a high-tier item: no
// texted code, replayed or guessed from what it saw, completes one.
func TestAForgedOwnerTextCannotApproveAHighTierItem(t *testing.T) {
	const ownerNum = "+15550000999"
	l := modemlink.New(modemlink.Config{Owner: ownerNum, SendWait: 5 * time.Second, PollWait: 100 * time.Millisecond})
	var mu sync.Mutex
	var decided []owner.Decision
	ch, err := owner.New(owner.Config{
		Owner: ownerNum, Modem: l, Engine: engine{}, Store: &owner.MemStore{},
		Secrets: owner.Secrets{TOTPSeed: []byte("12345678901234567890"), GridSeed: []byte("synthetic-grid-seed")},
		Limits:  owner.Limits{Hold: 7 * 24 * time.Hour, AmountLimit: 10000}, Location: time.UTC,
		Decide: func(d owner.Decision) { mu.Lock(); decided = append(decided, d); mu.Unlock() },
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go ch.Run(ctx)
	sock := ops{l}
	sock.call(t, bridgeproto.OpState, bridgeproto.State{OwnerLine: bridgeproto.StateOK}, nil)

	// The bridge: send everything, and remember every text it saw.
	seen := make(chan string, 64)
	go func() {
		for ctx.Err() == nil {
			var out struct{ Item *bridgeproto.Item }
			if sock.call(nil, bridgeproto.OpOutbox, struct{}{}, &out) != nil || out.Item == nil {
				continue
			}
			seen <- out.Item.Text
			sock.call(nil, bridgeproto.OpSent, bridgeproto.Sent{ID: out.Item.ID, Code: bridgeproto.CodeOK}, nil)
		}
	}()
	low := owner.Item{Ref: "low", Object: "invoice 1042", Recipient: "billing@acme.example",
		Facts: owner.Facts{Verb: "send", RecipientChecked: true, RecipientExists: true, RecipientByOwner: true}}
	high := owner.Item{Ref: "high", Object: "a new grant", Facts: owner.Facts{Kind: owner.GrantChange, Verb: "grant", NoRecipient: true}}
	if _, err := ch.Request([]owner.Item{low}, 0); err != nil {
		t.Fatal(err)
	}
	id, err := ch.Request([]owner.Item{high}, 0)
	if err != nil {
		t.Fatal(err)
	}
	codes := regexp.MustCompile(`[0-9]{6}`)
	var guesses []string
	for i := 0; i < 2; i++ {
		select {
		case s := <-seen:
			guesses = append(guesses, codes.FindAllString(s, -1)...)
		case <-time.After(5 * time.Second):
			t.Fatal("the requests were not texted")
		}
	}
	if len(guesses) == 0 {
		t.Fatal("the low request carried no code to replay")
	}
	for _, g := range append(guesses, "", "000000", "123456") {
		text := "YES " + id
		if g != "" {
			text += " " + g
		}
		sock.call(t, bridgeproto.OpInbound, bridgeproto.Inbound{Line: bridgeproto.LineOwner, From: ownerNum, Text: text}, nil)
	}
	time.Sleep(300 * time.Millisecond)
	mu.Lock()
	for _, d := range decided {
		if d.Ref == "high" && d.Approved {
			t.Fatalf("a forged text approved the high-tier item: %+v", d)
		}
	}
	mu.Unlock()
	// The same path approves it with the owner's code generator, so the
	// refusals above are the tier's, not a broken path.
	id, err = ch.Request([]owner.Item{high}, 0)
	if err != nil {
		t.Fatal(err)
	}
	<-seen
	sock.call(t, bridgeproto.OpInbound, bridgeproto.Inbound{Line: bridgeproto.LineOwner, From: ownerNum,
		Text: "YES " + id + " " + owner.TOTP([]byte("12345678901234567890"), time.Now())}, nil)
	for deadline := time.Now().Add(5 * time.Second); ; time.Sleep(20 * time.Millisecond) {
		mu.Lock()
		ok := len(decided) > 0 && decided[len(decided)-1].Ref == "high" && decided[len(decided)-1].Approved
		mu.Unlock()
		if ok {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("the owner's code generator did not approve through the bridge")
		}
	}
}
