package main

// REQ: ARC-6 (DEL-1b, DEL-1e)

import (
	"context"
	"fmt"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/guest"
)

// fakeOutbox stands in for the guest plane's outbox.
type fakeOutbox struct {
	mu      sync.Mutex
	pending []guest.PendingReply
	sent    func() []string
	early   []string // replies retired before they were sent
}

func (f *fakeOutbox) PendingReplies() []guest.PendingReply {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.pending)
}

func (f *fakeOutbox) ReplyDone(machine, id string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	for i, p := range f.pending {
		if p.Machine == machine && p.ID == id {
			if !slices.Contains(f.sent(), p.Text) {
				f.early = append(f.early, id)
			}
			f.pending = slices.Delete(f.pending, i, i+1)
			return nil
		}
	}
	return nil
}

func (f *fakeOutbox) add(text string) {
	f.mu.Lock()
	f.pending = append(f.pending, guest.PendingReply{Machine: "agent", Private: true, Reply: guest.Reply{ID: "id" + text, Text: text}})
	f.mu.Unlock()
}

// DEL-1b: replies already waiting when agentosd starts (a crash left
// them) go out first, in the order the guests sent them, then each new
// one as it is poked; each leaves the outbox only after it went out.
func TestDEL1OutboxDrainsInOrder(t *testing.T) {
	r := newEvRig(t, "")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	src := &fakeOutbox{sent: r.texts}
	for i := 0; i < 3; i++ {
		src.add(fmt.Sprint(i))
	}
	r.ev.wake = make(chan struct{}, 1)
	go r.ev.run(ctx)
	r.ev.serve(src)
	for i := 3; i < 6; i++ {
		src.add(fmt.Sprint(i))
		r.ev.poke()
	}
	deadline := time.Now().Add(5 * time.Second)
	for (len(r.texts()) < 6 || len(src.PendingReplies()) > 0) && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if got := r.texts(); !slices.Equal(got, []string{"0", "1", "2", "3", "4", "5"}) {
		t.Fatalf("order %q", got)
	}
	if len(src.PendingReplies()) != 0 || len(src.early) != 0 {
		t.Fatalf("left %d, retired before sent %q", len(src.PendingReplies()), src.early)
	}
}

type waitingReplies bool

func (w waitingReplies) RepliesWaiting() bool { return bool(w) }

// DEL-1e: while the outbox refuses replies, STATUS says so.
func TestDEL1StatusSaysRepliesWait(t *testing.T) {
	l := &lateStatus{off: agentNoMachines}
	if l.Status() != agentNoMachines {
		t.Fatal(l.Status())
	}
	l.replies.Store(&replyWait{waitingReplies(true)})
	if l.Status() != repliesWaiting {
		t.Fatal(l.Status())
	}
	l.replies.Store(&replyWait{waitingReplies(false)})
	if l.Status() != agentNoMachines {
		t.Fatal(l.Status())
	}
}
