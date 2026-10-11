package owner

import (
	"context"
	"testing"
	"time"
)

// REQ: CH-16, ADP-2

// TestUndoHookTakesOnlyTheChannelsMisses: an UNDO for a queued auto-reply
// or a released one is the channel's, exactly as without a hook; only an
// ID the channel does not hold goes to the hook (SR3-mail-w2 W2-d). The
// hook's reply is sent as it is, whatever its wording, and it runs outside
// the channel's lock.
func TestUndoHookTakesOnlyTheChannelsMisses(t *testing.T) {
	r := newRig(t, nil)
	if got := r.say("UNDO KQZ"); got != "Nothing to undo for KQZ." {
		t.Fatalf("no hook: %q", got)
	}
	var asked []string
	r.ch.SetUndo(func(_ context.Context, id string) (string, bool) {
		asked = append(asked, id)
		// Outside the lock: a call back into the channel does not block.
		r.ch.UndoneAfterRelease(id)
		switch id {
		case "KQZ":
			return "Restored 2; 1 skipped (changed since).", true
		case "KQX":
			// Wording the channel uses for its own replies decides nothing.
			return "Nothing to undo for KQX.", true
		}
		return "", false
	})

	res, err := r.ch.QueueAutoReply(AutoReply{Ref: "r1", Recipients: []string{"sam@example.com"}, Body: "Thanks Sam, got it."})
	if err != nil || res.Queued == nil {
		t.Fatalf("%+v %v", res, err)
	}
	r.inbox()
	id := res.Queued.ID
	if got := r.say("UNDO " + id); got != "Cancelled "+id+". The reply was not sent." {
		t.Fatalf("queued: %q", got)
	}
	res, _ = r.ch.QueueAutoReply(AutoReply{Ref: "r2", Recipients: []string{"sam@example.com"}, Body: "Sounds good."})
	r.inbox()
	r.advance(10 * time.Minute)
	if due := r.ch.DueAutoReplies(); len(due) != 1 {
		t.Fatalf("due %+v", due)
	}
	if got := r.say("UNDO " + res.Queued.ID); got != res.Queued.ID+" is past its undo window; it was released." {
		t.Fatalf("released: %q", got)
	}
	if len(asked) != 0 {
		t.Fatalf("the hook was asked for the channel's own IDs: %q", asked)
	}

	if got := r.say("UNDO KQZ"); got != "Restored 2; 1 skipped (changed since)." {
		t.Fatalf("hook: %q", got)
	}
	if got := r.say("undo kqx"); got != "Nothing to undo for KQX." {
		t.Fatalf("hook's own wording: %q", got)
	}
	if got := r.say("UNDO KQY"); got != "Nothing to undo for KQY." {
		t.Fatalf("hook miss: %q", got)
	}
	if len(asked) != 3 || asked[0] != "KQZ" || asked[1] != "KQX" || asked[2] != "KQY" {
		t.Fatalf("asked %q", asked)
	}
}
