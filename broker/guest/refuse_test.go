package guest

// REQ: CH-11

import (
	"strings"
	"sync/atomic"
	"testing"
)

// CH-11 (#2196): a reply the broker refuses goes back to the guest in the
// answer to its POST, as a 400 the bridge does not retry, carrying the
// check's words; nothing is stored or queued and the message is still
// open, so a text reply to it then goes through. The check sees the
// summary too, which the owner may be texted instead of the reply.
func TestReplyCheckRefusesBeforeTheStore(t *testing.T) {
	shortPoll(t)
	var wakes atomic.Int64
	r := outboxRig(t, "", "", &wakes)
	r.client("m1")
	r.p.CheckReplies(func(text string) string {
		if strings.HasPrefix(text, "Liked ") {
			return "agent reactions are refused; reply in text"
		}
		return ""
	})
	a := r.hand("m1", "book the dentist")
	code, body := r.do("m1", "POST", "/owner/reply", reply(a, `Liked "book the dentist"`))
	if code != 400 || strings.TrimSpace(body) != "agent reactions are refused; reply in text" {
		t.Fatalf("reaction: %d %q", code, body)
	}
	code, body = r.do("m1", "POST", "/owner/reply", `{"id":"`+a+`","text":"booked","summary":"Liked \"book the dentist\""}`)
	if code != 400 || !strings.Contains(body, "reply in text") {
		t.Fatalf("reaction summary: %d %q", code, body)
	}
	if wakes.Load() != 0 || len(r.p.PendingReplies()) != 0 {
		t.Fatalf("refused reply queued: wakes %d, pending %d", wakes.Load(), len(r.p.PendingReplies()))
	}
	if code, body := r.do("m1", "POST", "/owner/reply", reply(a, "booked for Tuesday")); code != 204 {
		t.Fatalf("text reply after the refusal: %d %s", code, body)
	}
	if got := r.p.PendingReplies(); wakes.Load() != 1 || len(got) != 1 || got[0].Text != "booked for Tuesday" {
		t.Fatalf("text reply: wakes %d, pending %+v", wakes.Load(), got)
	}
}
