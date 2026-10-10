package guest

// REQ: ARC-6 (DEL-1a, DEL-1b, DEL-1c, DEL-1e)

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// outboxRig is a plane whose replies wait in the outbox for a consumer
// (Config.Replies), as agentosd runs it.
func outboxRig(t *testing.T, path string, dir string, wakes *atomic.Int64) *rig {
	t.Helper()
	return newRig(t, func(c *Config) {
		c.InboxPath = path
		if dir != "" {
			c.Dir = dir
		}
		c.Label = func(string) string { return "private" }
		c.Replies = func() { wakes.Add(1) }
	})
}

func shortPoll(t *testing.T) {
	pollWait = 100 * time.Millisecond
	t.Cleanup(func() { pollWait = 25 * time.Second })
}

func reply(id, text string) string {
	return fmt.Sprintf(`{"id":%q,"text":%q}`, id, text)
}

// hand delivers text to machine and has its guest fetch it.
func (r *rig) hand(machine, text string) string {
	r.t.Helper()
	id, err := r.p.DeliverOwner(machine, text, false)
	if err != nil {
		r.t.Fatal(err)
	}
	if code, body := r.do(machine, "GET", "/owner/next", ""); code != 200 || !strings.Contains(body, id) {
		r.t.Fatalf("next: %d %s", code, body)
	}
	return id
}

// DEL-1a, DEL-1b: a reply the broker answered 204 is on disk before the
// 204, so a crash before the evidence worker runs loses nothing: after
// the reopen the reply is still waiting, in receive order, the message
// is not handed out again, and it leaves only when the consumer is done.
func TestDEL1ReplySurvivesACrashAfterTheAck(t *testing.T) {
	shortPoll(t)
	path := filepath.Join(t.TempDir(), "inbox.json")
	var wakes atomic.Int64
	r := outboxRig(t, path, "", &wakes)
	r.client("m1")
	a := r.hand("m1", "book the dentist")
	if code, _ := r.do("m1", "POST", "/owner/reply", reply(a, "booked for Tuesday")); code != 204 {
		t.Fatalf("reply: %d", code)
	}
	b := r.hand("m1", "and the vet")
	if code, _ := r.do("m1", "POST", "/owner/reply", `{"id":"`+b+`","text":"vet on Friday","summary":"  Vet\n Friday "}`); code != 204 {
		t.Fatalf("reply: %d", code)
	}
	if wakes.Load() != 2 || len(r.reps) != 0 {
		t.Fatalf("wakes %d, direct replies %q", wakes.Load(), r.reps)
	}
	if fi, err := os.Stat(path); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("store %v %v", fi, err)
	}
	r.p.Shutdown() // the crash: nobody took the replies

	r2 := outboxRig(t, path, r.p.cfg.Dir, &wakes)
	got := r2.p.PendingReplies()
	if len(got) != 2 || got[0].ID != a || got[0].Text != "booked for Tuesday" || got[1].ID != b || got[1].Summary != "Vet Friday" {
		t.Fatalf("after restart: %+v", got)
	}
	if got[0].Machine != "m1" || !got[0].Private || got[0].At.IsZero() {
		t.Fatalf("entry %+v", got[0])
	}
	r2.client("m1")
	if code, body := r2.do("m1", "GET", "/owner/next", ""); code != 204 {
		t.Fatalf("an answered message came back: %s", body)
	}
	if r2.p.OwnerPending("m1") {
		t.Fatal("answered messages still pending")
	}
	if err := r2.p.ReplyDone("m1", a); err != nil {
		t.Fatal(err)
	}
	r2.p.Shutdown()

	r3 := outboxRig(t, path, r.p.cfg.Dir, &wakes)
	if got := r3.p.PendingReplies(); len(got) != 1 || got[0].ID != b {
		t.Fatalf("after done: %+v", got)
	}
}

// DEL-1a, DEL-1c: a store left with the message still pending and its
// reply in the outbox (a crash between the two writes, were they two)
// sends the reply once: the message is not handed out again, and the
// guest's repeated POST is a 204 that changes nothing.
func TestDEL1CrashBetweenOutboxAndInboxSendsOnce(t *testing.T) {
	shortPoll(t)
	path := filepath.Join(t.TempDir(), "inbox.json")
	var wakes atomic.Int64
	r := outboxRig(t, path, "", &wakes)
	r.client("m1")
	id := r.hand("m1", "book the dentist")
	if code, _ := r.do("m1", "POST", "/owner/reply", reply(id, "booked")); code != 204 {
		t.Fatalf("reply: %d", code)
	}
	r.p.Shutdown()
	// Put the message back in the inbox, as if the inbox write was lost.
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var f map[string]json.RawMessage
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	f["inbox"], _ = json.Marshal(map[string][]storedMsg{"m1": {{ID: id, Text: "book the dentist"}}})
	raw, _ = json.Marshal(f)
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}

	r2 := outboxRig(t, path, r.p.cfg.Dir, &wakes)
	r2.client("m1")
	if code, body := r2.do("m1", "GET", "/owner/next", ""); code != 204 {
		t.Fatalf("the answered message was handed out again: %s", body)
	}
	if code, _ := r2.do("m1", "POST", "/owner/reply", reply(id, "booked")); code != 204 {
		t.Fatalf("repeat: %d", code)
	}
	if got := r2.p.PendingReplies(); len(got) != 1 {
		t.Fatalf("outbox %+v", got)
	}
}

// DEL-1a: a store write failure is a 503 and the message stays pending,
// so the guest's retry lands once the store is writable again.
func TestDEL1StoreFailureLeavesTheMessagePending(t *testing.T) {
	path := filepath.Join(t.TempDir(), "inbox.json")
	var wakes atomic.Int64
	r := outboxRig(t, path, "", &wakes)
	r.client("m1")
	id := r.hand("m1", "book the dentist")
	// The store writes through path.tmp: a directory there fails it,
	// even for root.
	if err := os.Mkdir(path+".tmp", 0o700); err != nil {
		t.Fatal(err)
	}
	if code, _ := r.do("m1", "POST", "/owner/reply", reply(id, "booked")); code != 503 {
		t.Fatalf("failed store: %d", code)
	}
	if !r.p.OwnerPending("m1") || len(r.p.PendingReplies()) != 0 || wakes.Load() != 0 {
		t.Fatal("a reply that was not stored was taken")
	}
	os.Remove(path + ".tmp")
	if code, _ := r.do("m1", "POST", "/owner/reply", reply(id, "booked")); code != 204 {
		t.Fatalf("retry: %d", code)
	}
	if r.p.OwnerPending("m1") || len(r.p.PendingReplies()) != 1 {
		t.Fatal("retry not taken")
	}
}

// DEL-1c: a reply is applied once. The same body again is a 204 no-op,
// while waiting and after it is done; a different body is a 409; another
// machine naming the ID gets 404, as does an ID never handed out.
func TestDEL1ReplyIsAppliedOnce(t *testing.T) {
	path := filepath.Join(t.TempDir(), "inbox.json")
	var wakes atomic.Int64
	r := outboxRig(t, path, "", &wakes)
	r.client("m1")
	r.client("m2")
	id := r.hand("m1", "book the dentist")
	for i, c := range []struct {
		machine, body string
		code          int
	}{
		{"m1", reply(id, "booked"), 204},
		{"m1", reply(id, "booked"), 204},
		{"m1", reply(id, "booked twice"), 409},
		{"m1", `{"id":"` + id + `","text":"booked","summary":"other"}`, 409},
		{"m2", reply(id, "booked"), 404},
		{"m1", reply("000000000000", "booked"), 404},
	} {
		if code, _ := r.do(c.machine, "POST", "/owner/reply", c.body); code != c.code {
			t.Fatalf("case %d: %d, want %d", i, code, c.code)
		}
	}
	if got := r.p.PendingReplies(); len(got) != 1 || got[0].Text != "booked" || wakes.Load() != 1 {
		t.Fatalf("outbox %+v, wakes %d", got, wakes.Load())
	}
	r.p.ReplyDone("m1", id)
	if code, _ := r.do("m1", "POST", "/owner/reply", reply(id, "booked")); code != 204 {
		t.Fatalf("after done: %d", code)
	}
	if code, _ := r.do("m1", "POST", "/owner/reply", reply(id, "changed")); code != 409 {
		t.Fatalf("after done, changed: %d", code)
	}
	if len(r.p.PendingReplies()) != 0 || wakes.Load() != 1 {
		t.Fatal("a repeat was applied again")
	}
}

// DEL-1c without an outbox consumer: OwnerReply is told each reply once.
func TestDEL1DirectRepliesAreAppliedOnce(t *testing.T) {
	r := newRig(t, nil)
	r.client("m1")
	id := r.hand("m1", "book the dentist")
	for _, want := range []int{204, 204} {
		if code, _ := r.do("m1", "POST", "/owner/reply", reply(id, "booked")); code != want {
			t.Fatalf("reply: %d", code)
		}
	}
	if len(r.reps) != 1 || len(r.p.PendingReplies()) != 0 {
		t.Fatalf("replies %q", r.reps)
	}
}

// DEL-1e: the outbox is bounded. When it is full a reply is a 503 (the
// guest retries), the message stays pending, and RepliesWaiting says so;
// once the consumer finishes one, the retry is taken.
func TestDEL1FullOutboxRefusesWithoutLoss(t *testing.T) {
	path := filepath.Join(t.TempDir(), "inbox.json")
	var wakes atomic.Int64
	r := outboxRig(t, path, "", &wakes)
	var first string
	for i := 0; i < MaxOutbox; i++ {
		m := fmt.Sprintf("m%d", i/inboxSize)
		r.client(m)
		id := r.hand(m, fmt.Sprint("task ", i))
		if i == 0 {
			first = id
		}
		if code, _ := r.do(m, "POST", "/owner/reply", reply(id, fmt.Sprint("done ", i))); code != 204 {
			t.Fatalf("reply %d: %d", i, code)
		}
	}
	if r.p.RepliesWaiting() {
		t.Fatal("waiting before the outbox refused anything")
	}
	r.client("late")
	id := r.hand("late", "one more")
	if code, _ := r.do("late", "POST", "/owner/reply", reply(id, "done late")); code != 503 {
		t.Fatalf("full outbox: %d", code)
	}
	if !r.p.OwnerPending("late") || !r.p.RepliesWaiting() || len(r.p.PendingReplies()) != MaxOutbox {
		t.Fatal("full outbox lost or took the reply")
	}
	r.p.ReplyDone("m0", first)
	if code, _ := r.do("late", "POST", "/owner/reply", reply(id, "done late")); code != 204 {
		t.Fatalf("retry: %d", code)
	}
	got := r.p.PendingReplies()
	if len(got) != MaxOutbox || got[len(got)-1].ID != id {
		t.Fatalf("outbox after retry: %d", len(got))
	}
}
