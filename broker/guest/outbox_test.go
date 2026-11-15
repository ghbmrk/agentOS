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
	// A directory at the store's path fails the rename, even for root.
	os.Remove(path)
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	if code, _ := r.do("m1", "POST", "/owner/reply", reply(id, "booked")); code != 503 {
		t.Fatalf("failed store: %d", code)
	}
	if !r.p.OwnerPending("m1") || len(r.p.PendingReplies()) != 0 || wakes.Load() != 0 {
		t.Fatal("a reply that was not stored was taken")
	}
	os.Remove(path)
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

// REQ: CAP-3 (DEL-1-f1a)
// DEL-1-f1a: a deletion drops every reply waiting in the outbox in one
// durable write. After a reopen none is pending, and a guest that
// retries a dropped reply gets a 204 that queues nothing.
func TestDEL1f1ForgetDropsWaitingReplies(t *testing.T) {
	shortPoll(t)
	path := filepath.Join(t.TempDir(), "inbox.json")
	var wakes atomic.Int64
	r := outboxRig(t, path, "", &wakes)
	r.client("m1")
	r.client("m2")
	a := r.hand("m1", "book the dentist")
	b := r.hand("m2", "and the vet")
	for _, c := range []struct{ machine, body string }{
		{"m1", reply(a, "canary-del1f1-a booked")},
		{"m2", reply(b, "canary-del1f1-b vet on Friday")},
	} {
		if code, _ := r.do(c.machine, "POST", "/owner/reply", c.body); code != 204 {
			t.Fatalf("reply: %d", code)
		}
	}
	if len(r.p.PendingReplies()) != 2 {
		t.Fatalf("outbox %+v", r.p.PendingReplies())
	}
	if err := r.p.ForgetReplies(); err != nil {
		t.Fatal(err)
	}
	if got := r.p.PendingReplies(); len(got) != 0 {
		t.Fatalf("after forget: %+v", got)
	}
	if raw, err := os.ReadFile(path); err != nil || strings.Contains(string(raw), "canary-del1f1") {
		t.Fatalf("store still holds a dropped reply: %v %s", err, raw)
	}
	r.p.Shutdown()

	w := wakes.Load()
	r2 := outboxRig(t, path, r.p.cfg.Dir, &wakes)
	if got := r2.p.PendingReplies(); len(got) != 0 {
		t.Fatalf("after reopen: %+v", got)
	}
	r2.client("m1")
	if code, _ := r2.do("m1", "POST", "/owner/reply", reply(a, "canary-del1f1-a booked")); code != 204 {
		t.Fatalf("retry: %d", code)
	}
	if got := r2.p.PendingReplies(); len(got) != 0 || wakes.Load() != w {
		t.Fatalf("a retry was queued again: %+v, wakes %d", got, wakes.Load()-w)
	}
	if code, _ := r2.do("m1", "GET", "/owner/next", ""); code != 204 {
		t.Fatal("a dropped reply's message was handed out again")
	}
}

// DEL-1-f1a: a forget whose write fails says so and still holds nothing
// it dropped in memory.
func TestDEL1f1ForgetWriteFailure(t *testing.T) {
	path := filepath.Join(t.TempDir(), "inbox.json")
	var wakes atomic.Int64
	r := outboxRig(t, path, "", &wakes)
	r.client("m1")
	a := r.hand("m1", "book the dentist")
	if code, _ := r.do("m1", "POST", "/owner/reply", reply(a, "booked")); code != 204 {
		t.Fatalf("reply: %d", code)
	}
	r.p.store.path = filepath.Join(path, "not-a-dir", "inbox.json")
	if err := r.p.ForgetReplies(); err == nil {
		t.Fatal("a failed write was not reported")
	}
	if got := r.p.PendingReplies(); len(got) != 0 {
		t.Fatalf("held after a failed forget: %+v", got)
	}
}

// REQ: CAP-3 (DEL-1-f1a)
// DEL-1-f1a (#2361): a forget whose write failed is not done until a
// write succeeds. Its retry writes even though memory already holds
// nothing, reports the failure while the store is still unwritable, and
// once it succeeds a reopen from disk holds no dropped reply.
func TestDEL1f1ForgetRetryAfterFailedWrite(t *testing.T) {
	path := filepath.Join(t.TempDir(), "inbox.json")
	var wakes atomic.Int64
	r := outboxRig(t, path, "", &wakes)
	r.client("m1")
	a := r.hand("m1", "book the dentist")
	if code, _ := r.do("m1", "POST", "/owner/reply", reply(a, "canary-2361 booked")); code != 204 {
		t.Fatalf("reply: %d", code)
	}
	good := r.p.store.path
	r.p.store.path = filepath.Join(path, "not-a-dir", "inbox.json")
	for i := 0; i < 2; i++ {
		if err := r.p.ForgetReplies(); err == nil {
			t.Fatalf("forget %d reported done before a write succeeded", i)
		}
	}
	r.p.store.path = good
	if err := r.p.ForgetReplies(); err != nil {
		t.Fatal(err)
	}
	if raw, err := os.ReadFile(path); err != nil || strings.Contains(string(raw), "canary-2361") {
		t.Fatalf("store still holds a dropped reply: %v %s", err, raw)
	}
	// The successful write cleared the mark: with nothing waiting, a
	// forget does not write, so an unwritable store is not an error.
	r.p.store.path = filepath.Join(path, "not-a-dir", "inbox.json")
	if err := r.p.ForgetReplies(); err != nil {
		t.Fatalf("a forget with nothing to drop wrote again: %v", err)
	}
	r.p.store.path = good
	r.p.Shutdown()
	r2 := outboxRig(t, path, r.p.cfg.Dir, &wakes)
	if got := r2.p.PendingReplies(); len(got) != 0 {
		t.Fatalf("after reopen: %+v", got)
	}
}

// REQ: CAP-3 (DEL-1-f1a)
// DEL-1-f1a (#2361): a ReplyDone whose write failed leaves the reply in
// the file though not in memory; a later forget still writes, so a
// reopen holds no reply the deletion dropped.
func TestDEL1f1ForgetAfterFailedReplyDone(t *testing.T) {
	path := filepath.Join(t.TempDir(), "inbox.json")
	var wakes atomic.Int64
	r := outboxRig(t, path, "", &wakes)
	r.client("m1")
	a := r.hand("m1", "book the dentist")
	if code, _ := r.do("m1", "POST", "/owner/reply", reply(a, "canary-2361-retire booked")); code != 204 {
		t.Fatalf("reply: %d", code)
	}
	good := r.p.store.path
	r.p.store.path = filepath.Join(path, "not-a-dir", "inbox.json")
	if err := r.p.ReplyDone("m1", a); err == nil {
		t.Fatal("a failed write was not reported")
	}
	r.p.store.path = good
	if err := r.p.ForgetReplies(); err != nil {
		t.Fatal(err)
	}
	if raw, err := os.ReadFile(path); err != nil || strings.Contains(string(raw), "canary-2361-retire") {
		t.Fatalf("store still holds a dropped reply: %v %s", err, raw)
	}
	r.p.Shutdown()
	r2 := outboxRig(t, path, r.p.cfg.Dir, &wakes)
	if got := r2.p.PendingReplies(); len(got) != 0 {
		t.Fatalf("after reopen: %+v", got)
	}
}

func TestOwnerMutStoredMessagesRaiseTheLabelOnce(t *testing.T) {
	// The TestOwnerMut tests each fail when one owner.go statement that
	// mutgate found unchecked is deleted (GUEST-mut-owner, #5749). Here:
	// messages loaded from the store raise the label before the first
	// fetch, and only then (owner.go:127, 302).
	shortPoll(t)
	path := filepath.Join(t.TempDir(), "inbox.json")
	var wakes atomic.Int64
	r := outboxRig(t, path, "", &wakes)
	r.client("m1")
	id, err := r.p.DeliverOwner("m1", "book the dentist", true)
	if err != nil {
		t.Fatal(err)
	}
	r.p.Shutdown()
	r2 := outboxRig(t, path, r.p.cfg.Dir, &wakes)
	r2.client("m1")
	if code, body := r2.do("m1", "GET", "/owner/next", ""); code != 200 || !strings.Contains(body, id) {
		t.Fatalf("stored message: %d %s", code, body)
	}
	if code, _ := r2.do("m1", "GET", "/owner/next", ""); code != 204 {
		t.Fatalf("second fetch: %d", code)
	}
	r2.ms.mu.Lock()
	defer r2.ms.mu.Unlock()
	raised := 0
	for _, e := range r2.ms.events {
		if e == "private m1" {
			raised++
		}
	}
	if raised != 1 {
		t.Fatalf("the label was raised %d times for one stored message; want 1 (%v)", raised, r2.ms.events)
	}
}

func TestOwnerMutClosedInboxTakesAndHandsOutNothing(t *testing.T) {
	// owner.go:143, 164, 308: a closed inbox refuses a new message, hands
	// out none it holds, and its fetch is a 503 at once, not a 204 after
	// the poll.
	pollWait = 5 * time.Second
	t.Cleanup(func() { pollWait = 25 * time.Second })
	r := newRig(t, nil)
	r.client("m1")
	if _, err := r.p.DeliverOwner("m1", "book the dentist", true); err != nil {
		t.Fatal(err)
	}
	box := r.p.get("m1").box
	box.close(false)
	if err := box.put(&ownerMsg{ID: "late", Text: "one more"}); err == nil {
		t.Fatal("a closed inbox took a message")
	}
	start := time.Now()
	if code, body := r.do("m1", "GET", "/owner/next", ""); code != 503 || !strings.Contains(body, "machine closed") {
		t.Fatalf("fetch from a closed inbox: %d %s", code, body)
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("a closed inbox's fetch waited %v", d)
	}
	if m, wait := box.next(); m != nil || wait != nil {
		t.Fatalf("a closed inbox handed out %+v, wait %v", m, wait)
	}
}

func TestOwnerMutFullInboxRefuses(t *testing.T) {
	// owner.go:146: the inbox holds inboxSize unanswered messages, no more.
	r := newRig(t, nil)
	r.client("m1")
	for i := 0; i < inboxSize; i++ {
		if _, err := r.p.DeliverOwner("m1", fmt.Sprint("task ", i), true); err != nil {
			t.Fatalf("message %d: %v", i, err)
		}
	}
	if _, err := r.p.DeliverOwner("m1", "one too many", true); err == nil {
		t.Fatal("a full inbox took a message")
	}
	box := r.p.get("m1").box
	if err := box.put(&ownerMsg{ID: "late", Text: "one too many"}); err != ErrInboxFull {
		t.Fatalf("full inbox: %v; want ErrInboxFull", err)
	}
	box.mu.Lock()
	n := len(box.msgs)
	box.mu.Unlock()
	if n != inboxSize {
		t.Fatalf("inbox holds %d; want %d", n, inboxSize)
	}
}

func TestOwnerMutAnswerTakesOnlyItsMessage(t *testing.T) {
	// owner.go:203, 208, 209: a reply removes its own message, and the
	// others stay stored with their IDs and texts.
	shortPoll(t)
	path := filepath.Join(t.TempDir(), "inbox.json")
	var wakes atomic.Int64
	r := outboxRig(t, path, "", &wakes)
	r.client("m1")
	a := r.hand("m1", "book the dentist")
	b := r.hand("m1", "renew the passport")
	if code, _ := r.do("m1", "POST", "/owner/reply", reply(b, "renewed")); code != 204 {
		t.Fatalf("reply: %d", code)
	}
	if got := r.p.get("m1").box.handed(); len(got) != 1 || got[0] != a {
		t.Fatalf("handed after answering %s: %v; want [%s]", b, got, a)
	}
	r.p.Shutdown()
	r2 := outboxRig(t, path, r.p.cfg.Dir, &wakes)
	r2.client("m1")
	code, body := r2.do("m1", "GET", "/owner/next", "")
	var got ownerMsg
	if code != 200 || json.Unmarshal([]byte(body), &got) != nil || got.ID != a || got.Text != "book the dentist" {
		t.Fatalf("after reopen: %d %s; want %s with its text", code, body, a)
	}
	if code, body := r2.do("m1", "GET", "/owner/next", ""); code != 204 {
		t.Fatalf("after reopen, a second message: %d %s", code, body)
	}
}

func TestOwnerMutStoreErrorsAreLogged(t *testing.T) {
	// owner.go:266, 363: a failed inbox write is logged with its cause,
	// on delivery and on a reply.
	path := filepath.Join(t.TempDir(), "inbox.json")
	logs := make(chan string, 64)
	r := newRig(t, func(c *Config) {
		c.InboxPath = path
		c.Logf = func(f string, a ...any) {
			select {
			case logs <- fmt.Sprintf(f, a...):
			default:
			}
		}
	})
	r.client("m1")
	id := r.hand("m1", "book the dentist")
	// A directory at the store's path fails the rename, even for root.
	os.Remove(path)
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	logged := func(want string) bool {
		for {
			select {
			case l := <-logs:
				if strings.Contains(l, want) {
					return true
				}
			default:
				return false
			}
		}
	}
	if _, err := r.p.DeliverOwner("m1", "renew the passport", true); err == nil {
		t.Fatal("a failed store took a message")
	}
	if !logged("guest m1: inbox store: ") {
		t.Fatal("a failed delivery write was not logged")
	}
	code, body := r.do("m1", "POST", "/owner/reply", reply(id, "booked"))
	if code != 503 || !strings.Contains(body, "reply not stored; retry") {
		t.Fatalf("failed reply write: %d %s", code, body)
	}
	if !logged("guest m1: inbox store: ") {
		t.Fatal("a failed reply write was not logged")
	}
}

func TestOwnerMutRoutesTakeOneMethod(t *testing.T) {
	// owner.go:291, 293, 314, 328: a fetch is a GET whose message is JSON,
	// a reply a POST; a refused fetch hands nothing out.
	shortPoll(t)
	r := newRig(t, nil)
	r.client("m1")
	id, err := r.p.DeliverOwner("m1", "book the dentist", true)
	if err != nil {
		t.Fatal(err)
	}
	if code, _ := r.do("m1", "POST", "/owner/next", ""); code != 405 {
		t.Fatalf("POST /owner/next: %d; want 405", code)
	}
	if got := r.p.get("m1").box.handed(); len(got) != 0 {
		t.Fatalf("a refused fetch handed out %v", got)
	}
	if code, _ := r.do("m1", "GET", "/owner/reply", reply(id, "booked")); code != 405 {
		t.Fatalf("GET /owner/reply: %d; want 405", code)
	}
	resp, err := r.client("m1").Get("http://broker/owner/next")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 || resp.Header.Get("Content-Type") != "application/json" {
		t.Fatalf("fetch: %d, Content-Type %q", resp.StatusCode, resp.Header.Get("Content-Type"))
	}
}

func TestOwnerMutSummaryCutsAtARuneStart(t *testing.T) {
	// owner.go:341: a summary cut at MaxSummary bytes keeps whole runes.
	r := newRig(t, nil)
	r.client("m1")
	id := r.hand("m1", "book the dentist")
	long := strings.Repeat("a", MaxSummary-1) + "é and more"
	if code, _ := r.do("m1", "POST", "/owner/reply", fmt.Sprintf(`{"id":%q,"text":"booked","summary":%q}`, id, long)); code != 204 {
		t.Fatalf("reply: %d", code)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	want := "m1 " + id + " booked|" + strings.Repeat("a", MaxSummary-1)
	if len(r.reps) != 1 || r.reps[0] != want {
		t.Fatalf("replies %q; want [%q]", r.reps, want)
	}
}

func TestOwnerMutOutboxKeepsThePublicLabel(t *testing.T) {
	// owner.go:351, 352: a reply from a machine labelled public is kept as
	// not private; one from a private machine as private.
	r := newRig(t, func(c *Config) {
		c.Label = func(id string) string {
			if id == "pub" {
				return "public"
			}
			return "private"
		}
		c.Replies = func() {}
	})
	for _, m := range []string{"pub", "priv"} {
		r.client(m)
		id, err := r.p.DeliverOwner(m, "book the dentist", true)
		if err != nil {
			t.Fatal(err)
		}
		r.do(m, "GET", "/owner/next", "")
		if code, _ := r.do(m, "POST", "/owner/reply", reply(id, "booked")); code != 204 {
			t.Fatalf("%s reply: %d", m, code)
		}
	}
	got := r.p.PendingReplies()
	if len(got) != 2 || got[0].Machine != "pub" || got[0].Private || got[1].Machine != "priv" || !got[1].Private {
		t.Fatalf("outbox %+v; want pub not private, then priv private", got)
	}
}

func TestOwnerMutFullOutboxSaysSo(t *testing.T) {
	// owner.go:358, 359: a reply refused because the outbox is full is
	// logged and answered as such, not as a failed write.
	logs := make(chan string, 4*MaxOutbox)
	var wakes atomic.Int64
	r := newRig(t, func(c *Config) {
		c.Label = func(string) string { return "private" }
		c.Replies = func() { wakes.Add(1) }
		// Each rig request dials anew; room for them all keeps the test fast.
		c.MaxOpenConns = 4 * MaxOutbox
		c.Logf = func(f string, a ...any) {
			select {
			case logs <- fmt.Sprintf(f, a...):
			default:
			}
		}
	})
	for i := 0; i < MaxOutbox; i++ {
		m := fmt.Sprintf("m%d", i/inboxSize)
		r.client(m)
		id := r.hand(m, fmt.Sprint("task ", i))
		if code, _ := r.do(m, "POST", "/owner/reply", reply(id, fmt.Sprint("done ", i))); code != 204 {
			t.Fatalf("reply %d: %d", i, code)
		}
	}
	r.client("late")
	id := r.hand("late", "one more")
	code, body := r.do("late", "POST", "/owner/reply", reply(id, "done late"))
	if code != 503 || !strings.Contains(body, "replies waiting; retry") {
		t.Fatalf("full outbox: %d %s", code, body)
	}
	want := fmt.Sprintf("guest late: reply outbox full (%d waiting); the guest will retry", MaxOutbox)
	for {
		select {
		case l := <-logs:
			if l == want {
				return
			}
		default:
			t.Fatalf("no log line %q", want)
		}
	}
}

func TestOwnerMutNilCheckRefusesNothing(t *testing.T) {
	// owner.go:390: CheckReplies(nil) removes the check set before it.
	r := newRig(t, nil)
	r.client("m1")
	r.p.CheckReplies(func(string) string { return "refused" })
	r.p.CheckReplies(nil)
	id := r.hand("m1", "book the dentist")
	if code, body := r.do("m1", "POST", "/owner/reply", reply(id, "booked")); code != 204 {
		t.Fatalf("reply after the check was removed: %d %s", code, body)
	}
}

func TestOwnerMutLineageIsCachedOnlyWhenKnown(t *testing.T) {
	// goal.go:25, 26, 29, which an owner delivery runs (taken here off
	// GUEST-mut-dispatch, #5750): a known lineage is cached, so the manager
	// is asked once; an unknown one is not, so it is asked again.
	r := newRig(t, nil)
	r.client("m1")
	r.client("m2")
	set := func(f func()) { r.ms.mu.Lock(); f(); r.ms.mu.Unlock() }
	set(func() { r.ms.lineage["m1"] = "first"; r.ms.gone["m2"] = true })
	m1, m2 := r.p.get("m1"), r.p.get("m2")
	if l := r.p.lineageOf(m1); l != "first" {
		t.Fatalf("lineage %q; want first", l)
	}
	if l := r.p.lineageOf(m2); l != "" {
		t.Fatalf("an unknown machine's lineage %q; want none", l)
	}
	set(func() { r.ms.lineage["m1"] = "second"; r.ms.lineage["m2"] = "later"; delete(r.ms.gone, "m2") })
	if l := r.p.lineageOf(m1); l != "first" {
		t.Fatalf("a cached lineage became %q; want first", l)
	}
	if l := r.p.lineageOf(m2); l != "later" {
		t.Fatalf("a lineage the manager now knows is %q; want later", l)
	}
}
