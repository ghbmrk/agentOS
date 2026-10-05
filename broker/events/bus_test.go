package events

// REQ: CAP-4, CAP-3, REV-5, CRED-1

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/recall"
)

type recorder struct {
	mu   sync.Mutex
	got  []Delivery
	fail int // fail this many calls first
}

func (r *recorder) start(_ context.Context, d Delivery) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.fail > 0 {
		r.fail--
		return errors.New("busy")
	}
	r.got = append(r.got, d)
	return nil
}

func (r *recorder) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.got)
}

func mustOpen(t *testing.T, s recall.Store, ts []Trigger, opts ...Option) *Bus {
	t.Helper()
	b, err := Open(s, ts, opts...)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func mustPublish(t *testing.T, b *Bus, e Event) (string, bool) {
	t.Helper()
	id, fresh, err := b.Publish(e)
	if err != nil {
		t.Fatal(err)
	}
	return id, fresh
}

var ctx = context.Background()

func TestEventsTriggerMatchingWork(t *testing.T) {
	mail, all := &recorder{}, &recorder{}
	b := mustOpen(t, &recall.MemStore{}, []Trigger{
		{Name: "invoices", Kinds: []Kind{Mail}, Match: func(e Event) bool { return strings.Contains(e.Summary, "Invoice") }, Start: mail.start},
		{Name: "all", Start: all.start},
	})
	mustPublish(t, b, Event{Kind: Mail, Account: "owner@example.test", Ref: "<1@x>", Version: "<1@x>", Summary: "Invoice 42 from Acme"})
	mustPublish(t, b, Event{Kind: Mail, Account: "owner@example.test", Ref: "<2@x>", Version: "<2@x>", Summary: "Lunch?"})
	mustPublish(t, b, Event{Kind: File, Ref: "/home/o/report.odt", Version: "mtime-1"})
	mustPublish(t, b, Event{Kind: Calendar, Ref: "evt-9", Version: "etag-1"})
	mustPublish(t, b, Event{Kind: Web, Ref: "https://example.test/status", Version: "sha-a", Label: recall.Public})
	if n := b.Pump(ctx); n != 6 {
		t.Fatalf("want 6 deliveries, got %d", n)
	}
	if mail.count() != 1 || mail.got[0].Event.Summary != "Invoice 42 from Acme" {
		t.Fatalf("matching trigger: %+v", mail.got)
	}
	if all.count() != 5 || b.Pending() != 0 {
		t.Fatalf("all: %d pending %d", all.count(), b.Pending())
	}
	if d := mail.got[0]; d.Key != d.Event.ID+"/invoices" || d.Attempt != 1 {
		t.Fatalf("delivery key: %+v", d)
	}
}

func TestOnlyChangesCauseWork(t *testing.T) {
	r := &recorder{}
	b := mustOpen(t, &recall.MemStore{}, []Trigger{{Name: "watch", Kinds: []Kind{Web}, Start: r.start}})
	_, fresh := mustPublish(t, b, Event{Kind: Web, Ref: "https://example.test/p", Version: "h1"})
	_, again := mustPublish(t, b, Event{Kind: Web, Ref: "https://example.test/p", Version: "h1"})
	_, changed := mustPublish(t, b, Event{Kind: Web, Ref: "https://example.test/p", Version: "h2"})
	if !fresh || again || !changed {
		t.Fatalf("dedupe: %v %v %v", fresh, again, changed)
	}
	b.Pump(ctx)
	if r.count() != 2 {
		t.Fatalf("want 2 deliveries, got %d", r.count())
	}
}

func TestLabels(t *testing.T) {
	b := mustOpen(t, &recall.MemStore{}, nil)
	cases := []struct {
		e    Event
		want recall.Label
	}{
		{Event{Kind: Mail, Ref: "m", Label: recall.Public}, recall.Private},
		{Event{Kind: File, Ref: "f", Label: recall.Public}, recall.Private},
		{Event{Kind: Calendar, Ref: "c", Label: recall.Public}, recall.Private},
		{Event{Kind: Web, Ref: "w"}, recall.Private},
		{Event{Kind: Web, Ref: "w2", Label: recall.Public}, recall.Public},
		{Event{Kind: Timer, Ref: "t", Label: "public?"}, recall.Private},
	}
	r := &recorder{}
	b = mustOpen(t, &recall.MemStore{}, []Trigger{{Name: "r", Start: r.start}})
	for _, c := range cases {
		mustPublish(t, b, c.e)
	}
	b.Pump(ctx)
	for i, d := range r.got {
		if d.Event.Label != cases[i].want {
			t.Fatalf("%s/%s: label %q want %q", d.Event.Kind, d.Event.Ref, d.Event.Label, cases[i].want)
		}
	}
}

func TestDurableAcrossRestartAndRetries(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bus.jsonl")
	st, err := recall.OpenFile(path)
	if err != nil {
		t.Fatal(err)
	}
	r := &recorder{fail: 2}
	att := NewAttention()
	b := mustOpen(t, st, []Trigger{{Name: "w", Start: r.start}}, WithMaxAttempts(5), WithAttention(att))
	id, _ := mustPublish(t, b, Event{Kind: Mail, Ref: "<a@x>", Summary: "hello"})
	b.Pump(ctx) // fails once
	st.Close()

	// Restart: the pending delivery survives with its attempt count.
	st, _ = recall.OpenFile(path)
	b = mustOpen(t, st, []Trigger{{Name: "w", Start: r.start}}, WithMaxAttempts(5), WithAttention(att))
	if b.Pending() != 1 {
		t.Fatalf("pending after restart: %d", b.Pending())
	}
	b.Pump(ctx) // fails again
	b.Pump(ctx) // succeeds
	if r.count() != 1 || r.got[0].Attempt != 3 || r.got[0].Event.ID != id {
		t.Fatalf("retries: %+v", r.got)
	}
	// Republishing a delivered event after restart does nothing.
	st.Close()
	st, _ = recall.OpenFile(path)
	defer st.Close()
	b = mustOpen(t, st, []Trigger{{Name: "w", Start: r.start}})
	if _, fresh := mustPublish(t, b, Event{Kind: Mail, Ref: "<a@x>", Summary: "hello"}); fresh {
		t.Fatal("a delivered event must not be delivered again after restart")
	}
}

func TestDeadDeliveryGoesToDigest(t *testing.T) {
	att := NewAttention()
	bad := Trigger{Name: "flaky", Start: func(context.Context, Delivery) error { panic("boom") }}
	b := mustOpen(t, &recall.MemStore{}, []Trigger{bad}, WithMaxAttempts(2), WithAttention(att))
	mustPublish(t, b, Event{Kind: File, Ref: "/x"})
	b.Pump(ctx)
	b.Pump(ctx)
	if b.Pending() != 0 {
		t.Fatal("a delivery past its tries must stop")
	}
	notes, decisions := att.TakeDigest()
	if len(notes) != 1 || !strings.Contains(notes[0], "flaky") || len(decisions) != 0 {
		t.Fatalf("digest: %v %v", notes, decisions)
	}
}

func TestTimers(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bus.jsonl")
	st, _ := recall.OpenFile(path)
	r := &recorder{}
	trig := []Trigger{{Name: "t", Kinds: []Kind{Timer}, Start: r.start}}
	b := mustOpen(t, st, trig)
	t0 := time.Date(2026, 10, 5, 6, 0, 0, 0, time.UTC)
	sched := Schedule{Name: "daily-review", First: t0, Every: 24 * time.Hour, Summary: "review my week"}
	if err := b.AddTimer(sched); err != nil {
		t.Fatal(err)
	}
	b.Tick(t0.Add(-time.Minute))
	b.Tick(t0)
	b.Tick(t0.Add(time.Hour))
	b.Pump(ctx)
	if r.count() != 1 || r.got[0].Event.Label != recall.Private {
		t.Fatalf("first firing: %+v", r.got)
	}
	st.Close()
	// Down for three days: one coalesced firing, for the latest due time.
	st, _ = recall.OpenFile(path)
	defer st.Close()
	b = mustOpen(t, st, trig)
	b.AddTimer(sched)
	b.Tick(t0.Add(3*24*time.Hour + time.Hour))
	b.Tick(t0.Add(3*24*time.Hour + 2*time.Hour))
	b.Pump(ctx)
	if r.count() != 2 || !r.got[1].Event.At.Equal(t0.Add(3*24*time.Hour)) {
		t.Fatalf("coalesced firing: %+v", r.got)
	}
}

func TestEventsIndexedAndDeletionPropagates(t *testing.T) {
	dir := t.TempDir()
	busPath := filepath.Join(dir, "bus.jsonl")
	bst, _ := recall.OpenFile(busPath)
	defer bst.Close()
	ix, err := recall.Open(&recall.MemStore{})
	if err != nil {
		t.Fatal(err)
	}
	slow := &recorder{fail: 100}
	b := mustOpen(t, bst, []Trigger{IndexInto(ix), {Name: "slow", Start: slow.start}}, WithMaxAttempts(1000))
	ix.OnDelete(b.ForgetSource)

	mustPublish(t, b, Event{Kind: Mail, Account: "o@example.test", Ref: "<lab@x>", Summary: "Lab results", Body: "glucose quokkafruit normal"})
	b.Pump(ctx)
	rs := ix.Lookup(recall.Query{Text: "quokkafruit"})
	if len(rs) != 1 || rs[0].Source.Kind != "mail" || rs[0].Source.Ref != "<lab@x>" || rs[0].Label != recall.Private {
		t.Fatalf("event not indexed with provenance: %+v", rs)
	}
	// "slow" still holds a pending delivery carrying the content. Deleting
	// the item in recall must drop it from the bus and its store too.
	if b.Pending() != 1 {
		t.Fatalf("pending: %d", b.Pending())
	}
	if _, err := ix.Delete(rs[0].ID); err != nil {
		t.Fatal(err)
	}
	if b.Pending() != 0 {
		t.Fatal("deletion did not reach the pending delivery")
	}
	data, _ := os.ReadFile(busPath)
	if strings.Contains(string(data), "quokkafruit") {
		t.Fatal("deleted content remains in the bus store")
	}
	if _, fresh := mustPublish(t, b, Event{Kind: Mail, Account: "o@example.test", Ref: "<lab@x>", Summary: "Lab results"}); fresh {
		t.Fatal("a deleted event must not be redelivered")
	}
}

func TestSettledContentLeavesStore(t *testing.T) {
	st := &recall.MemStore{}
	r := &recorder{}
	b := mustOpen(t, st, []Trigger{{Name: "r", Start: r.start}})
	for i := 0; i < 100; i++ {
		mustPublish(t, b, Event{Kind: File, Ref: "/f", Version: string(rune('a'+i%26)) + strings.Repeat("x", i), Body: "secretplan wombat"})
		b.Pump(ctx)
	}
	data, _ := st.ReadAll()
	if n := strings.Count(string(data), "wombat"); n > 64 {
		t.Fatalf("settled bodies are not compacted away: %d remain", n)
	}
}

func TestCredentialsScrubbed(t *testing.T) {
	st := &recall.MemStore{}
	r := &recorder{}
	b := mustOpen(t, st, []Trigger{{Name: "r", Start: r.start}})
	key := "sk-" + "Q7v" + "Lr2Zp9XwT4kYb8NcJ3mHd6FsA1gEu5RoVi0"
	mustPublish(t, b, Event{Kind: Mail, Ref: "https://mail.example.test/m?token=" + key,
		Summary: "Your API key", Body: "api_key: " + key + "\nAuthorization: Bearer " + key})
	data, _ := st.ReadAll()
	if strings.Contains(string(data), key[3:20]) {
		t.Fatal("credential stored in the bus")
	}
	b.Pump(ctx)
	if strings.Contains(r.got[0].Event.Body, key[3:20]) {
		t.Fatal("credential delivered")
	}
}

func TestTriggerValidation(t *testing.T) {
	if _, err := Open(&recall.MemStore{}, []Trigger{{Name: "x"}}); !errors.Is(err, ErrTrigger) {
		t.Fatalf("nil Start: %v", err)
	}
	ok := func(context.Context, Delivery) error { return nil }
	if _, err := Open(&recall.MemStore{}, []Trigger{{Name: "x", Start: ok}, {Name: "x", Start: ok}}); !errors.Is(err, ErrTrigger) {
		t.Fatalf("duplicate: %v", err)
	}
	b := mustOpen(t, &recall.MemStore{}, nil)
	if _, _, err := b.Publish(Event{Kind: Mail}); !errors.Is(err, ErrNoRef) {
		t.Fatalf("no ref: %v", err)
	}
}

func TestRunDeliversOnPublish(t *testing.T) {
	r := &recorder{}
	b := mustOpen(t, &recall.MemStore{}, []Trigger{{Name: "r", Start: r.start}})
	c, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() { b.Run(c, time.Hour); close(done) }()
	mustPublish(t, b, Event{Kind: File, Ref: "/run"})
	deadline := time.Now().Add(5 * time.Second)
	for r.count() == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	<-done
	if r.count() != 1 {
		t.Fatal("Run did not deliver a published event")
	}
}
