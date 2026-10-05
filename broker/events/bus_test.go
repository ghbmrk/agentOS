package events

// REQ: CAP-4, CAP-3, REV-5, CRED-1

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"

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

var testKeyer = func() recall.Keyer {
	k, err := recall.NewKeyer([]byte("synthetic-test-key-0123456789"))
	if err != nil {
		panic(err)
	}
	return k
}()

// stores is a log and a seen store for one bus.
type stores struct{ log, seen recall.Store }

func mem() stores { return stores{&recall.MemStore{}, &recall.MemStore{}} }

func files(t *testing.T, dir string) (stores, func()) {
	t.Helper()
	l, err := recall.OpenFile(filepath.Join(dir, "bus.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	s, err := recall.OpenFile(filepath.Join(dir, "seen.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	return stores{l, s}, func() { l.Close(); s.Close() }
}

func mustOpen(t *testing.T, s stores, ts []Trigger, opts ...Option) *Bus {
	t.Helper()
	b, err := Open(Config{Log: s.log, Seen: s.seen, Keyer: testKeyer, Triggers: ts}, opts...)
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
	b := mustOpen(t, mem(), []Trigger{
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
	b := mustOpen(t, mem(), []Trigger{{Name: "watch", Kinds: []Kind{Web}, Start: r.start}})
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
	cases := []struct {
		e    Event
		want recall.Label
	}{
		{Event{Kind: Mail, Ref: "m", Label: recall.Public}, recall.Private},
		{Event{Kind: File, Ref: "f", Label: recall.Public}, recall.Private},
		{Event{Kind: Calendar, Ref: "c", Label: recall.Public}, recall.Private},
		{Event{Kind: "contact", Ref: "k", Label: recall.Public}, recall.Private},
		{Event{Kind: "credentialed", Ref: "cr", Label: recall.Public}, recall.Private},
		{Event{Kind: "webb", Ref: "typo", Label: recall.Public}, recall.Private},
		{Event{Kind: Web, Ref: "w"}, recall.Private},
		{Event{Kind: Web, Ref: "w2", Label: recall.Public}, recall.Public},
		{Event{Kind: Timer, Ref: "t", Label: "public?"}, recall.Private},
	}
	r := &recorder{}
	b := mustOpen(t, mem(), []Trigger{{Name: "r", Start: r.start}})
	for _, c := range cases {
		mustPublish(t, b, c.e)
	}
	b.Pump(ctx)
	if r.count() != len(cases) {
		t.Fatalf("deliveries: %d of %d", r.count(), len(cases))
	}
	for i, d := range r.got {
		if d.Event.Label != cases[i].want {
			t.Fatalf("%s/%s: label %q want %q", d.Event.Kind, d.Event.Ref, d.Event.Label, cases[i].want)
		}
	}
	for _, k := range []Kind{"owner", "preference"} {
		if _, _, err := b.Publish(Event{Kind: k, Ref: "x"}); !errors.Is(err, ErrReservedKind) {
			t.Fatalf("%s: reserved kind accepted: %v", k, err)
		}
	}
}

func TestDurableAcrossRestartAndRetries(t *testing.T) {
	dir := t.TempDir()
	now := time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)
	clock := WithClock(func() time.Time { return now })
	r := &recorder{fail: 2}
	att := NewAttention()
	st, done := files(t, dir)
	b := mustOpen(t, st, []Trigger{{Name: "w", Start: r.start}}, WithMaxAttempts(5), WithAttention(att), clock)
	id, _ := mustPublish(t, b, Event{Kind: Mail, Ref: "<a@x>", Summary: "hello"})
	b.Pump(ctx) // fails once
	b.Pump(ctx) // backing off: not tried
	if r.fail != 1 {
		t.Fatal("a failed delivery must back off before the next try")
	}
	done()

	// Restart: the pending delivery survives with its attempt count.
	st, done = files(t, dir)
	b = mustOpen(t, st, []Trigger{{Name: "w", Start: r.start}}, WithMaxAttempts(5), WithAttention(att), clock)
	if b.Pending() != 1 {
		t.Fatalf("pending after restart: %d", b.Pending())
	}
	b.Pump(ctx) // fails again
	now = now.Add(time.Hour)
	b.Pump(ctx) // succeeds
	if r.count() != 1 || r.got[0].Attempt != 3 || r.got[0].Event.ID != id {
		t.Fatalf("retries: %+v", r.got)
	}
	done()
	// Republishing a delivered event after restart does nothing.
	st, done = files(t, dir)
	defer done()
	b = mustOpen(t, st, []Trigger{{Name: "w", Start: r.start}})
	if _, fresh := mustPublish(t, b, Event{Kind: Mail, Ref: "<a@x>", Summary: "hello"}); fresh {
		t.Fatal("a delivered event must not be delivered again after restart")
	}
}

func TestDeadDeliveryGoesToDigest(t *testing.T) {
	att := NewAttention()
	now := time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)
	bad := Trigger{Name: "flaky", Start: func(context.Context, Delivery) error { panic("boom") }}
	b := mustOpen(t, mem(), []Trigger{bad}, WithMaxAttempts(2), WithAttention(att), WithClock(func() time.Time { return now }))
	mustPublish(t, b, Event{Kind: File, Ref: "/x"})
	b.Pump(ctx)
	now = now.Add(time.Hour)
	b.Pump(ctx)
	if b.Pending() != 0 {
		t.Fatal("a delivery past its tries must stop")
	}
	notes, decisions := att.TakeDigest()
	if len(notes) != 1 || !strings.Contains(notes[0], "flaky") || !strings.Contains(notes[0], "won't try again") || len(decisions) != 0 {
		t.Fatalf("digest: %v %v", notes, decisions)
	}
}

func TestTimers(t *testing.T) {
	dir := t.TempDir()
	st, done := files(t, dir)
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
	// Enough settled events to compact the log: timer state must survive it.
	for i := 0; i < 2*staleLimit; i++ {
		b.Publish(Event{Kind: Timer, Ref: fmt.Sprint("other-", i), Version: "v"})
		b.Pump(ctx)
	}
	done()
	// Down for three days: one coalesced firing, for the latest due time.
	st, done = files(t, dir)
	defer done()
	b = mustOpen(t, st, trig)
	b.AddTimer(sched)
	b.Tick(t0.Add(3*24*time.Hour + time.Hour))
	b.Tick(t0.Add(3*24*time.Hour + 2*time.Hour))
	b.Pump(ctx)
	var daily []Delivery
	for _, d := range r.got {
		if d.Event.Ref == "daily-review" {
			daily = append(daily, d)
		}
	}
	if len(daily) != 2 || !daily[1].Event.At.Equal(t0.Add(3*24*time.Hour)) {
		t.Fatalf("coalesced firing: %+v", daily)
	}
}

// indexedBus is a recall index on a file store and a bus sharing its keyer.
func indexedBus(t *testing.T, dir string, extra ...Trigger) (*recall.Index, *Bus, func()) {
	t.Helper()
	rst, err := recall.OpenFile(filepath.Join(dir, "recall.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	ix, err := recall.Open(rst)
	if err != nil {
		t.Fatal(err)
	}
	st, done := files(t, dir)
	b, err := Open(Config{Log: st.log, Seen: st.seen, Keyer: ix.Keyer(), Triggers: append([]Trigger{IndexInto(ix)}, extra...)},
		WithMaxAttempts(1000))
	if err != nil {
		t.Fatal(err)
	}
	if err := ix.OnDelete(b.ForgetSource); err != nil {
		t.Fatal(err)
	}
	return ix, b, func() { done(); rst.Close() }
}

func TestEventsIndexedAndDeletionPropagates(t *testing.T) {
	dir := t.TempDir()
	slow := &recorder{fail: 100}
	ix, b, done := indexedBus(t, dir, Trigger{Name: "slow", Start: slow.start})
	defer done()

	mustPublish(t, b, Event{Kind: Mail, Account: "o@example.test", Ref: "<lab@x>", Summary: "Lab results", Body: "glucose quokkafruit normal"})
	b.Pump(ctx)
	rs := ix.Lookup(recall.Query{Text: "quokkafruit"})
	if len(rs) != 1 || rs[0].Source.Kind != "mail" || rs[0].Source.Ref != "<lab@x>" || rs[0].Label != recall.Private {
		t.Fatalf("event not indexed with provenance: %+v", rs)
	}
	if b.Pending() != 1 {
		t.Fatalf("pending: %d", b.Pending())
	}
	// Deleting by the raw source name reaches the item and the bus's
	// pending copy, and leaves no copy in the bus log.
	if _, err := ix.DeleteSource("mail", "o@example.test", "<lab@x>"); err != nil {
		t.Fatal(err)
	}
	if ix.Len() != 0 || b.Pending() != 0 {
		t.Fatalf("deletion did not propagate: items %d pending %d", ix.Len(), b.Pending())
	}
	data, _ := os.ReadFile(filepath.Join(dir, "bus.jsonl"))
	if strings.Contains(string(data), "quokkafruit") {
		t.Fatal("deleted content remains in the bus store")
	}
	if _, fresh := mustPublish(t, b, Event{Kind: Mail, Account: "o@example.test", Ref: "<lab@x>", Summary: "Lab results"}); fresh {
		t.Fatal("a deleted event must not be redelivered")
	}
}

// A random-looking ref (scrubbed for display) is still deletable by its raw
// form after a bus ingest (review item 3).
func TestDeleteByRawRefAfterBusIngest(t *testing.T) {
	ix, b, done := indexedBus(t, t.TempDir())
	defer done()
	raw := "https://files.example.test/s/Kx9vQ2mWp7LrT4nZ8bYc?sig=Ab3dE5fG7hJ9kL1mN3pQ"
	mustPublish(t, b, Event{Kind: Web, Ref: raw, Version: "1", Body: "shared doc"})
	mustPublish(t, b, Event{Kind: Web, Ref: "https://files.example.test/s/Qw8eR4tY6uI2oP9aS5dF?sig=Zx1cV3bN5mL7kJ9hG2fD", Version: "1", Body: "other doc"})
	b.Pump(ctx)
	if ix.Len() != 2 {
		t.Fatalf("refs that scrub alike collided: %d items", ix.Len())
	}
	rep, err := ix.DeleteSource("web", "", raw)
	if err != nil || len(rep.Items) != 1 || ix.Len() != 1 {
		t.Fatalf("delete by raw ref: %v %+v", err, rep)
	}
}

// A deletion that arrives while the event is still pending on the bus, or
// during Pump, is not undone (review items 4 and 5).
func TestDeletionBeforeAndDuringIndexing(t *testing.T) {
	dir := t.TempDir()
	ix, b, done := indexedBus(t, dir)
	defer done()
	mustPublish(t, b, Event{Kind: Mail, Account: "o", Ref: "<early@x>", Body: "early marmoset"})
	if _, err := ix.DeleteSource("mail", "o", "<early@x>"); err != nil {
		t.Fatal(err)
	}
	b.Pump(ctx)
	if ix.Len() != 0 || b.Pending() != 0 {
		t.Fatalf("deletion before indexing lost: items %d pending %d", ix.Len(), b.Pending())
	}

	// During Pump: the first trigger deletes the source; the indexing
	// trigger, already queued in the same Pump, must not bring it back.
	var once sync.Once
	var target *recall.Index
	deleter := Trigger{Name: "a-deleter", Start: func(context.Context, Delivery) error {
		once.Do(func() { target.DeleteSource("mail", "o", "<race@x>") })
		return nil
	}}
	ix2, b2, done2 := indexedBus(t, t.TempDir(), deleter)
	defer done2()
	target = ix2
	// Future-dated by its source: the date must not outrun the deletion.
	mustPublish(t, b2, Event{Kind: Mail, Account: "o", Ref: "<race@x>", At: time.Now().Add(48 * time.Hour), Received: time.Now().Add(72 * time.Hour), Body: "race lemur"})
	b2.Pump(ctx)
	if ix2.Len() != 0 {
		t.Fatal("a deletion during Pump was undone by a stale delivery")
	}

	// A stale IndexInto that already passed the bus re-check is refused by
	// the recall tombstone.
	old := Event{Kind: Mail, Account: "o", Ref: "<stale@x>", At: time.Now().Add(48 * time.Hour), Received: time.Now().Add(-time.Hour), Body: "stale"}
	old.Source = ix2.SourceID("mail", "o", "<stale@x>")
	if _, err := ix2.DeleteSource("mail", "o", "<stale@x>"); err != nil {
		t.Fatal(err)
	}
	if err := IndexInto(ix2).Start(ctx, Delivery{Event: old}); err != nil || ix2.Len() != 0 {
		t.Fatalf("stale ingest after deletion: %v, %d items", err, ix2.Len())
	}
}

// Tombstones replay to the bus on restart, so a deletion a crash cut off
// before the bus heard of it still reaches the bus.
func TestDeletionReplayedAtStart(t *testing.T) {
	dir := t.TempDir()
	slow := &recorder{fail: 100}
	_, b, done := indexedBus(t, dir, Trigger{Name: "slow", Start: slow.start})
	mustPublish(t, b, Event{Kind: File, Ref: "/secret.txt", Body: "pangolin"})
	done()

	// The deletion lands in recall while the bus is down (as after a crash
	// between the tombstone and the hook).
	rst, err := recall.OpenFile(filepath.Join(dir, "recall.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	ix, err := recall.Open(rst)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ix.DeleteSource("file", "", "/secret.txt"); err != nil {
		t.Fatal(err)
	}
	rst.Close()

	_, b, done = indexedBus(t, dir, Trigger{Name: "slow", Start: slow.start})
	defer done()
	if b.Pending() != 0 {
		t.Fatalf("tombstone not replayed to the bus: %d pending", b.Pending())
	}
	data, _ := os.ReadFile(filepath.Join(dir, "bus.jsonl"))
	if strings.Contains(string(data), "pangolin") {
		t.Fatal("deleted content remains in the bus log")
	}
}

func TestSettledContentLeavesStore(t *testing.T) {
	st := mem()
	r := &recorder{}
	b := mustOpen(t, st, []Trigger{{Name: "r", Start: r.start}})
	for i := 0; i < 100; i++ {
		mustPublish(t, b, Event{Kind: File, Ref: "/f", Version: fmt.Sprint(i), Body: "secretplan wombat"})
		b.Pump(ctx)
	}
	data, _ := st.log.ReadAll()
	if n := strings.Count(string(data), "wombat"); n >= staleLimit {
		t.Fatalf("settled bodies are not compacted away: %d remain", n)
	}
	seen, _ := st.seen.ReadAll()
	if strings.Contains(string(seen), "wombat") || strings.Contains(string(seen), "/f") {
		t.Fatal("the seen list must hold IDs only")
	}
}

func TestCredentialsScrubbedAndBodyCut(t *testing.T) {
	st := mem()
	r := &recorder{}
	b := mustOpen(t, st, []Trigger{{Name: "r", Start: r.start}})
	key := "sk-" + "Q7v" + "Lr2Zp9XwT4kYb8NcJ3mHd6FsA1gEu5RoVi0"
	mustPublish(t, b, Event{Kind: Mail, Ref: "https://mail.example.test/m?token=" + key,
		Summary: "Your API key", Body: "api_key: " + key + "\nAuthorization: Bearer " + key})
	data, _ := st.log.ReadAll()
	if strings.Contains(string(data), key[3:20]) {
		t.Fatal("credential stored in the bus")
	}
	mustPublish(t, b, Event{Kind: File, Ref: "/big", Body: strings.Repeat("é", MaxBody)})
	b.Pump(ctx)
	if strings.Contains(r.got[0].Event.Body, key[3:20]) {
		t.Fatal("credential delivered")
	}
	if body := r.got[1].Event.Body; len(body) > MaxBody+16 || !utf8.ValidString(body) {
		t.Fatalf("body not cut cleanly: %d bytes", len(body))
	}
}

func TestOpenValidation(t *testing.T) {
	ok := func(context.Context, Delivery) error { return nil }
	m := mem()
	if _, err := Open(Config{Log: m.log, Seen: m.seen, Keyer: testKeyer, Triggers: []Trigger{{Name: "x"}}}); !errors.Is(err, ErrTrigger) {
		t.Fatalf("nil Start: %v", err)
	}
	if _, err := Open(Config{Log: m.log, Seen: m.seen, Keyer: testKeyer, Triggers: []Trigger{{Name: "x", Start: ok}, {Name: "x", Start: ok}}}); !errors.Is(err, ErrTrigger) {
		t.Fatalf("duplicate: %v", err)
	}
	if _, err := Open(Config{Log: m.log, Seen: m.seen}); !errors.Is(err, ErrConfig) {
		t.Fatalf("no keyer: %v", err)
	}
	b := mustOpen(t, mem(), nil)
	if _, _, err := b.Publish(Event{Kind: Mail}); !errors.Is(err, ErrNoRef) {
		t.Fatalf("no ref: %v", err)
	}
	// A corrupt line does not stop the bus.
	m.log.Append([]byte("{garbage\n"))
	if _, err := Open(Config{Log: m.log, Seen: m.seen, Keyer: testKeyer}); err != nil {
		t.Fatalf("corrupt line: %v", err)
	}
}

func TestRunDeliversOnPublish(t *testing.T) {
	r := &recorder{}
	b := mustOpen(t, mem(), []Trigger{{Name: "r", Start: r.start}})
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
