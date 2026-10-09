package main

import (
	"context"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/change"
	"github.com/ghbmrk/agentos/broker/control"
	"github.com/ghbmrk/agentos/broker/digestqueue"
	"github.com/ghbmrk/agentos/broker/grants"
	"github.com/ghbmrk/agentos/broker/journal"
	"github.com/ghbmrk/agentos/broker/modemlink"
)

// fakeDigestTransport answers each Deliver with out(n), n counting from 1.
type fakeDigestTransport struct {
	mu    sync.Mutex
	texts []string
	out   func(n int) (digestqueue.Outcome, string)
}

func (f *fakeDigestTransport) Deliver(_ context.Context, text string) (digestqueue.Outcome, string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.texts = append(f.texts, text)
	if f.out == nil {
		return digestqueue.TransportAccepted, fmt.Sprintf("item-%d", len(f.texts))
	}
	return f.out(len(f.texts))
}

func (f *fakeDigestTransport) sent() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.texts...)
}

// failStore is a digest store that does not read.
type failStore struct{}

func (failStore) Load() ([]byte, error) { return nil, errors.New("disk: unreadable") }
func (failStore) Save([]byte) error     { return errors.New("disk: unreadable") }

// keepRefStore refuses the next refuse saves that would drop ref from bytes
// holding it, so the queue refuses that many forgets of ref (ErrRecovery)
// while every other write goes through: a refusal with no batch in flight,
// now that an unknown batch no longer refuses one (W5-Dc-r7).
type keepRefStore struct {
	change.MemStore
	ref    string
	refuse int
}

func (s *keepRefStore) Save(b []byte) error {
	old, _ := s.MemStore.Load()
	if s.refuse > 0 && strings.Contains(string(old), s.ref) && !strings.Contains(string(b), s.ref) {
		s.refuse--
		return errors.New("disk: refused")
	}
	return s.MemStore.Save(b)
}

// testSource is a DIG-1-shaped source: one pending generation until acked.
type testSource struct {
	name     string
	gen      uint64
	lines    []string
	refs     []string
	acked    uint64
	ackFail  int
	peekFail int
}

func (s *testSource) Peek(context.Context) (*digestqueue.Snapshot, error) {
	if s.peekFail > 0 {
		s.peekFail--
		return nil, errors.New("source: not readable yet")
	}
	if s.gen == 0 || s.acked >= s.gen {
		return nil, nil
	}
	snap, err := digestqueue.NewSnapshot(s.name, s.gen, s.lines, s.refs)
	return &snap, err
}

func (s *testSource) Ack(_ context.Context, snap digestqueue.Snapshot) error {
	if s.ackFail > 0 {
		s.ackFail--
		return errors.New("source: ack not saved")
	}
	s.acked = max(s.acked, snap.Generation)
	return nil
}

type digestRig struct {
	t       *testing.T
	now     time.Time
	queue   digestqueue.Store
	state   digestqueue.Store
	tr      *fakeDigestTransport
	informs []string
	d       *digestBox
	reg     *capLines
}

// day0 is a Monday; the digest time is 08:00 UTC in these tests.
var day0 = time.Date(2026, 10, 5, 0, 0, 0, 0, time.UTC)

func newDigestRig(t *testing.T, queue digestqueue.Store, sources map[string]digestqueue.Source) *digestRig {
	t.Helper()
	r := &digestRig{t: t, now: day0.Add(7 * time.Hour), queue: queue, state: &change.MemStore{}, tr: &fakeDigestTransport{}}
	r.boot(sources)
	return r
}

// boot starts a fresh digestBox over the rig's stores, as a restart does.
func (r *digestRig) boot(sources map[string]digestqueue.Source) {
	r.make(sources)
	r.d.open(context.Background())
}

// make builds a fresh digestBox without opening its queue, as main does
// before attach.
func (r *digestRig) make(sources map[string]digestqueue.Source) {
	r.d = newDigestBox(digestConfig{
		Queue: r.queue, State: r.state, Sources: sources, Transport: r.tr,
		Inform: func(s string) error { r.informs = append(r.informs, s); return nil },
		Now:    func() time.Time { return r.now }, Loc: time.UTC, Logf: r.t.Logf,
	})
	r.reg = &capLines{}
	r.d.register(r.reg)
}

// at moves the clock to day d, hh:mm and runs one step.
func (r *digestRig) at(d, hh, mm int) {
	r.now = day0.AddDate(0, 0, d).Add(time.Duration(hh)*time.Hour + time.Duration(mm)*time.Minute)
	r.d.step(context.Background(), r.now)
}

// day runs day d from the digest time to just before the next, every
// 30 minutes, as the box's minute ticker would (the retry cadence).
func (r *digestRig) day(d int) {
	for m := 8 * 60; m < 32*60; m += 30 {
		r.at(d, m/60, m%60)
	}
}

func (r *digestRig) status() string { return strings.Join(r.reg.Digest(), "|") }

// holding counts the queued batches with a snapshot holding ref.
func (r *digestRig) holding(ref string) int {
	n := 0
	for _, b := range r.batches() {
		if refersTo(b, map[string]bool{ref: true}) {
			n++
		}
	}
	return n
}

func (r *digestRig) batches() []digestqueue.Batch {
	r.t.Helper()
	bs, err := r.d.q.List()
	if err != nil {
		r.t.Fatal(err)
	}
	return bs
}

// REQ: CH-15
func TestDigestGoesOnceADayWithTheDayLine(t *testing.T) {
	r := newDigestRig(t, &change.MemStore{}, nil)
	r.at(0, 7, 59)
	if got := r.tr.sent(); len(got) != 0 {
		t.Fatalf("before the digest time: %q", got)
	}
	r.at(0, 8, 0)
	r.at(0, 8, 30)
	r.at(0, 20, 0)
	got := r.tr.sent()
	if len(got) != 1 || !strings.Contains(got[0], digestDayLine) || !strings.HasPrefix(got[0], fmt.Sprintf(digestHead, "Mon 5 Oct")) {
		t.Fatalf("day 0: %q", got)
	}
	// A restart the same day does not send it again.
	r.boot(nil)
	r.at(0, 21, 0)
	r.at(1, 8, 0)
	if got = r.tr.sent(); len(got) != 2 || !strings.Contains(got[1], digestDayLine) {
		t.Fatalf("day 1: %q", got)
	}
	// Accepted batches are compacted away.
	if bs := r.batches(); len(bs) != 0 || r.status() != "" {
		t.Fatalf("batches %+v status %q", bs, r.status())
	}
}

// REQ: CH-15
func TestDigestDayLineOnlyWhenNothingElseIsPending(t *testing.T) {
	src := &testSource{name: "loops", gen: 1, lines: []string{"Loops: two changes adopted; reply UNDO 4 to undo one."}}
	r := newDigestRig(t, &change.MemStore{}, map[string]digestqueue.Source{"loops": src})
	r.at(0, 8, 0)
	got := r.tr.sent()
	if len(got) != 1 || strings.Contains(got[0], digestDayLine) || !strings.Contains(got[0], src.lines[0]) {
		t.Fatalf("day 0: %q", got)
	}
	r.at(1, 8, 0)
	if got = r.tr.sent(); len(got) != 2 || !strings.Contains(got[1], digestDayLine) {
		t.Fatalf("day 1: %q", got)
	}
}

// An unknown outcome is never resent (OP-2): STATUS names it until a
// digest carrying its line is accepted, and that line goes once.
// REQ: OP-2, OP-9, CH-15
func TestDigestUnknownIsSurfacedOnceAndNeverResent(t *testing.T) {
	r := newDigestRig(t, &change.MemStore{}, nil)
	r.tr.out = func(n int) (digestqueue.Outcome, string) {
		if n == 1 {
			return digestqueue.OutcomeUnknown, "item-1"
		}
		return digestqueue.TransportAccepted, fmt.Sprintf("item-%d", n)
	}
	r.day(0)
	if got := r.tr.sent(); len(got) != 1 {
		t.Fatalf("resent: %q", got)
	}
	if r.status() != digestUnknownStatus {
		t.Fatalf("status %q", r.status())
	}
	r.at(1, 8, 0)
	got := r.tr.sent()
	line := fmt.Sprintf(digestUnknownLine, "Mon 5 Oct")
	if len(got) != 2 || !strings.Contains(got[1], line) || strings.Contains(got[1], digestDayLine) {
		t.Fatalf("day 1: %q", got)
	}
	if r.status() != "" {
		t.Fatalf("status after the accepted digest: %q", r.status())
	}
	r.boot(nil)
	r.day(2)
	if got = r.tr.sent(); len(got) != 3 || strings.Contains(got[2], line) {
		t.Fatalf("day 2: %q", got)
	}
	if bs := r.batches(); bs[0].State != digestqueue.Unknown || bs[0].Attempts != 1 {
		t.Fatalf("first batch %+v", bs[0])
	}
}

// The carrier of an unknown line going unknown itself re-offers the line.
// REQ: OP-2, OP-9
func TestDigestUnknownLineReofferedWhenItsCarrierIsUnknown(t *testing.T) {
	r := newDigestRig(t, &change.MemStore{}, nil)
	r.tr.out = func(n int) (digestqueue.Outcome, string) {
		if n <= 2 {
			return digestqueue.OutcomeUnknown, ""
		}
		return digestqueue.TransportAccepted, fmt.Sprintf("item-%d", n)
	}
	r.at(0, 8, 0)
	r.at(1, 8, 0)
	r.at(2, 8, 0)
	got := r.tr.sent()
	if len(got) != 3 || !strings.Contains(got[2], fmt.Sprintf(digestUnknownLine, "Mon 5 Oct")) ||
		!strings.Contains(got[2], fmt.Sprintf(digestUnknownLine, "Tue 6 Oct")) {
		t.Fatalf("day 2: %q", got)
	}
	if r.status() != "" {
		t.Fatalf("status %q", r.status())
	}
}

// A batch the line refused all day is held, goes late once with the late
// head, and if it cannot go then either it is surfaced, never re-armed.
// REQ: CH-15, OP-9
func TestDigestHeldGoesLateOnceThenIsSurfaced(t *testing.T) {
	r := newDigestRig(t, &change.MemStore{}, nil)
	r.tr.out = func(n int) (digestqueue.Outcome, string) {
		if n <= 3 {
			return digestqueue.NotSent, "not-queued"
		}
		return digestqueue.TransportAccepted, fmt.Sprintf("item-%d", n)
	}
	r.at(0, 8, 0) // refused; the box is then off until the next digest time
	r.at(1, 8, 0) // day 0 goes late (refused), then day 1 (refused)
	got := r.tr.sent()
	if len(got) != 3 || !strings.HasPrefix(got[1], fmt.Sprintf(digestLateHead, "Mon 5 Oct")) || !strings.Contains(got[1], digestDayLine) {
		t.Fatalf("day 1: %q", got)
	}
	r.at(2, 8, 0) // day 0 held after Late: surfaced; day 1 goes late
	got = r.tr.sent()
	if n := strings.Count(strings.Join(got, "|"), fmt.Sprintf(digestLateHead, "Mon 5 Oct")); n != 1 {
		t.Fatalf("day 0 went late %d times: %q", n, got)
	}
	last := got[len(got)-1]
	if !strings.Contains(last, fmt.Sprintf(digestHeldLine, "Mon 5 Oct")) {
		t.Fatalf("day 2: %q", got)
	}
	if !strings.Contains(strings.Join(got[3:], "|"), fmt.Sprintf(digestLateHead, "Tue 6 Oct")) {
		t.Fatalf("day 1 not late: %q", got)
	}
	if r.status() != "" {
		t.Fatalf("status %q", r.status())
	}
}

// W5-Dc-r4: a NotSent costs one attempt. The box tries a batch every 30
// minutes from its digest time (48 tries a day) and again on its late day
// (48 more), so digestLimits.MaxAttempts is 96; a line down for two whole
// days exhausts it and the batch is surfaced.
// REQ: CH-15, OP-9
func TestDigestAttemptBudgetCoversItsDayAndItsLateDay(t *testing.T) {
	if digestLimits.MaxAttempts != 96 || digestRetry != 30*time.Minute {
		t.Fatalf("limits %+v retry %v", digestLimits, digestRetry)
	}
	r := newDigestRig(t, &change.MemStore{}, nil)
	down := true
	r.tr.out = func(n int) (digestqueue.Outcome, string) {
		if down {
			return digestqueue.NotSent, "not-queued"
		}
		return digestqueue.TransportAccepted, fmt.Sprintf("item-%d", n)
	}
	r.day(0)
	if bs := r.batches(); bs[0].Attempts != 48 || bs[0].State != digestqueue.Ready {
		t.Fatalf("after day 0: %+v", bs[0])
	}
	r.day(1)
	bs := r.batches()
	if bs[0].Attempts != 96 || bs[0].State != digestqueue.Failed || !bs[0].Late {
		t.Fatalf("after day 1: %+v", bs[0])
	}
	if r.status() != digestFailedStatus {
		t.Fatalf("status %q", r.status())
	}
	down = false
	r.at(2, 8, 0)
	got := r.tr.sent()
	if !strings.Contains(got[len(got)-1], fmt.Sprintf(digestFailedLine, "Mon 5 Oct")) || r.status() != "" {
		t.Fatalf("day 2: %q status %q", got[len(got)-1], r.status())
	}
}

// A batch none of whose sources consumed it expires; its lines come back
// in the next digest.
// REQ: CH-15
func TestDigestExpiredLinesArriveNextDay(t *testing.T) {
	src := &testSource{name: "a-src", gen: 3, lines: []string{"Learning: one change adopted; reply UNDO 2 to undo it."}, ackFail: 1}
	r := newDigestRig(t, &change.MemStore{}, map[string]digestqueue.Source{"a-src": src})
	r.at(0, 8, 0)
	if got := r.tr.sent(); len(got) != 0 {
		t.Fatalf("day 0 sent %q", got)
	}
	r.at(1, 8, 0)
	got := r.tr.sent()
	if len(got) != 1 || !strings.Contains(got[0], src.lines[0]) {
		t.Fatalf("day 1: %q", got)
	}
	if src.acked != 3 || len(r.batches()) != 0 {
		t.Fatalf("batches %+v acked %d", r.batches(), src.acked)
	}
}

// The queue's file not reading: STATUS says so while it lasts, one fixed
// outage line goes that day (DC-8, provisional) and no batch is sent.
// REQ: OP-9, CH-15
func TestDigestQueueUnavailable(t *testing.T) {
	r := newDigestRig(t, failStore{}, nil)
	if r.status() != digestDownStatus {
		t.Fatalf("status %q", r.status())
	}
	r.day(0)
	r.boot(nil)
	r.at(0, 23, 0)
	if len(r.informs) != 1 || r.informs[0] != digestOutageLine || len(r.tr.sent()) != 0 {
		t.Fatalf("informs %q sent %q", r.informs, r.tr.sent())
	}
	r.at(1, 8, 0)
	if len(r.informs) != 2 || r.status() != digestDownStatus {
		t.Fatalf("day 1 informs %q status %q", r.informs, r.status())
	}
	// The store reads again: the next digest time reopens it.
	r.queue = &change.MemStore{}
	r.d.cfg.Queue = r.queue
	r.at(2, 8, 0)
	if got := r.tr.sent(); len(got) != 1 || r.status() != "" || len(r.informs) != 2 {
		t.Fatalf("day 2 sent %q status %q informs %q", got, r.status(), r.informs)
	}
}

// A forget reaches the queue: a ready batch loses the forgotten snapshot,
// and an unknown one is redacted whole (W5-Dc-r7), so the forget is done.
// REQ: CAP-3, CAP-3 (W5-Dc-r7 UF-3)
func TestDigestForgetReachesTheQueue(t *testing.T) {
	src := &testSource{name: "notes", gen: 1, lines: []string{"Notes: task 3 finished; reply MORE 3 for it."}, refs: []string{"owner:a"}}
	r := newDigestRig(t, &change.MemStore{}, map[string]digestqueue.Source{"notes": src})
	r.tr.out = func(int) (digestqueue.Outcome, string) { return digestqueue.OutcomeUnknown, "" }
	r.at(0, 8, 0)
	if err := r.d.forget("owner:a"); err != nil {
		t.Fatalf("unknown: %v", err)
	}
	src.gen, src.refs = 2, []string{"owner:b"}
	r.tr.out = func(int) (digestqueue.Outcome, string) { return digestqueue.NotSent, "not-queued" }
	r.at(1, 8, 0)
	if err := r.d.forget("owner:b"); err != nil {
		t.Fatal(err)
	}
	for _, b := range r.batches() {
		for _, s := range b.Snapshots {
			if s.Source == "notes" && s.Generation == 2 {
				t.Fatalf("forgotten snapshot kept: %+v", b)
			}
		}
	}
	// Queue unavailable: the forget cannot be done, so it is not.
	q := newDigestRig(t, failStore{}, nil)
	if err := q.d.forget("owner:a"); err == nil {
		t.Fatal("forget with no queue reported done")
	}
}

// L3 1 on #592: a collection that fails keeps the day owed. STATUS says
// so while it is owed, the box collects again on the retry cadence, and
// exactly one digest goes that day, with the source's lines.
// REQ: CH-15, OP-9
func TestDigestFailedCollectionRetriesTheDay(t *testing.T) {
	src := &testSource{name: "notes", gen: 1, lines: []string{"Notes: task 3 finished; reply MORE 3 for it."}, peekFail: 2}
	r := newDigestRig(t, &change.MemStore{}, map[string]digestqueue.Source{"notes": src})
	r.at(0, 8, 0)
	if got := r.tr.sent(); len(got) != 0 || r.status() != digestOwedStatus {
		t.Fatalf("08:00 sent %q status %q", got, r.status())
	}
	r.at(0, 8, 1) // not before the retry cadence
	if src.peekFail != 1 || len(r.tr.sent()) != 0 {
		t.Fatalf("collected again before the retry: %q", r.tr.sent())
	}
	r.day(0)
	got := r.tr.sent()
	if len(got) != 1 || !strings.Contains(got[0], src.lines[0]) || r.status() != "" {
		t.Fatalf("day 0 sent %q status %q", got, r.status())
	}
	// A restart while it is owed collects the day at once.
	src.gen, src.peekFail = 2, 1
	r.at(1, 8, 0)
	r.boot(map[string]digestqueue.Source{"notes": src})
	r.at(1, 8, 1)
	if got = r.tr.sent(); len(got) != 2 || !strings.Contains(got[1], src.lines[0]) {
		t.Fatalf("day 1 sent %q", got)
	}
}

// Security B2 on #592: a forget asked before the queue opens (main opens
// it after attach, which replays owed forgets) is not done, and the queue
// drops the reference when it opens, before anything is sent.
// REQ: CAP-3, OP-2
func TestDigestForgetBeforeOpenPurgesOnOpen(t *testing.T) {
	src := &testSource{name: "notes", gen: 1, lines: []string{"Notes: task 3 finished; reply MORE 3 for it."}, refs: []string{"owner:a"}}
	sources := map[string]digestqueue.Source{"notes": src}
	r := newDigestRig(t, &change.MemStore{}, sources)
	r.tr.out = func(int) (digestqueue.Outcome, string) { return digestqueue.NotSent, "not-queued" }
	r.at(0, 8, 0)
	r.tr.out = nil
	r.make(sources)
	if err := r.d.forget("owner:a"); err == nil {
		t.Fatal("forget before open reported done")
	}
	r.d.open(context.Background())
	r.at(0, 9, 0)
	// The first is the 08:00 try the bridge did not send.
	if got := r.tr.sent(); len(got) != 1 {
		t.Fatalf("forgotten lines sent: %q", got)
	}
	if held := r.holding("owner:a"); held != 0 {
		t.Fatalf("open left %d batches holding the forgotten reference", held)
	}
	if err := r.d.forget("owner:a"); err != nil {
		t.Fatalf("forget after open: %v", err)
	}
}

// A forget the queue refused is kept in the digest's own state, so a
// restart holds its ready batch from the first step, before the forget
// owner asks again or even when it never does (its owed save failed)
// (security B2' on #592). The queue refuses through its store, once: the
// open after the restart purges the reference, so the replay is done.
// REQ: CAP-3, OP-2, CAP-3 (W5-Dc-r7 UF-3)
func TestDigestRefusedForgetHoldsItsReadyBatchAfterARestart(t *testing.T) {
	for _, tc := range []struct {
		name string
		// ask is the forget owner's replay after the restart: none when
		// its owed save failed.
		ask bool
	}{{"replay after the first step", true}, {"owed save failed", false}} {
		t.Run(tc.name, func(t *testing.T) {
			src := &testSource{name: "notes", gen: 1, lines: []string{"Notes: task 3 finished; reply MORE 3 for it."}, refs: []string{"owner:a"}}
			srcs := map[string]digestqueue.Source{"notes": src}
			r := newDigestRig(t, &keepRefStore{ref: "owner:a", refuse: 1}, srcs)
			r.tr.out = func(int) (digestqueue.Outcome, string) { return digestqueue.OutcomeUnknown, "" }
			r.at(0, 8, 0)
			src.gen, src.lines = 2, []string{"Notes: task 4 finished; reply MORE 4 for it."}
			r.tr.out = func(int) (digestqueue.Outcome, string) { return digestqueue.NotSent, "not-queued" }
			r.at(1, 8, 0)
			if err := r.d.forget("owner:a"); !errors.Is(err, digestqueue.ErrRecovery) {
				t.Fatalf("forget: %v", err)
			}
			n := len(r.tr.sent())
			r.tr.out = nil
			r.boot(srcs)
			r.at(1, 9, 0)
			if tc.ask {
				if err := r.d.forget("owner:a"); err != nil {
					t.Fatalf("forget after restart: %v", err)
				}
			}
			r.day(1)
			for _, s := range r.tr.sent()[n:] {
				if strings.Contains(s, src.lines[0]) {
					t.Fatalf("forgotten reference sent after restart: %q", s)
				}
			}
		})
	}
}

// A forget asked before the queue opened is kept in the digest's state
// too, so the open after a restart purges it from the queue on disk.
// REQ: CAP-3
func TestDigestForgetBeforeOpenSurvivesARestart(t *testing.T) {
	src := &testSource{name: "notes", gen: 1, lines: []string{"Notes: task 3 finished; reply MORE 3 for it."}, refs: []string{"owner:a"}}
	sources := map[string]digestqueue.Source{"notes": src}
	r := newDigestRig(t, &change.MemStore{}, sources)
	r.tr.out = func(int) (digestqueue.Outcome, string) { return digestqueue.NotSent, "not-queued" }
	r.at(0, 8, 0)
	r.tr.out = nil
	r.make(sources)
	if err := r.d.forget("owner:a"); err == nil {
		t.Fatal("forget before open reported done")
	}
	if r.d.st.LastDay == 0 {
		t.Fatal("forget before open lost the saved digest state")
	}
	r.boot(sources) // the restart comes before this box opened
	if held := r.holding("owner:a"); held != 0 {
		t.Fatalf("open after a restart left %d batches holding the forgotten reference", held)
	}
	r.boot(sources)
	if len(r.d.st.Forgets) != 0 {
		t.Fatalf("purged forget still kept: %q", r.d.st.Forgets)
	}
}

// A ready batch holding a reference the queue refused to forget (its store
// refused the forget's save) is not sent: the reopen purges it first.
// REQ: CAP-3, OP-2, CAP-3 (W5-Dc-r7 UF-3)
func TestDigestRefusedForgetHoldsItsReadyBatch(t *testing.T) {
	src := &testSource{name: "notes", gen: 1, lines: []string{"Notes: task 3 finished; reply MORE 3 for it."}, refs: []string{"owner:a"}}
	r := newDigestRig(t, &keepRefStore{ref: "owner:a", refuse: 1}, map[string]digestqueue.Source{"notes": src})
	r.tr.out = func(int) (digestqueue.Outcome, string) { return digestqueue.OutcomeUnknown, "" }
	r.at(0, 8, 0)
	src.gen, src.lines = 2, []string{"Notes: task 4 finished; reply MORE 4 for it."}
	r.tr.out = func(int) (digestqueue.Outcome, string) { return digestqueue.NotSent, "not-queued" }
	r.at(1, 8, 0)
	if err := r.d.forget("owner:a"); !errors.Is(err, digestqueue.ErrRecovery) {
		t.Fatalf("forget: %v", err)
	}
	n := len(r.tr.sent())
	r.tr.out = nil
	r.day(1)
	for _, s := range r.tr.sent()[n:] {
		if strings.Contains(s, src.lines[0]) {
			t.Fatalf("batch of a refused forget sent: %q", s)
		}
	}
}

// A ready batch holding a reference whose forget is held is not sent. No
// queue refusal reaches this with the queue open now that an unknown batch
// no longer refuses (W5-Dc-r7), so the hold is set directly.
// REQ: CAP-3, OP-2, CAP-3 (W5-Dc-r7 UF-3)
func TestDigestHeldForgetKeepsItsReadyBatchUnsent(t *testing.T) {
	src := &testSource{name: "notes", gen: 1, lines: []string{"Notes: task 3 finished; reply MORE 3 for it."}, refs: []string{"owner:a"}}
	r := newDigestRig(t, &change.MemStore{}, map[string]digestqueue.Source{"notes": src})
	r.tr.out = func(int) (digestqueue.Outcome, string) { return digestqueue.NotSent, "not-queued" }
	r.at(0, 8, 0)
	r.d.mu.Lock()
	r.d.hold("owner:a")
	r.d.mu.Unlock()
	n := len(r.tr.sent())
	r.tr.out = nil
	r.day(0)
	for _, s := range r.tr.sent()[n:] {
		if strings.Contains(s, src.lines[0]) {
			t.Fatalf("batch of a held forget sent: %q", s)
		}
	}
	if r.holding("owner:a") != 1 {
		t.Fatal("ready batch not kept")
	}
}

// A forget of a reference only an unknown batch holds is done: the batch is
// redacted whole and stays unknown, so STATUS and the next digest still say
// that day's digest may not have arrived (W5-Dc-r7).
// REQ: CAP-3 (W5-Dc-r7 UF-3), OP-9, CH-15
func TestDigestForgetOfAnUnknownDigestCompletes(t *testing.T) {
	src := &testSource{name: "notes", gen: 1, lines: []string{"Notes: task 3 finished; reply MORE 3 for it."}, refs: []string{"owner:a"}}
	srcs := map[string]digestqueue.Source{"notes": src}
	r := newDigestRig(t, &change.MemStore{}, srcs)
	r.tr.out = func(int) (digestqueue.Outcome, string) { return digestqueue.OutcomeUnknown, "" }
	r.at(0, 8, 0)
	if err := r.d.forget("owner:a"); err != nil {
		t.Fatalf("forget: %v", err)
	}
	if len(r.d.forgets) != 0 {
		t.Fatalf("done forget still held: %v", r.d.forgets)
	}
	// The source keeps its duty: it drops the reference.
	src.gen, src.lines, src.refs = 2, []string{"Notes: task 4 finished; reply MORE 4 for it."}, []string{"owner:b"}
	r.boot(srcs)
	if len(r.d.st.Forgets) != 0 || len(r.d.forgets) != 0 {
		t.Fatalf("done forget kept after a reboot: %q", r.d.st.Forgets)
	}
	if held := r.holding("owner:a"); held != 0 {
		t.Fatalf("%d batches hold the forgotten reference", held)
	}
	if bs := r.batches(); bs[0].State != digestqueue.Unknown || !bs[0].Redacted || bs[0].Attempts != 1 {
		t.Fatalf("unknown batch %+v", bs[0])
	}
	if r.status() != digestUnknownStatus {
		t.Fatalf("status %q", r.status())
	}
	r.tr.out = nil
	r.at(1, 8, 0)
	got := r.tr.sent()
	if len(got) != 2 || !strings.Contains(got[1], fmt.Sprintf(digestUnknownLine, "Mon 5 Oct")) {
		t.Fatalf("day 1: %q", got)
	}
	for _, s := range got[1:] {
		if strings.Contains(s, "task 3") {
			t.Fatalf("forgotten line sent: %q", s)
		}
	}
}

// Security B2 on #592: a forget owed across a restart because the digest
// refused it is not told done at start until the digest's forget holds.
// REQ: CAP-3
func TestOwedForgetPurgesTheDigestAfterARestart(t *testing.T) {
	store := &change.MemStore{}
	r := restartRig(t, store)
	r.f.digest = func(string) error { return digestqueue.ErrInFlight }
	ended := make(chan struct{})
	r.f.sleep = func(context.Context, time.Duration) bool { return false } // shutdown
	r.f.retried = func() { close(ended) }
	since := time.Date(2026, 10, 5, 13, 2, 0, 0, time.UTC)
	if out := r.f.Execute(context.Background(), forgetIntent(fmt.Sprintf("1.1.%d", since.UnixNano()), "owner:a"), 1); out.Result != journal.ResultSucceeded {
		t.Fatalf("execute: %+v", out)
	}
	<-ended
	again := restart(t, store, map[string]bool{"owner:a": true})
	var mu sync.Mutex
	var asked []string
	refuse := 1
	again.f.digest = func(ref string) error {
		mu.Lock()
		defer mu.Unlock()
		asked = append(asked, ref)
		if refuse > 0 {
			refuse--
			return errors.New("digest: queue not open")
		}
		return nil
	}
	gate, purged := make(chan struct{}), make(chan struct{})
	again.f.sleep = func(context.Context, time.Duration) bool { <-gate; return true }
	again.f.retried = func() { close(purged) }
	again.f.finishOwed(context.Background())
	again.mu.Lock()
	early := len(again.texts)
	again.mu.Unlock()
	if early != 0 {
		t.Fatalf("done text before the digest's forget: %q", again.texts)
	}
	close(gate)
	<-purged
	again.mu.Lock()
	defer again.mu.Unlock()
	mu.Lock()
	defer mu.Unlock()
	if want := "Your task from Mon 5 Oct 13:02 is forgotten now."; len(again.texts) != 1 || !strings.HasPrefix(again.texts[0], want) ||
		strings.Join(asked, ",") != "owner:a,owner:a" {
		t.Fatalf("texts %q asked %q", again.texts, asked)
	}
}

// Security R3 on #592: the digest directory is made or tightened to 0700,
// a leftover temp file is removed, and a symlink or a file is refused.
// REQ: OP-2
func TestPrepareDigestDir(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "digest")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	tmp := filepath.Join(dir, "queue.json.tmp")
	if err := os.WriteFile(tmp, []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := prepareDigestDir(dir); err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Stat(dir); err != nil || fi.Mode().Perm() != 0o700 {
		t.Fatalf("dir %v %v", fi.Mode(), err)
	}
	if _, err := os.Stat(tmp); !os.IsNotExist(err) {
		t.Fatalf("temp file kept: %v", err)
	}
	if err := prepareDigestDir(filepath.Join(root, "new")); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "link")
	if err := os.Symlink(dir, link); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(root, "file")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{link, file} {
		if err := prepareDigestDir(p); err == nil {
			t.Errorf("%s accepted", p)
		}
	}
}

// ownerForget's done text waits for the digest queue's forget too.
// REQ: CAP-3
func TestForgetStaysOwedWhileTheDigestHoldsItInFlight(t *testing.T) {
	r := newForgetRig(t)
	inFlight := 2
	var asked []string
	r.f.digest = func(ref string) error {
		asked = append(asked, ref)
		if inFlight > 0 {
			inFlight--
			return digestqueue.ErrInFlight
		}
		return nil
	}
	done := make(chan struct{})
	r.f.retried = func() { close(done) }
	in := journal.Intent{ID: grants.ForgetID("1", "owner:a"), Origin: grants.OriginForget, Account: journal.BrokerAccount,
		Action: journal.ActionLearnForget, Executor: grants.ForgetExecutor}
	if out := r.f.Execute(context.Background(), in, 1); out.Result != journal.ResultSucceeded || out.Evidence != "forgetting; retrying" {
		t.Fatalf("execute: %+v", out)
	}
	<-done
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.texts) != 1 || !strings.HasPrefix(r.texts[0], "Forgotten.") || strings.Join(asked, ",") != "owner:a,owner:a,owner:a" {
		t.Fatalf("texts %q asked %q", r.texts, asked)
	}
}

// W5-Dc-r6: the adapter keeps only Receipt.Evidence (an item ID or fixed
// tag), never the recipient or the bridge code, and sends the text through
// Disclose and Fit as Inform does.
// REQ: OP-2
func TestDigestTransportKeepsOnlyReceiptEvidence(t *testing.T) {
	const owner = "+15550100123"
	cases := []struct {
		r    modemlink.Receipt
		out  digestqueue.Outcome
		evid string
	}{
		{modemlink.Receipt{Outcome: modemlink.ReceiptAccepted, Evidence: "a1b2", Code: "ok"}, digestqueue.TransportAccepted, "a1b2"},
		{modemlink.Receipt{Outcome: modemlink.ReceiptNotSent, Evidence: "recipient:a1b3", Code: "recipient"}, digestqueue.NotSent, "recipient:a1b3"},
		{modemlink.Receipt{Outcome: modemlink.ReceiptUnknown, Evidence: "a1b4", Code: "timeout"}, digestqueue.OutcomeUnknown, "a1b4"},
		{modemlink.Receipt{Outcome: "garbled", Evidence: owner}, digestqueue.OutcomeUnknown, ""},
	}
	for _, c := range cases {
		var to, text string
		tr := digestTransport{to: owner, send: func(t, s string) (modemlink.Receipt, error) { to, text = t, s; return c.r, errors.New("down") }}
		long := strings.Repeat("é", control.MaxText+5)
		out, evid := tr.Deliver(context.Background(), long)
		if out != c.out || evid != c.evid || to != owner || text != control.Fit(long) {
			t.Fatalf("%+v: %s %q to %q", c.r, out, evid, to)
		}
	}
	// End to end, the batch keeps the receipt's evidence and nothing else
	// (an unknown batch, so Compact keeps it to look at).
	r := newDigestRig(t, &change.MemStore{}, nil)
	var seen string
	r.d.cfg.Transport = digestTransport{to: owner, send: func(_, s string) (modemlink.Receipt, error) {
		seen = s
		return modemlink.Receipt{Outcome: modemlink.ReceiptUnknown, Evidence: "c0ffee", Code: "timeout"}, errors.New("down")
	}}
	r.d.open(context.Background())
	r.at(0, 8, 0)
	bs := r.batches()
	if len(bs) != 1 || bs[0].Evidence != "c0ffee" || !strings.Contains(seen, digestDayLine) {
		t.Fatalf("batches %+v text %q", bs, seen)
	}
}

// A secret-shaped digest goes as the pointer, as Inform's text would.
// REQ: CH-15
func TestDigestTransportDiscloses(t *testing.T) {
	var text string
	tr := digestTransport{to: "o", send: func(_, s string) (modemlink.Receipt, error) {
		text = s
		return modemlink.Receipt{Outcome: modemlink.ReceiptAccepted, Evidence: "x1"}, nil
	}}
	tr.Deliver(context.Background(), "Notes: key sk-ant-api03-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA; rotate it.")
	if strings.Contains(text, "sk-ant") {
		t.Fatalf("secret sent: %q", text)
	}
}

// A digest too long for one text is refused at render, so it is never cut
// silently: the attempt is NotSent and, exhausted, surfaced.
// REQ: CH-15, OP-9
func TestDigestRenderRefusesAnOverlongDigest(t *testing.T) {
	d := newDigestBox(digestConfig{Loc: time.UTC})
	snap, _ := digestqueue.NewSnapshot("notes", 1, []string{strings.Repeat("x", control.MaxText)}, nil)
	if _, err := d.render(digestqueue.Batch{Created: day0, Snapshots: []digestqueue.Snapshot{snap}}); err == nil {
		t.Fatal("overlong digest rendered")
	}
}

// Every digest line and STATUS line is owner-worded; the STATUS ones are
// in capLineTexts, so its wording test checks them too.
// REQ: OP-9, CH-15
func TestDigestLinesAreOwnerWorded(t *testing.T) {
	for _, l := range digestLineTexts() {
		if err := ownerWorded(l); err != nil {
			t.Errorf("%q: %v", l, err)
		}
	}
	all := strings.Join(capLineTexts(), "|")
	for _, l := range []string{digestUnknownStatus, digestFailedStatus, digestHeldStatus, digestDownStatus, digestOwedStatus} {
		if !strings.Contains(all, l) {
			t.Errorf("%q not in capLineTexts", l)
		}
	}
}

// A saved LastDay later than tomorrow is clock skew (the clock was set back,
// or a skewed save): the digest does not wait for that day, it goes today.
// REQ: CH-15, OP-9
func TestDigestSkewedLastDayDoesNotStopTheDigest(t *testing.T) {
	r := newDigestRig(t, &change.MemStore{}, nil)
	r.at(0, 8, 0)
	n := len(r.tr.sent())
	r.d.mu.Lock()
	r.d.st.LastDay = r.d.dayOf(r.now) + 400
	r.d.mu.Unlock()
	r.at(1, 8, 0)
	if got := r.tr.sent(); len(got) != n+1 {
		t.Fatalf("digest stopped by a LastDay far ahead: %q", got)
	}
	if want := r.d.dayOf(r.now); r.d.st.LastDay != want {
		t.Fatalf("LastDay %d, want %d", r.d.st.LastDay, want)
	}
	// Tomorrow's LastDay is not skew (a save just after midnight): no resend today.
	r.at(1, 9, 0)
	if got := r.tr.sent(); len(got) != n+1 {
		t.Fatalf("resent the same day: %q", got)
	}
}

// The skew reset never underflows: a clock at the epoch (today 0) with a
// saved day ahead resets to 0, not past the end of uint64, and the digest
// goes once the clock is right again.
// REQ: CH-15, OP-9
func TestDigestSkewResetAtDayZeroDoesNotUnderflow(t *testing.T) {
	r := newDigestRig(t, &change.MemStore{}, nil)
	r.d.mu.Lock()
	r.d.st.LastDay = 400
	r.d.mu.Unlock()
	r.now = time.Unix(0, 0)
	r.d.step(context.Background(), r.now)
	if got := r.d.st.LastDay; got != 0 {
		t.Fatalf("LastDay %d after a reset at day 0, want 0", got)
	}
	r.at(0, 8, 0)
	if got := r.tr.sent(); len(got) != 1 {
		t.Fatalf("digest stopped after the epoch clock: %q", got)
	}
}

// LastDay of today or tomorrow is not skew and stays as saved; the day after
// is. The test also covers a clock near the top of the range, where
// today+1 would wrap.
// REQ: CH-15, OP-9
func TestDigestSkewEdges(t *testing.T) {
	r := newDigestRig(t, &change.MemStore{}, nil)
	r.now = day0.Add(7 * time.Hour) // before the digest time: nothing else moves LastDay
	today := r.d.dayOf(r.now)
	for _, c := range []struct {
		last, want uint64
	}{{today, today}, {today + 1, today + 1}, {today + 2, today - 1}, {0, 0}} {
		r.d.mu.Lock()
		r.d.st.LastDay = c.last
		r.d.mu.Unlock()
		r.d.step(context.Background(), r.now)
		if r.d.st.LastDay != c.want {
			t.Fatalf("LastDay %d (today %d) became %d, want %d", c.last, today, r.d.st.LastDay, c.want)
		}
	}
	if skewed(math.MaxUint64, math.MaxUint64) || !skewed(math.MaxUint64, 5) {
		t.Fatal("skewed wraps at the top of the range")
	}
}
