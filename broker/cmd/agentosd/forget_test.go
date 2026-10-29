package main

// REQ: LOG-4, OWN-6

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/change"
	"github.com/ghbmrk/agentos/broker/owner/kernelsock"
)

// fakeKernel is the kernel's owner seam over a few subjects: Erase marks
// one erased and its readers become erased reads, as the kernel's
// projection does.
type fakeKernel struct {
	mu       sync.Mutex
	labels   map[string]string // subject: label
	items    map[string][]kernelsock.Item
	readers  map[string][]kernelsock.ErasedRead
	erased   map[string]bool
	erases   []string
	conf     kernelsock.Confirmation // fields copied into each erase's answer
	eraseErr map[string]error        // an erase that does not go through
	readsErr error
	closed   bool
	unread   []string
	unerased []kernelsock.Unerased
}

func newFakeKernel() *fakeKernel {
	return &fakeKernel{labels: map[string]string{}, items: map[string][]kernelsock.Item{}, readers: map[string][]kernelsock.ErasedRead{},
		erased: map[string]bool{}, eraseErr: map[string]error{}}
}

// add opens subject sub labelled label with n messages, read by lineages
// at the given times.
func (f *fakeKernel) add(sub, label string, n int, reads map[string]int64) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.labels[sub] = label
	f.items[sub] = []kernelsock.Item{{Store: "mail", Class: kernelsock.ClassLabel}}
	for range n {
		f.items[sub] = append(f.items[sub], kernelsock.Item{Store: "mail", Class: "message"})
	}
	for l, at := range reads {
		f.readers[sub] = append(f.readers[sub], kernelsock.ErasedRead{Subject: sub, Lineage: l, First: at})
	}
}

func (f *fakeKernel) Named(_ context.Context, label string) (found, unread []string, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed {
		return nil, nil, kernelsock.ErrContentClosed
	}
	for _, sub := range slices.Sorted(func(yield func(string) bool) {
		for s := range f.labels {
			if !yield(s) {
				return
			}
		}
	}) {
		if !f.erased[sub] && strings.EqualFold(f.labels[sub], label) {
			found = append(found, sub)
		}
	}
	return found, f.unread, nil
}

func (f *fakeKernel) Recall(_ context.Context, sub string) (kernelsock.Recall, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.labels[sub]; !ok {
		return kernelsock.Recall{}, false, nil
	}
	return kernelsock.Recall{Subject: sub, Items: f.items[sub], Erased: f.erased[sub]}, true, nil
}

func (f *fakeKernel) Erase(_ context.Context, sub string) (kernelsock.Confirmation, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.eraseErr[sub]; err != nil {
		return kernelsock.Confirmation{}, err
	}
	if _, ok := f.labels[sub]; !ok {
		return kernelsock.Confirmation{}, kernelsock.ErrSubject
	}
	if f.erased[sub] {
		return kernelsock.Confirmation{}, kernelsock.ErrErased
	}
	f.erased[sub] = true
	f.erases = append(f.erases, sub)
	c := f.conf
	c.Subject = sub
	return c, nil
}

func (f *fakeKernel) Unerased(context.Context) ([]kernelsock.Unerased, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.readsErr != nil {
		return nil, f.readsErr
	}
	return f.unerased, nil
}

func (f *fakeKernel) ErasedReads(context.Context) ([]kernelsock.ErasedRead, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.readsErr != nil {
		return nil, f.readsErr
	}
	var out []kernelsock.ErasedRead
	for sub, rs := range f.readers {
		if f.erased[sub] {
			out = append(out, rs...)
		}
	}
	slices.SortFunc(out, func(a, b kernelsock.ErasedRead) int { return strings.Compare(a.Subject+a.Lineage, b.Subject+b.Lineage) })
	return out, nil
}

// rewindMachines records ForgetSince calls; block, when set, holds each call
// until it is closed, and fail makes each fail.
type rewindMachines struct {
	mu    sync.Mutex
	calls []string
	since map[string]time.Time
	block chan struct{}
	fail  error
}

func (m *rewindMachines) ForgetSince(_ context.Context, lineage string, since time.Time) error {
	if m.block != nil {
		<-m.block
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.since == nil {
		m.since = map[string]time.Time{}
	}
	m.calls = append(m.calls, lineage)
	m.since[lineage] = since
	return m.fail
}

// forgetBox is a forget flow over fakes, its record in dir.
type forgetBox struct {
	k       *fakeKernel
	m       *rewindMachines
	rw      *eraseRewind
	f       *forgetFlow
	dir     string
	dropped int
	logs    []string
	// queued is the approval queue: what each lineage asked for, and
	// when; void closes it as grants.Gate.VoidSince does.
	queued  []queuedAsk
	voided  []string
	voidErr error
}

type queuedAsk struct {
	id, lineage string
	at          time.Time
}

func (b *forgetBox) void(lineage string, since time.Time) ([]string, error) {
	if b.voidErr != nil {
		return nil, b.voidErr
	}
	var ids []string
	b.queued = slices.DeleteFunc(b.queued, func(q queuedAsk) bool {
		if q.lineage == lineage && !q.at.Before(since) {
			ids = append(ids, q.id)
			return true
		}
		return false
	})
	b.voided = append(b.voided, ids...)
	return ids, nil
}

func newForgetBox(t *testing.T, k *fakeKernel, m *rewindMachines, dir string) *forgetBox {
	t.Helper()
	b := &forgetBox{k: k, m: m, dir: dir}
	b.rw = openEraseRewind(filepath.Join(dir, eraseRewoundFile), func(f string, a ...any) { b.logs = append(b.logs, f) })
	b.rw.attach(k, func() lineageForgetter { return m }, func() error { b.dropped++; return nil }, b.void)
	b.rw.startWait = 0
	b.f = newForgetFlow(k, b.rw)
	return b
}

func (b *forgetBox) forget(t *testing.T, name string) forgetResult {
	t.Helper()
	found, err := b.f.find(context.Background(), name)
	if err != nil || found.Handle == "" {
		t.Fatalf("find %q: %+v %v", name, found, err)
	}
	r, err := b.f.confirm(context.Background(), found.Handle)
	if err != nil {
		t.Fatalf("confirm: %v", err)
	}
	return r
}

// D-169: confirm does not return until every lineage that read the erased
// content has gone back to before its first read; the lineage is contained
// meanwhile, and the kept agent replies are dropped. Catches a reply sent
// first.
func TestTheReplyFollowsTheRewind(t *testing.T) {
	k := newFakeKernel()
	k.add("s1", "Alice", 2, map[string]int64{"helper.1": 5000})
	k.add("s2", "Alice", 1, map[string]int64{"helper.1": 3000})
	m := &rewindMachines{block: make(chan struct{})}
	b := newForgetBox(t, k, m, t.TempDir())
	b.rw.settle(context.Background(), func(string) error { return nil })
	if b.rw.Contained("helper.1") {
		t.Fatal("contained before anything was erased")
	}
	found, err := b.f.find(context.Background(), "alice")
	if err != nil || found.Items != 3 || found.Kinds["message"] != 3 {
		t.Fatalf("find: %+v %v", found, err)
	}
	done := make(chan forgetResult)
	go func() {
		r, err := b.f.confirm(context.Background(), found.Handle)
		if err != nil {
			t.Error(err)
		}
		done <- r
	}()
	deadline := time.Now().Add(5 * time.Second)
	for !b.rw.Contained("helper.1") {
		if time.Now().After(deadline) {
			t.Fatal("the reader was never contained")
		}
		time.Sleep(time.Millisecond)
	}
	select {
	case <-done:
		t.Fatal("confirm returned before the rewind")
	case <-time.After(50 * time.Millisecond):
	}
	if b.rw.Contained("other.1") {
		t.Fatal("a lineage that read nothing is contained")
	}
	close(m.block)
	r := <-done
	if !slices.Equal(r.Rewound, []string{"helper.1"}) || r.Held != nil || r.Erased != 2 {
		t.Fatalf("result: %+v", r)
	}
	if !slices.Equal(m.calls, []string{"helper.1"}) || !m.since["helper.1"].Equal(time.UnixMilli(3000)) {
		t.Fatalf("one rewind, to the earliest read: %v %v", m.calls, m.since)
	}
	if b.dropped != 1 {
		t.Fatalf("kept replies dropped %d times", b.dropped)
	}
	if b.rw.Contained("helper.1") || b.rw.Note() != "" {
		t.Fatalf("still contained after the rewind: %q", b.rw.Note())
	}
	if !strings.Contains(r.Text(), "Agent helper went back to before it read them.") {
		t.Fatalf("text: %q", r.Text())
	}
}

// D-169 when the kernel answers late: the start-up pass cannot read the
// erased reads, so watch rewinds once it can, and tells the owner then,
// once, not at the next restart (L3 1 on #3691).
func TestWatchTellsTheOwnerOfItsRewind(t *testing.T) {
	k := newFakeKernel()
	k.add("s1", "Alice", 1, map[string]int64{"helper.1": 5000})
	k.erased["s1"] = true
	k.readsErr = errors.New("kernel not up")
	m := &rewindMachines{}
	b := newForgetBox(t, k, m, t.TempDir())
	var mu sync.Mutex
	var told []string
	tell := func(s string) error { mu.Lock(); told = append(told, s); mu.Unlock(); return nil }
	b.rw.settle(context.Background(), tell)
	if !b.rw.Contained("helper.1") || !b.rw.Contained("other.1") || len(told) != 0 {
		t.Fatalf("reads unknown: told %q", told)
	}
	k.mu.Lock()
	k.readsErr = nil
	k.mu.Unlock()
	watchUntilCleanup(t, b.rw, tell)
	deadline := time.Now().Add(5 * time.Second)
	for {
		mu.Lock()
		n := len(told)
		mu.Unlock()
		if n > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("watch rewound but never told the owner")
		}
		time.Sleep(time.Millisecond)
	}
	time.Sleep(20 * time.Millisecond)
	mu.Lock()
	defer mu.Unlock()
	if len(told) != 1 || !strings.HasPrefix(told[0], "Agent helper had read something you had me forget") || len(m.calls) != 1 || b.rw.Contained("helper.1") {
		t.Fatalf("told %q, rewinds %v", told, m.calls)
	}
}

// A confirm's rewind is told by its result: its record is marked told only
// once the result is built, and no later pass tells it again (L3 2 on
// #3691).
func TestAConfirmsRewindIsToldOnce(t *testing.T) {
	dir := t.TempDir()
	k := newFakeKernel()
	k.add("s1", "Alice", 1, map[string]int64{"helper.1": 5000})
	m := &rewindMachines{}
	b := newForgetBox(t, k, m, dir)
	b.rw.settle(context.Background(), func(string) error { return nil })
	b.forget(t, "Alice")
	var told []string
	newForgetBox(t, k, m, dir).rw.settle(context.Background(), func(s string) error { told = append(told, s); return nil })
	if len(told) != 0 || len(m.calls) != 1 {
		t.Fatalf("told again %q, rewinds %v", told, m.calls)
	}
}

// D-169 at start: an erased subject with a reader and no record (a crash
// after the erase) is rewound by the start-up pass and the owner told
// once; a recorded one is not rewound again.
func TestStartRewindsWhatACrashLeft(t *testing.T) {
	dir := t.TempDir()
	k := newFakeKernel()
	k.add("s1", "Alice", 1, map[string]int64{"helper.1": 5000})
	k.add("s2", "Bob", 1, map[string]int64{"writer.1": 6000})
	k.erased["s1"] = true // erased, then the crash: no rewind, no record
	m := &rewindMachines{}
	b := newForgetBox(t, k, m, dir)
	if !b.rw.Contained("helper.1") || !b.rw.Contained("writer.1") {
		t.Fatal("before the start-up pass every agent is contained")
	}
	var told []string
	tell := func(s string) error { told = append(told, s); return nil }
	b.rw.settle(context.Background(), tell)
	if !slices.Equal(m.calls, []string{"helper.1"}) || len(told) != 1 || !strings.HasPrefix(told[0], "Agent helper had read something you had me forget") {
		t.Fatalf("rewinds %v, told %q", m.calls, told)
	}
	if b.rw.Contained("helper.1") || b.rw.Contained("writer.1") {
		t.Fatal("contained after the pass")
	}
	// The next start rewinds nothing again and tells nobody again.
	b2 := newForgetBox(t, k, m, dir)
	b2.rw.settle(context.Background(), tell)
	if len(m.calls) != 1 || len(told) != 1 {
		t.Fatalf("second start: rewinds %v, told %q", m.calls, told)
	}
	// A rewind settled with the owner untold (a crash before the notice)
	// is told at the next start, once, with no second rewind.
	k.erased["s2"] = true
	b3 := newForgetBox(t, k, m, dir)
	b3.rw.settle(context.Background(), func(string) error { return errors.New("no owner channel") })
	b4 := newForgetBox(t, k, m, dir)
	b4.rw.settle(context.Background(), tell)
	if !slices.Equal(m.calls, []string{"helper.1", "writer.1"}) || len(told) != 2 || !strings.HasPrefix(told[1], "Agent writer") {
		t.Fatalf("untold rewind: rewinds %v, told %q", m.calls, told)
	}
}

// Fail closed: ForgetSince fails, so the lineage stays contained (no fork
// or merge), STATUS has its line, and the next start tries again.
func TestAFailedRewindStaysContained(t *testing.T) {
	dir := t.TempDir()
	k := newFakeKernel()
	k.add("s1", "Alice", 1, map[string]int64{"helper.1": 5000})
	m := &rewindMachines{fail: errors.New("disk full")}
	b := newForgetBox(t, k, m, dir)
	b.rw.settle(context.Background(), func(string) error { return nil })
	r := b.forget(t, "Alice")
	if r.Rewound != nil || !slices.Equal(r.Held, []string{"helper.1"}) {
		t.Fatalf("result: %+v", r)
	}
	if !strings.Contains(r.Text(), "Agent helper could not go back yet; it is held from copying itself until it does.") {
		t.Fatalf("text: %q", r.Text())
	}
	if !b.rw.Contained("helper.1") || b.rw.Contained("other.1") {
		t.Fatal("the failed lineage is not contained, or another is")
	}
	if line := b.rw.Note(); line != forgetHeldLine([]string{"helper.1"}) || ownerWorded(line) != nil {
		t.Fatalf("STATUS %q", line)
	}
	m.fail = nil
	b2 := newForgetBox(t, k, m, dir)
	b2.rw.settle(context.Background(), func(string) error { return nil })
	if !slices.Equal(m.calls, []string{"helper.1", "helper.1"}) || b2.rw.Contained("helper.1") || b2.rw.Note() != "" {
		t.Fatalf("the next start: %v %q", m.calls, b2.rw.Note())
	}
	// Kept replies that do not drop settle nothing: the lineage stays held.
	k.add("s2", "Bob", 1, map[string]int64{"writer.1": 7000})
	b2.rw.attach(k, func() lineageForgetter { return m }, func() error { return errors.New("read-only") }, nil)
	r = b2.forget(t, "Bob")
	if !slices.Equal(r.Held, []string{"writer.1"}) || !b2.rw.Contained("writer.1") || len(m.calls) != 3 {
		t.Fatalf("replies not dropped: %+v %v", r, m.calls)
	}
	// Erased reads the kernel does not answer contain every agent until it
	// does; an unreadable record contains every agent and is kept.
	k.readsErr = errors.New("unreachable")
	b3 := newForgetBox(t, k, m, dir)
	b3.rw.settle(context.Background(), func(string) error { return nil })
	if !b3.rw.Contained("other.1") || b3.rw.Note() != forgetReadsUnknown {
		t.Fatalf("reads unknown: %q", b3.rw.Note())
	}
	k.readsErr = nil
	b3.rw.rewind(context.Background())
	if b3.rw.Contained("other.1") {
		t.Fatal("still all contained once the reads are known")
	}
	// A record that cannot be read contains every agent and is kept.
	bad := t.TempDir()
	if err := os.Mkdir(filepath.Join(bad, eraseRewoundFile), 0o700); err != nil {
		t.Fatal(err)
	}
	b4 := newForgetBox(t, k, m, bad)
	b4.rw.settle(context.Background(), func(string) error { return nil })
	if !b4.rw.Contained("other.1") || b4.rw.Note() != forgetRecordUnread {
		t.Fatalf("unreadable record: %q", b4.rw.Note())
	}
	if fi, err := os.Stat(filepath.Join(bad, eraseRewoundFile)); err != nil || !fi.IsDir() {
		t.Fatalf("unreadable record replaced: %v", err)
	}
	// A corrupt one is set aside, and every reader goes back again and
	// the owner is told, so the agents are not held for good (L3 3 on
	// #3691).
	corrupt := t.TempDir()
	if err := os.WriteFile(filepath.Join(corrupt, eraseRewoundFile), []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	before := len(m.calls)
	var told []string
	b5 := newForgetBox(t, k, m, corrupt)
	b5.rw.settle(context.Background(), func(s string) error { told = append(told, s); return nil })
	if b5.rw.Contained("helper.1") || b5.rw.Contained("other.1") || len(m.calls) != before+2 || len(told) != 2 {
		t.Fatalf("corrupt record: rewinds %v, told %q, note %q", m.calls[before:], told, b5.rw.Note())
	}
	if got, err := os.ReadFile(filepath.Join(corrupt, eraseRewoundFile+".corrupt")); err != nil || string(got) != "{" {
		t.Fatalf("corrupt record not set aside: %q %v", got, err)
	}
	// No kernel attached: nothing was ever erased here, nothing contained.
	if none := openEraseRewind(filepath.Join(t.TempDir(), eraseRewoundFile), t.Logf); none.Contained("x") || none.Note() != "" {
		t.Fatal("contained with no kernel")
	}
}

// Exactness: confirm erases the subjects its find showed and no other, even
// one labelled the same since; an expired or reused handle erases nothing.
func TestConfirmErasesOnlyWhatWasShown(t *testing.T) {
	ctx := context.Background()
	k := newFakeKernel()
	k.add("s1", "Alice", 1, nil)
	b := newForgetBox(t, k, &rewindMachines{}, t.TempDir())
	found, err := b.f.find(ctx, "Alice")
	if err != nil {
		t.Fatal(err)
	}
	k.add("s2", "Alice", 1, nil) // labelled the same after the find
	if _, err := b.f.confirm(ctx, found.Handle); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(k.erases, []string{"s1"}) {
		t.Fatalf("erased %v", k.erases)
	}
	if _, err := b.f.confirm(ctx, found.Handle); !errors.Is(err, ErrForgetHandle) {
		t.Fatalf("reused handle: %v", err)
	}
	if _, err := b.f.confirm(ctx, "not-a-handle"); !errors.Is(err, ErrForgetHandle) {
		t.Fatalf("unknown handle: %v", err)
	}
	now := time.Now()
	b.f.now = func() time.Time { return now }
	found, _ = b.f.find(ctx, "Alice")
	b.f.now = func() time.Time { return now.Add(forgetFor) }
	if _, err := b.f.confirm(ctx, found.Handle); !errors.Is(err, ErrForgetHandle) || len(k.erases) != 1 {
		t.Fatalf("expired handle: %v, erased %v", err, k.erases)
	}
	// One erased meanwhile is counted, not an error.
	b.f.now = time.Now
	found, _ = b.f.find(ctx, "Alice")
	k.erased["s2"] = true
	r, err := b.f.confirm(ctx, found.Handle)
	if err != nil || r.Already != 1 || r.Erased != 0 {
		t.Fatalf("erased meanwhile: %+v %v", r, err)
	}
	// Nothing found gives no handle; the finds waiting are bounded.
	if f, err := b.f.find(ctx, "Carol"); err != nil || f.Handle != "" || f.Text() != "Nothing named Carol was found." {
		t.Fatalf("nothing found: %+v %v", f, err)
	}
	k.add("s3", "Dana", 1, nil)
	for range maxForgets + 3 {
		if _, err := b.f.find(ctx, "Dana"); err != nil {
			t.Fatal(err)
		}
	}
	if len(b.f.pending) != maxForgets {
		t.Fatalf("%d finds waiting", len(b.f.pending))
	}
	k.closed = true
	if f, err := b.f.find(ctx, "Dana"); err != nil || !f.Closed || f.Handle != "" || f.Text() != "Stored content can't be read right now, so nothing was forgotten." {
		t.Fatalf("content closed: %+v %v", f, err)
	}
}

// OWN-6: each result leads with its outcome, names the key table "the
// key", never promises deletion from a disk, and says "not finished" from
// the stores owed.
func TestForgetResultWording(t *testing.T) {
	base := forgetResult{Name: "Alice", Items: 3, Erased: 1}
	for _, c := range []struct {
		name string
		r    func(r *forgetResult)
		want string
	}{
		{"done", func(*forgetResult) {}, "Forgot everything named Alice (3 items). It can no longer be read."},
		{"key owed", func(r *forgetResult) { r.Owed = []string{kernelsock.KeyTable} },
			"Forgot everything named Alice (3 items), but it is not finished: the key has not deleted them yet. I keep trying, and STATUS shows it."},
		{"a store owed", func(r *forgetResult) { r.Owed = []string{"mail", kernelsock.KeyTable} },
			"Forgot everything named Alice (3 items), but it is not finished: the key and the mail store have not deleted them yet. I keep trying, and STATUS shows it."},
		{"still held", func(r *forgetResult) {
			r.StillHeld = []kernelsock.BackupHold{{Backup: "drive", Why: "the drive is not plugged in"}}
		}, "Forgot everything named Alice (3 items). It can no longer be read. The older backup drive may still hold them: the drive is not plugged in."},
		{"backups unknown", func(r *forgetResult) { r.BackupsUnknown = true },
			"Forgot everything named Alice (3 items). It can no longer be read. Older backups may still hold them."},
		{"unread", func(r *forgetResult) { r.Unread = true },
			"Forgot everything named Alice (3 items). It can no longer be read. Some things could not be checked, so anything named Alice in them is still kept."},
		{"not erased", func(r *forgetResult) { r.Erased, r.NotErased = 0, 1 },
			"Nothing was forgotten: I could not forget everything named Alice (3 items) just now, so it is still kept. Look the name up again."},
		{"part erased", func(r *forgetResult) { r.NotErased = 1 },
			"Not finished: I could not forget 1 thing of everything named Alice (3 items) just now, so those are still kept. Look the name up again."},
		{"already", func(r *forgetResult) { r.Erased, r.Already, r.Items = 0, 1, 1 },
			"Forgot everything named Alice (1 item). It can no longer be read. 1 thing had already been forgotten."},
		{"unchecked", func(r *forgetResult) { r.Unchecked = true },
			"Forgot everything named Alice (3 items). It can no longer be read. I could not check which agents read them, so no agent can copy itself until I can."},
	} {
		r := base
		c.r(&r)
		got := r.Text()
		if got != c.want {
			t.Errorf("%s:\n got %q\nwant %q", c.name, got, c.want)
		}
		for _, bad := range []string{kernelsock.KeyTable, "disk", "deleted from"} {
			if strings.Contains(got, bad) {
				t.Errorf("%s: %q holds %q", c.name, got, bad)
			}
		}
	}
	// The kernel's real confirmation reaches the text through confirm.
	k := newFakeKernel()
	k.add("s1", "Alice", 2, nil)
	k.conf = kernelsock.Confirmation{Unconfirmed: []string{kernelsock.KeyTable}, BackupsUnknown: true}
	r := newForgetBox(t, k, &rewindMachines{}, t.TempDir()).forget(t, "Alice")
	if want := "Forgot everything named Alice (2 items), but it is not finished: the key has not deleted them yet. I keep trying, and STATUS shows it. Older backups may still hold them."; r.Text() != want {
		t.Fatalf("through confirm: %q", r.Text())
	}
}

// keepingMachines keeps a reply built from the erased content while the
// first reader is going back, as a second reader still running would.
type keepingMachines struct {
	kept  *keptReplies
	calls []string
}

func (m *keepingMachines) ForgetSince(_ context.Context, lineage string, _ time.Time) error {
	if len(m.calls) == 0 {
		m.kept.keep("reply built from CANARY-mail")
	}
	m.calls = append(m.calls, lineage)
	return nil
}

// LOG-4, D-169: the kept replies are dropped only after every reader has
// gone back, so a reply one posts while another goes back does not survive
// (Security 1 on #3691); a drop that fails settles nothing and watch tries
// all of it again.
func TestNoReplyKeptDuringTheRewindSurvives(t *testing.T) {
	dir := t.TempDir()
	k := newFakeKernel()
	k.add("s1", "Alice", 1, map[string]int64{"a.1": 1000, "b.1": 2000})
	kept := &keptReplies{store: change.FileStore{Path: filepath.Join(dir, "kept.json")}, now: time.Now}
	kept.keep("old reply")
	m := &keepingMachines{kept: kept}
	rw := openEraseRewind(filepath.Join(dir, eraseRewoundFile), t.Logf)
	fail := errors.New("read-only")
	drops := 0
	rw.attach(k, func() lineageForgetter { return m }, func() error {
		if drops++; drops == 2 {
			return fail
		}
		_, err := kept.forget()
		return err
	}, nil)
	rw.settle(context.Background(), func(string) error { return nil })
	f := newForgetFlow(k, rw)
	found, _ := f.find(context.Background(), "Alice")
	r, err := f.confirm(context.Background(), found.Handle)
	if err != nil {
		t.Fatal(err)
	}
	if l := kept.list(); len(l) != 0 {
		t.Fatalf("kept replies still hold %q after %q", l[0].Text, r.Text())
	}
	if !strings.Contains(r.Text(), "Agents a and b went back to before they read them.") {
		t.Fatalf("text: %q", r.Text())
	}
	// A drop that fails: the readers stay held, and watch retries.
	k.add("s2", "Bob", 1, map[string]int64{"c.1": 3000})
	found, _ = f.find(context.Background(), "Bob")
	r, _ = f.confirm(context.Background(), found.Handle)
	if r.Rewound != nil || !slices.Equal(r.Held, []string{"c.1"}) || !rw.Contained("c.1") {
		t.Fatalf("failed drop: %+v", r)
	}
	told := make(chan string, 4)
	watchUntilCleanup(t, rw, func(s string) error {
		select {
		case told <- s:
		default:
		}
		return nil
	})
	select {
	case s := <-told:
		if !strings.HasPrefix(s, "Agent c had read") || rw.Contained("c.1") {
			t.Fatalf("after the retry: %q", s)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("watch never retried the held reader")
	}
}

// watchUntilCleanup runs watch until the test ends and waits for it to
// return, so it never writes into a TempDir that cleanup is removing.
func watchUntilCleanup(t *testing.T, rw *eraseRewind, tell func(string) error) {
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); rw.watch(ctx, time.Millisecond, tell) }()
	t.Cleanup(func() { cancel(); <-done })
}

// ctxMachines: the owner's page request ends as the rewind starts, and
// vm's ForgetSince honours ctx.
type ctxMachines struct{ cancel func() }

func (m *ctxMachines) ForgetSince(ctx context.Context, _ string, _ time.Time) error {
	m.cancel()
	return ctx.Err()
}

// LOG-4 fails closed: the surface's request ending mid-confirm cancels
// neither the erase nor the rewind (Security 2 on #3691).
func TestAnEndedRequestStillRewinds(t *testing.T) {
	k := newFakeKernel()
	k.add("s1", "Alice", 1, map[string]int64{"a.1": 1000})
	ctx, cancel := context.WithCancel(context.Background())
	rw := openEraseRewind(filepath.Join(t.TempDir(), eraseRewoundFile), t.Logf)
	rw.attach(k, func() lineageForgetter { return &ctxMachines{cancel: cancel} }, func() error { return nil }, nil)
	rw.settle(context.Background(), func(string) error { return nil })
	f := newForgetFlow(k, rw)
	found, _ := f.find(ctx, "Alice")
	r, err := f.confirm(ctx, found.Handle)
	if err != nil || r.Held != nil || !slices.Equal(r.Rewound, []string{"a.1"}) {
		t.Fatalf("held=%v rewound=%v %v", r.Held, r.Rewound, err)
	}
}

// LOG-4, D-169 (Security 3 on #3691): what a reader queued from the
// content, an approval card or an effect in its undo window, is closed
// before confirm returns, and the result says so; its asks from before
// the read, and another agent's, are kept. A queue that cannot be closed
// holds the reader.
func TestARewoundReadersQueueIsVoided(t *testing.T) {
	k := newFakeKernel()
	k.add("s1", "Alice", 1, map[string]int64{"helper.1": 5000})
	b := newForgetBox(t, k, &rewindMachines{}, t.TempDir())
	ask := func(id, l string, ms int64) queuedAsk { return queuedAsk{id, l, time.UnixMilli(ms)} }
	b.queued = []queuedAsk{ask("before", "helper.1", 4999), ask("card", "helper.1", 5000), ask("held", "helper.1", 7000), ask("other", "other.1", 6000)}
	b.rw.settle(context.Background(), func(string) error { return nil })
	r := b.forget(t, "Alice")
	if !slices.Equal(r.Voided, []string{"card", "held"}) || len(b.queued) != 2 || b.queued[0].id != "before" || b.queued[1].id != "other" {
		t.Fatalf("voided %v, kept %v", r.Voided, b.queued)
	}
	if !strings.Contains(r.Text(), "I cancelled 2 requests an agent made after reading them, so they will not run.") {
		t.Fatalf("text: %q", r.Text())
	}
	k.add("s2", "Bob", 1, map[string]int64{"writer.1": 8000})
	b.voidErr = errors.New("journal unreadable")
	r = b.forget(t, "Bob")
	if r.Rewound != nil || !slices.Equal(r.Held, []string{"writer.1"}) || !b.rw.Contained("writer.1") {
		t.Fatalf("queue not closed, yet: %+v", r)
	}
}

// D-169 "before any is served" (Security 4 on #3691): the start-up pass
// waits a bound for the kernel's first answer, so a reader a crash left
// is rewound before machines are served; past the bound every agent stays
// contained and STATUS says so.
func TestStartWaitsForTheErasedReads(t *testing.T) {
	k := newFakeKernel()
	k.add("s1", "Alice", 1, map[string]int64{"helper.1": 5000})
	k.erased["s1"] = true
	k.readsErr = errors.New("kernel not up")
	m := &rewindMachines{}
	b := newForgetBox(t, k, m, t.TempDir())
	b.rw.startWait = 5 * time.Second
	go func() {
		time.Sleep(50 * time.Millisecond)
		k.mu.Lock()
		k.readsErr = nil
		k.mu.Unlock()
	}()
	b.rw.settle(context.Background(), func(string) error { return nil })
	if !slices.Equal(m.calls, []string{"helper.1"}) || b.rw.Contained("helper.1") {
		t.Fatalf("served before the rewind: %v", m.calls)
	}
	k.mu.Lock()
	k.readsErr = errors.New("kernel not up")
	k.mu.Unlock()
	b2 := newForgetBox(t, k, &rewindMachines{}, t.TempDir())
	b2.rw.startWait = 20 * time.Millisecond
	b2.rw.settle(context.Background(), func(string) error { return nil })
	if !b2.rw.Contained("helper.1") || !b2.rw.Contained("other.1") || b2.rw.Note() != forgetReadsUnknown {
		t.Fatalf("past the bound: %q", b2.rw.Note())
	}
}

// D-169 "then tells the owner" (delta L3 1 on #3691): a confirm marks told
// only the rewinds it made, so an earlier one whose notice did not go is
// still told, and watch sends it without waiting for another rewind.
func TestAConfirmLeavesAnEarlierUntoldRewind(t *testing.T) {
	dir := t.TempDir()
	k := newFakeKernel()
	k.add("s1", "Alice", 1, map[string]int64{"helper.1": 5000})
	k.erased["s1"] = true
	k.add("s2", "Bob", 1, map[string]int64{"helper.1": 9000})
	m := &rewindMachines{}
	b := newForgetBox(t, k, m, dir)
	b.rw.settle(context.Background(), func(string) error { return errors.New("owner channel down") })
	b.forget(t, "Bob")
	told := make(chan string, 4)
	watchUntilCleanup(t, b.rw, func(s string) error { told <- s; return nil })
	select {
	case s := <-told:
		if !strings.HasPrefix(s, "Agent helper had read") || len(m.calls) != 2 {
			t.Fatalf("told %q after rewinds %v", s, m.calls)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the earlier rewind was never told")
	}
}

// Delta L3 2 on #3691: a record that is not written reports the readers
// held, never also gone, and marks nothing told.
func TestAnUnsavedRewindIsOnlyHeld(t *testing.T) {
	dir := t.TempDir()
	k := newFakeKernel()
	k.add("s1", "Alice", 1, map[string]int64{"helper.1": 5000})
	b := newForgetBox(t, k, &rewindMachines{}, dir)
	b.rw.settle(context.Background(), func(string) error { return nil })
	if err := os.MkdirAll(filepath.Join(dir, eraseRewoundFile, "x"), 0o700); err != nil {
		t.Fatal(err)
	}
	r := b.forget(t, "Alice")
	if r.Rewound != nil || !slices.Equal(r.Held, []string{"helper.1"}) || strings.Contains(r.Text(), "went back") || !b.rw.Contained("helper.1") {
		t.Fatalf("unsaved: %+v %q", r, r.Text())
	}
}
