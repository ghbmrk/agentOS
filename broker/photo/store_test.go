// REQ: CH-23, CH-26, OP-11, CAP-3, RES-4

package photo

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/clock"
	"github.com/ghbmrk/agentos/broker/journal"
	"github.com/ghbmrk/agentos/broker/recall"
)

type allowAll struct{}

func (allowAll) Check(context.Context, journal.Phase, journal.Intent) error { return nil }

// fakeClock is the trusted clock: one reading for both bounds.
type fakeClock struct {
	t  *time.Time
	st clock.Status
}

func (c *fakeClock) Earliest(context.Context) (time.Time, clock.Status) { return *c.t, c.st }
func (c *fakeClock) Latest(context.Context) (time.Time, clock.Status)   { return *c.t, c.st }

var verified = clock.Status{State: clock.Agreed, Verified: true}

type rig struct {
	t   *testing.T
	dir string
	mem *journal.MemStore
	eng *journal.Engine
	s   *Store
	now time.Time
	clk *fakeClock
}

var t0 = time.Date(2026, 10, 17, 9, 0, 0, 0, time.UTC)

func newRig(t *testing.T) *rig {
	t.Helper()
	r := &rig{t: t, dir: t.TempDir(), mem: &journal.MemStore{}, now: t0}
	r.clk = &fakeClock{t: &r.now, st: verified}
	r.open()
	return r
}

// open (re)starts the store and its engine on the rig's journal and
// directory, as a boot does.
func (r *rig) open() {
	r.t.Helper()
	r.s = &Store{Dir: r.dir, Clock: r.clk, Location: time.UTC, Now: func() time.Time { return r.now }}
	var err error
	r.eng, err = journal.Open(r.mem, allowAll{}, map[string]journal.Executor{Executor: r.s},
		func(s string) string { return s }, journal.WithClock(func() time.Time { return r.now }))
	if err != nil {
		r.t.Fatal(err)
	}
	r.s.Journal = r.eng
	if err := r.s.Open(); err != nil {
		r.t.Fatal(err)
	}
	r.eng.Reconcile(context.Background())
}

func photoN(n int) Photo {
	return Photo{Format: "png", Width: 40 + n, Height: 30, ThumbWidth: 4, ThumbHeight: 3,
		Image: []byte(fmt.Sprintf("synthetic-image-%d", n)), Thumb: []byte(fmt.Sprintf("synthetic-thumb-%d", n))}
}

func upload(ps ...Photo) []Received {
	out := make([]Received, len(ps))
	for i, p := range ps {
		out[i] = Received{Photo: p, Source: SourceUpload, Task: "task-1"}
	}
	return out
}

func (r *rig) keep(ps ...Photo) []Entry {
	r.t.Helper()
	got, err := r.s.Keep(context.Background(), upload(ps...))
	if err != nil {
		r.t.Fatal(err)
	}
	return got
}

func (r *rig) list() []Entry {
	r.t.Helper()
	es, err := r.s.List()
	if err != nil {
		r.t.Fatal(err)
	}
	return es
}

func hashOf(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }

// files lists the store directory's names, sorted.
func files(t *testing.T, dir string) []string {
	t.Helper()
	des, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, d := range des {
		out = append(out, d.Name())
	}
	sort.Strings(out)
	return out
}

// photoIntents lists the photo intents the journal records, by ID.
func photoIntents(t *testing.T, e *journal.Engine) map[string]journal.Intent {
	t.Helper()
	recs, err := e.ReadTrail()
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]journal.Intent{}
	for _, rec := range recs {
		if rec.Type == journal.RecSubmitted && rec.Intent != nil && strings.HasPrefix(rec.Intent.Action, "photo.") {
			out[rec.ID] = *rec.Intent
		}
	}
	return out
}

func succeeded(t *testing.T, e *journal.Engine, id string) bool {
	t.Helper()
	st, err := e.Get(id)
	return err == nil && st.State == journal.Succeeded
}

func TestStoreKeepsByHash(t *testing.T) {
	r := newRig(t)
	got := r.keep(photoN(1), photoN(1), photoN(2))
	if len(got) != 3 || got[0].ID != "P1" || got[1].ID != "P2" || got[2].ID != "P3" {
		t.Fatalf("kept %+v, want P1..P3", got)
	}
	h1, h2 := hashOf(photoN(1).Image), hashOf(photoN(2).Image)
	if got[0].Hash != h1 || got[1].Hash != h1 || got[2].Hash != h2 {
		t.Fatalf("hashes %s %s %s", got[0].Hash, got[1].Hash, got[2].Hash)
	}
	want := []string{h1, h1 + thumbSuffix, h2, h2 + thumbSuffix}
	sort.Strings(want)
	if f := files(t, r.dir); fmt.Sprint(f) != fmt.Sprint(want) {
		t.Fatalf("files %v, want one copy per hash %v", f, want)
	}
	img, err := r.s.Image("P2")
	if err != nil || !bytes.Equal(img, photoN(1).Image) {
		t.Fatalf("Image(P2) = %q, %v", img, err)
	}
	th, err := r.s.Thumb("P3")
	if err != nil || !bytes.Equal(th, photoN(2).Thumb) {
		t.Fatalf("Thumb(P3) = %q, %v", th, err)
	}
	e := r.list()[2]
	if e.Source != SourceUpload || e.Task != "task-1" || e.Width != 42 || e.Height != 30 || !e.Received.Equal(t0) ||
		!e.Expires.Equal(t0.AddDate(0, 0, DefaultDays)) {
		t.Fatalf("entry %+v", e)
	}
	// A kept file whose bytes no longer match its name is not served.
	if err := os.WriteFile(filepath.Join(r.dir, h2), []byte("tampered"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := r.s.Image("P3"); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("tampered Image = %v, want ErrCorrupt", err)
	}
}

func TestStoreJournalsReceiptDeliveryDeletion(t *testing.T) {
	r := newRig(t)
	ctx := context.Background()
	r.keep(photoN(1))
	if err := r.s.Deliver(ctx, "P1", "agent-1"); err != nil {
		t.Fatal(err)
	}
	if err := r.s.Deliver(ctx, "P1", "agent-1"); err != nil {
		t.Fatalf("a repeated delivery: %v", err)
	}
	r.open() // the listing is the journal's, after a restart too
	if es := r.list(); len(es) != 1 || fmt.Sprint(es[0].Machines) != "[agent-1]" {
		t.Fatalf("listing after restart %+v", es)
	}
	ins := photoIntents(t, r.eng)
	for id, action := range map[string]string{"photo:keep:P1": ActionKeep + SourceUpload, "photo:deliver:P1:agent-1": ActionDeliver} {
		if ins[id].Action != action || !succeeded(t, r.eng, id) {
			t.Fatalf("intent %s = %+v, want %s succeeded", id, ins[id], action)
		}
	}
	if _, err := r.s.Delete(ctx, "P1"); err != nil {
		t.Fatal(err)
	}
	if !succeeded(t, r.eng, "photo:delete:P1") || photoIntents(t, r.eng)["photo:delete:P1"].Action != ActionDelete {
		t.Fatal("the deletion is not a succeeded journal intent")
	}
	if err := r.s.Deliver(ctx, "P1", "agent-2"); !errors.Is(err, ErrUnknown) {
		t.Fatalf("delivering a deleted photo = %v, want ErrUnknown", err)
	}
	r.open()
	if es := r.list(); len(es) != 0 {
		t.Fatalf("deleted photo listed after restart: %+v", es)
	}
	if got := r.keep(photoN(2)); got[0].ID != "P2" {
		t.Fatalf("next ID after a deletion = %s, want P2 (IDs are never reused)", got[0].ID)
	}
}

func TestStoreDailyCap200(t *testing.T) {
	l, ok := journal.LifecycleOf(ActionKeep + SourceUpload)
	if !ok || l.DailyCap != DailyCap || DailyCap != 200 || l.Inverse != journal.Irreversible {
		t.Fatalf("keep lifecycle %+v, %v", l, ok)
	}
	r := newRig(t)
	ctx := context.Background()
	n := 0
	for b := 0; b < 20; b++ {
		var ps []Photo
		for i := 0; i < MaxPerUpload; i++ {
			n++
			ps = append(ps, photoN(n))
		}
		r.keep(ps...)
	}
	// Deleting and delivering are not receipts: they free no place.
	if _, err := r.s.Delete(ctx, "P1"); err != nil {
		t.Fatal(err)
	}
	if err := r.s.Deliver(ctx, "P2", "agent-1"); err != nil {
		t.Fatal(err)
	}
	before := len(photoIntents(t, r.eng))
	if _, err := r.s.Keep(ctx, upload(photoN(999))); !errors.Is(err, ErrDailyCap) {
		t.Fatalf("201st photo = %v, want ErrDailyCap", err)
	}
	r.open()
	if _, err := r.s.Keep(ctx, upload(photoN(999))); !errors.Is(err, ErrDailyCap) {
		t.Fatalf("201st photo after a restart = %v, want ErrDailyCap", err)
	}
	if len(photoIntents(t, r.eng)) != before {
		t.Fatal("a refused photo was journaled")
	}
	// A batch that would cross the cap is refused whole.
	r.now = time.Date(2026, 10, 18, 0, 0, 0, 0, time.UTC) // the box's next day
	got := r.keep(photoN(1000))
	if got[0].ID != "P201" {
		t.Fatalf("next day's first photo = %s", got[0].ID)
	}
	// The day is the box's: a box an hour east of UTC is already on the
	// 19th at 23:30 UTC on the 18th.
	r.s.Location = time.FixedZone("UTC+1", 3600)
	r.now = time.Date(2026, 10, 18, 23, 30, 0, 0, time.UTC)
	var ps []Photo
	for i := 0; i < MaxPerUpload; i++ {
		ps = append(ps, photoN(2000+i))
	}
	for i := 0; i < 20; i++ {
		r.keep(ps...)
	}
	if _, err := r.s.Keep(ctx, upload(photoN(3000))); !errors.Is(err, ErrDailyCap) {
		t.Fatalf("over the cap on the box's day = %v", err)
	}
}

func TestStoreTenPerUpload(t *testing.T) {
	r := newRig(t)
	var ps []Photo
	for i := 0; i <= MaxPerUpload; i++ {
		ps = append(ps, photoN(i))
	}
	if MaxPerUpload != 10 {
		t.Fatalf("MaxPerUpload = %d", MaxPerUpload)
	}
	if _, err := r.s.Keep(context.Background(), upload(ps...)); !errors.Is(err, ErrTooMany) {
		t.Fatalf("11 in one upload = %v, want ErrTooMany", err)
	}
	if len(photoIntents(t, r.eng)) != 0 || len(files(t, r.dir)) != 0 {
		t.Fatal("part of a refused upload was kept")
	}
	if got := r.keep(ps[:MaxPerUpload]...); len(got) != MaxPerUpload {
		t.Fatalf("kept %d of 10", len(got))
	}
	if _, err := r.s.Keep(context.Background(), nil); !errors.Is(err, ErrEmpty) {
		t.Fatalf("an empty upload = %v", err)
	}
	bad := upload(photoN(50))
	bad[0].Source = "web"
	if _, err := r.s.Keep(context.Background(), bad); !errors.Is(err, ErrSource) {
		t.Fatalf("an unknown source = %v", err)
	}
}

func TestStoreRefusesWhenReserveShort(t *testing.T) {
	r := newRig(t)
	var asked []int64
	free := int64(len(photoN(1).Image) + len(photoN(1).Thumb))
	r.s.Reserve = func(need int64) error {
		asked = append(asked, need)
		if need > free {
			return errors.New("state disk: reserve would be crossed")
		}
		return nil
	}
	_, err := r.s.Keep(context.Background(), upload(photoN(1), photoN(2)))
	if !errors.Is(err, ErrReserve) {
		t.Fatalf("Keep past the reserve = %v, want ErrReserve", err)
	}
	if len(photoIntents(t, r.eng)) != 0 || len(files(t, r.dir)) != 0 {
		t.Fatal("a photo the reserve refused was kept in part")
	}
	want := int64(len(photoN(1).Image) + len(photoN(1).Thumb) + len(photoN(2).Image) + len(photoN(2).Thumb))
	if len(asked) != 1 || asked[0] != want {
		t.Fatalf("reserve asked %v, want once for the whole upload, %d", asked, want)
	}
	if got := r.keep(photoN(1)); len(got) != 1 {
		t.Fatal("a photo that fits was refused")
	}
}

// crashAt runs a keep that the process "dies" in at the rename numbered
// n (1: the thumbnail, 2: the image, 3: after both): the journal and the
// directory are copied as they stood at that moment and a fresh boot is
// opened on the copies.
func crashAt(t *testing.T, n int) *rig {
	r := newRig(t)
	crash := newRig(t)
	calls := 0
	snap := func() {
		data, _ := r.mem.ReadAll()
		crash.mem = &journal.MemStore{}
		if err := crash.mem.Append(data); err != nil {
			t.Fatal(err)
		}
		os.RemoveAll(crash.dir)
		copyDir(t, r.dir, crash.dir)
	}
	r.s.rename = func(from, to string) error {
		calls++
		if calls == n {
			snap()
		}
		err := renameDurable(from, to)
		if n == 3 && calls == 2 {
			snap()
		}
		return err
	}
	r.keep(photoN(1))
	crash.open()
	return crash
}

func copyDir(t *testing.T, from, to string) {
	t.Helper()
	if err := os.MkdirAll(to, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, name := range files(t, from) {
		b, err := os.ReadFile(filepath.Join(from, name))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(to, name), b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

func TestStoreCrashLeavesNoPartial(t *testing.T) {
	h := hashOf(photoN(1).Image)
	for _, n := range []int{1, 2} {
		c := crashAt(t, n)
		if es := c.list(); len(es) != 0 {
			t.Fatalf("crash at rename %d: listed %+v", n, es)
		}
		if f := files(t, c.dir); len(f) != 0 {
			t.Fatalf("crash at rename %d left %v", n, f)
		}
		if st, err := c.eng.Get("photo:keep:P1"); err != nil || st.State != journal.NotApplied {
			t.Fatalf("crash at rename %d: keep is %v, %v; want not applied", n, st.State, err)
		}
		if got := c.keep(photoN(2)); got[0].ID != "P2" {
			t.Fatalf("after a crash the next ID is %s", got[0].ID)
		}
	}
	c := crashAt(t, 3) // both renames done, the outcome not yet journaled
	if es := c.list(); len(es) != 1 || es[0].Hash != h {
		t.Fatalf("crash after the renames: listed %+v", es)
	}
	if f := files(t, c.dir); fmt.Sprint(f) != fmt.Sprint([]string{h, h + thumbSuffix}) {
		t.Fatalf("crash after the renames: files %v", f)
	}
}

func TestExpiryAfterDays(t *testing.T) {
	r := newRig(t)
	r.s.Days = func() int { return 2 }
	ctx := context.Background()
	r.keep(photoN(1))
	r.s.Days = nil // the owner's setting at receipt decides; the default now is 30
	r.keep(photoN(2))
	r.now = t0.Add(48*time.Hour - time.Second)
	if n, err := r.s.Sweep(ctx); err != nil || n != 0 {
		t.Fatalf("sweep a second early = %d, %v", n, err)
	}
	r.now = t0.Add(48 * time.Hour)
	if n, err := r.s.Sweep(ctx); err != nil || n != 1 {
		t.Fatalf("sweep at two days = %d, %v", n, err)
	}
	if es := r.list(); len(es) != 1 || es[0].ID != "P2" {
		t.Fatalf("after expiry %+v", es)
	}
	if _, err := os.Stat(filepath.Join(r.dir, hashOf(photoN(1).Image))); !os.IsNotExist(err) {
		t.Fatalf("expired bytes still on disk: %v", err)
	}
	if !succeeded(t, r.eng, "photo:delete:P1") {
		t.Fatal("expiry is not a journaled deletion")
	}
	r.now = t0.AddDate(0, 0, DefaultDays)
	r.open() // the boot sweep
	if es := r.list(); len(es) != 0 {
		t.Fatalf("the boot sweep left %+v", es)
	}
}

func TestExpiryWaitsForTrustedClock(t *testing.T) {
	r := newRig(t)
	ctx := context.Background()
	r.keep(photoN(1))
	r.now = t0.AddDate(0, 0, DefaultDays+1)
	for _, st := range []clock.Status{
		{State: clock.Unchecked, Verified: true},
		{State: clock.Agreed, Verified: false},
		{State: clock.Disagree, Verified: true},
	} {
		r.clk.st = st
		if n, err := r.s.Sweep(ctx); n != 0 || !errors.Is(err, ErrUntrustedClock) {
			t.Fatalf("sweep on %v (verified %v) = %d, %v", st.State, st.Verified, n, err)
		}
		r.open()
		if len(r.list()) != 1 {
			t.Fatalf("a boot on %v deleted by time", st.State)
		}
	}
	r.s.Clock = nil
	if n, err := r.s.Sweep(ctx); n != 0 || !errors.Is(err, ErrUntrustedClock) {
		t.Fatalf("sweep with no trusted clock = %d, %v", n, err)
	}
	r.clk.st = verified
	r.s.Clock = r.clk
	if n, err := r.s.Sweep(ctx); err != nil || n != 1 {
		t.Fatalf("sweep on a trusted clock = %d, %v", n, err)
	}
}

func TestDeleteErasesBytesAndJournalContent(t *testing.T) {
	r := newRig(t)
	ctx := context.Background()
	r.keep(photoN(1), photoN(1), photoN(2))
	if err := r.s.Deliver(ctx, "P1", "agent-1"); err != nil {
		t.Fatal(err)
	}
	h1, h2 := hashOf(photoN(1).Image), hashOf(photoN(2).Image)
	if _, err := r.s.Delete(ctx, "P1"); err != nil {
		t.Fatal(err)
	}
	// P2 holds the same bytes: they stay until it goes too.
	if img, err := r.s.Image("P2"); err != nil || !bytes.Equal(img, photoN(1).Image) {
		t.Fatalf("shared bytes gone with P1: %v", err)
	}
	if _, err := r.s.Image("P1"); !errors.Is(err, ErrUnknown) {
		t.Fatalf("Image of a deleted photo = %v", err)
	}
	cs, err := r.s.DeleteAll(ctx)
	if err != nil || len(cs) != 2 {
		t.Fatalf("DeleteAll = %+v, %v", cs, err)
	}
	if f := files(t, r.dir); len(f) != 0 {
		t.Fatalf("bytes or thumbnails left: %v", f)
	}
	raw, _ := r.mem.ReadAll()
	for _, h := range []string{h1, h2} {
		if bytes.Contains(raw, []byte(h)) {
			t.Fatalf("the journal still names hash %s", h)
		}
	}
	erased := map[string]bool{}
	for _, id := range r.eng.Erased() {
		erased[id] = true
	}
	for id := range photoIntents(t, r.eng) {
		if !erased[id] {
			t.Fatalf("intent %s not erased", id)
		}
	}
	if es := r.list(); len(es) != 0 {
		t.Fatalf("listed after DeleteAll: %+v", es)
	}
	if _, err := r.s.Delete(ctx, "P1"); err != nil {
		t.Fatalf("a repeated delete: %v", err)
	}
	if _, err := r.s.Delete(ctx, "P9"); !errors.Is(err, ErrUnknown) {
		t.Fatalf("deleting an unknown photo = %v", err)
	}
}

func TestDeleteConfirmationNamesRunningMachine(t *testing.T) {
	r := newRig(t)
	ctx := context.Background()
	r.keep(photoN(1))
	for _, m := range []string{"agent-1", "agent-2"} {
		if err := r.s.Deliver(ctx, "P1", m); err != nil {
			t.Fatal(err)
		}
	}
	r.s.Running = func(m string) bool { return m == "agent-1" }
	var since time.Time
	r.s.Backups = func(received time.Time) []string { since = received; return []string{"backup of Oct 17"} }
	c, err := r.s.Delete(ctx, "P1")
	if err != nil {
		t.Fatal(err)
	}
	if c.ID != "P1" || fmt.Sprint(c.Machines) != "[agent-1]" || fmt.Sprint(c.Backups) != "[backup of Oct 17]" || !since.Equal(t0) {
		t.Fatalf("confirmation %+v (backups asked since %v)", c, since)
	}
	if line := c.Line(); !strings.Contains(line, "agent-1") || !strings.Contains(line, "backup of Oct 17") || strings.Contains(line, "agent-2") {
		t.Fatalf("confirmation line %q", line)
	}
	r.keep(photoN(2))
	c, err = r.s.Delete(ctx, "P2")
	if err != nil || len(c.Machines) != 0 {
		t.Fatalf("an undelivered photo's confirmation %+v, %v", c, err)
	}
}

func TestDeleteReachesRecall(t *testing.T) {
	k, err := recall.NewKeyer([]byte("synthetic-test-identity-key-0001"))
	if err != nil {
		t.Fatal(err)
	}
	ix, err := recall.Open(recall.NewMemDir(), recall.WithKeyer(k))
	if err != nil {
		t.Fatal(err)
	}
	r := newRig(t)
	r.s.Recall = ix
	ctx := context.Background()
	r.keep(photoN(1), photoN(2))
	ids := map[string]string{}
	for _, p := range []string{"P1", "P2"} {
		kind, account, ref := RecallSource(p)
		item, err := ix.Ingest(recall.Item{Source: recall.Source{Kind: kind, Account: account, Ref: ref}, Text: "synthetic caption", Received: r.now})
		if err != nil {
			t.Fatal(err)
		}
		derived, err := ix.Ingest(recall.Item{Source: recall.Source{Kind: "task", Ref: "out-" + p, DerivedFrom: []string{item}},
			Text: "synthetic model output", Received: r.now})
		if err != nil {
			t.Fatal(err)
		}
		ids[p], ids[p+"/out"] = item, derived
	}
	if _, err := r.s.Delete(ctx, "P1"); err != nil {
		t.Fatal(err)
	}
	if !ix.Deleted(ids["P1"]) || !ix.Deleted(ids["P1/out"]) || ix.Deleted(ids["P2"]) {
		t.Fatal("deleting a photo did not take exactly its recall entries")
	}
	r.now = t0.AddDate(0, 0, DefaultDays)
	if _, err := r.s.Sweep(ctx); err != nil {
		t.Fatal(err)
	}
	if !ix.Deleted(ids["P2"]) || !ix.Deleted(ids["P2/out"]) {
		t.Fatal("deletion by time did not reach recall")
	}
}

// A box clock behind the guard's floor must not stamp a receipt with a
// passed expiry: the photo stays its full days once the clock is trusted.
func TestExpiryNeverEarlyOnBoxClockBehind(t *testing.T) {
	r := newRig(t)
	ctx := context.Background()
	guard := t0
	r.clk.t = &guard
	r.clk.st = clock.Status{State: clock.Unchecked}
	r.now = t0.AddDate(0, 0, -60)
	e := r.keep(photoN(1))[0]
	if e.Received.Before(t0) || e.Expires.Before(t0.AddDate(0, 0, DefaultDays)) {
		t.Fatalf("received %v expires %v on a box clock behind the floor", e.Received, e.Expires)
	}
	guard, r.clk.st = t0.AddDate(0, 0, 1), verified
	if n, err := r.s.Sweep(ctx); err != nil || n != 0 {
		t.Fatalf("sweep a day after receipt = %d, %v", n, err)
	}
	guard = t0.AddDate(0, 0, DefaultDays)
	if n, err := r.s.Sweep(ctx); err != nil || n != 1 {
		t.Fatalf("sweep at expiry = %d, %v", n, err)
	}
}

// submitDelete leaves a delete intent submitted and never run, as a run
// that failed after Submit does, carrying a removal decision that may go
// stale.
func (r *rig) submitDelete(id string, last bool) {
	r.t.Helper()
	e := r.s.mustEntry(r.t, id)
	in := r.s.intent(deleteID(id), ActionDelete, map[string]any{"photo": id, "hash": e.Hash, "last": last, "why": "owner"})
	if _, err := r.eng.Submit(in); err != nil {
		r.t.Fatal(err)
	}
}

func (s *Store) mustEntry(t *testing.T, id string) Entry {
	t.Helper()
	es, err := s.List()
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range es {
		if e.ID == id {
			return e
		}
	}
	t.Fatalf("%s not live", id)
	return Entry{}
}

// Whether a delete removes shared bytes is decided when it runs: a retried
// delete neither leaves the last copy's bytes nor removes a live photo's.
func TestDeleteDecidesSharedBytesAtRun(t *testing.T) {
	ctx := context.Background()
	t.Run("last copy deleted after a stale retry", func(t *testing.T) {
		r := newRig(t)
		r.keep(photoN(1), photoN(1))
		r.submitDelete("P1", false)
		for _, id := range []string{"P2", "P1"} {
			if _, err := r.s.Delete(ctx, id); err != nil {
				t.Fatal(err)
			}
		}
		if got := files(t, r.dir); len(got) != 0 {
			t.Fatalf("both photos deleted, files left %v", got)
		}
	})
	t.Run("retry keeps a newer copy's bytes", func(t *testing.T) {
		r := newRig(t)
		r.keep(photoN(1))
		r.submitDelete("P1", true)
		r.keep(photoN(1))
		if _, err := r.s.Delete(ctx, "P1"); err != nil {
			t.Fatal(err)
		}
		if _, err := r.s.Image("P2"); err != nil {
			t.Fatalf("P2 after P1's retried delete: %v", err)
		}
		if _, err := r.s.Thumb("P2"); err != nil {
			t.Fatalf("P2 thumbnail after P1's retried delete: %v", err)
		}
	})
}

// failRecall fails DeleteSource for one photo.
type failRecall struct{ ref string }

func (f *failRecall) DeleteSource(_, _, ref string) (recall.DeleteReport, error) {
	if ref == f.ref {
		return recall.DeleteReport{}, errors.New("synthetic recall failure")
	}
	return recall.DeleteReport{}, nil
}

// denyFirstDelete denies the first photo delete it is asked to authorize.
type denyFirstDelete struct{ done bool }

func (d *denyFirstDelete) Check(_ context.Context, _ journal.Phase, in journal.Intent) error {
	if in.Action == ActionDelete && !d.done {
		d.done = true
		return errors.New("synthetic denial")
	}
	return nil
}

// One photo that cannot be deleted does not hold the others past their
// expiry, and a deletion left part way is finished on a later sweep.
func TestSweepContinuesPastFailure(t *testing.T) {
	ctx := context.Background()
	t.Run("denied", func(t *testing.T) {
		r := newRig(t)
		r.keep(photoN(1), photoN(2), photoN(3))
		var err error
		r.eng, err = journal.Open(r.mem, &denyFirstDelete{}, map[string]journal.Executor{Executor: r.s},
			func(s string) string { return s }, journal.WithClock(func() time.Time { return r.now }))
		if err != nil {
			t.Fatal(err)
		}
		r.s.Journal = r.eng
		r.now = t0.AddDate(0, 0, DefaultDays+1)
		n, err := r.s.Sweep(ctx)
		if n != 2 || err == nil {
			t.Fatalf("sweep with P1 denied = %d, %v", n, err)
		}
		if es := r.list(); len(es) != 1 || es[0].ID != "P1" {
			t.Fatalf("live after sweep %v", es)
		}
	})
	t.Run("recall fails", func(t *testing.T) {
		r := newRig(t)
		r.keep(photoN(1), photoN(2))
		fr := &failRecall{ref: "P1"}
		r.s.Recall = fr
		r.now = t0.AddDate(0, 0, DefaultDays+1)
		if n, err := r.s.Sweep(ctx); n != 1 || err == nil {
			t.Fatalf("sweep with P1's recall failing = %d, %v", n, err)
		}
		if len(r.list()) != 0 {
			t.Fatal("expired photos still live")
		}
		fr.ref = ""
		if n, err := r.s.Sweep(ctx); n != 1 || err != nil {
			t.Fatalf("sweep finishing P1 = %d, %v", n, err)
		}
		if in, ok := photoIntents(t, r.eng)[keepID("P1")]; !ok || in.Params != nil {
			t.Fatalf("P1's receipt not erased: %+v", in)
		}
	})
}
