package projection

// Snapshot plus tail must rebuild exactly what a replay from empty builds,
// a damaged or mismatched snapshot must fall back to full replay, and only
// the latest snapshot of each projection is kept.
//
// REQ: OP-4, RES-4

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ghbmrk/agentos/broker/journal"
)

// canary is a synthetic subject an erase must remove from every snapshot.
const canary = "CANARY-proj-5e1d"

// tally is a test projection: per intent, its latest record type, its
// subject parameter (dropped when the intent is erased) and its quality
// verdict, plus counts of every record type.
type tally struct {
	name        string
	Last        map[string]string `json:"last"`
	Topic       map[string]string `json:"topic"`
	Judged      map[string]string `json:"judged"`
	Count       map[string]int    `json:"count"`
	At          uint64            `json:"at"`
	failRestore bool
}

func newTally(name string) *tally {
	t := &tally{name: name}
	t.reset()
	return t
}

func (t *tally) reset() {
	t.Last, t.Topic, t.Judged, t.Count, t.At = map[string]string{}, map[string]string{}, map[string]string{}, map[string]int{}, 0
}

func (t *tally) Name() string { return t.name }

func (t *tally) Apply(r journal.Record) {
	t.At = r.Seq
	t.Count[string(r.Type)]++
	if r.ID == "" {
		return
	}
	t.Last[r.ID] = string(r.Type)
	switch r.Type {
	case journal.RecSubmitted:
		if s, ok := r.Intent.Params["subject"].(string); ok {
			t.Topic[r.ID] = s
		}
	case journal.RecQuality:
		t.Judged[r.ID] = string(r.Verdict)
	case journal.RecErased:
		delete(t.Topic, r.ID)
	}
}

func (t *tally) Snapshot() ([]byte, error) { return json.Marshal(t) }

func (t *tally) Restore(data []byte, offset uint64) error {
	t.reset()
	if data == nil {
		return nil
	}
	if t.failRestore {
		return errors.New("restore refused")
	}
	if err := json.Unmarshal(data, t); err != nil {
		return err
	}
	if t.At != offset {
		return fmt.Errorf("snapshot at %d, offset %d", t.At, offset)
	}
	return nil
}

func state(t *testing.T, p Projection) string {
	t.Helper()
	b, err := p.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// fromEmpty builds a projection from the whole journal with no snapshot.
func fromEmpty(t *testing.T, src Source, name string) string {
	t.Helper()
	p := newTally(name)
	for _, r := range src.RecordsAfter(0) {
		p.Apply(r)
	}
	return state(t, p)
}

type allow struct{}

func (allow) Check(context.Context, journal.Phase, journal.Intent) error { return nil }

type svc struct{ rng *rand.Rand }

func (s svc) Execute(context.Context, journal.Intent, int) journal.Outcome {
	rs := []journal.Result{journal.ResultSucceeded, journal.ResultNotApplied, journal.ResultUnknown}
	return journal.Outcome{Result: rs[s.rng.Intn(len(rs))], Evidence: "ok"}
}

func (s svc) Reconcile(context.Context, journal.Intent, int) journal.Outcome {
	return journal.Outcome{Result: journal.ResultSucceeded, Evidence: "reconciled"}
}

func open(t *testing.T, st journal.Store, rng *rand.Rand) *journal.Engine {
	t.Helper()
	e, err := journal.Open(st, allow{}, map[string]journal.Executor{"svc": svc{rng}}, func(s string) string { return s })
	if err != nil {
		t.Fatal(err)
	}
	return e
}

// step runs one random operation on the engine. Errors are expected (an
// illegal transition is refused) and ignored: only the journal matters.
func step(e *journal.Engine, rng *rand.Rand, n int) {
	ctx := context.Background()
	id := fmt.Sprintf("i%d", rng.Intn(n/3+1))
	switch rng.Intn(8) {
	case 0, 1:
		e.Submit(journal.Intent{ID: id, Origin: "owner", Account: []string{"mail", "bank"}[rng.Intn(2)],
			Action: "send", Executor: "svc", Params: map[string]any{"subject": canary + "-" + id}})
	case 2:
		e.Authorize(ctx, id)
	case 3:
		e.Dispatch(ctx, id)
	case 4:
		e.Resolve(id, 1, journal.Outcome{Result: journal.ResultSucceeded, Evidence: "owner"}, "owner")
	case 5:
		e.RecordQuality(id, journal.Quality{Verdict: []journal.Verdict{journal.VerdictGood, journal.VerdictWrong}[rng.Intn(2)], Source: "owner"})
	case 6:
		if rng.Intn(4) == 0 {
			e.Erase([]string{id})
		}
	case 7:
		if rng.Intn(2) == 0 {
			e.Stop(ctx)
		} else {
			e.Resume()
		}
	}
}

func generated(t *testing.T, seed int64, n int) (*journal.Engine, *journal.MemStore, *rand.Rand) {
	t.Helper()
	rng := rand.New(rand.NewSource(seed))
	st := &journal.MemStore{}
	e := open(t, st, rng)
	for range n {
		step(e, rng, n)
	}
	return e, st, rng
}

// Property (OP-4): for a generated log and any cut, Restore(Snapshot at the
// cut) followed by the tail equals the projection built from empty.
func TestPropertySnapshotPlusTailEqualsReplayFromEmpty(t *testing.T) {
	for seed := int64(1); seed <= 60; seed++ {
		e, _, rng := generated(t, seed, 80)
		recs := e.RecordsAfter(0)
		want := fromEmpty(t, e, "t")
		for range 5 {
			k := rng.Intn(len(recs) + 1)
			a := newTally("t")
			for _, r := range recs[:k] {
				a.Apply(r)
			}
			snap, err := a.Snapshot()
			if err != nil {
				t.Fatal(err)
			}
			b := newTally("t")
			if err := b.Restore(snap, uint64(k)); err != nil {
				t.Fatalf("seed %d cut %d: restore: %v", seed, k, err)
			}
			for _, r := range e.RecordsAfter(uint64(k)) {
				b.Apply(r)
			}
			if got := state(t, b); got != want {
				t.Fatalf("seed %d cut %d: snapshot+tail\n%s\nfrom empty\n%s", seed, k, got, want)
			}
		}
	}
}

// Property (OP-4): the Projector's own boot path, across restarts of the
// broker and of the projector, restores the latest snapshot, replays the
// tail, and ends where a replay from empty ends.
func TestPropertyBootFromSnapshotEqualsReplayFromEmpty(t *testing.T) {
	restored := 0
	for seed := int64(1); seed <= 60; seed++ {
		rng := rand.New(rand.NewSource(seed))
		media := &journal.MemStore{}
		snaps := &MemStore{}
		e := open(t, media, rng)
		every := uint64(rng.Intn(7) + 1)
		p := newTally("t")
		pr, err := New(snaps, every, p)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := pr.Boot(e); err != nil {
			t.Fatal(err)
		}
		for i := range 120 {
			step(e, rng, 120)
			if rng.Intn(3) == 0 {
				if err := pr.Sync(e); err != nil {
					t.Fatalf("seed %d: sync: %v", seed, err)
				}
			}
			if i%40 == 39 {
				// Restart the broker and the projector.
				e = open(t, media, rng)
				p = newTally("t")
				if pr, err = New(snaps, every, p); err != nil {
					t.Fatal(err)
				}
				rep, err := pr.Boot(e)
				if err != nil {
					t.Fatalf("seed %d: boot: %v", seed, err)
				}
				if rep[0].Fallback != "" {
					t.Fatalf("seed %d: boot fell back: %s", seed, rep[0].Fallback)
				}
				if rep[0].From > 0 {
					restored++
				}
				if got, want := state(t, p), fromEmpty(t, e, "t"); got != want {
					t.Fatalf("seed %d: after boot\n%s\nfrom empty\n%s", seed, got, want)
				}
			}
		}
		if err := pr.Sync(e); err != nil {
			t.Fatal(err)
		}
		if got, want := state(t, p), fromEmpty(t, e, "t"); got != want {
			t.Fatalf("seed %d: after sync\n%s\nfrom empty\n%s", seed, got, want)
		}
	}
	if restored == 0 {
		t.Fatal("no boot restored a snapshot; the property ran vacuously")
	}
}

// bootWith writes one good snapshot, lets damage alter the stored copy, and
// boots a fresh projector from it.
func bootWith(t *testing.T, damage func(st *MemStore, e *journal.Engine), p *tally) (Boot, *journal.Engine) {
	t.Helper()
	e, _, _ := generated(t, 7, 60)
	st := &MemStore{}
	pr, err := New(st, 1, newTally("t"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pr.Boot(e); err != nil {
		t.Fatal(err)
	}
	if _, ok := st.files["t"]; !ok {
		t.Fatal("no snapshot was written")
	}
	damage(st, e)
	pr, err = New(st, 1, p)
	if err != nil {
		t.Fatal(err)
	}
	rep, err := pr.Boot(e)
	if err != nil {
		t.Fatalf("boot: %v", err)
	}
	if got, want := state(t, p), fromEmpty(t, e, "t"); got != want {
		t.Fatalf("after fallback\n%s\nfrom empty\n%s", got, want)
	}
	return rep[0], e
}

// A damaged, foreign or unusable snapshot is ignored: boot replays the
// whole journal and reports why (OP-4: projections are never a source of
// truth).
func TestCorruptSnapshotFallsBackToFullReplay(t *testing.T) {
	cases := map[string]struct {
		damage func(st *MemStore, e *journal.Engine)
		fail   bool
		want   string
	}{
		"flipped byte": {damage: func(st *MemStore, _ *journal.Engine) {
			b := st.files["t"]
			b[len(b)-3] ^= 0x20
		}, want: "checksum"},
		"truncated": {damage: func(st *MemStore, _ *journal.Engine) {
			st.files["t"] = st.files["t"][:len(st.files["t"])-5]
		}, want: "checksum"},
		"torn header": {damage: func(st *MemStore, _ *journal.Engine) {
			st.files["t"] = st.files["t"][:10]
		}, want: "malformed"},
		"empty": {damage: func(st *MemStore, _ *journal.Engine) { st.files["t"] = nil }, want: "malformed"},
		"beyond the journal": {damage: func(st *MemStore, e *journal.Engine) {
			st.files["t"] = reseal(t, st.files["t"], func(h *header) { h.Seq += 1000 })
		}, want: "beyond"},
		"another journal": {damage: func(st *MemStore, e *journal.Engine) {
			st.files["t"] = reseal(t, st.files["t"], func(h *header) { h.Anchor = strings.Repeat("0", 64) })
		}, want: "does not match"},
		"another projection": {damage: func(st *MemStore, e *journal.Engine) {
			st.files["t"] = reseal(t, st.files["t"], func(h *header) { h.Name = "other" })
		}, want: "names"},
		"newer format": {damage: func(st *MemStore, e *journal.Engine) {
			st.files["t"] = reseal(t, st.files["t"], func(h *header) { h.V = 99 })
		}, want: "version"},
		"restore refuses": {damage: func(*MemStore, *journal.Engine) {}, fail: true, want: "restore refused"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			p := newTally("t")
			p.failRestore = c.fail
			rep, _ := bootWith(t, c.damage, p)
			if rep.From != 0 || !strings.Contains(rep.Fallback, c.want) {
				t.Fatalf("report %+v, want full replay because %q", rep, c.want)
			}
		})
	}
}

// reseal rewrites a stored snapshot's header with a valid checksum, so only
// the field under test is wrong.
func reseal(t *testing.T, b []byte, edit func(*header)) []byte {
	t.Helper()
	h, data, err := decode(b)
	if err != nil {
		t.Fatal(err)
	}
	edit(&h)
	out, err := encode(h, data)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// A good snapshot is used: boot starts from its offset, not from 1.
func TestBootStartsFromTheLatestSnapshot(t *testing.T) {
	e, _, _ := generated(t, 3, 60)
	st := &MemStore{}
	pr, _ := New(st, 1, newTally("t"))
	if _, err := pr.Boot(e); err != nil {
		t.Fatal(err)
	}
	end := uint64(len(e.RecordsAfter(0)))
	p := newTally("t")
	pr, _ = New(st, 1, p)
	rep, err := pr.Boot(e)
	if err != nil {
		t.Fatal(err)
	}
	if rep[0].From != end || rep[0].Fallback != "" || rep[0].Name != "t" {
		t.Fatalf("report %+v, want From %d", rep[0], end)
	}
}

// RES-4: one projection keeps one snapshot on disk; a new one replaces the
// old atomically, with mode 0600, and no temporary file is left behind.
func TestDirStoreKeepsOnlyTheLatestSnapshot(t *testing.T) {
	dir := t.TempDir()
	st, err := OpenDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	rng := rand.New(rand.NewSource(1))
	media := &journal.MemStore{}
	e := open(t, media, rng)
	p := newTally("inbox")
	pr, err := New(st, 5, p)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pr.Boot(e); err != nil {
		t.Fatal(err)
	}
	for range 200 {
		step(e, rng, 200)
		if err := pr.Sync(e); err != nil {
			t.Fatal(err)
		}
	}
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(ents) != 1 || ents[0].Name() != "inbox.snap" {
		var names []string
		for _, x := range ents {
			names = append(names, x.Name())
		}
		t.Fatalf("snapshot dir holds %v, want only inbox.snap", names)
	}
	fi, _ := ents[0].Info()
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("snapshot mode %v, want 0600", fi.Mode().Perm())
	}
	// A fresh boot from the directory reaches the same state.
	st2, err := OpenDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	q := newTally("inbox")
	pr2, _ := New(st2, 5, q)
	rep, err := pr2.Boot(e)
	if err != nil || rep[0].From == 0 {
		t.Fatalf("boot from dir: %+v, %v", rep, err)
	}
	if got, want := state(t, q), fromEmpty(t, e, "inbox"); got != want {
		t.Fatalf("dir boot\n%s\nfrom empty\n%s", got, want)
	}
}

// RES-4: snapshots are written every `every` records, not on every record.
func TestSnapshotsArePeriodic(t *testing.T) {
	st := &countingStore{MemStore: &MemStore{}}
	rng := rand.New(rand.NewSource(2))
	e := open(t, &journal.MemStore{}, rng)
	pr, _ := New(st, 10, newTally("t"))
	if _, err := pr.Boot(e); err != nil {
		t.Fatal(err)
	}
	for i := range 35 {
		e.Submit(journal.Intent{ID: fmt.Sprintf("s%d", i), Origin: "owner", Account: "mail", Action: "send", Executor: "svc"})
		if err := pr.Sync(e); err != nil {
			t.Fatal(err)
		}
	}
	if st.saves != 3 {
		t.Fatalf("%d saves over 35 records with every=10, want 3", st.saves)
	}
}

type countingStore struct {
	*MemStore
	saves int
}

func (c *countingStore) Save(name string, b []byte) error { c.saves++; return c.MemStore.Save(name, b) }

// After an erase no stored snapshot still holds the erased subject: the
// snapshot taken before the erase is replaced as soon as the erase is
// applied, whatever the period.
func TestEraseReplacesOlderSnapshots(t *testing.T) {
	dir := t.TempDir()
	st, err := OpenDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	rng := rand.New(rand.NewSource(4))
	e := open(t, &journal.MemStore{}, rng)
	pr, _ := New(st, 1000, newTally("t"))
	ctx := context.Background()
	e.Submit(journal.Intent{ID: "x", Origin: "owner", Account: "mail", Action: "send", Executor: "svc",
		Params: map[string]any{"subject": canary}})
	if _, err := pr.Boot(e); err != nil {
		t.Fatal(err)
	}
	// Force one snapshot holding the canary.
	if err := pr.SnapshotNow(); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(filepath.Join(dir, "t.snap"))
	if !bytes.Contains(b, []byte(canary)) {
		t.Fatal("setup: snapshot does not hold the subject")
	}
	e.Authorize(ctx, "x")
	e.Dispatch(ctx, "x")
	if _, _, err := e.Erase([]string{"x"}); err != nil {
		t.Fatal(err)
	}
	if err := pr.Sync(e); err != nil {
		t.Fatal(err)
	}
	b, _ = os.ReadFile(filepath.Join(dir, "t.snap"))
	if bytes.Contains(b, []byte(canary)) {
		t.Fatal("snapshot still holds an erased subject")
	}
}

// When the save after an erase fails, the older snapshot, which may hold
// the erased content, is deleted rather than left on disk (P6).
func TestEraseDeletesTheSnapshotWhenItsReplacementFails(t *testing.T) {
	st := &saveFails{MemStore: &MemStore{}}
	rng := rand.New(rand.NewSource(6))
	e := open(t, &journal.MemStore{}, rng)
	pr, _ := New(st, 1000, newTally("t"))
	ctx := context.Background()
	e.Submit(journal.Intent{ID: "x", Origin: "owner", Account: "mail", Action: "send", Executor: "svc",
		Params: map[string]any{"subject": canary}})
	if _, err := pr.Boot(e); err != nil {
		t.Fatal(err)
	}
	if err := pr.SnapshotNow(); err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(st.files["t"], []byte(canary)) {
		t.Fatal("setup: snapshot does not hold the subject")
	}
	e.Authorize(ctx, "x")
	e.Dispatch(ctx, "x")
	if _, _, err := e.Erase([]string{"x"}); err != nil {
		t.Fatal(err)
	}
	st.fail = true
	if err := pr.Sync(e); err == nil {
		t.Fatal("the failing save was not reported")
	}
	if _, ok := st.files["t"]; ok {
		t.Fatal("a pre-erase snapshot survived a failed replacement")
	}
}

type saveFails struct {
	*MemStore
	fail bool
}

func (s *saveFails) Save(name string, data []byte) error {
	if s.fail {
		return errors.New("disk full")
	}
	return s.MemStore.Save(name, data)
}

// A failing snapshot store never loses projection state: the projection is
// current and the error is reported, and the next boot replays in full.
func TestFailingStoreKeepsTheProjectionCurrent(t *testing.T) {
	rng := rand.New(rand.NewSource(5))
	e := open(t, &journal.MemStore{}, rng)
	for range 30 {
		step(e, rng, 30)
	}
	p := newTally("t")
	pr, _ := New(brokenStore{}, 1, p)
	if _, err := pr.Boot(e); err == nil {
		t.Fatal("a failing save was not reported")
	}
	if got, want := state(t, p), fromEmpty(t, e, "t"); got != want {
		t.Fatalf("projection not current after a failing save")
	}
}

type brokenStore struct{}

func (brokenStore) Load(string) ([]byte, error) { return nil, os.ErrNotExist }
func (brokenStore) Save(string, []byte) error   { return errors.New("disk full") }
func (brokenStore) Delete(string) error         { return errors.New("disk full") }

func TestNewRefusesBadNames(t *testing.T) {
	for _, ps := range [][]Projection{
		{newTally("")},
		{newTally("../x")},
		{newTally("a.b")},
		{newTally("a"), newTally("a")},
	} {
		if _, err := New(&MemStore{}, 1, ps...); err == nil {
			t.Fatalf("New accepted %v", ps[0].Name())
		}
	}
	if _, err := New(&MemStore{}, 0, newTally("a")); err == nil {
		t.Fatal("New accepted a zero period")
	}
}
