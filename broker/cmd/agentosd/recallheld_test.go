package main

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/admission"
	"github.com/ghbmrk/agentos/broker/daemon"
	"github.com/ghbmrk/agentos/broker/vm"
)

// REQ: LOG-4

// recallBox is a box upgraded with a recall directory at rest.
type recallBox struct {
	t                  *testing.T
	state, img, recall string
	L, M               string // the lineages of machines lamp and moss
}

func newRecallBox(t *testing.T) *recallBox {
	d := t.TempDir()
	return &recallBox{t: t, state: filepath.Join(d, "machines"), img: t.TempDir(), recall: filepath.Join(d, "recall"), L: "lamp.1", M: "moss.1"}
}

// write sets a file under the recall directory to lines, each ended.
func (b *recallBox) write(name string, lines ...string) {
	b.t.Helper()
	p := filepath.Join(b.recall, name)
	must(b.t, os.MkdirAll(filepath.Dir(p), 0o700))
	var s string
	for _, l := range lines {
		s += l + "\n"
	}
	must(b.t, os.WriteFile(p, []byte(s), 0o600))
}

// rec is one JSON line.
func rec(v map[string]any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

func tomb(id string) string {
	return rec(map[string]any{"op": "tomb", "id": id, "at": time.Now().UTC()})
}

func read(l string, at time.Time, ids ...string) string {
	return rec(map[string]any{"l": l, "ids": ids, "at": at})
}

// open opens the machines as agentosd does, with contained as the hook.
func (b *recallBox) open(contained func(string) bool) *vm.Manager {
	b.t.Helper()
	var m *vm.Manager
	adm, err := admission.New(admission.Config{CapacityMB: 8000}, lateManager{&m})
	must(b.t, err)
	m, err = vm.Open(context.Background(), vm.Config{
		StateDir: b.state, Images: map[string]string{"base": b.img},
		Runtime: &sleepRuntime{running: map[string]bool{}}, Admit: adm, NoCgroups: true, NoQuota: true,
		FreeBytes: func(string) (int64, error) { return 1 << 50, nil },
		Contained: contained,
	})
	must(b.t, err)
	return m
}

// start is one agentosd start: the set read before the machines open,
// and the rollback after. wrap, when set, stands between settle and the
// manager.
func (b *recallBox) start(wrap func(*vm.Manager) lineageForgetter, intents []rollbackAnswer) (*vm.Manager, *recallHeld, []string) {
	b.t.Helper()
	var told []string
	m, h := b.startWith(wrap, answersJournal{as: intents}, func(*recallHeld, string) error { return nil }, &told)
	return m, h, told
}

// startWith is start reading the owner's NOs from j through ownerNos, with
// tell sending each notice; the sent ones are appended to told.
func (b *recallBox) startWith(wrap func(*vm.Manager) lineageForgetter, j answersJournal, tell func(*recallHeld, string) error, told *[]string) (*vm.Manager, *recallHeld) {
	b.t.Helper()
	h := openRecallHeld(b.recall, filepath.Join(b.state, recallSettledFile), b.t.Logf)
	m := b.open(h.Contained)
	var f lineageForgetter = m
	if wrap != nil {
		f = wrap(m)
	}
	h.settle(context.Background(), f, func() ([]recallNo, error) { return ownerNos(j) }, func(s string) error {
		if err := tell(h, s); err != nil {
			return err
		}
		*told = append(*told, s)
		return nil
	})
	return m, h
}

func (b *recallBox) guestWrite(id, s string) {
	b.t.Helper()
	dir := filepath.Join(b.state, "machines", id, "disk", "upper")
	must(b.t, os.MkdirAll(dir, 0o700))
	must(b.t, os.WriteFile(filepath.Join(dir, "notes"), []byte(s), 0o600))
}

func (b *recallBox) guestRead(id string) string {
	got, _ := os.ReadFile(filepath.Join(b.state, "machines", id, "disk", "upper", "notes"))
	return string(got)
}

// forgetCalls records settle's rollbacks; fail fails them for one lineage.
type forgetCalls struct {
	m     *vm.Manager
	fail  string
	calls []string
}

func (f *forgetCalls) ForgetSince(ctx context.Context, l string, since time.Time) error {
	f.calls = append(f.calls, l)
	if agentName(l) == f.fail {
		return errors.New("disk failed")
	}
	return f.m.ForgetSince(ctx, l, since)
}

// tick is a time strictly between snapshots on either side of it.
func tick() time.Time {
	time.Sleep(5 * time.Millisecond)
	t := time.Now().UTC()
	time.Sleep(5 * time.Millisecond)
	return t
}

// heldBox is L and M with snapshots either side of t1, and L reading the
// since-deleted X at t1.
type heldBox struct {
	*recallBox
	t1                    time.Time
	pre, after, mpre, mid vm.Snapshot
}

func newHeldBox(t *testing.T) *heldBox {
	b := &heldBox{recallBox: newRecallBox(t)}
	m := b.open(nil)
	spec := vm.Spec{Image: "base", Class: admission.Foreground, MemMB: 500}
	for _, id := range []string{"lamp", "moss"} {
		mc, err := m.Create(context.Background(), id, spec)
		must(t, err)
		if id == "lamp" {
			b.L = mc.Lineage
		} else {
			b.M = mc.Lineage
		}
	}
	b.guestWrite("lamp", "before")
	var err error
	b.pre, err = m.Checkpoint(context.Background(), "lamp")
	must(t, err)
	b.mpre, err = m.Step(context.Background(), "moss")
	must(t, err)
	b.t1 = tick()
	b.guestWrite("lamp", "secret")
	b.after, err = m.Step(context.Background(), "lamp")
	must(t, err)
	b.mid, err = m.Step(context.Background(), "moss")
	must(t, err)
	b.write("recall/meta.jsonl", tomb("X"))
	b.write("provenance.jsonl", read(b.L, b.t1, "X"))
	return b
}

func lineageSnapsFrom(m *vm.Manager, id string, t time.Time) []string {
	var out []string
	for _, s := range m.Snapshots(id) {
		if !s.Taken.Before(t) {
			out = append(out, s.ID)
		}
	}
	return out
}

// LOG-4 / CAP-3: an upgrade with a pending take-back rolls the held
// lineage back to before its read of the deleted record, tells the owner
// once, and leaves other lineages alone.
func TestLOG4HeldLineageRolledBackAtStart(t *testing.T) {
	b := newHeldBox(t)
	m, h, told := b.start(nil, nil)
	if mc, _ := m.Get("lamp"); mc.Last != b.pre.ID || b.guestRead("lamp") != "before" {
		t.Fatalf("L after start: last %s notes %q, want %s and before", mc.Last, b.guestRead("lamp"), b.pre.ID)
	}
	if got := lineageSnapsFrom(m, "lamp", b.t1); len(got) != 0 {
		t.Fatalf("L snapshots from t1 listed: %v", got)
	}
	if len(told) != 1 || !strings.Contains(told[0], "Agent lamp") || !strings.Contains(told[0], "went back") {
		t.Fatalf("owner told %q, want one notice for L", told)
	}
	for _, s := range []vm.Snapshot{b.mpre, b.mid} {
		if _, err := m.Snapshot(s.ID); err != nil {
			t.Fatalf("M's snapshot %s gone: %v", s.ID, err)
		}
	}
	if h.Contained(b.L) || h.Contained(b.M) || h.Note() != "" {
		t.Fatalf("after settling: L %v M %v note %q", h.Contained(b.L), h.Contained(b.M), h.Note())
	}
	if _, err := fork(m, "moss", []string{"moss2"}); err != nil {
		t.Fatalf("M fork: %v", err)
	}
	m2 := b.open(nil)
	if _, err := m2.Snapshot(b.after.ID); err == nil {
		t.Fatal("L's snapshot after t1 loads after a reopen")
	}
	if got := lineageSnapsFrom(m2, "lamp", b.t1); len(got) != 0 {
		t.Fatalf("L snapshots from t1 after a reopen: %v", got)
	}
}

// LOG-4: a settled lineage is never rolled back again, so work it does
// after its rollback stays, and the owner is not told twice.
func TestLOG4SettledLineageNotRolledBackAgain(t *testing.T) {
	b := newHeldBox(t)
	m, _, _ := b.start(nil, nil)
	must(t, m.Resume(context.Background(), "lamp"))
	b.guestWrite("lamp", "new work")
	s, err := m.Step(context.Background(), "lamp")
	must(t, err)

	fc := &forgetCalls{}
	m, h, told := b.start(func(m *vm.Manager) lineageForgetter { fc.m = m; return fc }, nil)
	if len(fc.calls) != 0 || len(told) != 0 {
		t.Fatalf("second start: rollbacks %v, notices %q", fc.calls, told)
	}
	if _, err := m.Snapshot(s.ID); err != nil || b.guestRead("lamp") != "new work" {
		t.Fatalf("L's new work lost: %v, notes %q", err, b.guestRead("lamp"))
	}
	if h.Contained(b.L) {
		t.Fatal("settled L contained")
	}
}

// LOG-4 fails closed: a rollback that fails leaves the lineage contained
// (no fork, merge or pre-allowance, named in STATUS) until a later start
// settles it.
func TestLOG4UnsettledLineageStaysContained(t *testing.T) {
	b := newHeldBox(t)
	fc := &forgetCalls{fail: "lamp"}
	m, h, told := b.start(func(m *vm.Manager) lineageForgetter { fc.m = m; return fc }, nil)
	if len(told) != 0 {
		t.Fatalf("owner told %q of a failed rollback", told)
	}
	if _, err := fork(m, "lamp", []string{"lamp2"}); !errors.Is(err, vm.ErrContained) {
		t.Fatalf("L fork: %v, want ErrContained", err)
	}
	if _, err := m.Merge(context.Background(), "moss", "lamp"); !errors.Is(err, vm.ErrContained) {
		t.Fatalf("merge of L: %v, want ErrContained", err)
	}
	var cfg daemon.Config
	h.wire(&cfg)
	if !cfg.Grants.Contained(b.L) || cfg.Grants.Contained(b.M) {
		t.Fatalf("grants contained: L %v M %v", cfg.Grants.Contained(b.L), cfg.Grants.Contained(b.M))
	}
	if n := cfg.Notes[len(cfg.Notes)-1](); !strings.Contains(n, "Agent lamp still holds a record you deleted") || !strings.Contains(n, "no fork or merge until it goes back, which I try again when I restart") {
		t.Fatalf("STATUS %q", n)
	}
	if _, err := fork(m, "moss", []string{"moss2"}); err != nil {
		t.Fatalf("M fork: %v", err)
	}

	m, h, told = b.start(nil, nil)
	if mc, _ := m.Get("lamp"); mc.Last != b.pre.ID || h.Contained(b.L) || len(told) != 1 {
		t.Fatalf("next start: L last %s contained %v told %q", mc.Last, h.Contained(b.L), told)
	}
	if _, err := fork(m, "lamp", []string{"lamp2"}); err != nil {
		t.Fatalf("L fork after settling: %v", err)
	}
}

// LOG-4: files that cannot be read contain every lineage and roll back
// none; a torn final line alone is what recall's stores left at a crash
// and is ignored.
func TestLOG4UnreadableRecallFilesContainEveryLineage(t *testing.T) {
	for _, name := range []string{"provenance.jsonl", "recall/meta.jsonl", "backs.jsonl"} {
		b := newHeldBox(t)
		data, err := os.ReadFile(filepath.Join(b.recall, name))
		if errors.Is(err, os.ErrNotExist) {
			err = nil
		}
		must(t, err)
		b.write(name, "{not json", strings.TrimSuffix(string(data), "\n"))
		if len(data) == 0 {
			b.write(name, "{not json", rec(map[string]any{"l": "Q", "tb": true}))
		}
		fc := &forgetCalls{}
		m, h, _ := b.start(func(m *vm.Manager) lineageForgetter { fc.m = m; return fc }, nil)
		if len(fc.calls) != 0 || !h.Contained(b.L) || !h.Contained(b.M) || !h.Contained("anyone") {
			t.Fatalf("%s corrupt: rollbacks %v, L %v M %v", name, fc.calls, h.Contained(b.L), h.Contained(b.M))
		}
		if _, err := fork(m, "moss", []string{"moss2"}); !errors.Is(err, vm.ErrContained) {
			t.Fatalf("%s corrupt: M fork %v", name, err)
		}
		if n := h.Note(); !strings.Contains(n, "could not be read") || !strings.Contains(n, "cannot fork or merge") {
			t.Fatalf("%s corrupt: STATUS %q", name, n)
		}
	}
	// An unreadable settled record contains every lineage and rolls
	// back none, so a settled lineage is not rolled back again.
	b := newHeldBox(t)
	must(t, os.MkdirAll(b.state, 0o700))
	must(t, os.WriteFile(filepath.Join(b.state, recallSettledFile), []byte("{"), 0o600))
	fc := &forgetCalls{}
	_, h, _ := b.start(func(m *vm.Manager) lineageForgetter { fc.m = m; return fc }, nil)
	if len(fc.calls) != 0 || !h.Contained(b.M) || !strings.Contains(h.Note(), "could not be read") {
		t.Fatalf("settled record corrupt: rollbacks %v, M %v, note %q", fc.calls, h.Contained(b.M), h.Note())
	}
	// A torn final line in each file is not unknown.
	b = newHeldBox(t)
	for _, name := range []string{"provenance.jsonl", "recall/meta.jsonl"} {
		p := filepath.Join(b.recall, name)
		f, err := os.OpenFile(p, os.O_APPEND|os.O_WRONLY, 0)
		must(t, err)
		_, err = f.WriteString(`{"l":"moss","ids":["X"`)
		must(t, err)
		must(t, f.Close())
	}
	_, h, told := b.start(nil, nil)
	if h.Contained(b.M) || h.Contained(b.L) || len(told) != 1 || h.Note() != "" {
		t.Fatalf("torn lines: M %v L %v told %q note %q", h.Contained(b.M), h.Contained(b.L), told, h.Note())
	}
}

// LOG-4: the owner's NO to the take-back stands: the lineage is neither
// rolled back nor contained, and STATUS names it; a deletion the NO did
// not cover holds it again.
func TestLOG4OwnerKeptLineageNotRolledBack(t *testing.T) {
	b := newHeldBox(t)
	other := rollbackAnswer{b.L, "X", "expired"} // no answer is not a NO
	wrong := ownerNo(b.M, "X")
	fc := &forgetCalls{}
	m, h, told := b.start(func(m *vm.Manager) lineageForgetter { fc.m = m; return fc }, []rollbackAnswer{other, wrong, ownerNo(b.L, "W,X")})
	if len(fc.calls) != 0 || len(told) != 0 || h.Contained(b.L) {
		t.Fatalf("kept L: rollbacks %v, told %q, contained %v", fc.calls, told, h.Contained(b.L))
	}
	if mc, _ := m.Get("lamp"); mc.Last != b.after.ID {
		t.Fatalf("kept L moved to %s", mc.Last)
	}
	if n := h.Note(); n != "Agent lamp still holds a record you deleted" {
		t.Fatalf("STATUS %q", n)
	}
	if _, err := fork(m, "lamp", []string{"lamp2"}); err != nil {
		t.Fatalf("kept L fork: %v", err)
	}
	// Before the journal is read, a kept lineage counts as held.
	fresh := openRecallHeld(b.recall, filepath.Join(b.state, recallSettledFile), t.Logf)
	if !fresh.Contained(b.L) {
		t.Fatal("L free before the journal was read")
	}
	// An unanswered question is no NO.
	fresh.keep(recallNos(journalAnswers([]rollbackAnswer{other})))
	if !fresh.Contained(b.L) {
		t.Fatal("L kept by an expired question")
	}

	// Y, deleted after the NO, was read by L too.
	b.write("recall/meta.jsonl", tomb("X"), tomb("Y"))
	b.write("provenance.jsonl", read(b.L, b.t1, "X"), read(b.L, b.t1.Add(time.Millisecond), "Y"))
	fc = &forgetCalls{fail: "lamp"}
	_, h, _ = b.start(func(m *vm.Manager) lineageForgetter { fc.m = m; return fc }, []rollbackAnswer{ownerNo(b.L, "X")})
	if len(fc.calls) != 1 || !h.Contained(b.L) {
		t.Fatalf("Y not covered by the NO: rollbacks %v, contained %v", fc.calls, h.Contained(b.L))
	}
}

func heldOf(t *testing.T, b *recallBox) map[string]heldLineage {
	t.Helper()
	held, err := readRecallHeld(b.recall)
	must(t, err)
	return held
}

func wantHeld(t *testing.T, what string, held map[string]heldLineage, since time.Time) {
	t.Helper()
	var h heldLineage
	ok := false
	for l, hl := range held {
		if agentName(l) == "lamp" {
			h, ok = hl, true
		}
	}
	switch {
	case since.IsZero() && ok:
		t.Fatalf("%s: L held from %v, want not held", what, h.Since)
	case !since.IsZero() && (!ok || !h.Since.Equal(since)):
		t.Fatalf("%s: L held %v from %v, want from %v", what, ok, h.Since, since)
	}
}

// LOG-4: a reset recorded before the upgrade already took back what it
// undid and is not repeated; reads after it, or inside it but after its
// begin, are held from their own time. A back, in either file, is
// credited the same way.
func TestLOG4RecordedResetNotRepeated(t *testing.T) {
	b := newHeldBox(t)
	t0 := b.t1.Add(-time.Second)
	t1 := b.t1
	t2 := t1.Add(time.Second)  // the reset began
	t2u := t2.Add(time.Second) // and was done
	t3 := t2u.Add(time.Second)
	reset := rec(map[string]any{"l": b.L, "at": t0, "reset": t2, "until": t2u})
	b.write("recall/meta.jsonl", tomb("X"), tomb("Y"), tomb("Z"))
	b.write("provenance.jsonl", read(b.L, t1, "X"), reset)
	fc := &forgetCalls{}
	m, h, _ := b.start(func(m *vm.Manager) lineageForgetter { fc.m = m; return fc }, nil)
	if len(fc.calls) != 0 || h.Contained(b.L) {
		t.Fatalf("recorded reset repeated: rollbacks %v, contained %v", fc.calls, h.Contained(b.L))
	}
	if mc, _ := m.Get("lamp"); mc.Last != b.after.ID {
		t.Fatalf("L's work since the reset lost: last %s", mc.Last)
	}

	b.write("provenance.jsonl", read(b.L, t1, "X"), reset, read(b.L, t3, "Z"))
	wantHeld(t, "Z read after the reset", heldOf(t, b.recallBox), t3)
	b.write("provenance.jsonl", read(b.L, t1, "X"), reset, read(b.L, t3, "X"))
	wantHeld(t, "X read again after the reset", heldOf(t, b.recallBox), t3)
	ty := t2.Add(time.Second / 2)
	b.write("provenance.jsonl", read(b.L, t1, "X"), reset, read(b.L, ty, "Y"))
	wantHeld(t, "Y read between reset and until", heldOf(t, b.recallBox), ty)

	back := rec(map[string]any{"l": b.L, "at": t0, "reset": t2, "until": t2u, "tb": true, "forget": true})
	b.write("provenance.jsonl", read(b.L, t1, "X"), back)
	wantHeld(t, "a back in provenance.jsonl", heldOf(t, b.recallBox), time.Time{})
	b.write("provenance.jsonl", read(b.L, t1, "X"), back, read(b.L, t3, "X"))
	wantHeld(t, "X read again after a back in provenance.jsonl", heldOf(t, b.recallBox), t3)

	// backs.jsonl is replayed first: a back known before the re-read.
	b.write("backs.jsonl", back)
	b.write("provenance.jsonl", read(b.L, t1, "X"), read(b.L, t3, "X"))
	wantHeld(t, "back in backs.jsonl, X read inside and after it", heldOf(t, b.recallBox), t3)
	b.write("provenance.jsonl", read(b.L, t1, "X"))
	wantHeld(t, "back in backs.jsonl over X", heldOf(t, b.recallBox), time.Time{})
	// A recorded reset with the same since replaces the back; finishing
	// it drops its items.
	finish := rec(map[string]any{"l": b.L, "at": t0, "reset": t2, "forget": true, "ids": []string{"X"}})
	b.write("provenance.jsonl", read(b.L, t1, "X"), reset, finish)
	wantHeld(t, "finished reset", heldOf(t, b.recallBox), time.Time{})
	// The recorded reset removed the back, so finishing it with no
	// items leaves nothing to credit the read.
	bare := rec(map[string]any{"l": b.L, "at": t0, "reset": t2, "forget": true})
	b.write("provenance.jsonl", read(b.L, t1, "X"), reset, bare)
	wantHeld(t, "reset over a back, finished with no items", heldOf(t, b.recallBox), t1)
}

// LOG-4: replay follows recalltool's apply: a plain forget drops reads, a
// later re-read holds again from its own time, and the take-back, reset
// finish with no items and anchor records drop nothing.
func TestLOG4ForgetRecordAndAnchorReplay(t *testing.T) {
	b := newRecallBox(t)
	t1 := time.Now().UTC().Add(-time.Hour)
	t2 := t1.Add(time.Minute)
	b.write("recall/meta.jsonl", tomb("X"), rec(map[string]any{"op": "hdr", "hdr": map[string]any{"embedder": "e"}}))
	forget := rec(map[string]any{"l": b.L, "ids": []string{"X"}, "forget": true})
	b.write("provenance.jsonl", read(b.L, t1, "X"), forget)
	wantHeld(t, "forget X", heldOf(t, b), time.Time{})
	b.write("provenance.jsonl", read(b.L, t1, "X"), rec(map[string]any{"l": b.L, "forget": true}))
	wantHeld(t, "forget all", heldOf(t, b), time.Time{})
	b.write("provenance.jsonl", read(b.L, t1, "X"), forget, read(b.L, t2, "X"))
	wantHeld(t, "X read again after forget", heldOf(t, b), t2)

	for name, r := range map[string]string{
		"reset+forget with no ids": rec(map[string]any{"l": b.L, "at": t2, "reset": t2.Add(time.Second), "forget": true}),
		"take-back":                rec(map[string]any{"l": b.L, "at": t2, "tb": true, "forget": true, "ids": []string{"X"}}),
		"anchor with forget":       rec(map[string]any{"l": b.L, "a": "anc", "seq": 1, "forget": true, "ids": []string{"X"}}),
		"note with forget":         rec(map[string]any{"l": b.L, "n": "k", "forget": true}),
		"no lineage forget":        rec(map[string]any{"forget": true}),
	} {
		b.write("provenance.jsonl", read(b.L, t1, "X"), r)
		wantHeld(t, name, heldOf(t, b), t1)
	}
	// An anchor adds no reads.
	b.write("provenance.jsonl", rec(map[string]any{"l": b.L, "a": "anc", "ids": []string{"X"}, "at": t1}))
	wantHeld(t, "anchor", heldOf(t, b), time.Time{})
	// A read keeps its earlier time.
	b.write("provenance.jsonl", read(b.L, t1, "X"), read(b.L, t2, "X"))
	wantHeld(t, "read twice", heldOf(t, b), t1)
}

// LOG-4: a fresh box has no recall directory: nothing is held or
// contained, and nothing is written.
func TestLOG4NoRecallDirectoryHoldsNothing(t *testing.T) {
	b := newRecallBox(t)
	m := b.open(nil)
	_, err := m.Create(context.Background(), "lamp", vm.Spec{Image: "base", Class: admission.Foreground, MemMB: 500})
	must(t, err)
	_, h, told := b.start(nil, nil)
	if h.Contained(b.L) || h.Note() != "" || len(told) != 0 {
		t.Fatalf("fresh box: contained %v note %q told %q", h.Contained(b.L), h.Note(), told)
	}
	if _, err := os.Stat(filepath.Join(b.state, recallSettledFile)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("settled record written on a fresh box: %v", err)
	}
	if _, err := os.Stat(b.recall); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("recall directory created: %v", err)
	}
}

// fork starts a machine left stopped by the restart, then forks it.
func fork(m *vm.Manager, id string, ids []string) (vm.Snapshot, error) {
	if mc, err := m.Get(id); err == nil && mc.State != vm.Running {
		if err := m.Resume(context.Background(), id); err != nil {
			return vm.Snapshot{}, err
		}
	}
	return m.Fork(context.Background(), id, ids)
}

// LOG-4: a journal that cannot be read may hide the owner's NO, so no
// lineage is rolled back against it: a lineage the owner kept stays
// contained, its work intact, until a start that reads the journal.
func TestLOG4UnreadableJournalRollsBackNothing(t *testing.T) {
	b := newHeldBox(t)
	kept := []rollbackAnswer{ownerNo(b.L, "X")}
	if _, err := ownerNos(answersJournal{as: kept, err: errors.New("disk failed")}); err == nil {
		t.Fatal("ownerNos read an unreadable journal")
	}
	fc := &forgetCalls{}
	var told []string
	m, h := b.startWith(func(m *vm.Manager) lineageForgetter { fc.m = m; return fc },
		answersJournal{as: kept, err: errors.New("disk failed")}, func(*recallHeld, string) error { return nil }, &told)
	if len(fc.calls) != 0 || len(told) != 0 || !h.Contained(b.L) || h.Contained(b.M) {
		t.Fatalf("journal unread: rollbacks %v, told %q, L %v M %v", fc.calls, told, h.Contained(b.L), h.Contained(b.M))
	}
	if mc, _ := m.Get("lamp"); mc.Last != b.after.ID {
		t.Fatalf("L moved to %s with the journal unread", mc.Last)
	}
	if _, err := fork(m, "lamp", []string{"lamp2"}); !errors.Is(err, vm.ErrContained) {
		t.Fatalf("L fork with the journal unread: %v, want ErrContained", err)
	}
	m, h, told = b.start(nil, kept)
	if mc, _ := m.Get("lamp"); mc.Last != b.after.ID || h.Contained(b.L) || len(told) != 0 {
		t.Fatalf("journal read: L last %s contained %v told %q", mc.Last, h.Contained(b.L), told)
	}
}

// LOG-4: a rollback whose notice failed is told at a later start, even
// when the recall files can no longer be read or the journal cannot.
func TestLOG4UntoldRollbackToldWhenFilesUnknown(t *testing.T) {
	for _, why := range []string{"recall files", "journal"} {
		b := newHeldBox(t)
		var told []string
		_, h := b.startWith(nil, answersJournal{}, func(*recallHeld, string) error { return errors.New("no owner channel") }, &told)
		if len(told) != 0 || h.Contained(b.L) {
			t.Fatalf("%s: first start told %q, L contained %v", why, told, h.Contained(b.L))
		}
		j := answersJournal{}
		if why == "recall files" {
			b.write("provenance.jsonl", "{not json")
		} else {
			j.err = errors.New("disk failed")
		}
		fc := &forgetCalls{}
		_, h = b.startWith(func(m *vm.Manager) lineageForgetter { fc.m = m; return fc }, j, func(*recallHeld, string) error { return nil }, &told)
		if len(fc.calls) != 0 || len(told) != 1 || !strings.Contains(told[0], "Agent lamp") {
			t.Fatalf("%s unknown: rollbacks %v, told %q, want one notice for L", why, fc.calls, told)
		}
		_, _ = b.startWith(nil, j, func(*recallHeld, string) error { return nil }, &told)
		if len(told) != 1 {
			t.Fatalf("%s unknown: told again %q", why, told)
		}
	}
}

// LOG-4: notices are sent outside the lock, so a slow owner channel never
// holds up Contained, which machines and grants call meanwhile.
func TestLOG4NoticeSentOutsideLock(t *testing.T) {
	b := newHeldBox(t)
	done := make(chan []string, 1)
	go func() {
		var told []string
		b.startWith(nil, answersJournal{}, func(h *recallHeld, _ string) error {
			c := make(chan bool, 1)
			go func() { c <- h.Contained(b.M) }()
			select {
			case <-c:
				return nil
			case <-time.After(5 * time.Second):
				return errors.New("Contained blocked while the notice was sent")
			}
		}, &told)
		done <- told
	}()
	select {
	case told := <-done:
		if len(told) != 1 {
			t.Fatalf("told %q, want one notice sent while Contained answered", told)
		}
	case <-time.After(20 * time.Second):
		t.Fatal("settle did not finish")
	}
}

// LOG-4: an item ingested again after its tombstone is live, as recall's
// Index.Deleted saw it, so a lineage that read it is not held; a later
// tombstone, or a copy received before the tombstone, holds it again.
func TestLOG4ReingestedItemNotHeld(t *testing.T) {
	b := newRecallBox(t)
	t1 := time.Now().UTC().Add(-time.Hour)
	at := t1.Add(time.Minute)
	tombAt := func(id string, at time.Time) string { return rec(map[string]any{"op": "tomb", "id": id, "at": at}) }
	item := func(id string, received time.Time) string {
		return rec(map[string]any{"id": id, "label": "private", "received": received})
	}
	b.write("recall/meta.jsonl", tombAt("X", at))
	b.write("provenance.jsonl", read(b.L, t1, "X"))
	b.write("recall/seg-00000001.jsonl", item("X", at.Add(-time.Second)), "{not json")
	wantHeld(t, "copy received before the tomb", heldOf(t, b), t1)
	b.write("recall/seg-00000002.jsonl", item("X", at.Add(time.Second)))
	wantHeld(t, "ingested again after the tomb", heldOf(t, b), time.Time{})
	b.write("recall/meta.jsonl", tombAt("X", at), tombAt("X", at.Add(time.Minute)))
	wantHeld(t, "deleted again", heldOf(t, b), t1)
	b.write("recall/meta.jsonl", tombAt("X", at))
	b.write("recall/seg-x.jsonl", item("X", at.Add(time.Hour)))
	must(t, os.Remove(filepath.Join(b.recall, "recall", "seg-00000002.jsonl")))
	wantHeld(t, "a file recall did not count as a segment", heldOf(t, b), t1)
	must(t, os.Mkdir(filepath.Join(b.recall, "recall", "seg-00000003.jsonl"), 0o700))
	if _, err := readRecallHeld(b.recall); err == nil {
		t.Fatal("unreadable segment read as nothing")
	}
}

// LOG-4: a settled record that cannot be decoded is never told from or
// rewritten, though Unmarshal keeps what it read before a type error, so
// it stays unknown at the next start and nothing is rolled back again.
func TestLOG4UndecodableRecordNotRewritten(t *testing.T) {
	b := newHeldBox(t)
	must(t, os.MkdirAll(b.state, 0o700))
	p := filepath.Join(b.state, recallSettledFile)
	bad := []byte(`{"` + b.L + `":{"ids":["X"],"since":"2026-01-01T00:00:00Z","told":false},"` + b.M + `":{"ids":5,"told":true}}`)
	must(t, os.WriteFile(p, bad, 0o600))
	for i := 0; i < 2; i++ {
		fc := &forgetCalls{}
		_, h, told := b.start(func(m *vm.Manager) lineageForgetter { fc.m = m; return fc }, nil)
		if len(fc.calls) != 0 || len(told) != 0 || !h.Contained(b.M) {
			t.Fatalf("start %d: rollbacks %v, told %q, M contained %v", i, fc.calls, told, h.Contained(b.M))
		}
		if got, _ := os.ReadFile(p); string(got) != string(bad) {
			t.Fatalf("start %d: record rewritten to %s", i, got)
		}
	}
}

// LOG-4: a settled record of exactly null decodes to a nil map with no
// error; it is unknown like any undecodable record, so start-up does not
// panic at the first rollback, every lineage stays contained, nothing is
// rolled back or told, and the record is left as it is.
func TestLOG4NullRecordContainsEveryLineage(t *testing.T) {
	for _, bad := range []string{"null", " null\n"} {
		b := newHeldBox(t)
		must(t, os.MkdirAll(b.state, 0o700))
		p := filepath.Join(b.state, recallSettledFile)
		must(t, os.WriteFile(p, []byte(bad), 0o600))
		fc := &forgetCalls{}
		_, h, told := b.start(func(m *vm.Manager) lineageForgetter { fc.m = m; return fc }, nil)
		if len(fc.calls) != 0 || len(told) != 0 || !h.Contained(b.L) || !h.Contained(b.M) || !h.Contained("anyone") {
			t.Fatalf("%q: rollbacks %v, told %q, L %v M %v", bad, fc.calls, told, h.Contained(b.L), h.Contained(b.M))
		}
		if !strings.Contains(h.Note(), "could not be read") {
			t.Fatalf("%q: STATUS %q", bad, h.Note())
		}
		if got, _ := os.ReadFile(p); string(got) != bad {
			t.Fatalf("%q: record rewritten to %s", bad, got)
		}
	}
}

// LOG-4 at rest: no directory holds nothing; a log that cannot be read
// is an error; a backs line that is not a back is not replayed; reads with
// no meta log are an error; segments are read only when something was
// deleted and only by their numbered names; held items are sorted.
func TestLOG4RecallFilesReadExactly(t *testing.T) {
	if held, err := readRecallHeld(filepath.Join(t.TempDir(), "none")); held != nil || err != nil {
		t.Fatalf("absent: %v %v", held, err)
	}
	at := time.Now().UTC().Add(-time.Hour)
	for _, c := range []struct{ name, dir string }{{"meta", "recall/meta.jsonl"}, {"provenance", "provenance.jsonl"}} {
		b := newRecallBox(t)
		b.write("recall/meta.jsonl", tomb("x"))
		b.write("provenance.jsonl", read(b.L, at, "x"))
		must(t, os.Remove(filepath.Join(b.recall, c.dir)))
		must(t, os.MkdirAll(filepath.Join(b.recall, c.dir), 0o700))
		if _, err := readRecallHeld(b.recall); err == nil {
			t.Fatalf("%s unreadable: no error", c.name)
		}
	}
	b := newRecallBox(t)
	b.write("provenance.jsonl", read(b.L, at, "x"))
	if _, err := readRecallHeld(b.recall); err == nil || !strings.Contains(err.Error(), "meta.jsonl is missing") {
		t.Fatalf("no meta: %v", err)
	}
	b = newRecallBox(t)
	b.write("recall/meta.jsonl")
	must(t, os.MkdirAll(filepath.Join(b.recall, "recall", "seg-1.jsonl"), 0o700))
	b.write("provenance.jsonl", read(b.L, at, "x"))
	if _, err := readRecallHeld(b.recall); err != nil {
		t.Fatalf("no tombs, a segment read: %v", err)
	}
	// 26 items, so a map's iteration order is never sorted by chance.
	ids := strings.Split("qwertyuiopasdfghjklzxcvbnm", "")
	var tombs []string
	for _, id := range ids {
		tombs = append(tombs, tomb(id))
	}
	b = newRecallBox(t)
	b.write("recall/meta.jsonl", tombs...)
	must(t, os.MkdirAll(filepath.Join(b.recall, "recall", "seg-new.jsonl"), 0o700))
	b.write("backs.jsonl", read(b.M, at, "a"))
	b.write("provenance.jsonl", read(b.L, at, ids...))
	held, err := readRecallHeld(b.recall)
	if err != nil || len(held) != 1 || strings.Join(held[b.L].IDs, "") != "abcdefghijklmnopqrstuvwxyz" {
		t.Fatalf("held %v %v", held, err)
	}
	b = &recallBox{t: t, recall: filepath.Join(t.TempDir(), "x[", "recall"), L: "lamp.1"}
	b.write("recall/meta.jsonl", tomb("x"))
	b.write("provenance.jsonl", read(b.L, at, "x"))
	if _, err := readRecallHeld(b.recall); err == nil {
		t.Fatal("segments unlisted: no error")
	}
}

// LOG-4 at start: the settled record is read only when something is held
// or the files are unknown; a record covering only some of a lineage's
// deleted items leaves it contained; each failure is logged; rollbacks
// and notices go in lineage order, each notice naming its time.
func TestLOG4SettleOrdersAndLogs(t *testing.T) {
	var logs, errs []string
	logf := func(f string, a ...any) {
		logs = append(logs, f)
		for _, x := range a {
			if e, ok := x.(error); ok {
				errs = append(errs, e.Error())
			}
		}
	}
	has := func(f string) bool {
		for _, l := range logs {
			if l == f {
				return true
			}
		}
		return false
	}
	state := t.TempDir()
	must(t, os.MkdirAll(filepath.Join(state, recallSettledFile), 0o700))
	if h := openRecallHeld(filepath.Join(t.TempDir(), "none"), filepath.Join(state, recallSettledFile), logf); h.Contained("lamp.1") || h.Note() != "" {
		t.Fatalf("nothing held, the record read: %q", h.Note())
	}
	b := newRecallBox(t)
	b.write("recall/meta.jsonl")
	must(t, os.MkdirAll(filepath.Join(b.recall, "provenance.jsonl"), 0o700))
	if h := openRecallHeld(b.recall, filepath.Join(state, recallSettledFile), logf); !h.Contained("lamp.1") ||
		!has("recall directory at rest unreadable, every agent contained: %v") || !has("%s unreadable, every agent contained: %v") {
		t.Fatalf("unknown: %q", logs)
	}
	at := time.Date(2026, 3, 4, 5, 6, 0, 0, time.Local)
	// 26 lineages: a map of 8 or fewer can iterate in sorted order by
	// chance (one group, a random rotation), so an unsorted pass could pass.
	names := strings.Split("qwertyuiopasdfghjklzxcvbnm", "")
	var tombs, reads []string
	for _, n := range names {
		tombs = append(tombs, tomb(n+"1"), tomb(n+"2"))
		reads = append(reads, read(n+".1", at, n+"1", n+"2"))
	}
	b = newRecallBox(t)
	b.write("recall/meta.jsonl", tombs...)
	b.write("provenance.jsonl", reads...)
	logs, errs = nil, nil
	// The read's own error is logged, not a decode of nothing.
	if h := openRecallHeld(b.recall, filepath.Join(state, recallSettledFile), logf); !h.Contained("anyone") || !has("%s unreadable, every agent contained: %v") ||
		len(errs) != 1 || !strings.Contains(errs[0], "is a directory") {
		t.Fatalf("record unreadable: %q %q", logs, errs)
	}
	sp := filepath.Join(t.TempDir(), recallSettledFile)
	must(t, os.WriteFile(sp, []byte(`{"a.1":{"ids":["a1"],"since":"2026-03-04T05:06:00Z","told":true}}`), 0o600))
	h := openRecallHeld(b.recall, sp, logf)
	if !h.Contained("a.1") {
		t.Fatal("a.1 settled over one of its two items")
	}
	h.settle(context.Background(), &rewindMachines{fail: errors.New("disk failed")}, func() ([]recallNo, error) { return nil, errors.New("journal gone") }, nil)
	if !has("journal unreadable, agents holding a record the owner deleted stay contained: %v") {
		t.Fatalf("logs %q", logs)
	}
	h.settle(context.Background(), &rewindMachines{fail: errors.New("disk failed")}, func() ([]recallNo, error) { return nil, nil }, nil)
	if !has("agent %s holds a record the owner deleted and could not go back: %v") {
		t.Fatalf("logs %q", logs)
	}
	m := &rewindMachines{}
	var told []string
	h.settle(context.Background(), m, func() ([]recallNo, error) { return nil, nil }, func(s string) error { told = append(told, s); return nil })
	sorted := strings.Split("abcdefghijklmnopqrstuvwxyz", "")
	if strings.Join(m.calls, " ") != strings.Join(sorted, ".1 ")+".1" || len(told) != len(sorted) {
		t.Fatalf("rollbacks %v, told %d", m.calls, len(told))
	}
	for i, n := range sorted {
		if want := "Agent " + n + " had read a record you deleted, so it went back to Mar 4 05:06;"; !strings.HasPrefix(told[i], want) {
			t.Fatalf("notice %d: %q", i, told[i])
		}
	}
	b.write("provenance.jsonl", append(reads, read("z.1", at, "a1"))...)
	h = openRecallHeld(b.recall, filepath.Join(t.TempDir(), recallSettledFile), logf)
	h.settle(context.Background(), &rewindMachines{}, func() ([]recallNo, error) { return nil, nil }, func(string) error { return errors.New("owner channel down") })
	if !has("rollback notice for agent %s not sent: %v") {
		t.Fatalf("logs %q", logs)
	}
	if got := holdLine([]string{"moss", "lamp"}); got != "Agents lamp and moss still hold a record you deleted" {
		t.Fatalf("hold line: %q", got)
	}
	if got := holdLine([]string{"lamp"}); got != "Agent lamp still holds a record you deleted" {
		t.Fatalf("hold line: %q", got)
	}
	if got := holdLine([]string{"moss", "lamp", "fern"}); got != "Agents fern, lamp and moss still hold a record you deleted" {
		t.Fatalf("hold line: %q", got)
	}
	if got := recallBackNotice("lamp.1", time.Time{}); !strings.Contains(got, "went back to its start;") {
		t.Fatalf("notice: %q", got)
	}
}
