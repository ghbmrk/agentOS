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
	h := openRecallHeld(b.recall, filepath.Join(b.state, recallSettledFile), b.t.Logf)
	m := b.open(h.Contained)
	var f lineageForgetter = m
	if wrap != nil {
		f = wrap(m)
	}
	var told []string
	h.settle(context.Background(), f, recallNos(journalAnswers(intents)), func(s string) error { told = append(told, s); return nil })
	return m, h, told
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
	if n := cfg.Notes[len(cfg.Notes)-1](); !strings.Contains(n, "lamp still holds a record you deleted") || !strings.Contains(n, "no fork or merge") {
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
	if n := h.Note(); n != "lamp still holds a record you deleted" {
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
