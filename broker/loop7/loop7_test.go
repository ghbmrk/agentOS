package loop7

// REQ: LOOP-7, LOOP-9

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/journal"
	"github.com/ghbmrk/agentos/broker/loops"
	"github.com/ghbmrk/agentos/broker/sockets"
	"github.com/ghbmrk/agentos/broker/sockprobe"
)

// fakeGuard stands in for *loops.Guard: the chain itself is tested in
// broker/loops (regress_test.go); here only what reaches it matters.
type fakeGuard struct {
	mu       sync.Mutex
	reported []loops.Finding
	open     map[string]loops.Finding
	resolved []string
	job      bool
}

func newFake() *fakeGuard { return &fakeGuard{open: map[string]loops.Finding{}} }

func (g *fakeGuard) Loop() loops.Loop { return loops.Secure }
func (g *fakeGuard) Next(context.Context, bool) (loops.Job, bool) {
	return loops.Job{Name: "passive"}, g.job
}
func (g *fakeGuard) Report(_ context.Context, f loops.Finding) (loops.Record, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	f.ID = string(f.Check) + ":" + f.Subject + ":" + f.Detail
	g.reported = append(g.reported, f)
	g.open[f.ID] = f
	return loops.Record{Finding: f, Reported: true}, nil
}
func (g *fakeGuard) Resolve(id string, r loops.Replay) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if f, ok := g.open[id]; !ok || !r.Passed || r.Evidence != f.Detail {
		return loops.ErrFinding
	}
	delete(g.open, id)
	g.resolved = append(g.resolved, id)
	return nil
}
func (g *fakeGuard) OpenReported(c loops.Check) []loops.Finding {
	g.mu.Lock()
	defer g.mu.Unlock()
	var out []loops.Finding
	for _, k := range sortedKeys(g.open) {
		if g.open[k].Check == c {
			out = append(out, g.open[k])
		}
	}
	return out
}

// planted builds a fuzz target whose decoder crashes on any input longer
// than three bytes when crash is set, and never otherwise: the
// planted-decoder control for the whole source.
func planted(t *testing.T, crash bool) string {
	t.Helper()
	if testing.Short() {
		t.Skip("builds a test binary")
	}
	src := t.TempDir()
	cond := "false"
	if crash {
		cond = "len(b) > 3"
	}
	files := map[string]string{
		"go.mod": "module planted\n\ngo 1.21\n",
		"planted_test.go": `package planted

import "testing"

func FuzzPlanted(f *testing.F) {
	f.Add([]byte("a"))
	f.Fuzz(func(t *testing.T, b []byte) {
		if ` + cond + ` {
			panic("planted decoder crash")
		}
	})
}
`}
	for n, c := range files {
		if err := os.WriteFile(filepath.Join(src, n), []byte(c), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	bin := filepath.Join(t.TempDir(), "planted.test")
	cmd := exec.Command("go", "test", "-c", "-fuzz=FuzzPlanted", "-o", bin, ".")
	cmd.Dir = src
	cmd.Env = append(os.Environ(), "GOWORK=off", "GOFLAGS=-mod=mod")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	return bin
}

func target(t *testing.T, bin string) Target {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "testdata", "fuzz", "FuzzPlanted"), 0o755); err != nil {
		t.Fatal(err)
	}
	return Target{Pkg: "planted", Name: "FuzzPlanted", Binary: bin, Dir: dir}
}

func newSource(t *testing.T, g *fakeGuard, cfg Config) *Source {
	t.Helper()
	cfg.Inner, cfg.Report = g, g
	if cfg.Release == "" && len(cfg.Targets) > 0 {
		cfg.Release = filepath.Dir(cfg.Targets[0].Binary)
	}
	if cfg.CacheDir == "" {
		cfg.CacheDir = t.TempDir()
	}
	s, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// Acceptance (LOOP-7, LOOP-9): a fuzz failure becomes a finding, with its
// crashing input kept in the corpus as evidence and as a regression that
// every later round replays; once the decoder is fixed the replay passes
// and the finding is resolved.
func TestAFuzzCrashIsReportedKeptAndResolved(t *testing.T) {
	g := newFake()
	tg := target(t, planted(t, true))
	s := newSource(t, g, Config{Targets: []Target{tg}, FuzzTime: 20 * time.Second})
	n, err := s.Fuzz(context.Background(), tg)
	if err != nil || n != 1 || len(g.reported) != 1 {
		t.Fatalf("n=%d err=%v reported %+v", n, err, g.reported)
	}
	f := g.reported[0]
	if f.Check != loops.CheckFuzz || f.Subject != "planted.FuzzPlanted" || f.Severity != loops.High {
		t.Fatalf("finding %+v", f)
	}
	kept, _ := os.ReadDir(filepath.Join(tg.Dir, "testdata", "fuzz", "FuzzPlanted"))
	if len(kept) != 1 {
		t.Fatalf("corpus %v", kept)
	}
	data, err := os.ReadFile(filepath.Join(tg.Dir, "testdata", "fuzz", "FuzzPlanted", kept[0].Name()))
	if err != nil || f.Detail != crashDetail(data) {
		t.Fatalf("evidence %q does not name the kept input", f.Detail)
	}
	// The next round replays the kept input first and reports it again
	// (Report returns the open record); still open.
	if n, err := s.replay(context.Background(), tg); err != nil || n != 1 || len(g.open) != 1 {
		t.Fatalf("replay n=%d err=%v open %v", n, err, g.open)
	}
	// An update fixes the decoder, but with the stored input gone nothing
	// replays it, so the finding stays open.
	if err := os.Rename(planted(t, false), tg.Binary); err != nil {
		t.Fatal(err)
	}
	stored := filepath.Join(tg.Dir, "testdata", "fuzz", "FuzzPlanted", kept[0].Name())
	aside := filepath.Join(t.TempDir(), "input")
	if err := os.Rename(stored, aside); err != nil {
		t.Fatal(err)
	}
	if n, err := s.replay(context.Background(), tg); err != nil || n != 0 || len(g.open) != 1 || len(g.resolved) != 0 {
		t.Fatalf("without the stored input n=%d err=%v open %v resolved %v", n, err, g.open, g.resolved)
	}
	if err := os.Rename(aside, stored); err != nil {
		t.Fatal(err)
	}
	// Replayed, the stored input passes and the finding is resolved.
	if n, err := s.replay(context.Background(), tg); err != nil || n != 0 || len(g.open) != 0 || len(g.resolved) != 1 {
		t.Fatalf("after the fix n=%d err=%v open %v resolved %v", n, err, g.open, g.resolved)
	}
}

// Two crashing seeds sort before the open finding's input: a panic stops
// the binary, so that input never runs and its finding stays open, since
// only its own passing subtest is a replay (Security 4a and L3 on #523).
func TestASeedThatNeverRanResolvesNothing(t *testing.T) {
	g := newFake()
	tg := target(t, planted(t, true))
	dir := filepath.Join(tg.Dir, "testdata", "fuzz", "FuzzPlanted")
	write := func(name, in string) []byte {
		data := []byte("go test fuzz v1\n[]byte(" + strconv.Quote(in) + ")\n")
		if err := os.WriteFile(filepath.Join(dir, name), data, 0o644); err != nil {
			t.Fatal(err)
		}
		return data
	}
	write("0crash", "synthetic crash")
	write("0crash2", "another synthetic crash")
	good := write("1good", "ab")
	open := loops.Finding{Check: loops.CheckFuzz, Subject: tg.subject(), Severity: loops.High, Detail: crashDetail(good)}
	if _, err := g.Report(context.Background(), open); err != nil {
		t.Fatal(err)
	}
	s := newSource(t, g, Config{Targets: []Target{tg}})
	if _, err := s.replay(context.Background(), tg); err != nil {
		t.Fatal(err)
	}
	if _, stillOpen := g.open[string(open.Check)+":"+open.Subject+":"+open.Detail]; !stillOpen || len(g.resolved) != 0 {
		t.Fatalf("open %v resolved %v", g.open, g.resolved)
	}
}

// LOOP-1: a fuzz job returns within the preemption target once its
// context is cancelled, and the source offers it again.
func TestAFuzzJobYieldsWithinThePreemptionTarget(t *testing.T) {
	g := newFake()
	tg := target(t, planted(t, false))
	clock := time.Unix(1_800_000_000, 0)
	s := newSource(t, g, Config{Targets: []Target{tg}, FuzzTime: time.Minute, Now: func() time.Time { return clock }})
	job, ok := s.Next(context.Background(), false)
	if !ok || job.Name != "fuzz" || job.UsesModel {
		t.Fatalf("job %+v %v", job, ok)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan loops.Result, 1)
	go func() { done <- job.Run(ctx) }()
	time.Sleep(time.Second) // into the fuzzing
	cancel()
	start := time.Now()
	select {
	case r := <-done:
		if r.Err != nil {
			t.Fatalf("a preempted job errs: %v", r.Err)
		}
	case <-time.After(2 * time.Second): // loops' YieldTarget default
		t.Fatal("did not yield within the preemption target")
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("yielded in %v", d)
	}
	if _, ok := s.Next(context.Background(), false); !ok {
		t.Fatal("a preempted job is not offered again")
	}
	if len(g.reported) != 0 {
		t.Fatalf("reported %+v", g.reported)
	}
}

// Inner's work comes first; LOOP-7 jobs come once per Every, taking
// turns: the probe, then each target.
func TestNextOffersInnerFirstThenTakesTurns(t *testing.T) {
	g := newFake()
	clock := time.Unix(1_800_000_000, 0)
	probe := func(context.Context) (string, []string, error) { return "m1", nil, nil }
	a := Target{Pkg: "p", Name: "FuzzA", Binary: "/nonexistent/p.test", Dir: t.TempDir()}
	b := a
	b.Name = "FuzzB"
	s := newSource(t, g, Config{Targets: []Target{a, b}, Probe: probe, Trail: func() []journal.Record { return nil }, Want: probeSet(),
		Every: time.Hour, Now: func() time.Time { return clock }})
	g.job = true
	if j, _ := s.Next(context.Background(), true); j.Name != "passive" {
		t.Fatalf("inner not first: %+v", j)
	}
	g.job = false
	var names []string
	for i := 0; i < 4; i++ {
		j, ok := s.Next(context.Background(), true)
		if !ok {
			t.Fatalf("turn %d not offered", i)
		}
		if _, again := s.Next(context.Background(), true); again {
			t.Fatal("two LOOP-7 jobs within Every")
		}
		names = append(names, j.Name)
		clock = clock.Add(time.Hour)
	}
	if strings.Join(names, ",") != "probe,fuzz,fuzz,probe" {
		t.Fatalf("turns %v", names)
	}
}

// The broker side of a probe round: each refusal journaled for the
// machine, no intent from it in the round. Planted controls: a missing
// note and an intent are each reported.
func note(at time.Time, m string, c sockets.Code) journal.Record {
	return journal.Record{At: at, Type: journal.RecEgress, Egress: &journal.EgressNote{Machine: m, Adapter: sockets.RefusalNote, Operation: c.Token(), Reason: "x"}}
}

// probeSet is the probe's refusal codes, as the wiring passes them.
func probeSet() []sockets.Code {
	var out []sockets.Code
	for _, f := range sockprobe.Frames {
		out = append(out, f.Want)
	}
	return out
}

// refusals is a broker trail with a refusal note at at for each code in
// the probe set.
func refusals(at time.Time, m string) []journal.Record {
	var out []journal.Record
	for _, f := range sockprobe.Frames {
		out = append(out, note(at, m, f.Want))
	}
	return out
}

func TestJournaledChecksTheProbeRound(t *testing.T) {
	start := time.Unix(1_800_000_000, 0)
	end := start.Add(time.Second)
	full := append(refusals(start, "m1"), note(start.Add(-30*time.Second), "m1", sockets.ErrUnknownOp))
	full = append(full[:2], full[3:]...) // ErrUnknownOp only from the earlier, coalesced note
	if f := Journaled("m1", probeSet(), full, start, end, time.Minute); len(f) != 0 {
		t.Fatalf("clean round: %q", f)
	}
	last := len(full) - 1
	without := func(extra ...journal.Record) []journal.Record {
		return append(append([]journal.Record{}, full[:last]...), extra...)
	}
	for name, trail := range map[string][]journal.Record{
		"missing":       without(),
		"other machine": without(note(start, "m2", sockets.ErrUnknownOp)),
		"too old":       without(note(start.Add(-2*time.Minute), "m1", sockets.ErrUnknownOp)),
		"effect":        append(append([]journal.Record{}, full...), journal.Record{At: end, Type: journal.RecSubmitted, Intent: &journal.Intent{Machine: "m1", Action: "send"}}),
	} {
		if f := Journaled("m1", probeSet(), trail, start, end, time.Minute); len(f) != 1 {
			t.Fatalf("%s: %q", name, f)
		}
	}
}

// A probe failure becomes a probe finding; a clean round resolves it.
func TestAProbeFailureIsReportedAndAPassResolvesIt(t *testing.T) {
	g := newFake()
	res := []string{"undeclared socket owner.sock is reachable"}
	journaled := true
	s := newSource(t, g, Config{Want: probeSet(), Probe: func(context.Context) (string, []string, error) { return "m1", res, nil },
		Trail: func() []journal.Record {
			if !journaled {
				return nil
			}
			return refusals(time.Now(), "m1")
		}})
	if n, err := s.probe(context.Background()); err != nil || n != 1 || len(g.open) != 1 {
		t.Fatalf("n=%d err=%v open %v", n, err, g.open)
	}
	f := g.reported[0]
	if f.Check != loops.CheckProbe || f.Subject != "socket.m1" || !strings.Contains(f.Detail, "owner.sock") {
		t.Fatalf("finding %+v", f)
	}
	// A guest that claims an empty round, with nothing journaled on the
	// broker side, does not clear it (Security 4a on #523).
	res, journaled = nil, false
	if n, err := s.probe(context.Background()); err != nil || n == 0 || len(g.resolved) != 0 || len(g.open) == 0 {
		t.Fatalf("empty guest result n=%d err=%v open %v resolved %v", n, err, g.open, g.resolved)
	}
	journaled = true
	if n, err := s.probe(context.Background()); err != nil || n != 0 || len(g.open) != 0 {
		t.Fatalf("clean round n=%d err=%v open %v", n, err, g.open)
	}
}
