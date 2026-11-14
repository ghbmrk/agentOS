package daemon

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

	"github.com/ghbmrk/agentos/broker/admission"
	"github.com/ghbmrk/agentos/broker/grants"
	"github.com/ghbmrk/agentos/broker/journal"
	"github.com/ghbmrk/agentos/broker/modem"
	ownerch "github.com/ghbmrk/agentos/broker/owner"
)

// REQ: OP-4, CH-12

const actionLoopsOn = "meta.loops.on" // loops.ActionOn

// crashLoops is the loop scheduler across a crash: Execute blocks until
// release closes (the broker dies mid-dispatch), and Reconcile answers
// from its saved state, or unknown while evidence is unavailable.
type crashLoops struct {
	fakeLoops
	entered chan struct{}
	release chan struct{}

	mu2       sync.Mutex
	saved     map[string]bool // the scheduler's saved state: settings applied
	down      int             // Reconcile answers unknown this many more times
	uncertain bool            // Reconcile can never tell
	asked     int
	// stall, if set, holds every Reconcile after the third until it
	// closes, so a test sees the fence before parking (OP-2) lifts it.
	stall chan struct{}
}

func (c *crashLoops) Execute(ctx context.Context, in journal.Intent, n int) journal.Outcome {
	if c.entered != nil {
		close(c.entered)
		<-c.release
		return journal.Outcome{Result: journal.ResultUnknown}
	}
	return c.fakeLoops.Execute(ctx, in, n)
}

func (c *crashLoops) Reconcile(_ context.Context, in journal.Intent, _ int) journal.Outcome {
	c.mu2.Lock()
	if c.stall != nil && c.asked >= 3 {
		c.mu2.Unlock()
		<-c.stall
		c.mu2.Lock()
	}
	defer c.mu2.Unlock()
	c.asked++
	if c.uncertain || c.down > 0 {
		c.down--
		return journal.Outcome{Result: journal.ResultUnknown, Evidence: "settings store unavailable"}
	}
	if c.saved[in.ID] {
		return journal.Outcome{Result: journal.ResultSucceeded}
	}
	return journal.Outcome{Result: journal.ResultNotApplied, Evidence: "not in saved state"}
}

func (c *crashLoops) askedCount() int {
	c.mu2.Lock()
	defer c.mu2.Unlock()
	return c.asked
}

func loopsCfg(dir, journalPath string, f *crashLoops) Config {
	return Config{
		JournalPath: journalPath, SocketDir: filepath.Join(dir, "run"),
		OwnerNumber: owner, ModemUID: os.Getuid(), Auth: unlocked{},
		Admission:       admission.Config{CapacityMB: 4500, HeadroomMB: 600},
		Grants:          grants.Config{Loops: f},
		BrokerExecutors: map[string]journal.Executor{"loops": f},
	}
}

func loopsIntent(id, action string) journal.Intent {
	return journal.Intent{ID: id, Origin: "owner", Account: journal.BrokerAccount, Action: action, Executor: "loops"}
}

// crashMidLoopsOff leaves a journal in which LOOPS OFF was dispatched and
// the broker died before its outcome was recorded, as a power pull would.
func crashMidLoopsOff(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	f := &crashLoops{entered: make(chan struct{}), release: make(chan struct{})}
	ctx, cancel := context.WithCancel(context.Background())
	d, err := Run(ctx, loopsCfg(dir, filepath.Join(dir, "journal.log"), f))
	if err != nil {
		t.Fatal(err)
	}
	in := loopsIntent("loops:off:1", journal.ActionLoopsOff)
	if _, err := d.Gate().Submit(in); err != nil {
		t.Fatal(err)
	}
	if st, err := d.Gate().Authorize(ctx, in.ID); err != nil || st.State != journal.Authorized {
		t.Fatalf("authorize: %s %v", st.State, err)
	}
	go d.Gate().Dispatch(ctx, in.ID)
	<-f.entered
	data, err := os.ReadFile(filepath.Join(dir, "journal.log"))
	if err != nil {
		t.Fatal(err)
	}
	crashed := filepath.Join(t.TempDir(), "journal.log")
	if err := os.WriteFile(crashed, data, 0o600); err != nil {
		t.Fatal(err)
	}
	close(f.release)
	cancel()
	d.Wait()
	return crashed
}

func fastSettle(t *testing.T) {
	old, oldMax := settleWait, settleMaxWait
	settleWait, settleMaxWait = time.Millisecond, 5*time.Millisecond
	t.Cleanup(func() { settleWait, settleMaxWait = old, oldMax })
}

func waitUnfenced(t *testing.T, d *Daemon) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for len(d.Engine().Fenced(journal.BrokerAccount)) > 0 {
		if time.Now().After(deadline) {
			t.Fatalf("broker account still fenced by %q", d.Engine().Fenced(journal.BrokerAccount))
		}
		time.Sleep(time.Millisecond)
	}
}

func loopsOn(t *testing.T, d *Daemon, id string) (journal.Status, error) {
	t.Helper()
	ctx := context.Background()
	in := loopsIntent(id, actionLoopsOn)
	if _, err := d.Gate().Submit(in); err != nil {
		t.Fatal(err)
	}
	st, err := d.Gate().Authorize(ctx, in.ID)
	if err != nil || st.State != journal.Authorized {
		t.Fatalf("authorize %s: %s %v", id, st.State, err)
	}
	return d.Gate().Dispatch(ctx, in.ID)
}

// A crash mid LOOPS OFF fences the broker account at restart (OP-4).
// agentosd reconciles it from evidence at startup: LOOPS ON then
// dispatches. LOOPS OFF runs again only when the evidence proves it was
// not done (OP-2: dispatched again under the recheck), and then once.
func TestOP4StartupReconcileReleasesTheBrokerAccount(t *testing.T) {
	fastSettle(t)
	for _, applied := range []bool{true, false} {
		crashed := crashMidLoopsOff(t)
		dir := t.TempDir()
		f := &crashLoops{saved: map[string]bool{"loops:off:1": applied}, down: 2}
		cancel, d := startLoops(t, dir, crashed, f)
		waitUnfenced(t, d)
		if f.askedCount() < 3 {
			t.Fatalf("applied=%v: evidence asked %d times; the unavailable answers were not retried", applied, f.askedCount())
		}
		want := journal.Succeeded
		if st, err := d.Engine().Get("loops:off:1"); err != nil || st.State != want {
			t.Fatalf("applied=%v: LOOPS OFF is %s %v, want %s", applied, st.State, err, want)
		}
		if st, err := loopsOn(t, d, "loops:on:1"); err != nil || st.State != journal.Succeeded {
			t.Fatalf("applied=%v: LOOPS ON after reconcile: %s %v", applied, st.State, err)
		}
		if r := strings.Join(text(t, dir, owner, "STATUS"), "\n"); strings.Contains(r, "cannot yet confirm") {
			t.Fatalf("applied=%v: STATUS after reconcile: %q", applied, r)
		}
		f.mu.Lock()
		ran := append([]string(nil), f.ran...)
		f.mu.Unlock()
		wantRan := []string{"loops:on:1"}
		if !applied {
			wantRan = []string{"loops:off:1", "loops:on:1"}
		}
		if strings.Join(ran, ",") != strings.Join(wantRan, ",") {
			t.Fatalf("applied=%v: executed %q, want %q", applied, ran, wantRan)
		}
		cancel()
		d.Wait()
	}
}

// When evidence cannot settle the outcome the account stays fenced: LOOPS
// ON is refused, nothing is re-executed, and STOP and narrowing intents
// still answer.
func TestOP4UncertainOutcomeStaysFencedAndStopAnswers(t *testing.T) {
	fastSettle(t)
	crashed := crashMidLoopsOff(t)
	dir := t.TempDir()
	f := &crashLoops{uncertain: true, stall: make(chan struct{})}
	cancel, d := startLoops(t, dir, crashed, f)
	defer func() { close(f.stall); cancel(); d.Wait() }()
	deadline := time.Now().Add(5 * time.Second)
	for f.askedCount() < 3 {
		if time.Now().After(deadline) {
			t.Fatalf("evidence asked %d times; startup reconcile is not retrying", f.askedCount())
		}
		time.Sleep(time.Millisecond)
	}
	if got := d.Engine().Fenced(journal.BrokerAccount); len(got) != 1 || got[0] != "loops:off:1" {
		t.Fatalf("fence = %q", got)
	}
	if _, err := loopsOn(t, d, "loops:on:1"); !errors.Is(err, journal.ErrUnreconciled) {
		t.Fatalf("LOOPS ON while the outcome is unknown: %v", err)
	}
	// STATUS says what is not confirmed, in the owner's words (#1373).
	const held = " I cannot yet confirm a setting change from before the restart. " + unconfirmedWait
	if r := strings.Join(text(t, dir, owner, "STATUS"), "\n"); !strings.Contains(r, held) || strings.Contains(r, "loops:") {
		t.Fatalf("STATUS while fenced: %q", r)
	}
	if r := text(t, dir, owner, "STOP"); len(r) == 0 || !strings.Contains(strings.ToLower(strings.Join(r, " ")), "stop") {
		t.Fatalf("STOP while fenced: %q", r)
	}
	if !d.Engine().Stopped() {
		t.Fatal("STOP did not take effect while fenced")
	}
	off := loopsIntent("loops:budget:1", journal.ActionLoopsBudgetLower)
	if _, err := d.Gate().Submit(off); err != nil {
		t.Fatal(err)
	}
	if st, err := d.Gate().Authorize(context.Background(), off.ID); err != nil || st.State != journal.Authorized {
		t.Fatalf("authorize narrowing: %s %v", st.State, err)
	}
	if st, err := d.Gate().Dispatch(context.Background(), off.ID); err != nil || st.State != journal.Succeeded {
		t.Fatalf("narrowing budget lower while fenced: %s %v", st.State, err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.ran) != 1 || f.ran[0] != "loops:budget:1" {
		t.Fatalf("executed %q; the unknown LOOPS OFF must not run again", f.ran)
	}
}

func startLoops(t *testing.T, dir, journalPath string, f *crashLoops) (context.CancelFunc, *Daemon) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	d, err := Run(ctx, loopsCfg(dir, journalPath, f))
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	return cancel, d
}

// refusedCfg is a config Run accepts, before a test breaks one field.
func refusedCfg(dir string) Config {
	return Config{
		JournalPath: filepath.Join(dir, "journal.log"), SocketDir: filepath.Join(dir, "run"),
		OwnerNumber: owner, ModemUID: os.Getuid(), Machines: []string{"m1"},
		Admission: admission.Config{CapacityMB: 4500, HeadroomMB: 600},
	}
}

// Run refuses a config it cannot serve, each for its own reason, and a
// refusal made after the journal is open closes it, so the next start on
// the same journal is not locked out of it (the journal holds an
// exclusive lock while open).
func TestRunRefusesABadConfigAndLeavesTheJournalFree(t *testing.T) {
	for _, c := range []struct {
		name string
		mod  func(*Config)
		want string
	}{
		{"no owner", func(c *Config) { c.OwnerNumber = "" }, "owner number required"},
		{"duplicate machine", func(c *Config) { c.Machines = []string{"m1", "m1"} }, "duplicate machine id"},
		{"bad admission", func(c *Config) { c.Admission = admission.Config{} }, "admission"},
		{"reserved executor", func(c *Config) {
			c.Executors = map[string]journal.Executor{grants.ExecutorName: unknownExec{}}
		}, "reserved"},
		{"undeclared executor", func(c *Config) {
			c.Executors = map[string]journal.Executor{"mail": unknownExec{}}
		}, "declares no operations"},
		{"reserved broker executor", func(c *Config) {
			c.BrokerExecutors = map[string]journal.Executor{grants.RecallExecutor: unknownExec{}}
		}, "reserved"},
		{"adapter and broker executor", func(c *Config) {
			c.Executors = map[string]journal.Executor{"mail": unknownExec{}}
			c.Grants.Declared = map[string]map[string]string{"mail": {"message.send": "send"}}
			c.BrokerExecutors = map[string]journal.Executor{"mail": unknownExec{}}
		}, "both an adapter and the broker's"},
		{"page without the owner channel", func(c *Config) { c.PageSocket = &PageSocket{UID: os.Getuid()} }, "needs the owner channel"},
	} {
		t.Run(c.name, func(t *testing.T) {
			cfg := refusedCfg(t.TempDir())
			c.mod(&cfg)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			d, err := Run(ctx, cfg)
			if err == nil {
				cancel()
				d.Wait()
				t.Fatal("Run accepted it")
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Fatalf("Run: %v, want %q", err, c.want)
			}
			s, err := journal.OpenFile(cfg.JournalPath)
			if err != nil {
				t.Fatalf("the refused start left the journal locked: %v", err)
			}
			s.Close()
		})
	}
}

// A journal another engine holds is Run's error: two engines never share
// one journal.
func TestRunRefusesAJournalAnotherEngineHolds(t *testing.T) {
	cfg := refusedCfg(t.TempDir())
	held, err := journal.OpenFile(cfg.JournalPath)
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	d, err := Run(ctx, cfg)
	if err == nil {
		cancel()
		d.Wait()
		t.Fatal("Run shared a journal another engine holds")
	}
	if !errors.Is(err, journal.ErrLocked) {
		t.Fatalf("Run: %v, want %v", err, journal.ErrLocked)
	}
}

// A journal that does not replay is Run's error, not a broker serving
// over it (OP-4).
func TestRunRefusesAJournalThatDoesNotReplay(t *testing.T) {
	cfg := refusedCfg(t.TempDir())
	if err := os.WriteFile(cfg.JournalPath, []byte("not a journal\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	d, err := Run(ctx, cfg)
	if err == nil {
		cancel()
		d.Wait()
		t.Fatal("Run served a journal that does not replay")
	}
	s, err := journal.OpenFile(cfg.JournalPath)
	if err != nil {
		t.Fatalf("the refused start left the journal locked: %v", err)
	}
	s.Close()
}

// With no Auth given, the owner is the owner's number and no one else: a
// stranger's STOP stops nothing, and the owner's does (CH-2).
func TestTheDefaultAuthIsTheOwnersNumber(t *testing.T) {
	dir := t.TempDir()
	_, d := startWith(t, dir, func(c *Config) { c.Auth = nil })
	text(t, dir, "+15550000077", "STOP")
	if d.Owned().Stopped() {
		t.Fatal("a stranger's STOP stopped the broker")
	}
	if r := text(t, dir, owner, "STOP"); len(r) != 1 || !strings.HasPrefix(r[0], "Stopped.") {
		t.Fatalf("the owner's STOP: %q", r)
	}
	if !d.Owned().Stopped() {
		t.Fatal("the owner's STOP did not stop the broker")
	}
}

// With no modem, serveOwner reports what a restart dropped, keeps serving
// (its minute tick expires requests) while its context lives, and returns
// once it ends (CH-13, OP-4).
func TestServeOwnerBootsServesAndStopsWithNoModem(t *testing.T) {
	dir := t.TempDir()
	_, d := start(t, dir)
	var mu sync.Mutex
	var decided []string
	store := &ownerch.MemStore{}
	store.Save(ownerch.State{Pending: []ownerch.PendingRef{{ID: "7", Refs: []string{"old/1"}}}})
	ch, err := ownerch.New(ownerch.Config{
		Owner: owner, Engine: d.Owned(), Store: store,
		Decide: func(dc ownerch.Decision) {
			mu.Lock()
			decided = append(decided, dc.Ref+" "+dc.Why)
			mu.Unlock()
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	served := make(chan struct{})
	go func() { serveOwner(ctx, ch, false, time.Minute); close(served) }()
	deadline := time.Now().Add(5 * time.Second)
	for {
		mu.Lock()
		got := slices.Clone(decided)
		mu.Unlock()
		if slices.Contains(got, "old/1 restart") {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("decided %q: want the restart's drop", got)
		}
		time.Sleep(time.Millisecond)
	}
	select {
	case <-served:
		t.Fatal("serveOwner returned while its context lives")
	case <-time.After(50 * time.Millisecond):
	}
	cancel()
	select {
	case <-served:
	case <-time.After(5 * time.Second):
		t.Fatal("serveOwner did not return once its context ended")
	}
}

// With no modem to run, serveOwner's own tick expires an open request
// once its deadline passes (CH-13).
func TestServeOwnerTickExpiresARequestWithNoModemRun(t *testing.T) {
	dir := t.TempDir()
	_, d := start(t, dir)
	var mu sync.Mutex
	now := time.Date(2026, 11, 14, 9, 0, 0, 0, time.UTC)
	var decided []string
	ch, err := ownerch.New(ownerch.Config{
		Owner: owner, Engine: d.Owned(), Store: &ownerch.MemStore{},
		Modem: modem.NewCarrier().Line("+15550000009"),
		Now: func() time.Time {
			mu.Lock()
			defer mu.Unlock()
			return now
		},
		Decide: func(dc ownerch.Decision) {
			mu.Lock()
			decided = append(decided, dc.Ref+" "+dc.Why)
			mu.Unlock()
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	it := ownerch.Item{Ref: "inv/1", Object: "invoice 1042", Recipient: "billing@acme.example",
		Facts: ownerch.Facts{Verb: "send", RecipientChecked: true, RecipientExists: true, RecipientByOwner: true}}
	if _, err := ch.Request([]ownerch.Item{it}, time.Minute); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	now = now.Add(2 * time.Minute)
	mu.Unlock()
	ctx, cancel := context.WithCancel(context.Background())
	served := make(chan struct{})
	go func() { serveOwner(ctx, ch, false, time.Millisecond); close(served) }()
	defer func() { cancel(); <-served }()
	deadline := time.Now().Add(5 * time.Second)
	for {
		mu.Lock()
		got := slices.Clone(decided)
		mu.Unlock()
		if slices.Contains(got, "inv/1 expired") {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("decided %q: want the request expired by the tick", got)
		}
		time.Sleep(time.Millisecond)
	}
}

// With a modem, serveOwner is the channel's Run and nothing else: when Run
// ends (here at once, for a channel that has no modem), serveOwner returns
// rather than falling back to the modemless loop, so the restart report is
// never made a second way and no minute tick outlives the modem's Run
// (CH-13, OP-4).
func TestServeOwnerWithAModemEndsWithRun(t *testing.T) {
	dir := t.TempDir()
	_, d := start(t, dir)
	var mu sync.Mutex
	var decided []string
	store := &ownerch.MemStore{}
	store.Save(ownerch.State{Pending: []ownerch.PendingRef{{ID: "7", Refs: []string{"old/1"}}}})
	ch, err := ownerch.New(ownerch.Config{
		Owner: owner, Engine: d.Owned(), Store: store,
		Decide: func(dc ownerch.Decision) {
			mu.Lock()
			decided = append(decided, dc.Ref+" "+dc.Why)
			mu.Unlock()
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	served := make(chan struct{})
	go func() { serveOwner(ctx, ch, true, time.Minute); close(served) }()
	select {
	case <-served:
	case <-time.After(5 * time.Second):
		t.Fatal("serveOwner kept serving after the modem's Run ended")
	}
	mu.Lock()
	defer mu.Unlock()
	if len(decided) != 0 {
		t.Fatalf("decided %q after Run ended: want nothing", decided)
	}
}

// With a modem, the owner channel serves it: the owner's text is answered
// on the line (P1-5).
func TestTheOwnerChannelServesTheModem(t *testing.T) {
	dir := t.TempDir()
	carrier := modem.NewCarrier()
	phone := carrier.Line(owner)
	startWith(t, dir, func(c *Config) {
		c.Auth, c.OwnerState, c.Modem = nil, filepath.Join(dir, "owner.json"), carrier.Line("+15550000009")
	})
	if err := phone.Send("+15550000009", "HELP"); err != nil {
		t.Fatal(err)
	}
	if got := nextText(t, phone); !strings.Contains(got, "STOP") {
		t.Fatalf("HELP by text: %q", got)
	}
}

// A restart carries an intent left pending under STOP: the owner channel's
// boot hands it to the gate, which holds it while STOP holds, and once
// RESUME lifts it the gate's tick asks about it again (GR10,
// SEC-failed-stop-latch), here refused, as there is no grant (OP-4). The
// tick is the gate's own (grants.DefaultTick), so this test waits for one;
// it runs in parallel with the others.
func TestARestartAsksAboutAPendingIntentAgainAfterRESUME(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	in := journal.Intent{ID: "m1/r1", Origin: "guest:m1", Account: "mail", Action: "message.send", Executor: "grants"}
	cancel, d := startWith(t, dir, func(c *Config) { c.Auth, c.OwnerState = nil, filepath.Join(dir, "owner.json") })
	if st, err := d.Gate().Submit(in); err != nil || st.State != journal.Pending {
		t.Fatalf("submit: %s %v", st.State, err)
	}
	if _, err := d.Owned().Stop(context.Background()); err != nil {
		t.Fatal(err)
	}
	cancel()
	d.Wait()
	_, d = startWith(t, dir, func(c *Config) {
		c.Auth, c.OwnerState = nil, filepath.Join(dir, "owner.json")
	})
	time.Sleep(20 * time.Millisecond)
	if st, err := d.Engine().Get(in.ID); err != nil || st.State != journal.Pending {
		t.Fatalf("under STOP the intent is %s %v", st.State, err)
	}
	if err := d.Owned().Resume(); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(grants.DefaultTick + 5*time.Second)
	for {
		st, err := d.Engine().Get(in.ID)
		if err != nil {
			t.Fatal(err)
		}
		if st.State == journal.Denied {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("after RESUME the intent is %s, not asked about again", st.State)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// With the owner channel on, the owner socket's texts reach it, not the
// bare control words: RETRY is the channel's (OP-2).
func TestTheOwnerSocketsTextsReachTheOwnerChannel(t *testing.T) {
	dir := t.TempDir()
	startWith(t, dir, func(c *Config) { c.Auth, c.OwnerState = nil, filepath.Join(dir, "owner.json") })
	if r := text(t, dir, owner, "RETRY"); len(r) != 1 || r[0] != "Nothing to retry." {
		t.Fatalf("RETRY on the owner socket: %q", r)
	}
}
