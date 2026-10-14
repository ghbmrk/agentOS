package daemon

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/admission"
	"github.com/ghbmrk/agentos/broker/grants"
	"github.com/ghbmrk/agentos/broker/journal"
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
