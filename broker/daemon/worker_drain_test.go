package daemon

import (
	"context"
	"errors"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/journal"
	"github.com/ghbmrk/agentos/broker/modem"
	ownerch "github.com/ghbmrk/agentos/broker/owner"
)

type drainBlockedLine struct {
	entered, release chan struct{}
	once             sync.Once
}

func (*drainBlockedLine) Number() string          { return "+15550000002" }
func (*drainBlockedLine) Inbox() <-chan modem.SMS { return nil }
func (m *drainBlockedLine) Send(string, string) error {
	m.once.Do(func() { close(m.entered) })
	<-m.release
	return nil
}

// REQ: CH-15, OP-4, CH-2
func TestDaemonWaitRetainsJournalDuringBlockedOwnerBoot(t *testing.T) {
	dir := t.TempDir()
	ownerState := filepath.Join(dir, "owner.json")
	carrier := modem.NewCarrier()
	seedCancel, seed := startWith(t, dir, func(cfg *Config) {
		cfg.OwnerState = ownerState
		cfg.Modem = carrier.Line("+15550000002")
	})
	if _, err := seed.Owner().Request([]ownerch.Item{{Ref: "synthetic", Facts: ownerch.Facts{Verb: "read"}, Object: "synthetic object"}}, time.Minute); err != nil {
		seedCancel()
		seed.Wait()
		t.Fatal(err)
	}
	seedCancel()
	seed.Wait()
	line := &drainBlockedLine{entered: make(chan struct{}), release: make(chan struct{})}
	cancel, d := startWith(t, dir, func(cfg *Config) { cfg.OwnerState = ownerState; cfg.Modem = line })
	var release sync.Once
	unblock := func() { release.Do(func() { close(line.release) }) }
	t.Cleanup(func() { unblock(); cancel(); d.Wait() })
	select {
	case <-line.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("restart send did not start")
	}
	if err := d.Owner().LocalStop(context.Background()); err != nil {
		t.Fatal(err)
	}
	cancel()
	// Socket shutdown is a completed deterministic boundary independent of Boot.
	d.srv.Wait()
	done := make(chan struct{})
	go func() { d.Wait(); close(done) }()
	select {
	case <-done:
		t.Fatal("Wait returned while owned restart report was blocked")
	case <-time.After(100 * time.Millisecond):
	}
	if reopened, err := journal.OpenFile(filepath.Join(dir, "journal.log")); !errors.Is(err, journal.ErrLocked) {
		if reopened != nil {
			reopened.Close()
		}
		t.Fatalf("journal custody released during worker: %v", err)
	}
	unblock()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Wait did not complete after owner returned")
	}
	reopened, err := journal.OpenFile(filepath.Join(dir, "journal.log"))
	if err != nil {
		t.Fatal(err)
	}
	reopened.Close()
}

type drainNeedsOwner struct{}

func (drainNeedsOwner) Error() string    { return "synthetic owner decision required" }
func (drainNeedsOwner) NeedsOwner() bool { return true }

type drainChanges struct{ entered, release chan struct{} }

func (*drainChanges) Check(context.Context, journal.Phase, journal.Intent) error {
	return drainNeedsOwner{}
}
func (*drainChanges) Line(journal.Intent) (ownerch.Item, error) {
	return ownerch.Item{Object: "synthetic change", Facts: ownerch.Facts{Kind: ownerch.GrantChange, Verb: "adopt", NoRecipient: true}}, nil
}
func (*drainChanges) Execute(context.Context, journal.Intent, int) journal.Outcome {
	return journal.Outcome{Result: journal.ResultNotApplied}
}
func (*drainChanges) Reconcile(context.Context, journal.Intent, int) journal.Outcome {
	return journal.Outcome{Result: journal.ResultUnknown}
}
func (c *drainChanges) Decided(context.Context, journal.Intent, bool) { close(c.entered); <-c.release }

// A Gate decision creates a settling goroutine that can outlive Gate.Run.
// No effect is approved/executed: this test declines a synthetic broker change.
// REQ: CH-15, OP-4
func TestDaemonWaitJoinsPendingGateSettlement(t *testing.T) {
	dir := t.TempDir()
	pipeline := &drainChanges{make(chan struct{}), make(chan struct{})}
	cancel, d := startWith(t, dir, func(cfg *Config) {
		cfg.Grants.Changes = pipeline
		cfg.BrokerExecutors = map[string]journal.Executor{"synthetic": pipeline}
	})
	var once sync.Once
	unblock := func() { once.Do(func() { close(pipeline.release) }) }
	t.Cleanup(func() { unblock(); cancel(); d.Gate().Wait(); d.Wait() })
	in := journal.Intent{ID: "synthetic-change", Origin: "change", Account: journal.BrokerAccount, Action: "meta.change.synthetic", Executor: "synthetic"}
	if _, err := d.Gate().Submit(in); err != nil {
		t.Fatal(err)
	}
	d.Gate().Decide(ownerch.Decision{Ref: in.ID, Why: "owner", Approved: false})
	select {
	case <-pipeline.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("settlement callback did not start")
	}
	st, err := d.Engine().Get(in.ID)
	if err != nil || st.State != journal.Denied || len(st.Attempts) != 0 {
		t.Fatalf("synthetic decline created execution: %+v %v", st, err)
	}
	cancel()
	d.srv.Wait()
	done := make(chan struct{})
	go func() { d.Wait(); close(done) }()
	select {
	case <-done:
		t.Fatal("Wait returned while Gate settlement callback was blocked")
	case <-time.After(100 * time.Millisecond):
	}
	if reopened, err := journal.OpenFile(filepath.Join(dir, "journal.log")); !errors.Is(err, journal.ErrLocked) {
		if reopened != nil {
			reopened.Close()
		}
		t.Fatalf("journal released during settlement: %v", err)
	}
	unblock()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Wait did not complete after settlement")
	}
	reopened, err := journal.OpenFile(filepath.Join(dir, "journal.log"))
	if err != nil {
		t.Fatal(err)
	}
	reopened.Close()
}
