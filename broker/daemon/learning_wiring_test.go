package daemon

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/ghbmrk/agentos/broker/admission"
	"github.com/ghbmrk/agentos/broker/grants"
	"github.com/ghbmrk/agentos/broker/journal"
	ownerch "github.com/ghbmrk/agentos/broker/owner"
)

// REQ: LOOP-0, LOOP-6, CHG-2

// fakeLoops is the loop scheduler as the daemon sees it: the gate's policy
// for meta.loops.* (grants.Loops), its executor, and the settings hook.
type fakeLoops struct {
	mu   sync.Mutex
	ran  []string
	text []string
}

func (f *fakeLoops) Check(_ context.Context, _ journal.Phase, in journal.Intent) error {
	if in.Origin != "owner" {
		return errors.New("owner only")
	}
	return nil
}

func (f *fakeLoops) Line(journal.Intent) (ownerch.Item, error) { return ownerch.Item{}, nil }

func (f *fakeLoops) Execute(_ context.Context, in journal.Intent, _ int) journal.Outcome {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.ran = append(f.ran, in.ID)
	return journal.Outcome{Result: journal.ResultSucceeded}
}

func (f *fakeLoops) Reconcile(context.Context, journal.Intent, int) journal.Outcome {
	return journal.Outcome{Result: journal.ResultNotApplied}
}

func (f *fakeLoops) Settings(_ context.Context, msg string, _ bool) (string, bool) {
	if msg != "LOOPS OFF" {
		return "", false
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.text = append(f.text, msg)
	return "Spare-time work is off.", true
}

// The learning plane's executors are the broker's own: they run without
// an adapter declaration, only intents the gate's Loops or Changes policy
// allows reach them, and no grant can name them. The settings hook and its
// HELP line reach the owner channel, and a narrowing setting runs while
// the session is locked.
func TestDaemonWiresTheLearningPlane(t *testing.T) {
	dir := t.TempDir()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	f := &fakeLoops{}
	d, err := Run(ctx, Config{
		JournalPath: filepath.Join(dir, "journal.log"), SocketDir: filepath.Join(dir, "run"),
		OwnerNumber: owner, ModemUID: os.Getuid(), Admission: admission.Config{CapacityMB: 4500, HeadroomMB: 600},
		OwnerState:      filepath.Join(dir, "owner.json"),
		Grants:          grants.Config{Loops: f},
		BrokerExecutors: map[string]journal.Executor{"loops": f},
		Settings:        f.Settings,
		Narrows:         func(msg string) bool { return msg == "LOOPS OFF" },
		HelpExtra:       "LOOPS OFF/ON: spare-time work.",
	})
	if err != nil {
		t.Fatal(err)
	}
	g := d.Gate()
	for _, c := range []struct {
		in    journal.Intent
		state journal.State
	}{
		{journal.Intent{ID: "loops:off:1", Origin: "owner", Account: journal.BrokerAccount, Action: journal.ActionLoopsOff, Executor: "loops"}, journal.Succeeded},
		{journal.Intent{ID: "loops:off:2", Origin: "guest:m1", Account: journal.BrokerAccount, Action: journal.ActionLoopsOff, Executor: "loops"}, journal.Denied},
		{journal.Intent{ID: "m1/x", Origin: "guest:m1", Account: "mail", Action: "message.send", Executor: "loops"}, journal.Denied},
	} {
		if _, err := g.Submit(c.in); err != nil {
			t.Fatal(err)
		}
		st, err := g.Authorize(ctx, c.in.ID)
		if err == nil && st.State == journal.Authorized {
			st, err = g.Dispatch(ctx, c.in.ID)
		}
		if err != nil || st.State != c.state {
			t.Fatalf("%s: %s %v", c.in.ID, st.State, err)
		}
	}
	if len(f.ran) != 1 || f.ran[0] != "loops:off:1" {
		t.Fatalf("executor ran %q", f.ran)
	}
	if got := d.Owner().Handle(ctx, owner, "LOOPS OFF"); len(got) != 1 || got[0] != "Spare-time work is off." {
		t.Fatalf("locked LOOPS OFF: %q", got)
	}
	if got := d.Owner().Handle(ctx, owner, "HELP"); len(got) != 1 || !strings.Contains(got[0], "LOOPS OFF/ON") {
		t.Fatalf("HELP: %q", got)
	}
	cancel()
	d.Wait()

	for _, ex := range []map[string]journal.Executor{{"grants": f}, {grants.RecallExecutor: f}} {
		_, err = Run(context.Background(), Config{
			JournalPath: filepath.Join(dir, "j2"), SocketDir: filepath.Join(dir, "run2"),
			OwnerNumber: owner, ModemUID: os.Getuid(), Admission: admission.Config{CapacityMB: 4500, HeadroomMB: 600},
			BrokerExecutors: ex,
		})
		if err == nil || !strings.Contains(err.Error(), "reserved") {
			t.Fatalf("reserved broker executor name: %v", err)
		}
	}
	_, err = Run(context.Background(), Config{
		JournalPath: filepath.Join(dir, "j3"), SocketDir: filepath.Join(dir, "run3"),
		OwnerNumber: owner, ModemUID: os.Getuid(), Admission: admission.Config{CapacityMB: 4500, HeadroomMB: 600},
		Grants:          grants.Config{Declared: map[string]map[string]string{"loops": {"x": "send"}}},
		Executors:       map[string]journal.Executor{"loops": f},
		BrokerExecutors: map[string]journal.Executor{"loops": f},
	})
	if err == nil || !strings.Contains(err.Error(), "both") {
		t.Fatalf("executor that is both an adapter and the broker's: %v", err)
	}
}
