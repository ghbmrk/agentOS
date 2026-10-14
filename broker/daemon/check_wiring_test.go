package daemon

// SIM-check wiring: the journal check reaches the owner as a STATUS line.
//
// REQ: OP-3, OP-5

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ghbmrk/agentos/broker/journal"
)

type allowAll struct{}

func (allowAll) Check(context.Context, journal.Phase, journal.Intent) error { return nil }

type applies struct{}

func (applies) Execute(context.Context, journal.Intent, int) journal.Outcome {
	return journal.Outcome{Result: journal.ResultSucceeded}
}
func (applies) Reconcile(context.Context, journal.Intent, int) journal.Outcome {
	return journal.Outcome{Result: journal.ResultSucceeded}
}

// A journal where an effect ran under a grant the owner had already revoked
// (a policy that skipped its recheck) replays cleanly, since the engine does
// not know grants; the check still names it on STATUS.
func TestStatusNamesAJournalCheckViolation(t *testing.T) {
	dir, err := os.MkdirTemp("", "bk")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	fs, err := journal.OpenFile(filepath.Join(dir, "journal.log"))
	if err != nil {
		t.Fatal(err)
	}
	e, err := journal.Open(fs, allowAll{}, map[string]journal.Executor{"x": applies{}}, func(s string) string { return s })
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	for _, in := range []journal.Intent{
		{ID: "send-1", Origin: "agent", Account: "mail", Action: "send", GrantRef: "grant-canary", Executor: "x"},
		{ID: "revoke-1", Origin: "owner", Account: journal.BrokerAccount, Action: journal.ActionGrantRevoke, GrantRef: "grant-canary", Executor: "x"},
	} {
		if _, err := e.Submit(in); err != nil {
			t.Fatal(err)
		}
		if _, err := e.Authorize(ctx, in.ID); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := e.Dispatch(ctx, "revoke-1"); err != nil {
		t.Fatal(err)
	}
	if _, err := e.Dispatch(ctx, "send-1"); err != nil {
		t.Fatal(err)
	}
	fs.Close()

	cancel, d := start(t, dir)
	defer func() { cancel(); d.Wait() }()
	r := text(t, dir, owner, "STATUS")
	if !strings.Contains(r[0], "Journal check failed (OP-3)") {
		t.Fatalf("STATUS: %q", r)
	}
}

func TestStatusIsQuietWhenTheJournalChecksClean(t *testing.T) {
	dir, err := os.MkdirTemp("", "bk")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	cancel, d := start(t, dir)
	defer func() { cancel(); d.Wait() }()
	if r := text(t, dir, owner, "STATUS"); strings.Contains(r[0], "Journal check") {
		t.Fatalf("STATUS: %q", r)
	}
}
