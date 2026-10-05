package daemon

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ghbmrk/agentos/broker/admission"
	"github.com/ghbmrk/agentos/broker/journal"
)

// REQ: REV-2, OP-5, ADP-9

// TestDaemonPolicyIsTheGrantsGate: the box's policy is the grants gate.
// With no grants every effect is denied with a reason and nothing routes;
// grants cannot be created without the local page; PAUSE and REVOKE reach
// the gate from the owner's number; a reserved executor name is refused.
func TestDaemonPolicyIsTheGrantsGate(t *testing.T) {
	dir := t.TempDir()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	d, err := Run(ctx, Config{
		JournalPath: filepath.Join(dir, "journal.log"), SocketDir: filepath.Join(dir, "run"),
		OwnerNumber: owner, ModemUID: os.Getuid(), Admission: admission.Config{CapacityMB: 4500, HeadroomMB: 600},
		OwnerState: filepath.Join(dir, "owner.json"),
	})
	if err != nil {
		t.Fatal(err)
	}
	g := d.Gate()
	if _, ok := g.Route("mail"); ok {
		t.Fatal("an ungranted account routes")
	}
	for _, in := range []journal.Intent{
		{ID: "m1/r1", Origin: "guest:m1", Account: "mail", Action: "message.send", Executor: "grants"},
		{ID: "m1/g1", Origin: "guest:m1", Account: journal.BrokerAccount, Action: journal.ActionGrantChange,
			Params: map[string]any{"grant": map[string]any{"account": "mail", "executor": "x", "ops": map[string]any{"s": "send"}}}, Executor: "grants"},
	} {
		if _, err := g.Submit(in); err != nil {
			t.Fatal(err)
		}
		st, err := g.Authorize(ctx, in.ID)
		if err != nil || st.State != journal.Denied || st.Permission.Reason == "" {
			t.Fatalf("%s: %s %q %v", in.ID, st.State, st.Permission.Reason, err)
		}
	}
	if got := d.Owner().Handle(ctx, owner, "PAUSE G1"); len(got) != 1 || !strings.Contains(got[0], "No grant G1") {
		t.Fatalf("PAUSE: %q", got)
	}
	cancel()
	d.Wait()

	_, err = Run(context.Background(), Config{
		JournalPath: filepath.Join(dir, "j2"), SocketDir: filepath.Join(dir, "run2"),
		OwnerNumber: owner, ModemUID: os.Getuid(), Admission: admission.Config{CapacityMB: 4500, HeadroomMB: 600},
		Executors: map[string]journal.Executor{"grants": nil},
	})
	if err == nil || !strings.Contains(err.Error(), "reserved") {
		t.Fatalf("reserved executor name: %v", err)
	}
}
