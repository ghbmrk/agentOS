package daemon

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/admission"
	"github.com/ghbmrk/agentos/broker/journal"
)

// REQ: OP-3, ADP-2

// TestDaemonJournalsOnConfigClock: Config.Now is the clock the journal
// stamps records with (SR3-mail-w2 W2-c), so an adapter given the same
// function reads the time the engine journals. Mutant: drop WithClock in
// Run; the stamp is the wall clock and the test fails.
func TestDaemonJournalsOnConfigClock(t *testing.T) {
	dir := t.TempDir()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	at := time.Date(2031, 3, 4, 5, 6, 7, 0, time.UTC)
	d, err := Run(ctx, Config{
		JournalPath: filepath.Join(dir, "journal.log"), SocketDir: filepath.Join(dir, "run"),
		OwnerNumber: owner, ModemUID: os.Getuid(), Admission: admission.Config{CapacityMB: 4500, HeadroomMB: 600},
		OwnerState: filepath.Join(dir, "owner.json"),
		Now:        func() time.Time { return at },
	})
	if err != nil {
		t.Fatal(err)
	}
	defer d.Wait()
	defer cancel()
	in := journal.Intent{ID: "m1/c1", Origin: "guest:m1", Account: "mail", Action: "message.send", Executor: "grants"}
	if _, err := d.Gate().Submit(in); err != nil {
		t.Fatal(err)
	}
	tr := d.Engine().Trail()
	if len(tr) == 0 {
		t.Fatal("nothing journaled")
	}
	for _, r := range tr {
		if !r.At.Equal(at) {
			t.Fatalf("record %s stamped %v, want %v", r.Type, r.At, at)
		}
	}
}
