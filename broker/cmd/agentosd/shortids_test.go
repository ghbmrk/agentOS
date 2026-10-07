package main

// REQ: CH-12, CHG-6

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/admission"
	"github.com/ghbmrk/agentos/broker/daemon"
	"github.com/ghbmrk/agentos/broker/modem"
	"github.com/ghbmrk/agentos/broker/owner"
)

// W5 (change C11): the change pipeline takes its adoption IDs from the
// owner channel's allocator once the daemon attaches (its own sequence
// until then), and the owner channel skips every ID the pipeline still
// answers to, so a digest's "UNDO K3" and a request's "YES K3" never meet.
func TestAdoptionIDsComeFromTheOwnerChannel(t *testing.T) {
	dir := t.TempDir()
	cfg := daemon.Config{
		JournalPath: filepath.Join(dir, "journal.log"), SocketDir: filepath.Join(dir, "run"),
		OwnerNumber: ownerNum, ModemUID: os.Getuid(), Admission: admission.Config{CapacityMB: 4500, HeadroomMB: 600},
		OwnerState: filepath.Join(dir, "owner.json"),
	}
	carrier := modem.NewCarrier()
	cfg.Modem = carrier.Line("+15550000100")
	carrier.Line(ownerNum)
	lp, err := openLearning(learnPaths{Dir: dir, Spare: filepath.Join(dir, "spare.json")}, false, &cfg)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.OwnerReserved == nil {
		t.Fatal("the owner channel is not told which IDs the pipeline uses")
	}
	if id, err := lp.ids.ShortID(func(string) bool { return false }); id != "" || err != nil {
		t.Fatalf("before the daemon attaches: %q %v (want the pipeline's own sequence)", id, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	d, err := daemon.Run(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	attachForTest(t, lp, ctx, cancel, d)
	req, err := d.Owner().Request([]owner.Item{{Ref: "r1", Object: "invoice 1042", Recipient: "billing@acme.example",
		Facts: owner.Facts{Verb: "send", RecipientChecked: true, RecipientExists: true, RecipientByOwner: true}}}, 10*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	lent, err := lp.ids.ShortID(func(string) bool { return false })
	if err != nil || lent == "" || lent == req {
		t.Fatalf("lent %q (open request %q) %v", lent, req, err)
	}
	if cfg.OwnerReserved(lent) {
		t.Fatal("an ID nothing adopted reads as in use")
	}
	cancel()
	d.Wait()
}
