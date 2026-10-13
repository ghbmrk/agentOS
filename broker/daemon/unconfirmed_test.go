package daemon

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/admission"
	"github.com/ghbmrk/agentos/broker/grants"
	"github.com/ghbmrk/agentos/broker/journal"
)

// REQ: CH-12, OP-4

// Two or more kinds read as a list joined with "or", each kind once, and
// an executor with no phrase is "an action" (U2 on #1382).
func TestCH12UnconfirmedListJoinsWithOr(t *testing.T) {
	in := func(id, ex string) journal.Intent { return journal.Intent{ID: id, Executor: ex} }
	for _, c := range []struct {
		ins  []journal.Intent
		want string
	}{
		{nil, ""},
		{[]journal.Intent{in("1", "loops")}, "I cannot yet confirm a setting change from before the restart."},
		{[]journal.Intent{in("1", "loops"), in("2", "loops"), in("3", "someday")},
			"I cannot yet confirm a setting change or an action from before the restart."},
		{[]journal.Intent{in("1", "mail"), in("2", grants.ExecutorName), in("3", "loops")},
			"I cannot yet confirm an email, a permission change or a setting change from before the restart."},
	} {
		if got := unconfirmedLine(c.ins); got != c.want {
			t.Errorf("%v: %q, want %q", c.ins, got, c.want)
		}
	}
}

// STATUS shows the unconfirmed lines whole through the real handler,
// which cuts each note at 100 characters: with six kinds left unconfirmed
// the kinds that do not fit are counted, and the "nothing is needed" line
// follows (S2 on #1382).
func TestCH12StatusShowsTheUnconfirmedLinesWhole(t *testing.T) {
	fastSettle(t)
	crashed := crashOnePerExecutor(t)
	dir := t.TempDir()
	brokers := map[string]journal.Executor{}
	var recall journal.Executor
	for _, n := range guardNames {
		g := &guard{t: t, name: n, down: 1 << 30}
		if n == grants.RecallExecutor {
			recall = g
		} else {
			brokers[n] = g
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	d, err := Run(ctx, Config{
		JournalPath: crashed, SocketDir: filepath.Join(dir, "run"),
		OwnerNumber: owner, ModemUID: os.Getuid(), Auth: unlocked{},
		Admission:       admission.Config{CapacityMB: 4500, HeadroomMB: 600},
		BrokerExecutors: brokers,
		Recall:          recall,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { cancel(); d.Wait() }()
	const line = "I cannot yet confirm a setting change, a learned change or 4 more from before the restart."
	var r string
	for deadline := time.Now().Add(5 * time.Second); ; time.Sleep(5 * time.Millisecond) {
		if r = strings.Join(text(t, dir, owner, "STATUS"), "\n"); strings.Contains(r, "cannot yet confirm") || time.Now().After(deadline) {
			break
		}
	}
	if len(line) > unconfirmedLineMax || len(unconfirmedWait) > unconfirmedLineMax {
		t.Fatalf("a line is over %d characters", unconfirmedLineMax)
	}
	if !strings.HasSuffix(r, " "+line+" "+unconfirmedWait) {
		t.Fatalf("STATUS: %q", r)
	}
}
