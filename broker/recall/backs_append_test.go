package recall_test

// REQ: CAP-3, SEC-BAL-1, SEC-BAL-2

import (
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/recall"
	"github.com/ghbmrk/agentos/broker/recalltool"
)

// flakyStore is a record whose appends fail while fail is set.
type flakyStore struct {
	*recall.MemStore
	fail bool
}

func (s *flakyStore) Append(line []byte) error {
	if s.fail {
		return errors.New("disk full")
	}
	return s.MemStore.Append(line)
}

// SEC-backs-append-latch (the finding's regression): two approved
// take-backs whose marks the record does not take both go to the
// back-marks file; the first append there is partial, the second works.
// Then the record takes the first mark again, and the broker restarts.
// The second take-back must still read as back, so Retry does not reset
// its machines again and lose the work since (W3-forget-reach-r2-2).
// Before the fix the second line was joined onto the first's remains and
// skipped at the reopen.
func TestBackMarkAfterAPartialSideAppendSurvivesARestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "backs.jsonl")
	side, err := recall.OpenFile(path)
	if err != nil {
		t.Fatal(err)
	}
	record := &flakyStore{MemStore: &recall.MemStore{}, fail: true}
	p, err := recalltool.OpenProvenanceWithBacks(record, side)
	if err != nil {
		t.Fatal(err)
	}
	t0 := time.Date(2026, 10, 19, 9, 0, 0, 0, time.UTC)
	first := recalltool.Reset{Since: t0, At: t0.Add(time.Minute), Until: t0.Add(90 * time.Second)}
	second := recalltool.Reset{Since: t0.Add(time.Hour), At: t0.Add(61 * time.Minute), Until: t0.Add(62 * time.Minute)}
	recall.FaultNextAppend(side, 10)
	if err := p.MarkBack("one", first); err == nil {
		t.Fatal("first MarkBack with the record failing reported nothing")
	}
	if err := p.MarkBack("two", second); err == nil {
		t.Fatal("second MarkBack with the record failing reported nothing")
	}
	if m := p.BacksInMemoryOnly(); len(m) != 1 || m[0].Lineage != "one" {
		t.Fatalf("held in memory only: %+v (want the first alone)", m)
	}
	record.fail = false
	if err := p.MarkBack("one", first); err != nil {
		t.Fatal(err)
	}
	side.Close() // the restart
	side, err = recall.OpenFile(path)
	if err != nil {
		t.Fatal(err)
	}
	defer side.Close()
	p2, err := recalltool.OpenProvenanceWithBacks(record, side)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]bool{}
	for _, b := range p2.Backs() {
		got[b.Lineage] = true
	}
	if !got["one"] || !got["two"] {
		t.Fatalf("backs after restart: %+v (want one and two)", p2.Backs())
	}
}
