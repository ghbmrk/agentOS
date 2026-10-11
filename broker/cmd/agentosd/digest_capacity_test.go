package main

import (
	"testing"

	"github.com/ghbmrk/agentos/broker/change"
	"github.com/ghbmrk/agentos/broker/digestqueue"
)

// A modem that never confirms a send leaves one unknown batch a day. The
// queue still takes each day's digest past MaxBatches days, and STATUS keeps
// naming the unknown digests (W5-Dc-r9).
// REQ: CH-15 (W5-Dc-r9 QC-5), OP-9 (W5-Dc-r9 QC-5)
func TestDigestGoesEveryDayPastAFullQueueOfUnknownDigests(t *testing.T) {
	r := newDigestRig(t, &change.MemStore{}, nil)
	r.tr.out = func(int) (digestqueue.Outcome, string) { return digestqueue.OutcomeUnknown, "" }
	days := digestLimits.MaxBatches + 2
	for d := 0; d < days; d++ {
		r.at(d, 8, 0)
		if got := len(r.tr.sent()); got != d+1 {
			t.Fatalf("day %d: %d digests sent", d, got)
		}
		if n := len(r.batches()); n > digestLimits.MaxBatches {
			t.Fatalf("day %d: %d batches", d, n)
		}
		if r.status() != digestUnknownStatus {
			t.Fatalf("day %d: status %q", d, r.status())
		}
	}
	bs := r.batches()
	if len(bs) != digestLimits.MaxBatches || bs[0].ID != uint64(days-digestLimits.MaxBatches+1) {
		t.Fatalf("not the oldest unknown batches evicted: %d batches, first %d", len(bs), bs[0].ID)
	}
}
