package main

import (
	"context"
	"encoding/json"
	"strings"
	"sync"

	"github.com/ghbmrk/agentos/broker/change"
	"github.com/ghbmrk/agentos/broker/daemon"
	"github.com/ghbmrk/agentos/broker/digestqueue"
	"github.com/ghbmrk/agentos/broker/journal"
)

const unclearDigestSource = "unclear"

// unclearLineMax is the most parked effects one digest names.
const unclearLineMax = 64

// unclearSource is the digest's source for effects whose outcome stayed
// unknown and that the broker parked rather than retried (OP-2b): one line
// for each, saying it was not retried and that RETRY may send it twice.
// Its generation is the newest park record's sequence number, so the
// digest names the list again only once something new is parked.
type unclearSource struct {
	parked func() []journal.ParkedIntent
	store  change.Store

	mu    sync.Mutex
	acked uint64
}

func newUnclearSource(parked func() []journal.ParkedIntent, store change.Store) (*unclearSource, error) {
	s := &unclearSource{parked: parked, store: store}
	raw, err := store.Load()
	if err != nil {
		return nil, err
	}
	if raw != nil {
		var st struct{ Acked uint64 }
		if err := json.Unmarshal(raw, &st); err != nil {
			return nil, err
		}
		s.acked = st.Acked
	}
	return s, nil
}

// unclearLine is the digest line for one parked effect, in the owner's
// words (CH-12: no internal parts).
func unclearLine(executor string) string {
	w := daemon.EffectWord(executor)
	return strings.ToUpper(w[:1]) + w[1:] + " from before a restart may not have gone; not retried. Text RETRY to try again; it may go twice."
}

func (s *unclearSource) Peek(context.Context) (*digestqueue.Snapshot, error) {
	s.mu.Lock()
	acked := s.acked
	s.mu.Unlock()
	ps := s.parked()
	var gen uint64
	for _, p := range ps {
		gen = max(gen, p.Seq)
	}
	if len(ps) == 0 || gen <= acked {
		return nil, nil
	}
	if len(ps) > unclearLineMax {
		ps = ps[:unclearLineMax]
	}
	lines := make([]string, 0, len(ps))
	for _, p := range ps {
		lines = append(lines, unclearLine(p.Intent.Executor))
	}
	snap, err := digestqueue.NewSnapshot(unclearDigestSource, gen, lines, nil)
	return &snap, err
}

func (s *unclearSource) Ack(_ context.Context, snap digestqueue.Snapshot) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if snap.Generation <= s.acked {
		return nil
	}
	b, err := json.Marshal(struct{ Acked uint64 }{snap.Generation})
	if err != nil {
		return err
	}
	if err := s.store.Save(b); err != nil {
		return err
	}
	s.acked = snap.Generation
	return nil
}
