package main

import (
	"context"
	"encoding/json"
	"log"
	"strings"
	"sync"
	"time"

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
// for each, saying when it was first tried, that it was not retried and
// that RETRY may send it twice. It also names each effect a check proved
// was not done but whose resend was refused (journal NotResent, OP-2 step
// 2): it did not go, and RETRY sends it, with no warning that it may go
// twice. Its generation is the newest such record's sequence number
// shifted by relistBits, so the digest names the list again once
// something new is listed, or once Relist asks for it (an owner retry was
// refused, OP-2c).
type unclearSource struct {
	parked func() []journal.ParkedIntent
	store  change.Store
	loc    *time.Location

	mu     sync.Mutex
	acked  uint64
	relist bool
}

// relistBits leaves room under each park's generation for the relists
// asked before the next park.
const relistBits = 16

// unclearState is what the source keeps across a restart.
type unclearState struct {
	Acked  uint64
	Relist bool `json:",omitempty"`
}

func newUnclearSource(parked func() []journal.ParkedIntent, store change.Store) (*unclearSource, error) {
	s := &unclearSource{parked: parked, store: store, loc: time.Local}
	raw, err := store.Load()
	if err != nil {
		return nil, err
	}
	if raw != nil {
		var st unclearState
		if err := json.Unmarshal(raw, &st); err != nil {
			return nil, err
		}
		s.acked, s.relist = st.Acked, st.Relist
	}
	return s, nil
}

// unclearLine is the digest line for one waiting effect, in the owner's
// words (CH-12: no internal parts), with when it was first tried.
func unclearLine(p journal.ParkedIntent, loc *time.Location) string {
	w := daemon.EffectWord(p.Intent.Executor)
	w = strings.ToUpper(w[:1]) + w[1:]
	if !p.Dispatched.IsZero() {
		w += " first tried " + p.Dispatched.In(loc).Format("15:04 Jan 2")
	}
	if p.NotDone {
		return w + " did not go; not resent. Text RETRY to send it."
	}
	return w + " may not have gone; not retried. Text RETRY to try again; it may go twice."
}

func (s *unclearSource) Peek(context.Context) (*digestqueue.Snapshot, error) {
	s.mu.Lock()
	acked, relist := s.acked, s.relist
	s.mu.Unlock()
	ps := s.parked()
	var gen uint64
	for _, p := range ps {
		gen = max(gen, p.Seq<<relistBits)
	}
	if relist {
		gen = max(gen, acked+1)
	}
	if len(ps) == 0 || gen <= acked {
		return nil, nil
	}
	if len(ps) > unclearLineMax {
		ps = ps[:unclearLineMax]
	}
	lines := make([]string, 0, len(ps))
	for _, p := range ps {
		lines = append(lines, unclearLine(p, s.loc))
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
	if err := s.saveLocked(unclearState{Acked: snap.Generation}); err != nil {
		return err
	}
	s.acked, s.relist = snap.Generation, false
	return nil
}

// Relist names the parked effects in the next digest again, whether or
// not something new was parked: an owner retry was refused, so the effect
// it named is still waiting (OP-2c).
func (s *unclearSource) Relist() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.saveLocked(unclearState{Acked: s.acked, Relist: true}); err != nil {
		// Still relisted until a restart.
		log.Printf("digest: saving the unclear relist: %v", err)
	}
	s.relist = true
}

func (s *unclearSource) saveLocked(st unclearState) error {
	b, err := json.Marshal(st)
	if err != nil {
		return err
	}
	return s.store.Save(b)
}
