package replay

import (
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"sync"

	"github.com/ghbmrk/agentos/broker/change"
	"github.com/ghbmrk/agentos/broker/journal"
)

// ErrUnrecorded: the guest asked for an effect the task did not record.
var ErrUnrecorded = errors.New("replay: unrecorded effect; replay fails closed")

// recorded answers one run's effect requests from the task's journaled
// intents. A request matches a recorded intent with the same account,
// action, params, and recipients; each recorded intent answers at most one
// request, so a guest that repeats an effect the task did once goes past
// the recording and fails closed. The replayed intent gets the recorded
// permission decision and final state, never an executor.
type recorded struct {
	mu         sync.Mutex
	pool       map[string][]journal.Status // by effect key, unused recordings
	ids        map[string]*replayed        // by the run's own intent ID
	onMiss     func(error)
	failure    error
	closed     bool
	pendingMCP int
}

type replayed struct {
	key string
	rec journal.Status // the recording it matched
	st  journal.Status // what the run's guest sees
}

func newRecorded(recs []journal.Status) *recorded {
	r := &recorded{pool: map[string][]journal.Status{}, ids: map[string]*replayed{}, onMiss: func(error) {}}
	for _, s := range recs {
		k := key(s.Intent)
		r.pool[k] = append(r.pool[k], s)
	}
	return r
}

// key is what makes two intents the same effect. Params and recipients go
// through JSON, so a recording read back from the journal and a request
// decoded from the guest compare equal.
func key(in journal.Intent) string {
	b, _ := json.Marshal(struct {
		Account    string         `json:"a"`
		Action     string         `json:"b"`
		Params     map[string]any `json:"c"`
		Recipients []string       `json:"d"`
	}{in.Account, in.Action, in.Params, in.Recipients})
	return string(b)
}

func (r *recorded) Submit(in journal.Intent) (journal.Status, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return journal.Status{}, ErrUnrecorded
	}
	k := key(in)
	if k == "" {
		return journal.Status{}, r.failed(ErrUnrecorded)
	}
	if p, ok := r.ids[in.ID]; ok {
		if p.key != k {
			return journal.Status{}, r.failed(journal.ErrConflict)
		}
		return p.st, nil
	}
	pool := r.pool[k]
	if len(pool) == 0 {
		err := fmt.Errorf("%w: %s %s", ErrUnrecorded, in.Account, in.Action)
		return journal.Status{}, r.failed(err)
	}
	r.pool[k] = pool[1:]
	p := &replayed{key: k, rec: pool[0], st: journal.Status{Intent: in, State: journal.Pending}}
	r.ids[in.ID] = p
	return p.st, nil
}

// failed is called with mu held. Keep the failure with the observations so a
// concurrent reply cannot turn a missed/conflicting request into a passing run.
func (r *recorded) failed(err error) error {
	if r.failure == nil {
		r.failure = err
	}
	r.onMiss(err)
	return err
}

// observeMCP starts before the authenticated guest plane parses a request.
// Non-effect calls finish immediately once classified. Refused effect calls
// (including ones that never reach Submit) fail the same frozen observation.
func (r *recorded) observeMCP() func(bool) {
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return func(bool) {}
	}
	r.pendingMCP++
	r.mu.Unlock()
	var once sync.Once
	return func(refused bool) {
		once.Do(func() {
			r.mu.Lock()
			defer r.mu.Unlock()
			r.pendingMCP--
			if refused && !r.closed {
				r.failed(ErrUnrecorded)
			}
		})
	}
}

// result freezes the broker's trace at completion. The guest controls only
// Reply; every effect and terminal state comes from this recorded handler.
func (r *recorded) result(reply []byte) ([]byte, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.closed = true
	if r.failure != nil {
		return nil, r.failure
	}
	if r.pendingMCP != 0 {
		return nil, ErrUnrecorded // a concurrent unclassified/effect call is not absence evidence
	}
	out := change.ObservedResult{Version: change.ObservedResultV1, Reply: reply}
	for _, p := range r.ids {
		fp, err := change.EffectFingerprint(p.st.Intent)
		if err != nil {
			return nil, err
		}
		out.Effects = append(out.Effects, change.ObservedEffect{Fingerprint: fp, State: p.st.State})
	}
	sort.Slice(out.Effects, func(i, j int) bool {
		if out.Effects[i].Fingerprint != out.Effects[j].Fingerprint {
			return out.Effects[i].Fingerprint < out.Effects[j].Fingerprint
		}
		return out.Effects[i].State < out.Effects[j].State
	})
	return json.Marshal(out)
}

func (r *recorded) Authorize(id string) (journal.Status, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return journal.Status{}, ErrUnrecorded
	}
	p, ok := r.ids[id]
	if !ok {
		return journal.Status{}, journal.ErrNotFound
	}
	if p.st.State != journal.Pending {
		return p.st, journal.ErrState
	}
	p.st.Permission = p.rec.Permission
	switch p.rec.State {
	case journal.Pending:
		// The task never got a decision; neither does its replay.
	case journal.Denied:
		p.st.State = journal.Denied
	default:
		p.st.State = journal.Authorized
	}
	return p.st, nil
}

func (r *recorded) Dispatch(id string) (journal.Status, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return journal.Status{}, ErrUnrecorded
	}
	p, ok := r.ids[id]
	if !ok {
		return journal.Status{}, journal.ErrNotFound
	}
	if p.st.State != journal.Authorized {
		return p.st, journal.ErrState
	}
	p.st.State = p.rec.State
	return p.st, nil
}

func (r *recorded) Get(id string) (journal.Status, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	p, ok := r.ids[id]
	if !ok {
		return journal.Status{}, journal.ErrNotFound
	}
	return p.st, nil
}
