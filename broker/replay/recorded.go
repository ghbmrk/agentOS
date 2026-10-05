package replay

import (
	"encoding/json"
	"fmt"
	"sync"

	"github.com/ghbmrk/agentos/broker/journal"
)

// recorded answers one run's effect requests from the task's journaled
// intents. A request matches a recorded intent with the same account,
// action, params, and recipients; each recorded intent answers at most one
// request, so a guest that repeats an effect the task did once goes past
// the recording and fails closed. The replayed intent gets the recorded
// permission decision and final state, never an executor.
type recorded struct {
	mu     sync.Mutex
	pool   map[string][]journal.Status // by effect key, unused recordings
	ids    map[string]*replayed        // by the run's own intent ID
	onMiss func(error)
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
	k := key(in)
	if p, ok := r.ids[in.ID]; ok {
		if p.key != k {
			return journal.Status{}, journal.ErrConflict
		}
		return p.st, nil
	}
	pool := r.pool[k]
	if len(pool) == 0 {
		err := fmt.Errorf("%w: %s %s", ErrUnrecorded, in.Account, in.Action)
		r.onMiss(err)
		return journal.Status{}, err
	}
	r.pool[k] = pool[1:]
	p := &replayed{key: k, rec: pool[0], st: journal.Status{Intent: in, State: journal.Pending}}
	r.ids[in.ID] = p
	return p.st, nil
}

func (r *recorded) Authorize(id string) (journal.Status, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
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
