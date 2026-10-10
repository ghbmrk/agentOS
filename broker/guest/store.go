package guest

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// store keeps unanswered owner messages on the broker's disk, so a broker
// restart hands them to the guest again instead of dropping them (G5),
// and each lineage's last handed-out message, so work after a restart
// still names the goal it serves (G14). The file is broker-held (0600)
// like the journal, and holds owner text only after the owner channel has
// stripped codes from it. With no path it keeps nothing.
type store struct {
	path  string
	mu    sync.Mutex
	msgs  map[string][]storedMsg // machine -> unanswered, oldest first
	goals map[string]storedGoal  // lineage -> last message handed out
	// outbox holds replies acknowledged to the guest and not yet handed
	// on, oldest first; done remembers the last doneSize replies handed
	// on, so a guest's retry of one is recognised (DEL-1). An inbox
	// message leaves in the same write that records its reply.
	outbox  []PendingReply
	done    []doneReply
	refused bool // a reply was refused because the outbox was full
}

// doneReply is a reply that has left the outbox.
type doneReply struct {
	Machine string `json:"machine"`
	ID      string `json:"id"`
	Hash    string `json:"hash"`
}

// MaxOutbox bounds the replies waiting to be handed on; past it a reply is
// refused (503) and the guest retries (DEL-1e). doneSize is how many
// handed-on replies are remembered for duplicate detection (DEL-1c).
const (
	MaxOutbox = 64
	doneSize  = 256
)

var errOutboxFull = errors.New("guest: reply outbox full")

// storedGoal is the message a lineage last served and when it last did.
type storedGoal struct {
	Msg  string    `json:"msg"`
	Last time.Time `json:"last"`
}

// file is the store's format on disk.
type file struct {
	Inbox  map[string][]storedMsg `json:"inbox"`
	Goals  map[string]storedGoal  `json:"goals"`
	Outbox []PendingReply         `json:"outbox,omitempty"`
	Done   []doneReply            `json:"done,omitempty"`
}

type storedMsg struct {
	ID   string `json:"id"`
	Text string `json:"text"`
}

func openStore(path string) (*store, error) {
	s := &store{path: path, msgs: map[string][]storedMsg{}, goals: map[string]storedGoal{}}
	if path == "" {
		return s, nil
	}
	b, err := os.ReadFile(path)
	switch {
	case errors.Is(err, os.ErrNotExist):
	case err != nil:
		return nil, err
	default:
		// Files written before G14 hold the inbox map alone.
		var f file
		if err := json.Unmarshal(b, &f); err != nil || f.Inbox == nil && f.Goals == nil && f.Outbox == nil && f.Done == nil {
			f = file{}
			if err := json.Unmarshal(b, &f.Inbox); err != nil {
				return nil, fmt.Errorf("guest: %s: %v", path, err)
			}
		}
		if f.Inbox != nil {
			s.msgs = f.Inbox
		}
		if f.Goals != nil {
			s.goals = f.Goals
		}
		s.outbox, s.done = f.Outbox, f.Done
	}
	return s, nil
}

// load returns machine's stored messages.
func (s *store) load(machine string) []storedMsg {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]storedMsg(nil), s.msgs[machine]...)
}

// goal returns lineage's last served message, if any.
func (s *store) goal(lineage string) storedGoal {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.goals[lineage]
}

// setGoal records that lineage served msg at at; an empty msg forgets the
// lineage. It is written through, best effort: on failure the memory copy
// still holds until the next successful save. A refresh of the same
// message within a minute is kept in memory only, so a busy guest does not
// write the file on every call.
func (s *store) setGoal(lineage, msg string, at time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	old, had := s.goals[lineage]
	if msg == "" {
		if !had {
			return
		}
		delete(s.goals, lineage)
	} else {
		s.goals[lineage] = storedGoal{Msg: msg, Last: at}
		if had && old.Msg == msg && at.Sub(old.Last) < time.Minute {
			return
		}
	}
	_ = s.save()
}

// set replaces machine's messages and writes the file. On failure the
// previous contents stay current, in memory and on disk.
func (s *store) set(machine string, msgs []storedMsg) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	old, had := s.msgs[machine]
	if len(msgs) == 0 {
		delete(s.msgs, machine)
	} else {
		s.msgs[machine] = msgs
	}
	if err := s.save(); err != nil {
		if had {
			s.msgs[machine] = old
		} else {
			delete(s.msgs, machine)
		}
		return err
	}
	return nil
}

// accept records rep as machine's answer and replaces machine's messages
// with msgs, in one write (DEL-1a). keep puts the reply in the outbox for
// a consumer (errOutboxFull when it is full); otherwise it is recorded as
// already handed on. On failure nothing changes, in memory or on disk.
func (s *store) accept(machine string, msgs []storedMsg, rep PendingReply, keep bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if keep && len(s.outbox) >= MaxOutbox {
		s.refused = true
		return errOutboxFull
	}
	old, had := s.msgs[machine]
	oldOut, oldDone := s.outbox, s.done
	if len(msgs) == 0 {
		delete(s.msgs, machine)
	} else {
		s.msgs[machine] = msgs
	}
	if keep {
		s.outbox = append(append([]PendingReply(nil), s.outbox...), rep)
	} else {
		s.done = addDone(s.done, rep)
	}
	if err := s.save(); err != nil {
		if had {
			s.msgs[machine] = old
		} else {
			delete(s.msgs, machine)
		}
		s.outbox, s.done = oldOut, oldDone
		return err
	}
	return nil
}

func addDone(done []doneReply, rep PendingReply) []doneReply {
	d := append([]doneReply(nil), done...)
	d = append(d, doneReply{Machine: rep.Machine, ID: rep.ID, Hash: rep.Hash})
	if len(d) > doneSize {
		d = d[len(d)-doneSize:]
	}
	return d
}

// answered returns the hash of machine's recorded reply to message id,
// waiting or handed on, if there is one.
func (s *store) answered(machine, id string) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, r := range s.outbox {
		if r.Machine == machine && r.ID == id {
			return r.Hash, true
		}
	}
	for _, r := range s.done {
		if r.Machine == machine && r.ID == id {
			return r.Hash, true
		}
	}
	return "", false
}

// pending returns the outbox, oldest first.
func (s *store) pending() []PendingReply {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]PendingReply(nil), s.outbox...)
}

// retire moves machine's reply to id from the outbox to done. Memory
// changes even if the write fails: the reply was handed on, and the worst
// a lost write does is hand it on again after a restart.
func (s *store) retire(machine, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, r := range s.outbox {
		if r.Machine == machine && r.ID == id {
			s.outbox = append(append([]PendingReply(nil), s.outbox[:i]...), s.outbox[i+1:]...)
			s.done = addDone(s.done, r)
			s.refused = false
			return s.save()
		}
	}
	return nil
}

func (s *store) waiting() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.refused
}

func (s *store) save() error {
	if s.path == "" {
		return nil
	}
	b, err := json.Marshal(file{Inbox: s.msgs, Goals: s.goals, Outbox: s.outbox, Done: s.done})
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(b); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, s.path); err != nil {
		return err
	}
	d, err := os.Open(filepath.Dir(s.path))
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
