package guest

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
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
	goals map[string]string      // lineage -> last message handed out
}

// file is the store's format on disk.
type file struct {
	Inbox map[string][]storedMsg `json:"inbox"`
	Goals map[string]string      `json:"goals"`
}

type storedMsg struct {
	ID   string `json:"id"`
	Text string `json:"text"`
}

func openStore(path string) (*store, error) {
	s := &store{path: path, msgs: map[string][]storedMsg{}, goals: map[string]string{}}
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
		if err := json.Unmarshal(b, &f); err != nil || f.Inbox == nil && f.Goals == nil {
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
	}
	return s, nil
}

// load returns machine's stored messages.
func (s *store) load(machine string) []storedMsg {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]storedMsg(nil), s.msgs[machine]...)
}

// goal returns lineage's last handed-out message, or "".
func (s *store) goal(lineage string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.goals[lineage]
}

// setGoal records msg as lineage's last handed-out message; an empty msg
// forgets the lineage. It is written through, best effort: on failure the
// memory copy still holds until the next successful save.
func (s *store) setGoal(lineage, msg string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.goals[lineage] == msg {
		return
	}
	if msg == "" {
		delete(s.goals, lineage)
	} else {
		s.goals[lineage] = msg
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

func (s *store) save() error {
	if s.path == "" {
		return nil
	}
	b, err := json.Marshal(file{Inbox: s.msgs, Goals: s.goals})
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
