package guest

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"sync"
	"time"
)

// Owner messages reach a guest through its own inbound API (ARC-6 (c)).
// The broker never connects into a machine: the guest's bridge fetches the
// next message from its socket (GET /owner/next, held open up to a poll
// interval), hands it to the guest's inbound endpoint, and posts the guest's
// answer back (POST /owner/reply). Delivery is at least once: a message
// stays pending until it is answered, and is handed out again if its lease
// runs out (the bridge died, or the machine was rolled back).

const (
	inboxSize    = 32
	maxReplyBody = 64 << 10
)

var (
	pollWait = 25 * time.Second
	lease    = 15 * time.Minute
)

// ErrInboxFull: the machine has too many unanswered owner messages.
var ErrInboxFull = errors.New("guest: owner inbox full")

type ownerMsg struct {
	ID   string    `json:"id"`
	Text string    `json:"text"`
	out  time.Time // when last handed out; zero if never
}

type inbox struct {
	mu     sync.Mutex
	msgs   []*ownerMsg
	wake   chan struct{}
	closed bool
}

func newInbox() *inbox { return &inbox{wake: make(chan struct{})} }

func (b *inbox) put(m *ownerMsg) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return errors.New("guest: machine closed")
	}
	if len(b.msgs) >= inboxSize {
		return ErrInboxFull
	}
	b.msgs = append(b.msgs, m)
	close(b.wake)
	b.wake = make(chan struct{})
	return nil
}

// next returns the oldest message not currently leased, or the channel to
// wait on for a new one.
func (b *inbox) next(now time.Time) (*ownerMsg, <-chan struct{}) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, m := range b.msgs {
		if m.out.IsZero() || now.Sub(m.out) > lease {
			m.out = now
			return m, nil
		}
	}
	return nil, b.wake
}

func (b *inbox) answer(id string) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	for i, m := range b.msgs {
		if m.ID == id && !m.out.IsZero() {
			b.msgs = append(b.msgs[:i], b.msgs[i+1:]...)
			return true
		}
	}
	return false
}

func (b *inbox) close() {
	b.mu.Lock()
	defer b.mu.Unlock()
	if !b.closed {
		b.closed = true
		close(b.wake)
	}
}

// DeliverOwner queues an owner message for machine and returns its ID.
// Unless the owner marked the task PUBLIC, the machine's label rises to
// private first (REV-5: owner chat is owner data), so no private message
// reaches a machine whose label still says public.
func (p *Plane) DeliverOwner(machine, text string, public bool) (string, error) {
	m := p.get(machine)
	if m == nil {
		return "", errors.New("guest: machine has no open services")
	}
	if !public {
		if err := p.cfg.Machines.RaisePrivate(machine); err != nil {
			return "", err
		}
	}
	var b [6]byte
	rand.Read(b[:])
	msg := &ownerMsg{ID: hex.EncodeToString(b[:]), Text: text}
	if err := m.box.put(msg); err != nil {
		return "", err
	}
	return msg.ID, nil
}

func (p *Plane) ownerNext(m *machine, w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "GET only", http.StatusMethodNotAllowed)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), pollWait)
	defer cancel()
	for {
		msg, wait := m.box.next(time.Now())
		if msg != nil {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(msg)
			return
		}
		select {
		case <-wait:
		case <-ctx.Done():
			w.WriteHeader(http.StatusNoContent)
			return
		}
	}
}

func (p *Plane) ownerReply(m *machine, w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	var rep struct {
		ID   string `json:"id"`
		Text string `json:"text"`
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, maxReplyBody+1))
	if err != nil || len(body) > maxReplyBody || json.Unmarshal(body, &rep) != nil {
		http.Error(w, "bad reply", http.StatusBadRequest)
		return
	}
	if !m.box.answer(rep.ID) {
		http.Error(w, "no such pending message", http.StatusNotFound)
		return
	}
	if p.cfg.OwnerReply != nil {
		p.cfg.OwnerReply(m.id, rep.ID, rep.Text)
	}
	w.WriteHeader(http.StatusNoContent)
}

// OwnerAgent delivers the owner's task chat to one machine's guest: the
// control handler's Agent (control.Agent). The guest's answer comes back
// through Config.OwnerReply.
type OwnerAgent struct {
	Plane   *Plane
	Machine string
}

// Deliver implements control.Agent.
func (a OwnerAgent) Deliver(_ context.Context, text string, public bool) error {
	_, err := a.Plane.DeliverOwner(a.Machine, text, public)
	return err
}
