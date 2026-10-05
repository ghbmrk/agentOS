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
// stays pending until it is answered. It is handed to the guest once per
// incarnation of the machine, and again after the machine restarts (from
// a preemption, a rebuild, a rollback, or a broker restart), never just
// because the guest is slow (G5). Unanswered messages are kept on disk
// (Config.InboxPath), so a broker restart does not drop them.

const (
	inboxSize    = 32
	maxReplyBody = 64 << 10
)

var pollWait = 25 * time.Second

// ErrInboxFull: the machine has too many unanswered owner messages.
var ErrInboxFull = errors.New("guest: owner inbox full")

type ownerMsg struct {
	ID   string `json:"id"`
	Text string `json:"text"`
	out  bool   // handed to this incarnation of the guest
}

type inbox struct {
	machine string
	store   *store
	mu      sync.Mutex
	msgs    []*ownerMsg
	wake    chan struct{}
	closed  bool
}

func newInbox(machine string, st *store) *inbox {
	b := &inbox{machine: machine, store: st, wake: make(chan struct{})}
	for _, m := range st.load(machine) {
		b.msgs = append(b.msgs, &ownerMsg{ID: m.ID, Text: m.Text})
	}
	return b
}

// persist writes the inbox through to the store. Called with mu held.
func (b *inbox) persist(msgs []*ownerMsg) error {
	out := make([]storedMsg, len(msgs))
	for i, m := range msgs {
		out[i] = storedMsg{ID: m.ID, Text: m.Text}
	}
	return b.store.set(b.machine, out)
}

func (b *inbox) put(m *ownerMsg) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return errors.New("guest: machine closed")
	}
	if len(b.msgs) >= inboxSize {
		return ErrInboxFull
	}
	next := append(append([]*ownerMsg(nil), b.msgs...), m)
	if err := b.persist(next); err != nil {
		return err
	}
	b.msgs = next
	close(b.wake)
	b.wake = make(chan struct{})
	return nil
}

// next returns the oldest message not yet handed to this incarnation, or
// the channel to wait on for a new one.
func (b *inbox) next() (*ownerMsg, <-chan struct{}) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return nil, nil
	}
	for _, m := range b.msgs {
		if !m.out {
			m.out = true
			return m, nil
		}
	}
	return nil, b.wake
}

// handed returns the IDs of messages handed to this incarnation and not
// yet answered.
func (b *inbox) handed() []string {
	b.mu.Lock()
	defer b.mu.Unlock()
	var ids []string
	for _, m := range b.msgs {
		if m.out {
			ids = append(ids, m.ID)
		}
	}
	return ids
}

func (b *inbox) answer(id string) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	for i, m := range b.msgs {
		if m.ID == id {
			next := append(append([]*ownerMsg(nil), b.msgs[:i]...), b.msgs[i+1:]...)
			// The answer goes out even if the store cannot be written;
			// the message may then be handed out again after a restart.
			_ = b.persist(next)
			b.msgs = next
			return true
		}
	}
	return false
}

// requeue hands every unanswered message out again: the machine restarted,
// so its guest no longer holds them.
func (b *inbox) requeue() {
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, m := range b.msgs {
		m.out = false
	}
	close(b.wake)
	b.wake = make(chan struct{})
}

// close ends the inbox. forget drops its stored messages (the machine was
// destroyed); otherwise they stay for the next start.
func (b *inbox) close(forget bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return
	}
	b.closed = true
	close(b.wake)
	if forget {
		_ = b.store.set(b.machine, nil)
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
	// New work has arrived: the lineage no longer serves its last
	// answered message (G14). Messages still held open keep their claim.
	if l := p.lineageOf(m); l != "" {
		p.store.setGoal(l, "", time.Time{})
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
		msg, wait := m.box.next()
		if msg == nil && wait == nil {
			http.Error(w, "machine closed", http.StatusServiceUnavailable)
			return
		}
		if msg != nil {
			p.handedOut(m, msg.ID)
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
