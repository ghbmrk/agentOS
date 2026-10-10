package guest

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
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
//
// A reply is on disk before the guest hears 204: the message leaves the
// inbox in the same write that records the reply (DEL-1a). With
// Config.Replies set the reply waits in the store's outbox until its
// consumer calls ReplyDone, so a crash before it is handed on loses
// nothing (DEL-1b). A reply is applied once: the same reply again is a
// 204 that changes nothing, a different one a 409 (DEL-1c).

const (
	inboxSize    = 32
	maxReplyBody = 64 << 10
)

// Reply is a guest's answer to one owner message (POST /owner/reply, a
// JSON object with these fields). Summary is optional: the agent's own
// one-line summary, which the broker texts instead of the reply when the
// reply goes to the owner's evidence destination (CH-20). The broker keeps
// it to one line of at most MaxSummary bytes; it is guest-written text
// like the reply.
type Reply struct {
	ID      string `json:"id"`
	Text    string `json:"text"`
	Summary string `json:"summary,omitempty"`
}

// PendingReply is a reply the broker acknowledged and has not yet handed
// on: Config.Replies' consumer reads them with PendingReplies, oldest
// first. Private is false only for a machine labelled public when the
// reply arrived.
type PendingReply struct {
	Machine string    `json:"machine"`
	Private bool      `json:"private"`
	At      time.Time `json:"at"`
	Reply
	Hash string `json:"hash"`
}

func replyHash(r Reply) string {
	h := sha256.Sum256([]byte(r.Text + "\x00" + r.Summary))
	return hex.EncodeToString(h[:])
}

// MaxSummary bounds a reply's summary.
const MaxSummary = 120

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
	// stored is set while messages loaded from the store have not yet been
	// handed out under a private label. The store can outlive the machine
	// record (a restored state directory, a destroy while the plane was
	// closed), so the machine now serving this ID may be a fresh public one;
	// stored messages are owner data, so the label rises before the guest
	// reads one (REV-5).
	stored bool
}

func newInbox(machine string, st *store) *inbox {
	b := &inbox{machine: machine, store: st, wake: make(chan struct{})}
	stale := false
	for _, m := range st.load(machine) {
		// A message whose reply is already recorded is answered, whatever
		// the inbox says: it is not handed out again.
		if _, ok := st.answered(machine, m.ID); ok {
			stale = true
			continue
		}
		b.msgs = append(b.msgs, &ownerMsg{ID: m.ID, Text: m.Text})
	}
	if stale {
		_ = b.persist(b.msgs)
	}
	b.stored = len(b.msgs) > 0
	return b
}

func (b *inbox) needsRaise() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.stored
}

func (b *inbox) raised() {
	b.mu.Lock()
	b.stored = false
	b.mu.Unlock()
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

// answer records rep as the reply to its message and returns the HTTP
// status for the guest, and whether the reply is new. keep holds it in
// the outbox for a consumer.
func (b *inbox) answer(rep PendingReply, keep bool) (int, bool, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if h, ok := b.store.answered(b.machine, rep.ID); ok {
		if h == rep.Hash {
			return http.StatusNoContent, false, nil
		}
		return http.StatusConflict, false, nil
	}
	for i, m := range b.msgs {
		if m.ID != rep.ID {
			continue
		}
		next := append(append([]*ownerMsg(nil), b.msgs[:i]...), b.msgs[i+1:]...)
		out := make([]storedMsg, len(next))
		for j, m := range next {
			out[j] = storedMsg{ID: m.ID, Text: m.Text}
		}
		if err := b.store.accept(b.machine, out, rep, keep); err != nil {
			return http.StatusServiceUnavailable, false, err
		}
		b.msgs = next
		return http.StatusNoContent, true, nil
	}
	return http.StatusNotFound, false, nil
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
		// The store error names the inbox path. Callers may log or text it.
		p.cfg.Logf("guest %s: inbox store: %v", machine, err)
		return "", errors.New("guest: the message was not stored")
	}
	// New work has arrived: the lineage no longer serves its last
	// answered message (G14). Messages still held open keep their claim.
	if l := p.lineageOf(m); l != "" {
		p.store.setGoal(l, "", time.Time{})
	}
	return msg.ID, nil
}

// OwnerPending reports an owner message to machine that is queued or
// handed out and not yet answered: the agent has work in hand, so the
// sleeper does not stop it (PE7 condition 2).
func (p *Plane) OwnerPending(machine string) bool {
	m := p.get(machine)
	if m == nil {
		return false
	}
	m.box.mu.Lock()
	defer m.box.mu.Unlock()
	return len(m.box.msgs) > 0
}

func (p *Plane) ownerNext(m *machine, w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "GET only", http.StatusMethodNotAllowed)
		return
	}
	// Not in Open: the machine manager opens services while holding the
	// machine's lock, which RaisePrivate takes.
	if m.box.needsRaise() {
		if err := p.cfg.Machines.RaisePrivate(m.id); err != nil {
			http.Error(w, "machine label", http.StatusServiceUnavailable)
			return
		}
		m.box.raised()
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
	var rep Reply
	body, err := io.ReadAll(io.LimitReader(r.Body, maxReplyBody+1))
	if err != nil || len(body) > maxReplyBody || json.Unmarshal(body, &rep) != nil {
		http.Error(w, "bad reply", http.StatusBadRequest)
		return
	}
	rep.Summary = strings.Join(strings.Fields(rep.Summary), " ")
	if len(rep.Summary) > MaxSummary {
		cut := MaxSummary
		for cut > 0 && !utf8.RuneStart(rep.Summary[cut]) {
			cut--
		}
		rep.Summary = rep.Summary[:cut]
	}
	label := ""
	if p.cfg.Label != nil {
		label = p.cfg.Label(m.id)
	}
	pr := PendingReply{Machine: m.id, Private: label != "public", At: p.cfg.Now(), Reply: rep, Hash: replyHash(rep)}
	keep := p.cfg.Replies != nil
	code, fresh, err := m.box.answer(pr, keep)
	switch {
	case errors.Is(err, errOutboxFull):
		p.cfg.Logf("guest %s: reply outbox full (%d waiting); the guest will retry", m.id, MaxOutbox)
		http.Error(w, "replies waiting; retry", code)
		return
	case err != nil:
		p.cfg.Logf("guest %s: inbox store: %v", m.id, err)
		http.Error(w, "reply not stored; retry", code)
		return
	case code == http.StatusConflict:
		http.Error(w, "message already answered differently", code)
		return
	case code == http.StatusNotFound:
		http.Error(w, "no such pending message", code)
		return
	}
	if fresh {
		if keep {
			p.cfg.Replies()
		} else if p.cfg.OwnerReply != nil {
			p.cfg.OwnerReply(m.id, rep)
		}
	}
	w.WriteHeader(http.StatusNoContent)
}

// PendingReplies returns the replies acknowledged and not yet handed on,
// oldest first (DEL-1b). Only Config.Replies' consumer leaves any.
func (p *Plane) PendingReplies() []PendingReply { return p.store.pending() }

// ReplyDone removes machine's reply to message id from the outbox: its
// consumer has handed it on. An error means the removal may not survive a
// restart, so the reply may be handed on again.
func (p *Plane) ReplyDone(machine, id string) error { return p.store.retire(machine, id) }

// RepliesWaiting reports that a guest's reply was refused because the
// outbox is full, until the consumer next removes one (DEL-1e).
func (p *Plane) RepliesWaiting() bool { return p.store.waiting() }

// OwnerAgent delivers the owner's task chat to one machine's guest: the
// control handler's Agent (control.Agent). The guest's answer comes back
// through Config.Replies or Config.OwnerReply.
type OwnerAgent struct {
	Plane   *Plane
	Machine string
	// Delivered, if set, is told each delivered message's goal ID (GoalID)
	// and text, for Loop 1's harvesting (W3).
	Delivered func(goal, text string, public bool)
}

// Deliver implements control.Agent.
func (a OwnerAgent) Deliver(_ context.Context, text string, public bool) error {
	id, err := a.Plane.DeliverOwner(a.Machine, text, public)
	if err == nil && a.Delivered != nil {
		a.Delivered(GoalID(id), text, public)
	}
	return err
}
