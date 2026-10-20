package inbox

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"sync"

	"github.com/ghbmrk/agentos/broker/clerk"
	"github.com/ghbmrk/agentos/broker/kernel"
	"github.com/ghbmrk/agentos/broker/kernel/key"
)

// Name is the clerk's name in every key and step that reaches it.
const Name = "mail"

// minRetentionDays is the shortest trash an account may have for a trash to
// count as undoable. Below it the clerk treats trash as the irreversible
// delete-remote and refuses it (ASSUMPTIONS.md).
const minRetentionDays = 7

// Mail is one message as the fake reader returns it: the clerk reads Raw and
// the class itself; neither leaves the clerk.
type Mail struct {
	ID    string `json:"id"`
	Raw   []byte `json:"raw"`
	Class string `json:"class"`
}

// Item is all the planner sees of a mail: its id, its class and, when VRB-2
// holds for the mail, an opaque sender handle to unsubscribe by.
type Item struct {
	Mail   string
	Class  string
	Sender string
}

// Effect is one change the clerk made to the mailbox.
type Effect struct {
	Verb  string `json:"verb"`
	Mail  string `json:"mail"`
	Label string `json:"label,omitempty"`
}

// Post is one request the clerk sent to an unsubscribe endpoint.
type Post struct {
	Method  string            `json:"method"`
	URL     string            `json:"url"`
	Headers map[string]string `json:"headers"`
	Body    string            `json:"body"`
}

// Refusal is one step the clerk would not run.
type Refusal struct {
	Op     string  `json:"op"`
	Mail   *string `json:"mail"`
	At     string  `json:"at"`
	Reason string  `json:"reason"`
}

// Account is the mail clerk over a synthetic mailbox (CLK-2, VRB-2, VRB-3).
// It is the only place a mail is read, an effect applied or a request made.
type Account struct {
	owner     ed25519.PublicKey
	body      string
	retention int
	items     []Item

	mu       sync.Mutex
	url      map[string]string // sender handle to its List-Unsubscribe URL
	mailOf   map[string]string // sender handle to the mail it was found in
	done     map[string]bool
	effects  []Effect
	posts    []Post
	refusals []Refusal
}

// Handle names a sender without revealing the address.
func Handle(addr string) string {
	h := sha256.Sum256([]byte(addr))
	return "sender-" + hex.EncodeToString(h[:4])
}

// NewAccount reads every mail once. A mail is unsubscribable when the reader
// calls it bulk and VRB-2 holds; only then does the planner get a handle.
func NewAccount(owner ed25519.PublicKey, w World, mails []Mail, retentionDays int, oneClickBody string) *Account {
	a := &Account{owner: owner, body: oneClickBody, retention: retentionDays,
		url: map[string]string{}, mailOf: map[string]string{}, done: map[string]bool{}}
	for _, m := range mails {
		it := Item{Mail: m.ID, Class: m.Class}
		if reason, u := Evaluate(m.Raw, w); reason == ROK && m.Class == "bulk" {
			it.Sender = Handle(FromAddress(m.Raw))
			if _, ok := a.url[it.Sender]; !ok {
				a.url[it.Sender], a.mailOf[it.Sender] = u, m.ID
			}
		}
		a.items = append(a.items, it)
	}
	return a
}

// Listing is the planner's whole view of the mailbox.
func (a *Account) Listing() []Item { return append([]Item(nil), a.items...) }

// Preload marks an earlier run's step as done, so it is not done again.
func (a *Account) Preload(idem string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.done[idem] = true
}

func (a *Account) Do(r kernel.Request, v kernel.View) kernel.Result {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.done[r.Idem] {
		return kernel.Result{Outcome: "ok", Detail: "already done"}
	}
	s := r.Step
	if rf := clerk.Check(a.owner, Name, nil, r, v); rf != nil {
		reason := rf.Code
		if reason == key.RVerb {
			reason = "outside-key"
		}
		return a.refuse(string(s.Verb), s.Args["target"].Value, reason)
	}
	switch s.Verb {
	case key.Organize, key.Trash:
		target := s.Args["target"].Value
		if !a.has(target) {
			return a.refuse(string(s.Verb), target, "unknown-mail")
		}
		if s.Verb == key.Trash && a.retention < minRetentionDays {
			return a.refuse(string(key.DeleteRemote), target, "trash-not-restorable")
		}
		a.effects = append(a.effects, Effect{Verb: string(s.Verb), Mail: target, Label: s.Args["label"].Value})
	case key.Unsubscribe:
		h := s.Args["to"].Value
		u, ok := a.url[h]
		if !ok {
			return a.refuse(string(s.Verb), "", "unknown-sender")
		}
		a.posts = append(a.posts, Post{Method: "POST", URL: u, Body: a.body,
			Headers: map[string]string{"Content-Type": "application/x-www-form-urlencoded"}})
		a.effects = append(a.effects, Effect{Verb: string(s.Verb), Mail: a.mailOf[h]})
	default:
		return a.refuse(string(s.Verb), s.Args["target"].Value, "outside-key")
	}
	a.done[r.Idem] = true
	return kernel.Result{Outcome: "ok"}
}

func (a *Account) Probe(r kernel.Request, _ kernel.View) string {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.done[r.Idem] {
		return "done"
	}
	return "notdone"
}

func (a *Account) has(id string) bool {
	for _, it := range a.items {
		if it.Mail == id {
			return true
		}
	}
	return false
}

func (a *Account) refuse(op, mail, reason string) kernel.Result {
	rf := Refusal{Op: op, At: "clerk", Reason: reason}
	if mail != "" {
		rf.Mail = &mail
	}
	a.refusals = append(a.refusals, rf)
	return kernel.Result{Outcome: "failed", Detail: reason}
}

// Effects, Posts and Refusals return copies of what the clerk did, in order.
func (a *Account) Effects() []Effect {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]Effect{}, a.effects...)
}

func (a *Account) Posts() []Post {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]Post{}, a.posts...)
}

func (a *Account) Refusals() []Refusal {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]Refusal{}, a.refusals...)
}

// Origin is the mail a sender handle was found in.
func (a *Account) Origin(handle string) string { return a.mailOf[handle] }
