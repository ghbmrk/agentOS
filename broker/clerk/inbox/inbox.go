package inbox

import (
	"context"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
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

// Account is the mail clerk (CLK-2, VRB-2, VRB-3) over one mailbox: the
// synthetic one of the eval, or the owner's (Live). It is the only place a
// mail is read, an effect applied or a request made.
type Account struct {
	anchors   []ed25519.PublicKey
	box       Mailbox
	secret    []byte
	world     func() World
	body      string
	retention int
	items     []Item
	mails     map[string]Mail   // by id: the clerk's own copy, never given out
	mailOf    map[string]string // sender handle to the mail it was found in
	// Clock is the clerk's own time, which holds are judged on (CLK-2); nil
	// reads the wall clock.
	Clock clerk.Clock

	mu       sync.Mutex
	state    *kernel.State
	done     map[string]bool
	sends    map[string]int // mailbox calls per step, for Probe's bound
	effects  []Effect
	posts    []Post
	refusals []Refusal
}

// classes is the closed list of classes a reader may give a mail. Any other
// class, the empty one included, leaves the mail unclassified, so a class
// never carries text into a label or a mailbox command.
var classes = map[string]bool{"bulk": true, "spam": true, "phishing": true, "personal": true, "alert": true}

// minSecret is the shortest handle secret: 128 bits.
const minSecret = 16

// Handle names a sender without revealing the address or letting anyone
// without the account's secret compute it from one.
func (a *Account) Handle(addr string) string {
	m := hmac.New(sha256.New, a.secret)
	m.Write([]byte(addr))
	return "sender-" + hex.EncodeToString(m.Sum(nil)[:minSecret])
}

// NewAccount reads every mail once. A mail with no class from the closed list
// is left alone and recorded as an unclassified read, so a reader that fails
// is seen, not mistaken for an inbox with nothing to tidy. A mail is
// unsubscribable when the reader calls it bulk, it is not an alert and VRB-2
// holds; only then does the planner get a handle. The
// world is read again when a step runs, so a verdict that has aged out is not
// acted on. secret keys the handles and must hold at least 128 bits. box is
// where the effects land, and must be the mailbox the mails were read from.
func NewAccount(anchors []ed25519.PublicKey, secret []byte, world func() World, mails []Mail, box Mailbox, retentionDays int, oneClickBody string) (*Account, error) {
	if len(secret) < minSecret {
		return nil, errors.New("inbox: handle secret shorter than 128 bits")
	}
	if box == nil {
		return nil, errors.New("inbox: no mailbox")
	}
	a := &Account{anchors: anchors, box: box, secret: append([]byte(nil), secret...), world: world, body: oneClickBody,
		retention: retentionDays, mails: map[string]Mail{}, mailOf: map[string]string{}, done: map[string]bool{}, sends: map[string]int{}}
	for _, m := range mails {
		if !classes[m.Class] {
			m.Class = ""
		}
		if m.Class == "" {
			a.refuse("read", m.ID, "unclassified")
		}
		it := Item{Mail: m.ID, Class: m.Class}
		a.mails[m.ID] = m
		if _, ok := a.eligible(m); ok {
			it.Sender = a.Handle(FromAddress(m.Raw))
			if _, ok := a.mailOf[it.Sender]; !ok {
				a.mailOf[it.Sender] = m.ID
			}
		}
		a.items = append(a.items, it)
	}
	return a, nil
}

// labelPrefix is the namespace the clerk files mail under; the label on a
// message is this plus the class the clerk itself assigned to it.
const labelPrefix = "agentOS/"

// eligible is the one rule for unsubscribing: the reader calls the mail bulk,
// it is not an alert and VRB-2 holds for it now. It returns the one-click URL
// to post to.
func (a *Account) eligible(m Mail) (string, bool) {
	w := a.world()
	reason, u := Evaluate(m.Raw, w)
	return u, m.Class == "bulk" && reason == ROK && !isAlert(m.Raw, w)
}

// Bind ties the account to the kernel whose log it serves, in the kernel's
// own process. Do then runs only a step that log shows the kernel
// dispatched, whatever view the caller passes. An account that is not bound
// (the clerk's own process, behind run.ServeClerk) judges the view the
// kernel sent with the request instead (ASSUMPTIONS.md MIG-4-mail-reader-6).
func (a *Account) Bind(s *kernel.State) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.state = s
}

// Listing is the planner's whole view of the mailbox.
func (a *Account) Listing() []Item { return append([]Item(nil), a.items...) }

// Preload marks an earlier run's step as done, so it is not done again.
func (a *Account) Preload(idem string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.done[idem] = true
}

// Reason is the refusal reason for a rejection code the planner could cause by
// asking for what its key does not allow.
func Reason(code string) string {
	if code == key.RVerb || code == kernel.CPlan {
		return "outside-key"
	}
	return code
}

// Do runs one step. It acts only on a step the bound kernel's log, or the
// kernel's view when unbound (Bind), shows it dispatched, and judges the mail
// from its own copy: class, VRB-2 and retention are the clerk's, not the
// caller's.
func (a *Account) Do(r kernel.Request, v kernel.View) kernel.Result {
	a.mu.Lock()
	defer a.mu.Unlock()
	s := r.Step()
	view := v
	if a.state != nil { // a nil *State in view would not be a nil View
		view = a.state
	}
	if view == nil {
		return a.refuse(string(s.Verb), s.Args["target"].Value, "not-dispatched")
	}
	if _, ok := view.Dispatched(r); !ok {
		return a.refuse(string(s.Verb), s.Args["target"].Value, "not-dispatched")
	}
	if a.done[r.Idem()] {
		return kernel.Result{Outcome: "ok", Detail: "already done"}
	}
	if rf := clerk.Check(a.anchors, Name, a.Facts, a.Clock.Now(), r, view); rf != nil {
		return a.refuse(string(s.Verb), s.Args["target"].Value, Reason(rf.Code))
	}
	switch s.Verb {
	case key.Organize, key.Trash:
		target := s.Args["target"].Value
		m, ok := a.mails[target]
		if !ok {
			return a.refuse(string(s.Verb), target, "unknown-mail")
		}
		if m.Class == "" {
			return a.refuse(string(s.Verb), target, "unclassified")
		}
		if s.Verb == key.Organize && s.Args["label"].Value != labelPrefix+m.Class {
			return a.refuse(string(s.Verb), target, "bad-label")
		}
		if s.Verb == key.Trash {
			if m.Class != "spam" && m.Class != "phishing" {
				return a.refuse(string(s.Verb), target, "not-trashable")
			}
			if isAlert(m.Raw, a.world()) {
				return a.refuse(string(s.Verb), target, "alert")
			}
			if a.retention < minRetentionDays {
				return a.refuse(string(key.DeleteRemote), target, "trash-not-restorable")
			}
		}
		a.sends[r.Idem()]++
		var err error
		if s.Verb == key.Trash {
			err = a.box.Trash(context.Background(), target)
		} else {
			err = a.box.Label(context.Background(), target, s.Args["label"].Value)
		}
		if res, ok := a.landed(string(s.Verb), target, err); !ok {
			return res
		}
		a.effects = append(a.effects, Effect{Verb: string(s.Verb), Mail: target, Label: s.Args["label"].Value})
	case key.Unsubscribe:
		h := s.Args["to"].Value
		id, ok := a.mailOf[h]
		if !ok {
			return a.refuse(string(s.Verb), "", "unknown-sender")
		}
		m := a.mails[id]
		u, ok := a.eligible(m)
		if !ok {
			return a.refuse(string(s.Verb), id, "no-longer-eligible")
		}
		a.sends[r.Idem()]++
		p := Post{Method: "POST", URL: u, Body: a.body,
			Headers: map[string]string{"Content-Type": "application/x-www-form-urlencoded"}}
		if res, ok := a.landed(string(s.Verb), id, a.box.Post(context.Background(), p)); !ok {
			return res
		}
		a.posts = append(a.posts, p)
		a.effects = append(a.effects, Effect{Verb: string(s.Verb), Mail: id})
	default:
		return a.refuse(string(s.Verb), s.Args["target"].Value, "outside-key")
	}
	a.done[r.Idem()] = true
	return kernel.Result{Outcome: "ok"}
}

// Facts is the clerk's reading of a step's claims: slice 1 keys set no
// content or label caveats, so a mail step claims none, and no inbox verb
// has an amount. Class, VRB-2 and retention are judged in Do (KEY-2).
func (a *Account) Facts(s key.Step) (string, []string, int64) { return "", nil, clerk.Amount(s) }

// Probe answers from the clerk's memory, never by acting (KRN-8). It says
// notdone, inviting a resend, only for organize and trash, whose mailbox
// effects are idempotent (a keyword set again; a moved mail is confirmed by
// the same read-back), and for at most MaxChecks mailbox calls per step;
// then unknown, so the kernel parks the step. An unconfirmed unsubscribe is
// never sent again: a one-click POST is not idempotent.
func (a *Account) Probe(r kernel.Request, _ kernel.View) string {
	a.mu.Lock()
	defer a.mu.Unlock()
	switch {
	case a.done[r.Idem()]:
		return "done"
	case a.sends[r.Idem()] >= kernel.MaxChecks:
		return "unknown"
	case r.Step().Verb == key.Organize || r.Step().Verb == key.Trash:
		return "notdone"
	}
	return "unknown"
}

// landed reads a mailbox's answer: nil is done; NotDone is a refusal before
// acting, recorded like the clerk's own; anything else may have acted and was
// not confirmed, so it is unknown and Probe decides whether it is sent again.
func (a *Account) landed(op, mail string, err error) (kernel.Result, bool) {
	var nd NotDone
	switch {
	case err == nil:
		return kernel.Result{}, true
	case errors.As(err, &nd):
		return a.refuse(op, mail, string(nd)), false
	}
	return kernel.Result{Outcome: "unknown", Detail: "unconfirmed"}, false
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
