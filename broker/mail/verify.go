package mail

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/ghbmrk/agentos/broker/grants"
	"github.com/ghbmrk/agentos/broker/journal"
	"github.com/ghbmrk/agentos/broker/owner"
	"github.com/ghbmrk/agentos/broker/verb"
)

// ErrUnverifiable is returned for operations whose fields come from the
// agent, not a source record (a new message): the gate then shows the
// owner what will run, marked unverified and high risk (grants GR5).
var ErrUnverifiable = errors.New("mail: a new message has no source record to verify")

var (
	_ grants.Verifier  = (*Adapter)(nil)
	_ grants.Escalator = (*Adapter)(nil)
)

// Verify reads, from the mailbox, the fields the owner judges and a
// pre-allowance tests (grants.Verifier). For a reply: the thread's
// participants as the source headers name them, whether the owner or a
// contact started the thread (ADP-11), and the message's subject.
func (a *Adapter) Verify(ctx context.Context, in journal.Intent) (grants.Verified, error) {
	o, p, err := a.intent(in)
	if err != nil {
		return grants.Verified{}, err
	}
	if p[ParamRecord] == "" || o.Name == OpDraft {
		return grants.Verified{}, ErrUnverifiable
	}
	m, err := a.locate(ctx, p[ParamRecord], p[ParamFolder])
	if err != nil {
		return grants.Verified{}, err
	}
	v := grants.Verified{Record: m.MessageID, Edited: m.Date}
	switch o.Verb {
	case verb.Send:
		rc := a.participants(m)
		if len(rc) == 0 {
			return grants.Verified{}, errors.New("mail: the thread has no one else to reply to")
		}
		known := a.cfg.Contacts != nil
		for _, r := range rc {
			known = known && a.cfg.Contacts(r)
		}
		v.Recipients = rc
		v.ThreadVerified = a.threadVerified(ctx, m, rc)
		v.Item = owner.Item{Object: "reply to " + quote(m.Subject), Recipient: strings.Join(rc, ", "),
			Facts: owner.Facts{RecipientChecked: true, RecipientExists: known}}
	default:
		v.Item = owner.Item{Object: describe(o.Name) + " " + quote(m.Subject) + " from " + m.From,
			Facts: owner.Facts{NoRecipient: true}}
	}
	return v, nil
}

// participants are a reply's recipients: the source message's sender and
// recipients, without the owner's own addresses. Reply-To is not used: a
// sender could point it anywhere.
func (a *Adapter) participants(m Message) []string {
	set := map[string]bool{}
	for _, x := range append(append([]string{m.From}, m.To...), m.Cc...) {
		if x != "" && !a.isSelf(x) {
			set[x] = true
		}
	}
	out := make([]string, 0, len(set))
	for x := range set {
		out = append(out, x)
	}
	sort.Strings(out)
	return out
}

// threadVerified reports whether a reply to m to rc may count as on a
// verified thread (ADP-11). Every header that names the thread is the
// sender's to write, so a cold sender could name a message the owner sent
// to someone else, plant a copy of one with a forged From, or copy anyone
// on its own message. So:
//
//   - The In-Reply-To chain is walked from m through messages the mailbox
//     holds (at most maxChain links); each message's sender must have been
//     a participant of the message it answers. A missing, ambiguous or
//     looping link fails.
//   - The thread's starter must be the owner, as the copy in the Sent
//     folder shows (not one in the inbox, which anyone can deliver), or a
//     contact whose message passes an aligned DMARC check.
//   - Every recipient, the latest sender included, must be a participant
//     of a vouched-for message in the chain: one in the owner's Sent
//     folder, or the contact's authenticated starter. Someone a third
//     party copied in is not.
func (a *Adapter) threadVerified(ctx context.Context, m Message, rc []string) bool {
	chain := []Message{m}
	seen := map[string]bool{m.MessageID: true}
	for cur := m; cur.InReplyTo != ""; {
		if len(chain) > maxChain || seen[cur.InReplyTo] {
			return false
		}
		seen[cur.InReplyTo] = true
		parent, err := a.locate(ctx, cur.InReplyTo, "")
		if err != nil || !a.participant(cur.From, parent) {
			return false
		}
		chain = append(chain, parent)
		cur = parent
	}
	// locate reads every message from the owner from its Sent copy, so its
	// headers, recipients and text are the owner's own.
	var vouched []Message
	for _, x := range chain {
		if a.isSelf(x.From) {
			vouched = append(vouched, x)
		}
	}
	starter := chain[len(chain)-1]
	if !a.isSelf(starter.From) {
		if a.cfg.Contacts == nil || starter.From == "" || !a.cfg.Contacts(starter.From) || !a.dmarcPass(starter) {
			return false
		}
		vouched = append(vouched, starter)
	}
	for _, r := range rc {
		ok := false
		for _, v := range vouched {
			ok = ok || a.participant(r, v)
		}
		if !ok {
			return false
		}
	}
	return true
}

// maxChain bounds the In-Reply-To links walked to verify a thread.
const maxChain = 50

// participant reports whether addr took part in x: its sender or one of
// its recipients (the owner's own addresses count as one).
func (a *Adapter) participant(addr string, x Message) bool {
	for _, y := range append(append([]string{x.From}, x.To...), x.Cc...) {
		if y == addr || a.isSelf(addr) && a.isSelf(y) {
			return true
		}
	}
	return false
}

// Thread returns what an ADP-11 reply composer may read for a reply to
// record: the thread's messages (the record and those its References and
// In-Reply-To name) whose participants include every recipient of the
// reply, as the broker computes them from source headers. So the
// composer can disclose only what every recipient already received. The
// owner's messages are read from Sent, so a planted copy never passes as
// the owner's text.
func (a *Adapter) Thread(ctx context.Context, record string) ([]Message, error) {
	m, err := a.locate(ctx, record, "")
	if err != nil {
		return nil, err
	}
	rc := a.participants(m)
	want := append(append([]string{}, m.References...), m.InReplyTo)
	var out []Message
	seen := map[string]bool{m.MessageID: true}
	for _, id := range want {
		if id == "" || seen[id] {
			continue
		}
		seen[id] = true
		x, err := a.locate(ctx, id, "")
		if errors.Is(err, ErrNotFound) || errors.Is(err, ErrNotSent) {
			continue
		}
		if err != nil {
			return nil, err
		}
		if a.covers(x, rc) {
			out = append(out, x)
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Date.Before(out[j].Date) })
	return append(out, m), nil
}

// covers reports whether every one of rc was a participant of x.
func (a *Adapter) covers(x Message, rc []string) bool {
	got := map[string]bool{x.From: true}
	for _, y := range append(append([]string{}, x.To...), x.Cc...) {
		got[y] = true
	}
	for _, r := range rc {
		if !got[r] {
			return false
		}
	}
	return true
}

func describe(op string) string {
	switch op {
	case OpArchive:
		return "archive"
	case OpUnarchive:
		return "move to inbox"
	case OpMove:
		return "move"
	case OpLabel:
		return "label"
	case OpUnlabel:
		return "unlabel"
	case OpMarkRead:
		return "mark read"
	case OpMarkUnread:
		return "mark unread"
	case OpStar:
		return "star"
	case OpUnstar:
		return "unstar"
	case OpDelete:
		return "move to trash"
	case OpReportSpam:
		return "report as spam"
	}
	return op
}

// quote is a subject as a line shows it: one line, at most 60 characters.
func quote(s string) string {
	s = strings.Join(strings.Fields(s), " ")
	if utf8.RuneCountInString(s) > 60 {
		r := []rune(s)
		s = string(r[:57]) + "..."
	}
	if s == "" {
		s = "(no subject)"
	}
	return fmt.Sprintf("%q", s)
}
