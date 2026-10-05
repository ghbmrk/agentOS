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
		v.ThreadVerified = a.threadVerified(ctx, m)
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
		if x != "" && !a.self[x] {
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

// threadVerified reports whether the thread was started by the owner, or
// by a contact in the owner's address book (ADP-11). The starter is the
// first message the References header names, or the message itself; one
// the mailbox no longer holds does not verify.
func (a *Adapter) threadVerified(ctx context.Context, m Message) bool {
	start := m
	if len(m.References) > 0 && m.References[0] != m.MessageID {
		s, err := a.locate(ctx, m.References[0], "")
		if err != nil {
			return false
		}
		start = s
	}
	if a.self[start.From] {
		return true
	}
	return a.cfg.Contacts != nil && start.From != "" && a.cfg.Contacts(start.From)
}

// Thread returns what an ADP-11 reply composer may read for a reply to
// record: the thread's messages (the record and those its References and
// In-Reply-To name) whose participants include every recipient of the
// reply, as the broker computes them from source headers. So the
// composer can disclose only what every recipient already received.
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
		if errors.Is(err, ErrNotFound) {
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
