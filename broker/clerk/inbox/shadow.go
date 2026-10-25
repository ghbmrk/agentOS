package inbox

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/ghbmrk/agentos/broker/kernel/key"
)

// The shadow week (TN-shadow, D-152, EVL-2): before any task changes the
// owner's real mailbox, the slice runs on it for seven days under a
// read-only grant (GmailReadCalls) with its effects landing on Synthetic, so
// nothing is sent. Shadow is the week's log: what the slice would have done
// with each mail, and what the owner did with it a day later.

// ShadowWeek is how long the shadow week proposes, and ShadowDelay how long
// after a proposal the owner's action is read back.
const (
	ShadowWeek  = 7 * 24 * time.Hour
	ShadowDelay = 24 * time.Hour
)

// The slice's verb for a mail that no effect touched.
const Leave = "leave"

// What the owner did with a mail, as an OwnerReader reads it.
const (
	OwnerRemoved  = "removed"  // in the trash or spam, or gone
	OwnerArchived = "archived" // out of the inbox
	OwnerRead     = "read"     // in the inbox, read
	OwnerUnread   = "unread"   // in the inbox, unread: not looked at yet
)

// OwnerReader reads what the owner has done with a mail the clerk read
// (Gmail.Owner). It changes nothing.
type OwnerReader interface {
	Owner(ctx context.Context, mail string) (string, error)
}

// Proposal is what the slice would have done with one mail, and what the
// owner did with it: Owner is "" until the read-back.
type Proposal struct {
	Mail  string    `json:"mail"`
	Class string    `json:"class"`
	Verb  string    `json:"verb"`
	At    time.Time `json:"at"`
	Owner string    `json:"owner,omitempty"`
}

// Shadow is the shadow week's log. It marshals to JSON for the clerk's
// process to keep sealed.
type Shadow struct {
	Start     time.Time  `json:"start"`
	Proposals []Proposal `json:"proposals"`
}

// strength orders the verbs: a mail several effects touched is proposed
// under the strongest.
var strength = map[string]int{Leave: 0, string(key.Organize): 1, string(key.Unsubscribe): 2, string(key.Trash): 3}

// Propose records one run at at: one proposal for each mail in listing that
// has none yet, under the strongest of the run's effects on it, or Leave.
// A mail read again later keeps its first proposal, and a run after the week
// proposes nothing.
func (s *Shadow) Propose(at time.Time, listing []Item, effects []Effect) {
	if at.Before(s.Start) || !at.Before(s.Start.Add(ShadowWeek)) {
		return
	}
	verb := map[string]string{}
	for _, e := range effects {
		if v, ok := strength[e.Verb]; ok && v > strength[verb[e.Mail]] {
			verb[e.Mail] = e.Verb
		}
	}
	seen := map[string]bool{}
	for _, p := range s.Proposals {
		seen[p.Mail] = true
	}
	for _, it := range listing {
		if seen[it.Mail] {
			continue
		}
		seen[it.Mail] = true
		v := verb[it.Mail]
		if v == "" {
			v = Leave
		}
		s.Proposals = append(s.Proposals, Proposal{Mail: it.Mail, Class: it.Class, Verb: v, At: at})
	}
}

// ReadBack reads the owner's action for each proposal made at least
// ShadowDelay before now and not yet read back, once each. A failed read
// stays for the next call; a dead grant (ErrReconnect) ends the pass.
func (s *Shadow) ReadBack(ctx context.Context, now time.Time, r OwnerReader) error {
	var errs []error
	for i := range s.Proposals {
		p := &s.Proposals[i]
		if p.Owner != "" || now.Before(p.At.Add(ShadowDelay)) {
			continue
		}
		o, err := r.Owner(ctx, p.Mail)
		if errors.Is(err, ErrReconnect) {
			return err
		}
		switch o {
		case OwnerRemoved, OwnerArchived, OwnerRead, OwnerUnread:
		default:
			if err == nil {
				err = fmt.Errorf("inbox: shadow: owner action %q", o)
			}
		}
		if err != nil {
			errs = append(errs, err)
			continue
		}
		p.Owner = o
	}
	return errors.Join(errs...)
}

// Waiting is how many proposals have not been read back yet.
func (s *Shadow) Waiting() int {
	n := 0
	for _, p := range s.Proposals {
		if p.Owner == "" {
			n++
		}
	}
	return n
}

// Done is whether the week is over and every proposal read back.
func (s *Shadow) Done(now time.Time) bool {
	return !now.Before(s.Start.Add(ShadowWeek)) && s.Waiting() == 0
}

// Agrees is whether the owner's action agrees with the slice's verb, and
// whether it counts at all: a mail still unread in the inbox (or not read
// back) was not looked at. Trash agrees with a removal, unsubscribe with a
// removal or an archive, and organize and leave with anything but a removal.
func Agrees(verb, owner string) (agree, counted bool) {
	switch owner {
	case OwnerRemoved, OwnerArchived, OwnerRead:
	default:
		return false, false
	}
	switch verb {
	case string(key.Trash):
		return owner == OwnerRemoved, true
	case string(key.Unsubscribe):
		return owner == OwnerRemoved || owner == OwnerArchived, true
	}
	return owner != OwnerRemoved, true
}

// shadowClasses is the order Line names the classes in.
var shadowClasses = []string{"spam", "phishing", "bulk", "personal", "alert", ""}

// Line is the shadow week's STATUS line: agreement by class over the mails
// the owner looked at, how many they have not, and that nothing was changed.
func (s *Shadow) Line() string {
	agreed, looked := map[string]int{}, map[string]int{}
	total, totalAgreed, open := 0, 0, 0
	for _, p := range s.Proposals {
		a, ok := Agrees(p.Verb, p.Owner)
		if !ok {
			open++
			continue
		}
		looked[p.Class]++
		total++
		if a {
			agreed[p.Class]++
			totalAgreed++
		}
	}
	var by []string
	for _, c := range shadowClasses {
		if looked[c] == 0 {
			continue
		}
		name := c
		if c == "" {
			name = "unclassified"
		}
		by = append(by, fmt.Sprintf("%s %d of %d", name, agreed[c], looked[c]))
	}
	line := fmt.Sprintf("Shadow week: I matched what you did with %d of the %d mails you dealt with", totalAgreed, total)
	if len(by) > 0 {
		line += " (" + strings.Join(by, ", ") + ")"
	}
	line += fmt.Sprintf("; %d you have not looked at yet. I changed nothing in your mailbox.", open)
	return line
}
