package mail

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/ghbmrk/agentos/broker/grants"
	"github.com/ghbmrk/agentos/broker/journal"
	"github.com/ghbmrk/agentos/broker/owner"
	"github.com/ghbmrk/agentos/broker/verb"
)

// dayWindow is the period the organize bound counts over.
const dayWindow = 24 * time.Hour

// Errors.
var (
	ErrNotFound = errors.New("mail: message not found")
	ErrTarget   = errors.New("mail: not an allowed organize target (ADP-2)")
	ErrAccount  = errors.New("mail: intent is for another account or executor")
	ErrOp       = errors.New("mail: operation not declared (ADP-1)")
)

// folders returns the account's folders by role and by name.
func (a *Adapter) folders(ctx context.Context) (map[Role]string, map[string]Role, error) {
	fs, err := a.cfg.Store.Folders(ctx)
	if err != nil {
		return nil, nil, err
	}
	byRole, byName := map[Role]string{}, map[string]Role{}
	for _, f := range fs {
		byName[f.Name] = f.Role
		if f.Role != "" {
			if _, ok := byRole[f.Role]; !ok {
				byRole[f.Role] = f.Name
			}
		}
	}
	if _, ok := byRole[Inbox]; !ok {
		byRole[Inbox] = "INBOX"
		byName["INBOX"] = Inbox
	}
	return byRole, byName, nil
}

// locate finds the record: in hint if one is given, else the inbox, the
// archive, then every other folder but trash, junk, drafts and the
// all-mail view, which would name a second copy.
func (a *Adapter) locate(ctx context.Context, record, hint string) (Message, error) {
	if !idPat.MatchString(record) || len(ids(record)) != 1 || ids(record)[0] != record {
		return Message{}, fmt.Errorf("mail: record must be one Message-ID: %w", ErrNotFound)
	}
	byRole, byName, err := a.folders(ctx)
	if err != nil {
		return Message{}, err
	}
	var order []string
	if hint != "" {
		if _, ok := byName[hint]; !ok {
			return Message{}, ErrNotFound
		}
		order = []string{hint}
	} else {
		order = append(order, byRole[Inbox])
		if n, ok := byRole[Archive]; ok {
			order = append(order, n)
		}
		var rest []string
		for n, r := range byName {
			if r == "" || r == Sent {
				rest = append(rest, n)
			}
		}
		sort.Strings(rest)
		order = append(order, rest...)
	}
	seen := map[string]bool{}
	for _, f := range order {
		if seen[f] {
			continue
		}
		seen[f] = true
		ms, err := a.cfg.Store.Find(ctx, f, record)
		if err != nil {
			return Message{}, err
		}
		if len(ms) > 0 {
			return ms[0], nil
		}
	}
	return Message{}, ErrNotFound
}

var trashNames = regexp.MustCompile(`(?i)(^|[/.\]])\s*(trash|bin|deleted( items| messages)?|junk|spam|bulk mail)\s*$`)

// folderClass says what moving a message into folder is: allowed
// (organize), share, or refused.
func (a *Adapter) folderClass(name string, byName map[string]Role) (string, error) {
	r, exists := byName[name]
	switch {
	case r == Trash || r == Junk || trashNames.MatchString(name) || contains(a.cfg.Retention, name):
		return "", ErrTarget
	case contains(a.cfg.Shared, name):
		return verb.Share, nil
	case r == Inbox || r == Archive || contains(a.cfg.Folders, name):
		if !exists {
			return "", ErrTarget
		}
		return verb.Organize, nil
	case strings.HasPrefix(name, Namespace) && len(name) > len(Namespace):
		return verb.Organize, nil
	}
	return "", ErrTarget
}

// labelClass says what adding or removing a label is.
func (a *Adapter) labelClass(label string) (string, error) {
	switch {
	case label == "" || strings.HasPrefix(label, `\`) || strings.ContainsAny(label, " ()[]{}%*\"\\\r\n"):
		return "", ErrTarget
	case trashNames.MatchString(label):
		return "", ErrTarget
	case contains(a.cfg.Shared, label):
		return verb.Share, nil
	case label == Keyword || strings.HasPrefix(label, Namespace) || contains(a.cfg.Labels, label):
		return verb.Organize, nil
	}
	return "", ErrTarget
}

// plan is what an organize operation will do to one message.
type plan struct {
	op     Op
	msg    Message
	to     string // target folder for a move, "" for none
	add    []string
	remove []string
	verb   string // organize or share
	hides  bool
	alert  bool
}

// planOrganize resolves an organize (or trash or spam) operation against
// the source and its guards.
func (a *Adapter) planOrganize(ctx context.Context, o Op, p map[string]string) (plan, error) {
	m, err := a.locate(ctx, p[ParamRecord], p[ParamFolder])
	if err != nil {
		return plan{}, err
	}
	byRole, byName, err := a.folders(ctx)
	if err != nil {
		return plan{}, err
	}
	pl := plan{op: o, msg: m, verb: o.Verb}
	inInbox := byName[m.Folder] == Inbox
	moveTo := func(dst string) error {
		if dst == "" {
			return ErrTarget
		}
		if dst == m.Folder {
			return nil
		}
		c, err := a.folderClass(dst, byName)
		if err != nil {
			return err
		}
		pl.to, pl.verb = dst, c
		return nil
	}
	switch o.Name {
	case OpArchive:
		err = moveTo(byRole[Archive])
		pl.hides = inInbox
	case OpUnarchive:
		err = moveTo(byRole[Inbox])
	case OpMove:
		err = moveTo(p[ParamTo])
		pl.hides = inInbox && pl.to != ""
	case OpLabel, OpUnlabel:
		var c string
		if c, err = a.labelClass(p[ParamLabel]); err == nil {
			pl.verb = c
			if o.Name == OpLabel {
				pl.add = []string{p[ParamLabel]}
			} else {
				pl.remove = []string{p[ParamLabel]}
			}
		}
	case OpMarkRead:
		pl.add, pl.hides = []string{Seen}, !has(m.Flags, Seen)
	case OpMarkUnread:
		pl.remove = []string{Seen}
	case OpStar:
		pl.add = []string{Flagged}
	case OpUnstar:
		pl.remove = []string{Flagged}
	case OpDelete, OpReportSpam:
		role := Trash
		if o.Name == OpReportSpam {
			role = Junk
		}
		pl.to = byRole[role]
		if pl.to == "" {
			err = fmt.Errorf("mail: the account has no %s folder", role)
		}
		pl.verb = o.Verb
	default:
		return plan{}, ErrOp
	}
	if err != nil {
		return plan{}, err
	}
	if o.Verb == verb.Organize && !(o.Name == OpLabel && p[ParamLabel] == Keyword) && !has(m.Flags, Keyword) {
		pl.add = append(pl.add, Keyword)
	}
	pl.alert = a.isAlert(m)
	return pl, nil
}

// AlertPhrases are the second net of ADP-2's alert guard: security-alert
// wording that marks a message an alert whoever sent it. The owner's
// languages add to them (Config.Phrases); Loop 2 grows them (LOOP-10).
var AlertPhrases = []string{
	"sign-in", "signin", "sign in", "signed in", "log-in attempt", "login attempt", "new login", "new sign",
	"new device", "password reset", "reset your password", "password was changed", "password changed",
	"security alert", "security notice", "security code", "suspicious", "unusual activity", "unusual sign",
	"is this you", "was this you", "unusual transaction", "verify your identity", "verification code",
	"two-step", "2-step", "two-factor", "recovery email", "recovery phone",
	"payment received", "payment failed", "payment declined", "payment notice", "payment due",
	"account change", "account was changed", "account details changed", "email address changed", "phone number changed",
}

// isAlert reports whether hiding m must be asked (ADP-2): a sender that
// passes an aligned DMARC check and is the provider's security sender, a
// service the owner holds an account with, or a sender the owner marked
// financial or identity; or, whoever sent it, security-alert wording or a
// code (CH-19).
func (a *Adapter) isAlert(m Message) bool {
	if a.dmarcPass(m) {
		known := senderIn(m.From, a.cfg.SecuritySenders) || senderIn(m.From, a.cfg.Financial)
		if !known && a.cfg.AccountSenders != nil {
			known = senderIn(m.From, a.cfg.AccountSenders())
		}
		if known {
			return true
		}
	}
	text := m.Subject + "\n" + m.Text
	if owner.SecretShaped(text) {
		return true
	}
	l := strings.ToLower(strings.Join(strings.Fields(text), " "))
	for _, list := range [][]string{AlertPhrases, a.cfg.Phrases} {
		for _, p := range list {
			if p != "" && strings.Contains(l, strings.ToLower(p)) {
				return true
			}
		}
	}
	return false
}

var (
	dmarcPat   = regexp.MustCompile(`(?i)(^|[;\s])dmarc\s*=\s*pass\b[^;]*`)
	headerFrom = regexp.MustCompile(`(?i)header\.from\s*=\s*"?([a-z0-9.-]+)`)
)

// dmarcPass reads only the topmost Authentication-Results header, and only
// if the provider's own server wrote it (its authserv-id): a sender can
// add more of these headers, never above the provider's.
func (a *Adapter) dmarcPass(m Message) bool {
	if a.cfg.AuthServ == "" || len(m.AuthResults) == 0 || m.From == "" {
		return false
	}
	ar := m.AuthResults[0]
	id, _, _ := strings.Cut(ar, ";")
	if f := strings.Fields(id); len(f) == 0 || !strings.EqualFold(f[0], a.cfg.AuthServ) {
		return false
	}
	for _, d := range dmarcPat.FindAllString(ar, -1) {
		if h := headerFrom.FindStringSubmatch(d); h != nil && strings.EqualFold(h[1], domainOf(m.From)) {
			return true
		}
	}
	return false
}

// Escalate is the gate's guard hook for this account (grants.Escalator).
// An organize effect whose target is not allowed is refused; one on a
// shared target is share; one that hides an alert is change-account; and
// past the day's bound each is asked.
func (a *Adapter) Escalate(ctx context.Context, in journal.Intent) (grants.Escalation, error) {
	o, p, err := a.intent(in)
	if err != nil {
		return grants.Escalation{}, err
	}
	if o.Verb != verb.Organize {
		return grants.Escalation{}, nil
	}
	pl, err := a.planOrganize(ctx, o, p)
	if err != nil {
		return grants.Escalation{}, err
	}
	var e grants.Escalation
	if pl.verb != verb.Organize {
		e.Verb = pl.verb
	}
	if pl.hides && pl.alert {
		e.Verb = verb.ChangeAccount
	}
	if a.organizedToday(in.ID) >= a.cfg.DailyLimit {
		e.Ask = true
	}
	return e, nil
}

// organizedToday counts the organize effects the journal authorized on
// this account in the last day, other than id. Without the journal hook
// every effect counts as past the bound, so none runs unasked.
func (a *Adapter) organizedToday(id string) int {
	if a.cfg.Authorized == nil {
		return a.cfg.DailyLimit
	}
	since := a.cfg.Now().Add(-dayWindow)
	n := 0
	for _, o := range ops {
		if o.Verb != verb.Organize {
			continue
		}
		for _, x := range a.cfg.Authorized(o.Name, since) {
			if x.ID != id && x.Account == a.cfg.Account {
				n++
			}
		}
	}
	return n
}

// intent checks in is for this adapter and returns its operation and
// params.
func (a *Adapter) intent(in journal.Intent) (Op, map[string]string, error) {
	if in.Account != a.cfg.Account || in.Executor != a.cfg.Executor {
		return Op{}, nil, ErrAccount
	}
	o, ok := byName[in.Action]
	if !ok {
		return Op{}, nil, ErrOp
	}
	p, err := checkParams(o, in.Params)
	if err != nil {
		return Op{}, nil, err
	}
	return o, p, nil
}

func has(l []string, s string) bool {
	for _, x := range l {
		if strings.EqualFold(x, s) {
			return true
		}
	}
	return false
}

func contains(l []string, s string) bool {
	for _, x := range l {
		if x == s {
			return true
		}
	}
	return false
}
