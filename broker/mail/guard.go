package mail

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"slices"
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
	// ErrAmbiguous: two different messages carry the record's Message-ID.
	ErrAmbiguous = errors.New("mail: two different messages carry this Message-ID")
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
	// Every candidate folder is searched: a Message-ID is the sender's
	// choice, so a second message claiming the same ID (a forged copy of
	// one the owner sent) makes the record ambiguous and is refused. Copies
	// of one message (the same sender, date, subject and recipients, e.g. a
	// label folder) are not ambiguous.
	seen := map[string]bool{}
	var found []Message
	for _, f := range order {
		if seen[f] {
			continue
		}
		seen[f] = true
		ms, err := a.cfg.Store.Find(ctx, f, record)
		if err != nil {
			return Message{}, err
		}
		found = append(found, ms...)
	}
	if len(found) == 0 {
		return Message{}, ErrNotFound
	}
	for _, m := range found[1:] {
		if !sameMessage(m, found[0]) {
			return Message{}, ErrAmbiguous
		}
	}
	return found[0], nil
}

// sameMessage reports whether two copies carrying one Message-ID are the
// same message: the same sender, date, subject and recipients.
func sameMessage(x, y Message) bool {
	return x.From == y.From && x.Date.Equal(y.Date) && x.Subject == y.Subject &&
		slices.Equal(sorted(x.To), sorted(y.To)) && slices.Equal(sorted(x.Cc), sorted(y.Cc))
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
	// The source is guarded like a target: nothing is organized out of
	// trash, junk or a retention folder (unarchiving from junk would put
	// phishing in the inbox), and an effect in a shared folder is share.
	src := byName[m.Folder]
	if src == Trash || src == Junk || trashNames.MatchString(m.Folder) || contains(a.cfg.Retention, m.Folder) {
		return plan{}, ErrTarget
	}
	if contains(a.cfg.Shared, m.Folder) && o.Verb == verb.Organize {
		pl.verb = verb.Share
	}
	inInbox := src == Inbox
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
		pl.to = dst
		if c == verb.Share {
			pl.verb = c
		}
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
			if c == verb.Share {
				pl.verb = c
			}
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

// dmarcPass reads only the topmost Authentication-Results header, and only
// if the provider's own server wrote it (its authserv-id): a sender can
// add more of these headers, never above the provider's. The header is
// parsed per RFC 8601 (parseAuthResults), so a result inside a comment or
// a quoted string does not count, and the DMARC result must be aligned
// with the From domain.
func (a *Adapter) dmarcPass(m Message) bool {
	if a.cfg.AuthServ == "" || len(m.AuthResults) == 0 || m.From == "" {
		return false
	}
	id, rs := parseAuthResults(m.AuthResults[0])
	if !strings.EqualFold(id, a.cfg.AuthServ) {
		return false
	}
	for _, r := range rs {
		if r.Method == "dmarc" && r.Result == "pass" && strings.EqualFold(r.Props["header.from"], domainOf(m.From)) {
			return true
		}
	}
	return false
}

// Escalate is the gate's guard hook for this account (grants.Escalator).
// An organize effect whose target is not allowed is refused; one on a
// shared target is share; one that hides an alert is change-account; and
// past the day's bound the owner is asked once and the rest are held
// (reserve).
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
	// Reasons are fixed words over broker-held fields only: an
	// owner-confirmed target name, the sender's domain, the bound. Never a
	// subject or body (CH-19). The owner channel caps a detail at 40
	// characters, so they are short.
	var e grants.Escalation
	var why []string
	if pl.verb == verb.Share {
		e.Verb = verb.Share
		switch {
		case contains(a.cfg.Shared, pl.msg.Folder):
			why = append(why, "in shared folder "+pl.msg.Folder)
		case pl.to != "":
			why = append(why, "into shared folder "+pl.to)
		default:
			why = append(why, "shared label "+p[ParamLabel])
		}
	}
	if pl.hides && pl.alert {
		e.Verb = verb.ChangeAccount
		why = append(why, "hides an alert from "+clip(domainOf(pl.msg.From), 20))
	}
	switch a.reserve(in.ID) {
	case askOnce:
		e.Ask = true
		why = append(why, fmt.Sprintf("past today's %d; YES allows %d", a.cfg.DailyLimit, a.cfg.DailyCeiling))
	case askEach:
		e.Ask = true
		why = append(why, fmt.Sprintf("past today's %d", a.cfg.DailyCeiling))
	case held:
		return grants.Escalation{}, ErrHeld
	}
	e.Reason = strings.Join(why, "; ")
	return e, nil
}

// clip shortens s to n characters, marking the cut.
func clip(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n-1]) + "…"
}

// place is what the day's organize bound says of one effect.
type place int

const (
	placed  place = iota // within the bound: runs unasked
	askOnce              // the first past the bound: the one ask
	held                 // past the bound while that ask is open or after a NO
	askEach              // past the ceiling a YES lifted the bound to
)

// ErrHeld refuses an organize effect past the day's bound while the owner
// has not said YES to the one ask (ADP-2); it may be tried again once the
// owner does, or tomorrow.
var ErrHeld = errors.New("mail: past today's organize bound; held until the owner allows more")

// reserve takes a place under the day's organize bound for id. The count
// and the reservation happen under one lock, so concurrent checks cannot
// all see room for the last place. The count is the journal's authorized
// organize intents in the last day (which survives restarts) together
// with places reserved here and not yet authorized there.
//
// Past the bound the owner is asked once (ADP-2's "asked once, as one
// batch"): the first effect past it is asked, and the rest are held while
// that ask is open, after a NO, or with no answer, until the count falls
// back under the bound. The journal shows a YES: only an owner's approval
// can authorize more than the bound, so a count above it means the bound
// is lifted for the day, up to DailyCeiling; past that each is asked.
// The YES lifts only the count: every effect still meets the target,
// share and alert guards. Without the journal hook every effect is asked.
func (a *Adapter) reserve(id string) place {
	if a.cfg.Authorized == nil {
		return askEach
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	now := a.cfg.Now()
	since := now.Add(-dayWindow)
	counted := map[string]bool{}
	for _, o := range ops {
		if o.Verb != verb.Organize {
			continue
		}
		for _, x := range a.cfg.Authorized(o.Name, since) {
			if x.Account == a.cfg.Account {
				counted[x.ID] = true
			}
		}
	}
	for r, at := range a.reserved {
		if at.Before(since) {
			delete(a.reserved, r)
			continue
		}
		counted[r] = true
	}
	if counted[id] {
		return placed // already holds a place (the recheck before dispatch)
	}
	limit := a.cfg.DailyLimit
	lifted := len(counted) > limit
	if lifted {
		limit = a.cfg.DailyCeiling
	}
	if len(counted) < limit {
		a.reserved[id] = now
		return placed
	}
	if lifted {
		return askEach
	}
	if a.over.id == "" || a.over.id == id || a.over.at.Before(since) {
		a.over = overAsk{id: id, at: now}
		return askOnce
	}
	return held
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
