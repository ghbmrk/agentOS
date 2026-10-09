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
	"unicode/utf8"

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
	// ErrNotSent: a message From the owner that the Sent folder does not
	// hold is not the owner's.
	ErrNotSent = errors.New("mail: a message from the owner's address that is not in Sent")
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

// find returns every copy of record in the candidate folders: hint
// alone if one is given, else the inbox, the archive, and every ordinary
// and Sent folder (not trash, junk, drafts or an all-mail view, which
// would name a second copy).
func (a *Adapter) find(ctx context.Context, record, hint string) ([]Message, map[Role]string, error) {
	if !idPat.MatchString(record) || len(ids(record)) != 1 || ids(record)[0] != record {
		return nil, nil, fmt.Errorf("mail: record must be one Message-ID: %w", ErrNotFound)
	}
	byRole, byName, err := a.folders(ctx)
	if err != nil {
		return nil, nil, err
	}
	var order []string
	if hint != "" {
		if _, ok := byName[hint]; !ok {
			return nil, nil, ErrNotFound
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
	var found []Message
	for _, f := range order {
		if seen[f] {
			continue
		}
		seen[f] = true
		ms, err := a.cfg.Store.Find(ctx, f, record)
		if err != nil {
			return nil, nil, err
		}
		found = append(found, ms...)
	}
	if len(found) == 0 {
		return nil, nil, ErrNotFound
	}
	return found, byRole, nil
}

// locate resolves a record to the message it is: the identity a reply,
// a thread's chain and a composer read. Every candidate folder is
// searched: a Message-ID is the sender's choice, so a second message
// claiming the same ID makes the record ambiguous and is refused. Copies
// of one message (sameMessage, e.g. a label folder) are not ambiguous.
//
// A message from the owner is the owner's only as the Sent folder holds
// it: its copy there (exactly one, From the owner, in the folder with the
// Sent role) is the message, and other copies From the owner (a mailing
// list's footer, a gateway's disclaimer, CRLF for LF) are ignored in its
// favour. A same-ID copy From anyone else stays ambiguous, and an owner
// message with no Sent copy is refused.
func (a *Adapter) locate(ctx context.Context, record string) (Message, error) {
	found, byRole, err := a.find(ctx, record, "")
	if err != nil {
		return Message{}, err
	}
	var mine, others []Message
	for _, m := range found {
		if a.isSelf(m.From) {
			mine = append(mine, m)
		} else {
			others = append(others, m)
		}
	}
	if len(mine) == 0 {
		return single(found)
	}
	if len(others) > 0 {
		return Message{}, ErrAmbiguous
	}
	var inSent []Message
	for _, m := range mine {
		if byRole[Sent] != "" && m.Folder == byRole[Sent] {
			inSent = append(inSent, m)
		}
	}
	switch len(inSent) {
	case 0:
		return Message{}, ErrNotSent
	case 1:
		return inSent[0], nil
	}
	return Message{}, ErrAmbiguous
}

// place finds the copy an organize, trash or spam effect acts on, with
// its own fields: the guards and the owner's line judge the message being
// moved, never a twin elsewhere. With a hint it is the copy in that
// folder; without one, the copies outside Sent, so the owner's Sent copy
// is acted on only when a hint names Sent. Differing copies among those
// are ambiguous, never silently picked. It never needs a Sent copy: spam
// spoofing the owner can be organized. It also reports whether any
// same-ID copy in the candidate folders is an alert, so a benign twin
// cannot launder one (ADP-2).
func (a *Adapter) place(ctx context.Context, record, hint string) (Message, bool, error) {
	all, byRole, err := a.find(ctx, record, "")
	if err != nil && !(errors.Is(err, ErrNotFound) && hint != "") {
		return Message{}, false, err
	}
	found := all
	if hint != "" {
		if found, _, err = a.find(ctx, record, hint); err != nil {
			return Message{}, false, err
		}
	} else {
		found = nil
		for _, m := range all {
			if byRole[Sent] == "" || m.Folder != byRole[Sent] {
				found = append(found, m)
			}
		}
		if len(found) == 0 {
			return Message{}, false, fmt.Errorf("mail: only the Sent copy holds this message; name the folder: %w", ErrNotFound)
		}
	}
	m, err := single(found)
	if err != nil {
		return Message{}, false, err
	}
	alert := a.isAlert(m)
	for _, x := range append(all, found...) {
		alert = alert || a.isAlert(x)
	}
	return m, alert, nil
}

// single returns the one message the copies are, or ErrAmbiguous.
func single(found []Message) (Message, error) {
	for _, m := range found[1:] {
		if !sameMessage(m, found[0]) {
			return Message{}, ErrAmbiguous
		}
	}
	return found[0], nil
}

// sameMessage reports whether two copies carrying one Message-ID are the
// same message: the same sender, date, subject, recipients, threading
// headers and text. A copy that differs in any of them (an inbox copy of
// the owner's reply with its In-Reply-To stripped) makes the ID ambiguous.
func sameMessage(x, y Message) bool {
	return x.From == y.From && x.Date.Equal(y.Date) && x.Subject == y.Subject &&
		slices.Equal(sorted(x.To), sorted(y.To)) && slices.Equal(sorted(x.Cc), sorted(y.Cc)) &&
		x.InReplyTo == y.InReplyTo && slices.Equal(x.References, y.References) && x.Text == y.Text
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

// LabelClass is labelClass, for Loop 2's corpus probe (LOOP-7).
func (a *Adapter) LabelClass(label string) (string, error) { return a.labelClass(label) }

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
	m, alert, err := a.place(ctx, p[ParamRecord], p[ParamFolder])
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
	pl.alert = alert
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
	return a.AlertWording(m.Subject + "\n" + m.Text)
}

// AlertWording is isAlert's second net alone: security-alert wording or
// a code (CH-19), whoever sent the text. Loop 2's corpus probe replays
// published attack texts through it (LOOP-7).
func (a *Adapter) AlertWording(text string) bool {
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
	// subject or body (CH-19). The owner channel caps a detail at
	// maxDetail characters, so the bound clause, which the owner's YES
	// answers, comes first and the rest is shortened to fit (UX-69-3).
	var e grants.Escalation
	var why []string
	switch a.reserve(in.ID) {
	case askOnce:
		e.Ask = true
		why = append(why, fmt.Sprintf("past %d, YES allows %d", a.cfg.DailyLimit, a.cfg.DailyCeiling))
	case askEach:
		e.Ask = true
		why = append(why, fmt.Sprintf("past %d today", a.cfg.DailyCeiling))
	case held:
		return grants.Escalation{Held: true, Reason: fmt.Sprintf("held past today's %d", a.cfg.DailyLimit)}, nil
	}
	// Clauses go in order of what the owner must see: the bound, then
	// the alert, then the share. Each takes the longest of its forms that
	// still fits, so the alert is never cut off by a long bound or name.
	alert := pl.hides && pl.alert
	var forms [][]string
	if alert {
		e.Verb = verb.ChangeAccount
		forms = append(forms, []string{"hides an alert from " + clip(domainOf(pl.msg.From), 20), "alert hidden", "alert"})
	}
	if pl.verb == verb.Share {
		if !alert {
			e.Verb = verb.Share
		}
		var name string
		switch {
		case contains(a.cfg.Shared, pl.msg.Folder):
			name = "in shared folder " + clip(pl.msg.Folder, 20)
		case pl.to != "":
			name = "into shared folder " + clip(pl.to, 20)
		default:
			name = "shared label " + clip(p[ParamLabel], 20)
		}
		forms = append(forms, []string{name, "shared"})
	}
	for _, f := range forms {
		for _, c := range f {
			if len(strings.Join(append(append([]string{}, why...), c), "; ")) <= maxDetail {
				why = append(why, c)
				break
			}
		}
	}
	e.Reason = clip(strings.Join(why, "; "), maxDetail)
	return e, nil
}

// maxDetail is the owner channel's cap, in bytes, on an approval line's
// detail.
const maxDetail = 40

// clip shortens s to at most n bytes, cutting at a character boundary
// and marking the cut with "..." (ASCII: the owner channel drops
// characters outside its field set).
func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	k := n - 3
	for k > 0 && !utf8.RuneStart(s[k]) {
		k--
	}
	return s[:k] + "..."
}

// place is what the day's organize bound says of one effect.
type place int

const (
	placed  place = iota // within the bound: runs unasked
	askOnce              // the first past the bound: the one ask
	held                 // past the bound while that ask is open or after a NO
	askEach              // past the ceiling a YES lifted the bound to
)

// reserve takes a place under the day's organize bound for id. The count
// and the reservation happen under one lock, so concurrent checks cannot
// all see room for the last place. The count is the journal's authorized
// organize intents in the last day (which survives restarts) together
// with places reserved here and not yet authorized there.
//
// Past the bound the owner is asked once (ADP-2's "asked once, as one
// batch"): the first effect past it is asked, and the rest are held while
// that ask is open, after a NO, or with no answer, until the count falls
// back under the bound. A YES is the journal authorizing that one asked
// effect (not any count above the bound, which owner-approved share or
// alert asks can also reach): it lifts the bound for the day the ask was
// made, up to DailyCeiling; past that each is asked. The open ask is kept
// in memory, so after a restart the owner may be asked once more.
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
	open := a.over.id != "" && !a.over.at.Before(since)
	lifted := open && counted[a.over.id]
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
	if !open || a.over.id == id {
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
