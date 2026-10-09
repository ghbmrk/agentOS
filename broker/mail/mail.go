// Package mail is the mail adapter (SPEC §10A, PLAN P2 package P2-6m).
// It maps a mailbox's operations onto the broker's fixed verb list
// (ADP-1, ADP-2), runs them as the journal's executor, reads the source
// fields the grants gate judges (Verifier, Escalator), and watches the
// mailbox, publishing what arrives to the event bus and so to recall
// (CAP-3, CAP-4).
//
// The package holds no credential and opens no network connection
// (CRED-1). It reaches the mailbox through Store, which the vault process
// serves: package mail/imapsmtp is the IMAP and SMTP implementation, and
// only a process holding the unlocked vault links it.
package mail

import (
	"context"
	"errors"
	"net/mail"
	"strings"
	"sync"
	"time"

	"github.com/ghbmrk/agentos/broker/journal"
)

// Role is a folder's special use (RFC 6154), or the inbox.
type Role string

const (
	Inbox   Role = "inbox"
	Archive Role = "archive"
	Drafts  Role = "drafts"
	Sent    Role = "sent"
	Trash   Role = "trash"
	Junk    Role = "junk"
	All     Role = "all" // a view of every message (Gmail's All Mail)
)

// Folder is one mailbox folder.
type Folder struct {
	Name string
	Role Role // empty for an ordinary folder
}

// Message is what the adapter reads of one message. Addresses are bare,
// lower-cased addresses, never display names.
type Message struct {
	Folder      string
	Validity    uint32 // the folder's UID validity when UID was read
	UID         uint32
	MessageID   string // as in the header, with angle brackets
	Date        time.Time
	From        string
	To, Cc      []string
	Subject     string
	InReplyTo   string
	References  []string
	Flags       []string
	AuthResults []string // Authentication-Results values, topmost first
	Text        string   // the plain text, bounded (MaxText)
	Attachments bool
}

// Ref is a message's remote identity: folder, UID validity and UID. A
// UID names a message only within one UID validity: a mailbox rebuilt
// under a new validity can give the same UID to another message, so a
// Ref is acted on only while the folder still has its validity
// (ErrValidity).
type Ref struct {
	Folder   string
	Validity uint32
	UID      uint32
}

// Ref is m's remote identity.
func (m Message) Ref() Ref { return Ref{Folder: m.Folder, Validity: m.Validity, UID: m.UID} }

// ErrValidity is a Store's refusal to act on a Ref (or fetch UIDs) whose
// UID validity is not the folder's current one, or is unknown: the UID
// may now name another message. Nothing was changed; the caller resolves
// the message again rather than retrying by the old UID.
var ErrValidity = errors.New("mail: the folder was rebuilt since the message was read; nothing changed, resolve it again")

// MaxText bounds the text read from one message.
const MaxText = 64 << 10

// Seen and Flagged are the IMAP system flags organize sets; Draft marks a
// saved draft.
const (
	Seen    = `\Seen`
	Flagged = `\Flagged`
	Draft   = `\Draft`
)

// Keyword is the label every organized item gets, so it stays findable
// (ADP-2), and Namespace is the folder and label prefix the broker owns.
const (
	Keyword   = "AgentOS"
	Namespace = "AgentOS/"
)

// Store is the mailbox as the vault process serves it. It carries only
// the operations below: nothing can expunge, empty a folder, or change a
// filter, forwarding or auto-reply setting, so a credentialed request that
// is not one of the adapter's declared operations cannot be made (ADP-10).
// UIDs are IMAP UIDs within a UID validity: every method that takes UIDs
// also takes the validity they were read under and, in the same selected
// session, refuses with ErrValidity before acting if the folder's
// validity differs. Messages it returns carry the validity they were
// read under.
type Store interface {
	Folders(ctx context.Context) ([]Folder, error)
	// UIDs lists every message in folder.
	UIDs(ctx context.Context, folder string) (validity uint32, uids []uint32, err error)
	// Fetch reads messages without marking them read.
	Fetch(ctx context.Context, folder string, validity uint32, uids []uint32) ([]Message, error)
	// Find returns the messages in folder whose Message-ID is id.
	Find(ctx context.Context, folder, id string) ([]Message, error)
	SetFlags(ctx context.Context, m Ref, add, remove []string) error
	Move(ctx context.Context, m Ref, to string) error
	// Ensure creates folder if it does not exist. The adapter calls it
	// only for folders in the broker's own namespace.
	Ensure(ctx context.Context, folder string) error
	Append(ctx context.Context, folder string, flags []string, date time.Time, raw []byte) error
	// Submit sends raw to rcpt from the account's own address.
	Submit(ctx context.Context, rcpt []string, raw []byte) error
}

// Config configures an Adapter.
type Config struct {
	// Account is the journal account the grant connects; Executor the
	// executor name registered with the engine (default "mail").
	Account  string
	Executor string
	// Address is the owner's address on this account; Aliases are other
	// addresses that are the owner's, read from the provider's verified
	// send-as list, never typed in. They are never a reply's recipient.
	Address string
	Aliases []string
	// Box marks the box's own mailbox (ADP-13), not the owner's: no
	// address on it is the owner's evidence destination (CH-20).
	Box   bool
	Store Store

	// Organize targets (ADP-2). Folders and Labels are the ones the owner
	// confirmed when granting; the inbox, the archive and the AgentOS/
	// namespace are always allowed. Shared names folders or labels that
	// are shared, delegated, synced to another party or watched by
	// another service: an effect on one is share. Retention names folders
	// with a retention or auto-delete policy: never a target, nor are
	// trash and junk.
	Folders   []string
	Labels    []string
	Shared    []string
	Retention []string

	// Alerts (ADP-2). AuthServ is the provider's authserv-id: only the
	// topmost Authentication-Results header, and only when it carries
	// this ID, is read for an aligned DMARC pass. SecuritySenders are the
	// provider's own security senders; AccountSenders lists the domains
	// of the services the owner holds accounts with (from the grants and
	// vault); Financial are senders the owner marked as financial or
	// identity. Each entry is an address or a domain (subdomains match).
	// Phrases are the owner's languages' additions to AlertPhrases.
	AuthServ        string
	SecuritySenders []string
	AccountSenders  func() []string
	Financial       []string
	Phrases         []string

	// DailyLimit bounds organize effects per account per day (default
	// 200). Past it the owner is asked once; while that ask is open or
	// after a NO, the rest are held, and a YES lifts the bound for the
	// day up to DailyCeiling (default 2000), past which each is asked.
	// InUse returns the intents with action that hold a place under the
	// bound counted from since (journal.Engine.InUse for this account):
	// authorized or in flight whatever their age, and dispatched since
	// then (SR3-2-f1). The count is the journal's, so it survives restarts
	// and a queue released long after its authorization. Nil: every
	// organize effect is asked.
	DailyLimit   int
	DailyCeiling int
	InUse        func(action string, since time.Time) []journal.Use

	// Contacts reports whether addr is in the owner's contacts, read from
	// the source (CH-10's existence rule for ADP-11 thread starters). Nil:
	// no contact counts.
	Contacts func(addr string) bool

	// AppendSent saves sent mail to the Sent folder, for providers that
	// do not (Gmail does; most IMAP servers do not).
	AppendSent bool

	// Redact, if set, rewrites an OpDeliver body before it is sent: the
	// vault process passes its redactor, so no vault value leaves in
	// evidence (CRED-7).
	Redact func(string) string

	Now func() time.Time
}

// DefaultDailyLimit is ADP-2's default organize bound, and
// DefaultDailyCeiling how far an owner's YES lifts it for the day.
const (
	DefaultDailyLimit   = 200
	DefaultDailyCeiling = 2000
)

// Adapter is one connected mail account.
type Adapter struct {
	cfg   Config
	self  map[string]bool
	alias map[string]bool // the aliases, exactly

	mu       sync.Mutex
	reserved map[string]time.Time // organize bound places not yet in the journal
	over     overAsk              // the open "past today's bound" ask
	pins     map[string][]pin     // by intent: what Escalate judged since the last Execute (SR3-5-f1)
	judged   map[attemptKey]pin   // an unknown attempt's pin, for Reconcile
}

// attemptKey names one attempt of an intent.
type attemptKey struct {
	id      string
	attempt int
}

// pin is what Escalate judged of an organize intent: the message it
// planned on, the folder the plan moves it to, and whether the call
// escalated hiding an alert (SR3-5-f1a). Execute acts only on that
// message, only when every judgement since the last Execute agrees on
// it, and only hides an alert they escalated.
type pin struct {
	ref   Ref
	to    string
	alert bool
	at    time.Time
}

// overAsk is the one intent asked past the day's bound, and when.
type overAsk struct {
	id string
	at time.Time
}

// ErrConfig is returned by New for an incomplete configuration.
var ErrConfig = errors.New("mail: Config needs Account, Address and Store")

// New checks cfg and returns the adapter.
func New(cfg Config) (*Adapter, error) {
	if cfg.Account == "" || cfg.Store == nil {
		return nil, ErrConfig
	}
	addr, ok := canon(cfg.Address)
	if !ok {
		return nil, ErrConfig
	}
	if cfg.Executor == "" {
		cfg.Executor = "mail"
	}
	if cfg.DailyLimit == 0 {
		cfg.DailyLimit = DefaultDailyLimit
	}
	if cfg.DailyCeiling == 0 {
		cfg.DailyCeiling = DefaultDailyCeiling
	}
	if cfg.DailyCeiling < cfg.DailyLimit {
		cfg.DailyCeiling = cfg.DailyLimit
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	a := &Adapter{cfg: cfg, self: map[string]bool{addr: true, selfKey(addr): true}, alias: map[string]bool{}, reserved: map[string]time.Time{},
		pins: map[string][]pin{}, judged: map[attemptKey]pin{}}
	for _, x := range cfg.Aliases {
		if c, ok := canon(x); ok {
			a.self[c], a.self[selfKey(c)], a.alias[c] = true, true, true
		}
	}
	a.cfg.Address = addr
	return a, nil
}

// canon returns a bare, lower-cased address.
func canon(s string) (string, bool) {
	a, err := mail.ParseAddress(strings.TrimSpace(s))
	if err != nil || a.Address == "" {
		return "", false
	}
	return strings.ToLower(a.Address), true
}

// isSelf reports whether addr is one of the owner's addresses, including
// a plus-address variant of one (owner+tag@example.com) and, on Gmail,
// one that differs only in dots in the local part.
func (a *Adapter) isSelf(addr string) bool {
	return a.self[addr] || a.self[selfKey(addr)]
}

// Owns reports whether addr is one of the owner's addresses on this
// account: the evidence destination must be (CH-20).
//
// Unlike isSelf it matches exactly: a +tag or Gmail-dot variant of the
// owner's address is not the destination (L3 SHOULD 5 on #148).
func (a *Adapter) Owns(addr string) bool {
	c, ok := canon(addr)
	return ok && !a.cfg.Box && (c == a.cfg.Address || a.alias[c])
}

// Address is the owner's main address on this account.
func (a *Adapter) Address() string { return a.cfg.Address }

// selfKey is addr with a +tag removed and, for Gmail's domains, the dots
// in the local part removed: the forms that reach the same mailbox.
func selfKey(addr string) string {
	local, dom, ok := strings.Cut(addr, "@")
	if !ok {
		return addr
	}
	if i := strings.IndexByte(local, '+'); i > 0 {
		local = local[:i]
	}
	if dom == "gmail.com" || dom == "googlemail.com" {
		local = strings.ReplaceAll(local, ".", "")
		dom = "gmail.com"
	}
	return local + "@" + dom
}

func domainOf(addr string) string {
	if i := strings.LastIndexByte(addr, '@'); i >= 0 {
		return strings.ToLower(addr[i+1:])
	}
	return ""
}

// senderIn reports whether addr matches an entry: the address itself, or
// a domain (with or without a leading @) of which addr's domain is the
// domain or a subdomain.
func senderIn(addr string, entries []string) bool {
	addr = strings.ToLower(addr)
	d := domainOf(addr)
	for _, e := range entries {
		e = strings.ToLower(strings.TrimSpace(e))
		if e == "" {
			continue
		}
		if strings.Contains(strings.TrimPrefix(e, "@"), "@") {
			if e == addr {
				return true
			}
			continue
		}
		e = strings.TrimPrefix(e, "@")
		if d == e || strings.HasSuffix(d, "."+e) {
			return true
		}
	}
	return false
}
