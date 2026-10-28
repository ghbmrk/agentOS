// Package imapsmtp is the mail clerk's transport to the owner's mailbox over
// IMAP and SMTP (CLK-2, SPEC "the mail clerk supports any IMAP and SMTP
// provider"). It takes the account's credential from its caller on each
// connection and keeps none (CRED-1), dials only through the home-network
// address policy (DEV-2), and never logs or returns the credential or a
// server's own words. It deals in raw messages and their references; what
// a message means is the clerk's.
//
// It links no IMAP parser (KRN-2, #2937 gap 2). It signs in itself, over a
// small bounded reader of the server's pre-auth lines, then hands the
// signed-in session to a connection process (imapconn) that runs go-imap
// over a socketpair while this side relays the bytes, holding the reply
// budget, the timeout and a filter that lets through only the commands the
// typed request needs. What the connection answers is untrusted and
// checked here. SMTP is the standard library's net/smtp.
package imapsmtp

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/smtp"
	"net/textproto"
	"slices"
	"strings"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"github.com/ghbmrk/agentos/broker/clerk/inbox/imapwire"
	"github.com/ghbmrk/agentos/broker/netguard"
)

// Login is an account credential as the caller hands it over: a password
// (or app password), or an OAuth access token (XOAUTH2).
type Login struct {
	User   string
	Secret string
	OAuth  bool
}

// Security is how a connection is protected.
type Security int

const (
	// TLS is implicit TLS (IMAP 993, SMTP submission 465).
	TLS Security = iota
	// StartTLS upgrades a plain connection before authenticating (SMTP
	// 587); refused if the server does not offer it.
	StartTLS
	// Plain is for the loopback test server only: a credential never
	// crosses a network in the clear, so Plain to any non-loopback
	// address is refused.
	Plain
)

// Config configures a Store.
type Config struct {
	IMAP, SMTP       string // host:port
	IMAPSec, SMTPSec Security
	TLS              *tls.Config // nil: system roots, the host's name
	Credential       func(ctx context.Context) (Login, error)
	From             string        // the envelope sender, the owner's address
	Timeout          time.Duration // per operation (default 60 s)
	MaxFetch         int           // bytes read per message (default 256 KiB)
	// Guard is the home-network address policy every dial goes through
	// (DEV-2). Nil means netguard.New with only the IANA registries.
	Guard *netguard.Policy
	// Conn returns the control connection to a fresh connection process,
	// one per session (imapconn; imapconn.Pipe for tests and the old
	// core). New refuses nil: there is no in-process fallback.
	Conn func(ctx context.Context) (*net.UnixConn, error)
}

// Store is the owner's mailbox over IMAP and SMTP.
type Store struct {
	cfg       Config
	replyBase int64 // see replyBudget; a field so tests can lower it
}

// The mailbox's types are the wire's (imapwire), so the connection
// process answers them without linking this package.
type (
	Role            = imapwire.Role
	Folder          = imapwire.Folder
	Ref             = imapwire.Ref
	Message         = imapwire.Message
	Mark            = imapwire.Mark
	LongHeaderError = imapwire.LongHeaderError
)

// The roles the clerk reads.
const (
	Inbox   = imapwire.Inbox
	Archive = imapwire.Archive
	Drafts  = imapwire.Drafts
	Sent    = imapwire.Sent
	Trash   = imapwire.Trash
	Junk    = imapwire.Junk
	All     = imapwire.All
)

// The connection's reports, as the wire carries them: see imapwire.
var (
	ErrNoMove        = imapwire.ErrNoMove
	ErrValidity      = imapwire.ErrValidity
	ErrNoUIDNext     = imapwire.ErrNoUIDNext
	ErrPartialStatus = imapwire.ErrPartialStatus
	ErrUnanswered    = imapwire.ErrUnanswered
	ErrLongHeader    = imapwire.ErrLongHeader
)

// ErrBadFlag is returned before acting for a flag that is neither a system
// flag nor an RFC 3501 keyword atom. go-imap writes flags into the command
// unquoted, so a space or a line break in one would add flags or commands.
var ErrBadFlag = errors.New("imapsmtp: a flag is not a system flag or a keyword atom")

// systemFlags are the RFC 3501 flags a client may set.
var systemFlags = map[string]bool{`\seen`: true, `\answered`: true, `\flagged`: true, `\deleted`: true, `\draft`: true}

// flagsValid says whether every flag is a system flag or a keyword: one or
// more ATOM-CHARs (printable ASCII but SP, "(", ")", "{", "%", "*", the
// double quote, the backslash and "]").
func flagsValid(flags []string) bool {
	for _, f := range flags {
		if systemFlags[strings.ToLower(f)] {
			continue
		}
		if f == "" {
			return false
		}
		for i := 0; i < len(f); i++ {
			c := f[i]
			if c <= 0x20 || c >= 0x7f || strings.IndexByte(`(){%*"\]`, c) >= 0 {
				return false
			}
		}
	}
	return true
}

// ErrInsecure is returned for a Plain connection to a non-loopback host.
var ErrInsecure = errors.New("imapsmtp: a plain connection is allowed only to loopback")

// New checks cfg.
func New(cfg Config) (*Store, error) {
	if cfg.IMAP == "" || cfg.SMTP == "" || cfg.Credential == nil || cfg.From == "" {
		return nil, errors.New("imapsmtp: Config needs IMAP, SMTP, Credential and From")
	}
	if cfg.Conn == nil {
		return nil, errors.New("imapsmtp: Config needs Conn, the connection process")
	}
	for _, x := range []struct {
		addr string
		sec  Security
	}{{cfg.IMAP, cfg.IMAPSec}, {cfg.SMTP, cfg.SMTPSec}} {
		switch {
		case x.sec != TLS && x.sec != StartTLS && x.sec != Plain:
			return nil, fmt.Errorf("imapsmtp: unknown connection security %d", x.sec)
		case x.sec == Plain && !loopback(x.addr):
			return nil, ErrInsecure
		}
	}
	if cfg.IMAPSec == StartTLS {
		return nil, errors.New("imapsmtp: IMAP uses implicit TLS, or plain to loopback only")
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = 60 * time.Second
	}
	if cfg.MaxFetch == 0 {
		cfg.MaxFetch = 256 << 10
	}
	if cfg.Guard == nil {
		cfg.Guard = netguard.New(netguard.Config{})
	}
	return &Store{cfg: cfg, replyBase: 16 << 20}, nil
}

// Guard is the address policy the store dials through, for the clerk's
// other egress (the one-click POSTer) to share.
func (s *Store) Guard() *netguard.Policy { return s.cfg.Guard }

// dial connects to addr. A Plain connection is a literal loopback address
// (New refused any other), which is the box itself, not the home network;
// it dials without a name lookup. Every other connection goes through the
// address policy, which resolves, checks every answer and checks the
// address connected (DEV-2). A dial that fails, unless the policy refused
// it or the caller stopped it, fails with ErrUnreachable, the timeout
// running out on the dial included: no server answered.
func (s *Store) dial(ctx context.Context, addr string, sec Security) (net.Conn, error) {
	var conn net.Conn
	var err error
	if sec == Plain {
		if !loopback(addr) {
			return nil, ErrInsecure
		}
		conn, err = (&net.Dialer{}).DialContext(ctx, "tcp", addr)
	} else {
		conn, err = s.cfg.Guard.DialContext(ctx, "tcp", addr)
	}
	if err != nil && !errors.Is(err, netguard.ErrDenied) && !errors.Is(err, context.Canceled) {
		err = fmt.Errorf("%w: %v", ErrUnreachable, err)
	}
	return conn, err
}

func loopback(addr string) bool {
	h, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	ip := net.ParseIP(h)
	return ip != nil && ip.IsLoopback()
}

func (s *Store) tlsConfig(addr string) *tls.Config {
	c := &tls.Config{MinVersion: tls.VersionTLS12}
	if s.cfg.TLS != nil {
		c = s.cfg.TLS.Clone()
	}
	if c.ServerName == "" {
		c.ServerName, _, _ = net.SplitHostPort(addr)
	}
	return c
}

// A session may read 16 MiB from the server, plus MaxFetch and
// fetchFrame for each message it fetches (SR3-mail-k18b). go-imap holds a
// whole reply in memory, so without a bound a server that never ends one
// (an endless atom, literal or stream of FETCH responses) grows the
// clerk's memory until the timeout. The 16 MiB covers a session's other
// replies: a folder list, a search's UIDs, and a Find's fetch of the
// few messages carrying one Message-ID.
const fetchFrame = 8 << 10 // a FETCH response's envelope around its body

// ErrReplyTooLarge ends a session whose replies passed their budget: the
// server sent more than the clerk reads, which is not a timeout or a refusal.
var ErrReplyTooLarge = errors.New("imapsmtp: the server's reply exceeded its size bound")

// ErrLoginRefused ends a session or submission whose sign-in the server
// refused. Signing in again with the same login risks the provider locking
// the account, so it waits for the owner to set the account up again.
var ErrLoginRefused = errors.New("imapsmtp: the server refused the login")

// ErrNoSignIn ends a session or submission whose server offers no sign-in
// the clerk supports for the account's login: no XOAUTH2 for a token,
// LOGINDISABLED without AUTH=PLAIN, or no SMTP AUTH with its mechanism.
// Nothing was sent, and signing in again cannot help: the owner must change
// the account's setup.
var ErrNoSignIn = errors.New("imapsmtp: the server offers no sign-in the clerk supports for this login")

// ErrUnreachable ends a session whose dial failed: the mail server was never
// reached, as when the box's own network is down, which is not the server
// stopping or refusing.
var ErrUnreachable = errors.New("imapsmtp: could not reach the mail server")

// ErrTimeout ends a session, or one of its steps, that ran past the timeout:
// the server stopped answering, which is not a refusal or a bad reply.
var ErrTimeout = errors.New("imapsmtp: the mail server stopped answering")

// stand is an error a session's step reached from what the server had
// already sent, which a timeout after it does not replace.
type stand struct{ error }

func (s *Store) replyBudget(fetches int) int64 {
	return s.replyBase + int64(fetches)*int64(s.cfg.MaxFetch+fetchFrame)
}

// budgetConn fails reads once left bytes have been read: a submission's
// replies (an IMAP session's budget is its relay's, relay.go).
type budgetConn struct {
	net.Conn
	left atomic.Int64
	over atomic.Bool // a read found the budget spent
}

func newBudgetConn(c net.Conn, budget int64) *budgetConn {
	b := &budgetConn{Conn: c}
	b.left.Store(budget)
	return b
}

func (b *budgetConn) Read(p []byte) (int, error) {
	left := b.left.Load()
	if left <= 0 {
		b.over.Store(true)
		return 0, ErrReplyTooLarge
	}
	if int64(len(p)) > left {
		p = p[:left]
	}
	n, err := b.Conn.Read(p)
	b.left.Add(-int64(n))
	return n, err
}

// Side is the side of the account a sign-in failed on, as the two are set
// up apart: the IMAP server reads, the SMTP server sends.
type Side string

const (
	Reading Side = "reading mail"
	Sending Side = "sending mail"
)

// SideOf is the side err's sign-in failed on, or "" for an error that is
// not a sign-in's (ErrLoginRefused or ErrNoSignIn).
func SideOf(err error) Side {
	var e sideError
	if errors.As(err, &e) {
		return e.s
	}
	return ""
}

// sideError is e on side s: errors.Is(side(e, s), e) holds.
type sideError struct {
	error
	s Side
}

func (e sideError) Error() string { return e.error.Error() + ", " + string(e.s) }
func (e sideError) Unwrap() error { return e.error }

func side(e error, s Side) error { return sideError{e, s} }

// ended is a session's or submission's error as it ended: an answer the
// server had sent (stand) as it is; otherwise, if it was cut off, why, not
// what the closed connection reports: its read budget spent, its timeout or
// a deadline, or its caller stopping it.
func ended(err error, over, late bool, caller context.Context) error {
	var st stand
	switch {
	case errors.Is(err, ErrConnRefused):
		return ErrConnRefused
	case errors.As(err, &st):
		return st.error
	case err == nil:
		return nil
	case over:
		return ErrReplyTooLarge
	case late:
		return ErrTimeout
	case caller.Err() == context.Canceled:
		return context.Canceled
	}
	return err
}

// signIn is a failed SMTP sign-in's error, standing as ErrLoginRefused
// when the server refused it with a 5xx. Any other failure passes with time
// and is mapped as the submission ended. IMAP's is the pre-auth reader's
// (preauth.go).
func signIn(err error, s Side) error {
	var tp *textproto.Error
	if errors.As(err, &tp) && tp.Code >= 500 {
		return stand{side(ErrLoginRefused, s)}
	}
	return errSignIn
}

var errSignIn = errors.New("imapsmtp: the sign-in did not complete")

// headMax bounds the From and Message-ID headers Seen reads of each message,
// and seenBatch the UIDs one of its batches fetches. Sign-in and the search
// read under replyBase; each batch's window is fixed by them, whatever the
// search found: seenBase for its tagged reply, its second search and the
// server's notices, plus headMax and fetchFrame for each UID. Two adjacent
// windows stay under one Fetch call's budget (M21,
// tests/test_egress_memory.py).
const (
	headMax   = 8 << 10
	seenBatch = 400
	seenBase  = 64 << 10
)

// subjectMax bounds the Subject a LongHeaderError reads.
const subjectMax = 1 << 10

// Folders lists the account's folders with their special-use roles.
func (s *Store) Folders(ctx context.Context) ([]Folder, error) {
	var out []Folder
	err := s.session(ctx, func(x *session) error {
		r, err := x.do(imapwire.Request{Op: imapwire.OpFolders}, s.replyBudget(0), read)
		if err != nil {
			return err
		}
		for _, f := range r.Folders {
			if f.Name == "" || !f.Role.Known() {
				return errLied
			}
		}
		out = r.Folders
		return nil
	})
	return out, err
}

// UIDs lists every message in folder.
func (s *Store) UIDs(ctx context.Context, folder string) (uint32, []uint32, error) {
	var validity uint32
	var uids []uint32
	err := s.session(ctx, func(x *session) error {
		r, err := x.do(imapwire.Request{Op: imapwire.OpUIDs, Folder: folder}, s.replyBudget(0), read)
		validity, uids = r.Validity, r.UIDs
		return err
	})
	return validity, uids, err
}

// Fetch reads messages with BODY.PEEK, so none is marked read, only
// while folder still has the UID validity the UIDs were listed under.
func (s *Store) Fetch(ctx context.Context, folder string, validity uint32, uids []uint32) ([]Message, error) {
	if len(uids) == 0 {
		return nil, nil
	}
	var out []Message
	err := s.session(ctx, func(x *session) error {
		r, err := x.do(imapwire.Request{Op: imapwire.OpFetch, Folder: folder, Validity: validity, UIDs: uids, MaxFetch: s.cfg.MaxFetch},
			s.replyBudget(len(uids)), read)
		if err != nil {
			return err
		}
		out, err = s.checked(r.Messages, folder, validity, set(uids), 0)
		return err
	})
	return out, err
}

// errLied is an answer from the connection process outside what its request
// allows: a message from another folder or validity, a UID not asked for,
// more than asked, or a field past its bound. The connection is untrusted
// (KRN-2), so its answer fails closed.
var errLied = errors.New("imapsmtp: the connection process answered outside its request")

func set(uids []uint32) map[uint32]bool {
	m := make(map[uint32]bool, len(uids))
	for _, u := range uids {
		m[u] = true
	}
	return m
}

// checked is ms if every message is in folder under validity, names a UID
// in want (when want is nil, one at least from), at most once, holds at
// most MaxFetch bytes and carries only flags as a server writes them; else
// errLied.
func (s *Store) checked(ms []Message, folder string, validity uint32, want map[uint32]bool, from uint32) ([]Message, error) {
	seen := map[uint32]bool{}
	for _, m := range ms {
		if m.Folder != folder || m.Validity != validity || seen[m.UID] || len(m.Raw) > s.cfg.MaxFetch ||
			want != nil && !want[m.UID] || want == nil && m.UID < from || !flagsRead(m.Flags) {
			return nil, errLied
		}
		seen[m.UID] = true
	}
	return ms, nil
}

// flagsRead says whether every flag is one a server can send: a keyword
// atom, or a backslash and one (\Seen, \Recent and the rest).
func flagsRead(flags []string) bool {
	for _, f := range flags {
		if !flagsValid([]string{strings.TrimPrefix(f, `\`)}) {
			return false
		}
	}
	return true
}

// Seen hands each the From and Message-ID headers of every message in folder
// that carries \Seen, read with BODY.PEEK[HEADER.FIELDS (FROM MESSAGE-ID)] so
// nothing is marked read, and its INTERNALDATE: the time the server took the
// mail in, which the sender does not set and COPY and MOVE keep (RFC 3501
// 6.4.7, RFC 6851), zero if the server sent none. It keeps none of them.
// The UIDs are searched and then fetched seenBatch at a time in one session,
// signed in once, each batch one typed request under a fresh read budget and
// timeout that only this side renews. Each searched message must answer with
// its headers, at most headMax bytes; one that did not answer is searched
// for again, and only one the owner deleted or marked unread since is let
// go. Anything else, or an error from each, fails the call, so no partial
// answer passes for a full one; a header too long names its folder and
// arrival, so the owner can find the mail.
func (s *Store) Seen(ctx context.Context, folder string, each func(header []byte, arrived time.Time) error) error {
	return s.session(ctx, func(x *session) error {
		r, err := x.do(imapwire.Request{Op: imapwire.OpSeenSearch, Folder: folder}, s.replyBudget(0), read)
		if err != nil {
			return err
		}
		uids := r.UIDs
		for i := 0; i < len(uids); i += seenBatch {
			batch := uids[i:min(i+seenBatch, len(uids))]
			want := set(batch)
			r, err := x.do(imapwire.Request{Op: imapwire.OpSeenBatch, Folder: folder, UIDs: batch},
				seenBase+seenBatch*(headMax+fetchFrame), read)
			if err != nil && r.Err == "" {
				return err
			}
			// As the server answered: each header in turn, then why the
			// batch ended. A fetch that failed stands over the caller's
			// error and a long header, as it did in one session.
			var bad error
			for _, h := range r.Heads {
				if !want[h.UID] || len(h.Header) > headMax {
					return errLied
				}
				delete(want, h.UID)
				if bad == nil {
					bad = each(h.Header, h.Arrived)
				}
			}
			switch {
			case r.Err != "" && r.Err != codeLong && r.Err != codeUnanswered:
				return err
			case bad != nil:
				return stand{bad}
			case r.Err == codeLong:
				return x.longHeader(folder, r.Long, want)
			case err != nil:
				return err
			}
		}
		return nil
	})
}

// longHeader is the LongHeaderError a batch of folder ended on, named by
// its Subject, or errLied for a mail the batch did not ask for or still
// owes. The subject read shares the batch's window: one that times out or
// fails leaves it empty, and the error stands.
func (x *session) longHeader(folder string, l *imapwire.LongHeaderError, want map[uint32]bool) error {
	if l == nil || !want[l.UID] {
		return errLied
	}
	lh := &LongHeaderError{Folder: folder, Arrived: l.Arrived, UID: l.UID}
	if q, err := x.do(imapwire.Request{Op: imapwire.OpSubject, Folder: folder, UIDs: []uint32{lh.UID}}, 0, read); err == nil {
		lh.Subject = subjectOf(q.Subject)
	}
	return stand{lh}
}

// subjectOf is a Subject the connection answered, as the owner may see it:
// at most subjectMax bytes and its cut mark, on one plain line; else empty.
func subjectOf(v string) string {
	if len(v) > subjectMax+len("…") || !utf8.ValidString(v) {
		return ""
	}
	for _, r := range v {
		if r < 0x20 || r == 0x7f || r >= 0x80 && r < 0xa0 || r >= 0x2066 && r <= 0x2069 || r >= 0x202a && r <= 0x202e ||
			r == 0x200e || r == 0x200f || r == 0x061c {
			return ""
		}
	}
	return v
}

// Next is folder's UID validity and the UID its next message will take, so
// a later FindSince can look at only what arrived since.
func (s *Store) Next(ctx context.Context, folder string) (validity, next uint32, err error) {
	err = s.session(ctx, func(x *session) error {
		r, err := x.do(imapwire.Request{Op: imapwire.OpNext, Folder: folder}, s.replyBudget(0), read)
		if err != nil {
			return err
		}
		if validity, next = r.Validity, r.Next; validity == 0 || next == 0 {
			return stand{ErrNoUIDNext}
		}
		return nil
	})
	return validity, next, err
}

// Find returns the messages in folder whose Message-ID header holds id and
// that match accepts. Servers match a header search by substring, so match
// checks the whole value.
func (s *Store) Find(ctx context.Context, folder, id string, match func(Message) bool) ([]Message, error) {
	return s.find(ctx, folder, 0, 0, id, match)
}

// FindSince is Find over only the messages that arrived in folder from UID
// from on, under validity (ErrValidity otherwise), both as Next gave them.
func (s *Store) FindSince(ctx context.Context, folder string, validity, from uint32, id string, match func(Message) bool) ([]Message, error) {
	if validity == 0 || from == 0 {
		return nil, ErrNoUIDNext
	}
	return s.find(ctx, folder, validity, from, id, match)
}

// find is Find, from UID from on under validity unless validity is 0. The
// connection returns the candidates; match runs here, on this side. An id
// holding a CR or LF (a Message-ID folded before a comment) matches
// nothing: the filter refuses one in a literal, which would read as a
// compromised connection (#3018's UX delta).
func (s *Store) find(ctx context.Context, folder string, validity, from uint32, id string, match func(Message) bool) ([]Message, error) {
	if strings.ContainsAny(id, "\r\n") {
		return nil, nil
	}
	var out []Message
	err := s.session(ctx, func(x *session) error {
		r, err := x.do(imapwire.Request{Op: imapwire.OpFind, Folder: folder, Validity: validity, From: from, ID: id, MaxFetch: s.cfg.MaxFetch},
			s.replyBudget(0), read)
		if err == nil && (validity != 0 && r.Validity != validity || r.Validity == 0 && len(r.Messages) > 0) {
			err = errLied
		}
		if err != nil {
			return err
		}
		ms, err := s.checked(r.Messages, folder, r.Validity, nil, from)
		for _, m := range ms {
			if match(m) {
				out = append(out, m)
			}
		}
		return err
	})
	return out, err
}

// SetFlags adds and removes flags on one message, only while its folder
// has the UID validity m was read under. The filter lets through only the
// UID STORE of these flags on this UID in m's folder.
func (s *Store) SetFlags(ctx context.Context, m Ref, add, remove []string) error {
	if !flagsValid(add) || !flagsValid(remove) {
		return ErrBadFlag
	}
	return s.session(ctx, func(x *session) error {
		_, err := x.do(imapwire.Request{Op: imapwire.OpSetFlags, Folder: m.Folder, Validity: m.Validity, UIDs: []uint32{m.UID}, Add: add, Remove: remove},
			s.replyBudget(0), allowance{store: m.UID, add: add, remove: remove, folder: selectArg(m.Folder), validity: m.Validity})
		return err
	})
}

// Move moves one message. Servers without MOVE are refused rather than
// emulated with COPY, flag and EXPUNGE: an EXPUNGE would also remove
// anything else the owner had marked deleted in that folder. Like
// SetFlags it acts only under the UID validity m was read under, and the
// filter lets through only a UID MOVE of this UID in m's folder to to.
func (s *Store) Move(ctx context.Context, m Ref, to string) error {
	return s.session(ctx, func(x *session) error {
		_, err := x.do(imapwire.Request{Op: imapwire.OpMove, Folder: m.Folder, Validity: m.Validity, UIDs: []uint32{m.UID}, To: to},
			s.replyBudget(0), allowance{move: m.UID, folder: selectArg(m.Folder), to: mailboxArg(to), validity: m.Validity})
		return err
	})
}

// Marks is the Mark of each selectable folder, sorted by name, listed and
// read in one session; on any error it is nil, never a partial list.
func (s *Store) Marks(ctx context.Context) ([]Mark, error) {
	var out []Mark
	err := s.session(ctx, func(x *session) error {
		r, err := x.do(imapwire.Request{Op: imapwire.OpMarks}, s.replyBudget(0), read)
		if err != nil {
			return err
		}
		for i, m := range r.Marks {
			if i > 0 && r.Marks[i-1].Folder >= m.Folder {
				return errLied
			}
		}
		out = r.Marks
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// Ensure creates folder if it does not exist. Only the old core calls it.
func (s *Store) Ensure(ctx context.Context, folder string) error {
	return s.session(ctx, func(x *session) error {
		_, err := x.do(imapwire.Request{Op: imapwire.OpEnsure, Folder: folder}, s.replyBudget(0), allowance{create: true})
		return err
	})
}

// Append stores raw in folder. Only the old core calls it.
func (s *Store) Append(ctx context.Context, folder string, flags []string, date time.Time, raw []byte) error {
	if !flagsValid(flags) {
		return ErrBadFlag
	}
	return s.session(ctx, func(x *session) error {
		_, err := x.do(imapwire.Request{Op: imapwire.OpAppend, Folder: folder, Flags: flags, Date: date, Raw: raw}, s.replyBudget(0), allowance{append: true})
		return err
	})
}

// An SMTP session may read 1 MiB from the server (SR3-mail-k18d-smtp).
// net/smtp reads each reply through textproto, which bounds neither a
// line nor the continuation lines of one reply, so without a budget a
// server that never ends a reply grows the clerk's memory until the
// timeout. A submission's replies and its TLS handshake, implicit or
// STARTTLS, are read through the same budget and take a few kilobytes.
const smtpReplyBudget = 1 << 20

// Submit sends raw over SMTP submission from the configured address.
// A submission cut off fails with why, as a session does (sessionR).
func (s *Store) Submit(ctx context.Context, rcpt []string, raw []byte) (err error) {
	caller := ctx
	var late atomic.Bool
	var bc *budgetConn
	defer func() { err = ended(err, bc != nil && bc.over.Load(), late.Load(), caller) }()
	ctx, cancel := context.WithTimeout(ctx, s.cfg.Timeout)
	defer cancel()
	conn, err := s.dial(ctx, s.cfg.SMTP, s.cfg.SMTPSec)
	if err != nil {
		late.Store(caller.Err() == context.DeadlineExceeded)
		return err
	}
	bc = newBudgetConn(conn, smtpReplyBudget)
	// The timeout closes the connection, marked late first, so what the
	// closed connection reports is never mistaken for the server's answer.
	tcp := conn
	stop := context.AfterFunc(ctx, func() {
		if ctx.Err() == context.DeadlineExceeded {
			late.Store(true)
		}
		tcp.Close()
	})
	defer stop()
	// The budget sits under TLS, so in implicit-TLS mode net/smtp still
	// sees a *tls.Conn and lets PLAIN and XOAUTH2 authenticate; it then
	// counts ciphertext, which is just as bounded.
	conn = bc
	switch s.cfg.SMTPSec {
	case TLS:
		conn = tls.Client(conn, s.tlsConfig(s.cfg.SMTP))
	case StartTLS, Plain:
	default:
		conn.Close()
		return errors.New("imapsmtp: unknown connection security")
	}
	host, _, _ := net.SplitHostPort(s.cfg.SMTP)
	c, err := smtp.NewClient(conn, host)
	if err != nil {
		conn.Close()
		return err
	}
	defer c.Close()
	if err := c.Hello("localhost"); err != nil {
		return err
	}
	if s.cfg.SMTPSec == StartTLS {
		if ok, _ := c.Extension("STARTTLS"); !ok {
			return errors.New("imapsmtp: the SMTP server does not offer STARTTLS")
		}
		if err := c.StartTLS(s.tlsConfig(s.cfg.SMTP)); err != nil {
			return err
		}
	}
	l, err := s.cfg.Credential(ctx)
	if err != nil {
		return errors.New("imapsmtp: no credential")
	}
	var auth smtp.Auth = smtp.PlainAuth("", l.User, l.Secret, host)
	mech := "PLAIN"
	if l.OAuth {
		auth, mech = smtpXOAuth2{xoauth2{l.User, l.Secret}}, "XOAUTH2"
	}
	if ok, mechs := c.Extension("AUTH"); !ok || !slices.Contains(strings.Fields(strings.ToUpper(mechs)), mech) {
		// Extension says false too when the EHLO failed: Noop returns that
		// failure, or the server's answer once it is there.
		if err := c.Noop(); err != nil {
			return err
		}
		return stand{side(ErrNoSignIn, Sending)}
	}
	if err := c.Auth(auth); err != nil {
		return signIn(err, Sending)
	}
	if err := c.Mail(s.cfg.From); err != nil {
		return err
	}
	for _, r := range rcpt {
		if err := c.Rcpt(r); err != nil {
			return fmt.Errorf("imapsmtp: a recipient was refused")
		}
	}
	w, err := c.Data()
	if err != nil {
		return err
	}
	if _, err := w.Write(raw); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	// The server took the mail at its answer to the data's end (RFC 5321
	// 4.1.1.4): a QUIT that fails after it is not a failed send, which a
	// caller would retry and so send twice.
	c.Quit()
	return nil
}

// xoauth2 is the XOAUTH2 initial response, for IMAP (preauth.go) and, as
// smtpXOAuth2, for SMTP (smtp.Auth).
type xoauth2 struct{ user, token string }

func (x xoauth2) ir() []byte {
	return []byte("user=" + x.user + "\x01auth=Bearer " + x.token + "\x01\x01")
}

type smtpXOAuth2 struct{ xoauth2 }

var _ smtp.Auth = smtpXOAuth2{}

// Start refuses to send the token without TLS except to loopback, as
// smtp.PlainAuth does for a password.
func (x smtpXOAuth2) Start(server *smtp.ServerInfo) (string, []byte, error) {
	if !server.TLS && !loopback(net.JoinHostPort(server.Name, "0")) {
		return "", nil, errors.New("imapsmtp: unencrypted connection")
	}
	return "XOAUTH2", x.ir(), nil
}

// Next answers an error challenge as xoauth2.Next does, so the server ends
// the exchange with its 5xx.
func (x smtpXOAuth2) Next(_ []byte, more bool) ([]byte, error) {
	if more {
		return []byte{}, nil
	}
	return nil, nil
}
