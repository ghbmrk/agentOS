// Package imapsmtp is the mail clerk's transport to the owner's mailbox over
// IMAP and SMTP (CLK-2, SPEC "the mail clerk supports any IMAP and SMTP
// provider"). It takes the account's credential from its caller on each
// connection and keeps none (CRED-1), dials only through the home-network
// address policy (DEV-2), and never logs or returns the credential or a
// server's own words. It deals in raw messages and their references; what
// a message means is the clerk's.
//
// It reuses github.com/emersion/go-imap (v1, MIT) as the IMAP client; SMTP
// is the standard library's net/smtp.
package imapsmtp

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/smtp"
	"slices"
	"strings"
	"sync/atomic"
	"time"
	"unicode"

	"github.com/emersion/go-imap"
	"github.com/emersion/go-imap/client"
	"github.com/emersion/go-imap/commands"
	"github.com/emersion/go-sasl"

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
}

// Store is the owner's mailbox over IMAP and SMTP.
type Store struct {
	cfg       Config
	replyBase int64 // see replyBudget; a field so tests can lower it
}

// Role is a folder's special use (RFC 6154), or "" for none.
type Role string

// The roles the clerk reads.
const (
	Inbox   Role = "inbox"
	Archive Role = "archive"
	Drafts  Role = "drafts"
	Sent    Role = "sent"
	Trash   Role = "trash"
	Junk    Role = "junk"
	All     Role = "all"
)

// Folder is one selectable folder.
type Folder struct {
	Name string
	Role Role
}

// Ref names one message by its full identity: its folder, the folder's UID
// validity when the UID was read, and the UID. Under another validity the
// same UID may be another message, so every change is checked against it.
type Ref struct {
	Folder   string
	Validity uint32
	UID      uint32
}

// Message is one message as the server holds it: its reference, its flags
// and its first MaxFetch bytes, read without marking it read.
type Message struct {
	Ref
	Flags []string
	Raw   []byte
}

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

// ErrNoMove is returned before acting by a server without MOVE.
var ErrNoMove = errors.New("imapsmtp: the server does not support MOVE")

// ErrValidity is returned before acting when a folder's UID validity is
// not the one a reference was read under.
var ErrValidity = errors.New("imapsmtp: the folder was renumbered since it was read")

// ErrInsecure is returned for a Plain connection to a non-loopback host.
var ErrInsecure = errors.New("imapsmtp: a plain connection is allowed only to loopback")

// New checks cfg.
func New(cfg Config) (*Store, error) {
	if cfg.IMAP == "" || cfg.SMTP == "" || cfg.Credential == nil || cfg.From == "" {
		return nil, errors.New("imapsmtp: Config needs IMAP, SMTP, Credential and From")
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

// session runs f on an authenticated IMAP connection.
func (s *Store) session(ctx context.Context, f func(c *client.Client) error) error {
	return s.sessionN(ctx, 0, f)
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

// budgetConn fails reads once left bytes have been read. left is atomic
// because the client's reader reads while renew, between a session's steps,
// sets it again.
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

// sessionN is session for a call that fetches up to n messages.
func (s *Store) sessionN(ctx context.Context, n int, f func(c *client.Client) error) error {
	return s.sessionB(ctx, s.replyBudget(n), f)
}

// sessionB is session with a reply budget of budget bytes.
func (s *Store) sessionB(ctx context.Context, budget int64, f func(c *client.Client) error) error {
	ctx, cancel := context.WithTimeout(ctx, s.cfg.Timeout)
	defer cancel()
	return s.sessionR(ctx, budget, func(c *client.Client, _ func(int64)) error { return f(c) })
}

// sessionR is sessionB for a session of steps, signed in once: renew(n),
// called before a step, gives it a fresh reply budget of n bytes and a fresh
// timeout. The client's reader reads ahead, so one reply can be charged to
// two adjacent windows, never more: what a step holds is bounded by its own
// window and the one before.
func (s *Store) sessionR(ctx context.Context, budget int64, f func(c *client.Client, renew func(n int64)) error) (err error) {
	// A session cut off fails with why, ErrReplyTooLarge or ErrTimeout, not
	// with what the closed connection reports; an error f reached from what
	// the server had already sent (stand) is kept, whenever the cut-off came.
	var late atomic.Bool
	var bc *budgetConn
	defer func() {
		var st stand
		switch {
		case errors.As(err, &st):
			err = st.error
		case err == nil:
		case bc != nil && bc.over.Load():
			err = ErrReplyTooLarge
		case late.Load():
			err = ErrTimeout
		}
	}()
	if err := ctx.Err(); err != nil {
		late.Store(err == context.DeadlineExceeded)
		return err
	}
	dctx, cancel := context.WithTimeout(ctx, s.cfg.Timeout)
	defer cancel()
	conn, err := s.dial(dctx, s.cfg.IMAP, s.cfg.IMAPSec)
	if err != nil {
		return err
	}
	// go-imap clears the connection's deadline at each command, so a timer
	// closes the connection instead: at the dial's deadline for the greeting,
	// handshake and sign-in, then once a step has run for the timeout, as
	// renew restarts it. Every cut-off goes through it and so marks the
	// session late.
	dl, _ := dctx.Deadline()
	raw := conn
	step := time.AfterFunc(time.Until(dl), func() { late.Store(true); raw.Close() })
	defer step.Stop()
	switch s.cfg.IMAPSec {
	case TLS:
		conn = tls.Client(conn, s.tlsConfig(s.cfg.IMAP))
	case Plain:
	default:
		conn.Close()
		return errors.New("imapsmtp: IMAP uses implicit TLS, or plain to loopback only")
	}
	// The connection is closed however the session ends: Logout does not
	// close it once the client's reader has stopped on a bad reply.
	defer conn.Close()
	bc = newBudgetConn(conn, budget)
	c, err := client.New(bc)
	if err != nil {
		return err
	}
	c.ErrorLog = quiet{}
	defer c.Logout()
	stop := context.AfterFunc(ctx, func() {
		if ctx.Err() == context.DeadlineExceeded {
			late.Store(true)
		}
		conn.Close()
	})
	defer stop()
	l, err := s.cfg.Credential(dctx)
	if err != nil {
		return errors.New("imapsmtp: no credential")
	}
	if l.OAuth {
		err = c.Authenticate(xoauth2{l.User, l.Secret})
	} else {
		err = c.Login(l.User, l.Secret)
	}
	if err != nil {
		return errors.New("imapsmtp: the server refused the login")
	}
	return f(c, func(n int64) { bc.left.Store(n); step.Reset(s.cfg.Timeout) })
}

type quiet struct{}

func (quiet) Printf(string, ...interface{}) {}
func (quiet) Println(...interface{})        {}

// Folders lists the account's folders with their special-use roles.
func (s *Store) Folders(ctx context.Context) ([]Folder, error) {
	var out []Folder
	err := s.session(ctx, func(c *client.Client) error {
		ch := make(chan *imap.MailboxInfo, 32)
		done := make(chan error, 1)
		go func() { done <- c.List("", "*", ch) }()
		for m := range ch {
			if has(m.Attributes, imap.NoSelectAttr) {
				continue
			}
			out = append(out, Folder{Name: m.Name, Role: role(m)})
		}
		return <-done
	})
	return out, err
}

func role(m *imap.MailboxInfo) Role {
	if strings.EqualFold(m.Name, "INBOX") {
		return Inbox
	}
	for a, r := range map[string]Role{imap.ArchiveAttr: Archive, imap.DraftsAttr: Drafts,
		imap.SentAttr: Sent, imap.TrashAttr: Trash, imap.JunkAttr: Junk, imap.AllAttr: All} {
		if has(m.Attributes, a) {
			return r
		}
	}
	return ""
}

func has(l []string, s string) bool {
	for _, x := range l {
		if strings.EqualFold(x, s) {
			return true
		}
	}
	return false
}

// UIDs lists every message in folder.
func (s *Store) UIDs(ctx context.Context, folder string) (uint32, []uint32, error) {
	var validity uint32
	var uids []uint32
	err := s.session(ctx, func(c *client.Client) error {
		st, err := c.Select(folder, true)
		if err != nil {
			return err
		}
		validity = st.UidValidity
		if st.Messages == 0 {
			return nil
		}
		uids, err = c.UidSearch(imap.NewSearchCriteria())
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
	err := s.sessionN(ctx, len(uids), func(c *client.Client) error {
		if err := selectAt(c, folder, true, validity); err != nil {
			return err
		}
		var err error
		out, err = s.fetch(c, folder, validity, uids)
		return err
	})
	return out, err
}

// selectAt selects folder and refuses (ErrValidity) unless its UID
// validity is the expected one: under another validity the UIDs the
// caller holds may name other messages. The check and what follows run
// in this one selected session.
func selectAt(c *client.Client, folder string, readOnly bool, validity uint32) error {
	st, err := c.Select(folder, readOnly)
	if err != nil {
		return err
	}
	if validity == 0 || st.UidValidity != validity {
		return ErrValidity
	}
	return nil
}

func (s *Store) fetch(c *client.Client, folder string, validity uint32, uids []uint32) ([]Message, error) {
	set := new(imap.SeqSet)
	set.AddNum(uids...)
	sec := &imap.BodySectionName{Peek: true, Partial: []int{0, s.cfg.MaxFetch}}
	items := []imap.FetchItem{imap.FetchUid, imap.FetchFlags, sec.FetchItem()}
	ch := make(chan *imap.Message, 16)
	done := make(chan error, 1)
	go func() { done <- c.UidFetch(set, items, ch) }()
	// Only the first response with a body for each requested UID is kept,
	// so a server that repeats or invents messages cannot grow out, and an
	// unsolicited FLAGS-only response does not take the slot (SR3-mail-k18b).
	want := make(map[uint32]bool, len(uids))
	for _, u := range uids {
		want[u] = true
	}
	var out []Message
	for m := range ch {
		if !want[m.Uid] || len(m.Body) == 0 {
			continue
		}
		delete(want, m.Uid)
		var raw []byte
		for _, l := range m.Body {
			if l != nil {
				raw, _ = io.ReadAll(l)
				break
			}
		}
		out = append(out, Message{Ref: Ref{Folder: folder, Validity: validity, UID: m.Uid},
			Flags: append([]string(nil), m.Flags...), Raw: raw})
	}
	return out, <-done
}

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

// ErrUnanswered is a FETCH that left a searched message, still there and
// still read, without its header, and ErrLongHeader headers longer than
// headMax: either would leave a mail out of what Seen found.
var (
	ErrUnanswered = errors.New("imapsmtp: the server did not answer for every message")
	ErrLongHeader = errors.New("imapsmtp: a mail's headers are too long to read")
)

// LongHeaderError is ErrLongHeader for one mail, named so the owner can find
// it: its folder, its INTERNALDATE (zero if the server sent none) and its
// Subject, read on its own under subjectMax bytes, since its other headers
// are what was too long. Error names the folder, arrival and UID, never the
// subject: that is the mail's content, for the owner's eyes, not a log.
type LongHeaderError struct {
	Folder  string
	Arrived time.Time
	UID     uint32
	Subject string
}

func (e *LongHeaderError) Error() string {
	at := "at an unknown time"
	if !e.Arrived.IsZero() {
		at = e.Arrived.Format("2006-01-02 15:04 -0700")
	}
	return fmt.Sprintf("%v: the mail in %s that arrived %s (UID %d)", ErrLongHeader, e.Folder, at, e.UID)
}

func (e *LongHeaderError) Unwrap() error { return ErrLongHeader }

// subjectMax bounds the Subject a LongHeaderError reads.
const subjectMax = 1 << 10

// Seen hands each the From and Message-ID headers of every message in folder
// that carries \Seen, read with BODY.PEEK[HEADER.FIELDS (FROM MESSAGE-ID)] so
// nothing is marked read, and its INTERNALDATE: the time the server took the
// mail in, which the sender does not set and COPY and MOVE keep (RFC 3501
// 6.4.7, RFC 6851), zero if the server sent none. It keeps none of them.
// The UIDs are searched and then fetched seenBatch at a time in one session,
// signed in once, each batch under a fresh read budget and timeout. Each
// searched message must answer with its headers, at most headMax bytes; one
// that did not answer is searched for again, and only one the owner deleted
// or marked unread since is let go. Anything else, or an error from each,
// fails the call, so no partial answer passes for a full one; a header too
// long names its folder and arrival, so the owner can find the mail.
func (s *Store) Seen(ctx context.Context, folder string, each func(header []byte, arrived time.Time) error) error {
	sec := &imap.BodySectionName{Peek: true, Partial: []int{0, headMax + 1},
		BodyPartName: imap.BodyPartName{Specifier: imap.HeaderSpecifier, Fields: []string{"From", "Message-Id"}}}
	items := []imap.FetchItem{imap.FetchUid, imap.FetchInternalDate, sec.FetchItem()}
	return s.sessionR(ctx, s.replyBase, func(c *client.Client, renew func(int64)) error {
		st, err := c.Select(folder, true)
		if err != nil || st.Messages == 0 {
			return err
		}
		uids, err := readUIDs(c, nil)
		if err != nil {
			return err
		}
		for i := 0; i < len(uids); i += seenBatch {
			renew(seenBase + seenBatch*(headMax+fetchFrame))
			batch := uids[i:min(i+seenBatch, len(uids))]
			want := make(map[uint32]bool, len(batch))
			for _, u := range batch {
				want[u] = true
			}
			set := new(imap.SeqSet)
			set.AddNum(batch...)
			ch := make(chan *imap.Message, 16)
			done := make(chan error, 1)
			go func() { done <- c.UidFetch(set, items, ch) }()
			// As in fetch: one header per requested UID, so a server that
			// repeats or invents messages adds nothing.
			var bad error
			for m := range ch {
				if bad != nil || !want[m.Uid] {
					continue
				}
				for _, l := range m.Body {
					if l == nil {
						continue
					}
					delete(want, m.Uid)
					h, _ := io.ReadAll(io.LimitReader(l, headMax+1))
					if len(h) > headMax {
						bad = &LongHeaderError{Folder: folder, Arrived: m.InternalDate, UID: m.Uid}
					} else {
						bad = each(h, m.InternalDate)
					}
					break
				}
			}
			if err := <-done; err != nil {
				return err
			}
			if lh, ok := bad.(*LongHeaderError); ok {
				lh.Subject = subject(c, lh.UID)
			}
			if bad != nil {
				return stand{bad}
			}
			if len(want) > 0 {
				left, err := readUIDs(c, want)
				if err != nil {
					return err
				}
				if len(left) > 0 {
					return stand{ErrUnanswered}
				}
			}
		}
		return nil
	})
}

// subject is mail uid's Subject header, unfolded and decoded, read with
// BODY.PEEK under subjectMax bytes; one cut there ends in "…". A failed read
// leaves it empty: the error it names stands without it.
func subject(c *client.Client, uid uint32) string {
	sec := &imap.BodySectionName{Peek: true, Partial: []int{0, subjectMax + 1},
		BodyPartName: imap.BodyPartName{Specifier: imap.HeaderSpecifier, Fields: []string{"Subject"}}}
	set := new(imap.SeqSet)
	set.AddNum(uid)
	ch := make(chan *imap.Message, 4)
	done := make(chan error, 1)
	go func() { done <- c.UidFetch(set, []imap.FetchItem{imap.FetchUid, sec.FetchItem()}, ch) }()
	// The client passes on only answers for uid; the first stands.
	var h []byte
	for m := range ch {
		for _, l := range m.Body {
			if l != nil && h == nil {
				h, _ = io.ReadAll(io.LimitReader(l, subjectMax+1))
			}
		}
	}
	if <-done != nil {
		return ""
	}
	cut := len(h) > subjectMax
	v := string(h[:min(len(h), subjectMax)])
	if name, rest, ok := strings.Cut(v, ":"); !ok || !strings.EqualFold(strings.TrimSpace(name), "Subject") {
		return ""
	} else {
		v = rest
	}
	// A cut inside an encoded word leaves it undecodable: it goes, rather
	// than show the owner its raw form. Q and B text carry no "?=".
	if i := strings.LastIndex(v, "=?"); cut && i >= 0 && !strings.Contains(v[i+2:], "?=") {
		v = v[:i]
	}
	if d, err := new(mime.WordDecoder).DecodeHeader(v); err == nil {
		v = d
	}
	// A cut can split a character; and the sender wrote this, so no control
	// or bidi character it carries can break or reorder the owner's line.
	v = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || unicode.Is(unicode.Bidi_Control, r) {
			return ' '
		}
		return r
	}, strings.ToValidUTF8(v, ""))
	v = strings.Join(strings.Fields(v), " ")
	if cut {
		v += "…"
	}
	return v
}

// readUIDs searches the selected folder for its read mail: all of it, or,
// given only, those of its UIDs still there and still read.
func readUIDs(c *client.Client, only map[uint32]bool) ([]uint32, error) {
	crit := imap.NewSearchCriteria()
	crit.WithFlags = []string{imap.SeenFlag}
	if only != nil {
		crit.Uid = new(imap.SeqSet)
		for u := range only {
			crit.Uid.AddNum(u)
		}
	}
	uids, err := c.UidSearch(crit)
	if only == nil || err != nil {
		return uids, err
	}
	return slices.DeleteFunc(uids, func(u uint32) bool { return !only[u] }), nil
}

// Find returns the messages in folder whose Message-ID header holds id and
// that match accepts. Servers match a header search by substring, so match
// checks the whole value.
func (s *Store) Find(ctx context.Context, folder, id string, match func(Message) bool) ([]Message, error) {
	var out []Message
	err := s.session(ctx, func(c *client.Client) error {
		st, err := c.Select(folder, true)
		if err != nil {
			return err
		}
		crit := imap.NewSearchCriteria()
		crit.Header.Add("Message-Id", id)
		uids, err := c.UidSearch(crit)
		if err != nil || len(uids) == 0 {
			return err
		}
		ms, err := s.fetch(c, folder, st.UidValidity, uids)
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
// has the UID validity m was read under.
func (s *Store) SetFlags(ctx context.Context, m Ref, add, remove []string) error {
	if !flagsValid(add) || !flagsValid(remove) {
		return ErrBadFlag
	}
	return s.session(ctx, func(c *client.Client) error {
		if err := selectAt(c, m.Folder, false, m.Validity); err != nil {
			return err
		}
		set := new(imap.SeqSet)
		set.AddNum(m.UID)
		for _, x := range []struct {
			op    imap.FlagsOp
			flags []string
		}{{imap.AddFlags, add}, {imap.RemoveFlags, remove}} {
			if len(x.flags) == 0 {
				continue
			}
			v := make([]interface{}, len(x.flags))
			for i, f := range x.flags {
				v[i] = f
			}
			if err := c.UidStore(set, imap.FormatFlagsOp(x.op, true), v, nil); err != nil {
				return err
			}
		}
		return nil
	})
}

// Move moves one message. Servers without MOVE are refused rather than
// emulated with COPY, flag and EXPUNGE: an EXPUNGE would also remove
// anything else the owner had marked deleted in that folder. Like
// SetFlags it acts only under the UID validity m was read under.
func (s *Store) Move(ctx context.Context, m Ref, to string) error {
	return s.session(ctx, func(c *client.Client) error {
		if ok, _ := c.Support("MOVE"); !ok {
			return ErrNoMove
		}
		if err := selectAt(c, m.Folder, false, m.Validity); err != nil {
			return err
		}
		set := new(imap.SeqSet)
		set.AddNum(m.UID)
		// UID MOVE itself, never go-imap's COPY, STORE and EXPUNGE
		// fallback.
		st, err := c.Execute(&commands.Uid{Cmd: &commands.Move{SeqSet: set, Mailbox: to}}, nil)
		if err != nil {
			return err
		}
		return st.Err()
	})
}

// Ensure creates folder if it does not exist.
func (s *Store) Ensure(ctx context.Context, folder string) error {
	return s.session(ctx, func(c *client.Client) error {
		ch := make(chan *imap.MailboxInfo, 4)
		done := make(chan error, 1)
		go func() { done <- c.List("", folder, ch) }()
		found := false
		for m := range ch {
			found = found || m.Name == folder
		}
		if err := <-done; err != nil {
			return err
		}
		if found {
			return nil
		}
		return c.Create(folder)
	})
}

// Append stores raw in folder.
func (s *Store) Append(ctx context.Context, folder string, flags []string, date time.Time, raw []byte) error {
	if !flagsValid(flags) {
		return ErrBadFlag
	}
	return s.session(ctx, func(c *client.Client) error {
		return c.Append(folder, flags, date, bytes.NewBuffer(raw))
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
	ctx, cancel := context.WithTimeout(ctx, s.cfg.Timeout)
	defer cancel()
	conn, err := s.dial(ctx, s.cfg.SMTP, s.cfg.SMTPSec)
	if err != nil {
		return err
	}
	bc := newBudgetConn(conn, smtpReplyBudget)
	defer func() {
		switch {
		case err == nil:
		case bc.over.Load():
			err = ErrReplyTooLarge
		case ctx.Err() == context.DeadlineExceeded:
			err = ErrTimeout
		}
	}()
	if dl, ok := ctx.Deadline(); ok {
		conn.SetDeadline(dl)
	}
	stop := context.AfterFunc(ctx, func() { conn.Close() })
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
	if l.OAuth {
		auth = smtpXOAuth2{xoauth2{l.User, l.Secret}}
	}
	if err := c.Auth(auth); err != nil {
		return errors.New("imapsmtp: the server refused the login")
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
	return c.Quit()
}

// xoauth2 is the XOAUTH2 mechanism for IMAP (sasl.Client); smtpXOAuth2
// is the same for SMTP (smtp.Auth).
type xoauth2 struct{ user, token string }

var _ sasl.Client = xoauth2{}

func (x xoauth2) ir() []byte {
	return []byte("user=" + x.user + "\x01auth=Bearer " + x.token + "\x01\x01")
}

func (x xoauth2) Start() (string, []byte, error) { return "XOAUTH2", x.ir(), nil }
func (x xoauth2) Next([]byte) ([]byte, error)    { return nil, errors.New("imapsmtp: XOAUTH2 refused") }

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

func (x smtpXOAuth2) Next(_ []byte, more bool) ([]byte, error) {
	if more {
		return nil, errors.New("imapsmtp: XOAUTH2 refused")
	}
	return nil, nil
}
