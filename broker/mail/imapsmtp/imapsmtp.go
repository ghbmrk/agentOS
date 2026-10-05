// Package imapsmtp is the mail adapter's Store over IMAP and SMTP. It
// takes the account's credential from the vault on each connection and
// keeps none, so it is linked only into the process that holds the
// unlocked vault (CRED-1), which serves it to the broker over a socket.
// Nothing here logs or returns the credential or a server's own words.
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
	"net"
	"net/smtp"
	"strings"
	"time"

	"github.com/emersion/go-imap"
	"github.com/emersion/go-imap/client"
	"github.com/emersion/go-imap/commands"
	"github.com/emersion/go-sasl"

	"github.com/ghbmrk/agentos/broker/mail"
)

// Login is an account credential as the vault hands it over: a password
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
}

// Store is a mail.Store over IMAP and SMTP.
type Store struct{ cfg Config }

var _ mail.Store = (*Store)(nil)

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
	return &Store{cfg: cfg}, nil
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
	ctx, cancel := context.WithTimeout(ctx, s.cfg.Timeout)
	defer cancel()
	d := &net.Dialer{}
	conn, err := d.DialContext(ctx, "tcp", s.cfg.IMAP)
	if err != nil {
		return err
	}
	if dl, ok := ctx.Deadline(); ok {
		conn.SetDeadline(dl)
	}
	switch s.cfg.IMAPSec {
	case TLS:
		conn = tls.Client(conn, s.tlsConfig(s.cfg.IMAP))
	case Plain:
	default:
		conn.Close()
		return errors.New("imapsmtp: IMAP uses implicit TLS, or plain to loopback only")
	}
	c, err := client.New(conn)
	if err != nil {
		conn.Close()
		return err
	}
	c.ErrorLog = quiet{}
	defer c.Logout()
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	l, err := s.cfg.Credential(ctx)
	if err != nil {
		return errors.New("imapsmtp: no credential from the vault")
	}
	if l.OAuth {
		err = c.Authenticate(xoauth2{l.User, l.Secret})
	} else {
		err = c.Login(l.User, l.Secret)
	}
	if err != nil {
		return errors.New("imapsmtp: the server refused the login")
	}
	return f(c)
}

type quiet struct{}

func (quiet) Printf(string, ...interface{}) {}
func (quiet) Println(...interface{})        {}

// Folders lists the account's folders with their special-use roles.
func (s *Store) Folders(ctx context.Context) ([]mail.Folder, error) {
	var out []mail.Folder
	err := s.session(ctx, func(c *client.Client) error {
		ch := make(chan *imap.MailboxInfo, 32)
		done := make(chan error, 1)
		go func() { done <- c.List("", "*", ch) }()
		for m := range ch {
			if has(m.Attributes, imap.NoSelectAttr) {
				continue
			}
			out = append(out, mail.Folder{Name: m.Name, Role: role(m)})
		}
		return <-done
	})
	return out, err
}

func role(m *imap.MailboxInfo) mail.Role {
	if strings.EqualFold(m.Name, "INBOX") {
		return mail.Inbox
	}
	for a, r := range map[string]mail.Role{imap.ArchiveAttr: mail.Archive, imap.DraftsAttr: mail.Drafts,
		imap.SentAttr: mail.Sent, imap.TrashAttr: mail.Trash, imap.JunkAttr: mail.Junk, imap.AllAttr: mail.All} {
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

// Fetch reads messages with BODY.PEEK, so none is marked read.
func (s *Store) Fetch(ctx context.Context, folder string, uids []uint32) ([]mail.Message, error) {
	if len(uids) == 0 {
		return nil, nil
	}
	var out []mail.Message
	err := s.session(ctx, func(c *client.Client) error {
		if _, err := c.Select(folder, true); err != nil {
			return err
		}
		var err error
		out, err = s.fetch(c, folder, uids)
		return err
	})
	return out, err
}

func (s *Store) fetch(c *client.Client, folder string, uids []uint32) ([]mail.Message, error) {
	set := new(imap.SeqSet)
	set.AddNum(uids...)
	sec := &imap.BodySectionName{Peek: true, Partial: []int{0, s.cfg.MaxFetch}}
	items := []imap.FetchItem{imap.FetchUid, imap.FetchFlags, sec.FetchItem()}
	ch := make(chan *imap.Message, 16)
	done := make(chan error, 1)
	go func() { done <- c.UidFetch(set, items, ch) }()
	var out []mail.Message
	for m := range ch {
		var raw []byte
		for _, l := range m.Body {
			if l != nil {
				raw, _ = io.ReadAll(l)
				break
			}
		}
		msg, err := mail.Parse(raw)
		if err != nil {
			msg = mail.Message{}
		}
		msg.Folder, msg.UID, msg.Flags = folder, m.Uid, append([]string(nil), m.Flags...)
		out = append(out, msg)
	}
	return out, <-done
}

// Find returns the messages in folder whose Message-ID is exactly id.
// Servers match a header search by substring, so the result is checked.
func (s *Store) Find(ctx context.Context, folder, id string) ([]mail.Message, error) {
	var out []mail.Message
	err := s.session(ctx, func(c *client.Client) error {
		if _, err := c.Select(folder, true); err != nil {
			return err
		}
		crit := imap.NewSearchCriteria()
		crit.Header.Add("Message-Id", id)
		uids, err := c.UidSearch(crit)
		if err != nil || len(uids) == 0 {
			return err
		}
		ms, err := s.fetch(c, folder, uids)
		for _, m := range ms {
			if m.MessageID == id {
				out = append(out, m)
			}
		}
		return err
	})
	return out, err
}

// SetFlags adds and removes flags on one message.
func (s *Store) SetFlags(ctx context.Context, folder string, uid uint32, add, remove []string) error {
	return s.session(ctx, func(c *client.Client) error {
		if _, err := c.Select(folder, false); err != nil {
			return err
		}
		set := new(imap.SeqSet)
		set.AddNum(uid)
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
// anything else the owner had marked deleted in that folder.
func (s *Store) Move(ctx context.Context, from string, uid uint32, to string) error {
	return s.session(ctx, func(c *client.Client) error {
		if ok, _ := c.Support("MOVE"); !ok {
			return errors.New("imapsmtp: the server does not support MOVE")
		}
		if _, err := c.Select(from, false); err != nil {
			return err
		}
		set := new(imap.SeqSet)
		set.AddNum(uid)
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
	return s.session(ctx, func(c *client.Client) error {
		return c.Append(folder, flags, date, bytes.NewBuffer(raw))
	})
}

// Submit sends raw over SMTP submission from the configured address.
func (s *Store) Submit(ctx context.Context, rcpt []string, raw []byte) error {
	ctx, cancel := context.WithTimeout(ctx, s.cfg.Timeout)
	defer cancel()
	d := &net.Dialer{}
	conn, err := d.DialContext(ctx, "tcp", s.cfg.SMTP)
	if err != nil {
		return err
	}
	if dl, ok := ctx.Deadline(); ok {
		conn.SetDeadline(dl)
	}
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
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
		return errors.New("imapsmtp: no credential from the vault")
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
