package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	netmail "net/mail"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/ghbmrk/agentos/broker/mail/imapsmtp"
	"github.com/ghbmrk/agentos/broker/mail/mailsock"
)

// The owner's mailbox (SR3-mail-w1, egress K18): the local UI sets it up
// on the unlock socket; agentosd reads and acts on it through mail.sock,
// which admits only the broker's uid. The password, the IMAP and SMTP
// clients and the server's own words stay in this process (CRED-1, M1).

// Vault entries: the settings record and the password, an entry of its
// own so the redactor matches it (CRED-7).
const (
	mailSettingsName = "mail-account"
	mailPasswordName = "mail-password"
	kindMailSettings = "mail_account"
	kindMailPassword = "mail_password"
)

// mailConns bounds the calls mail.sock serves at once.
const mailConns = 8

// Setup refusals: one fixed reason per field, never the value entered.
var (
	errMailAddress      = uerr(http.StatusBadRequest, "Enter the mailbox's own address, like you@example.com, with no name around it.")
	errMailServer       = uerr(http.StatusBadRequest, "Enter each server as name:port, like imap.example.com:993 and smtp.example.com:465, from your provider's settings page.")
	errMailUser         = uerr(http.StatusBadRequest, "Enter the sign-in name on one line, or leave it empty to sign in with the address.")
	errMailOtherKind    = uerr(http.StatusBadRequest, "The box already holds a different credential under this name. Remove the mail account first, then set it up again.")
	errWeakMailPassword = uerr(http.StatusBadRequest, "Paste the mailbox password or app password from your provider, 12 to 256 characters on one line.")
)

// Owner notices when the account changes, as for the second line.
const (
	noteMailReplaced = "The mail account was replaced on the box's Wi-Fi page."
	noteMailRemoved  = "The mail account was removed on the box's Wi-Fi page."
)

// mailSettings is the account as the owner enters it. IMAP is implicit
// TLS; SMTP is implicit TLS, or STARTTLS when StartTLS is set. A password
// or app password only: OAuth is not set up here (K18).
type mailSettings struct {
	Address  string `json:"address"`
	IMAP     string `json:"imap"` // host:port
	SMTP     string `json:"smtp"` // host:port
	StartTLS bool   `json:"starttls,omitempty"`
	User     string `json:"user,omitempty"` // sign-in name; empty is Address
}

func (s mailSettings) check() error {
	if a, err := netmail.ParseAddress(s.Address); err != nil || a.Name != "" || a.Address != s.Address {
		return errMailAddress
	}
	for _, hp := range []string{s.IMAP, s.SMTP} {
		if !hostPort(hp) {
			return errMailServer
		}
	}
	if len(s.User) > 256 || strings.IndexFunc(s.User, func(r rune) bool { return !unicode.IsPrint(r) }) >= 0 {
		return errMailUser
	}
	return nil
}

// hostPort accepts name:port with a DNS name or an IP and a port 1-65535.
func hostPort(s string) bool {
	host, port, err := net.SplitHostPort(s)
	if err != nil || host == "" || len(host) > 253 {
		return false
	}
	if p, err := strconv.Atoi(port); err != nil || p < 1 || p > 65535 {
		return false
	}
	for _, r := range host {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '.' || r == '-' || r == ':') {
			return false
		}
	}
	return true
}

func mailPassword(p string) bool {
	if len(p) < 12 || len(p) > 256 {
		return false
	}
	return strings.IndexFunc(p, func(r rune) bool { return !unicode.IsPrint(r) }) < 0
}

// mailRecord is the settings entry and when setup ran (Unix seconds).
type mailRecord struct {
	mailSettings
	SetAt int64 `json:"set_at"`
}

// mailStatusReply is what the local page reads; never the password.
type mailStatusReply struct {
	Set      bool         `json:"set"`
	Settings mailSettings `json:"settings"`
}

// setMail stores the account while the vault is open; the password goes
// first.
func (c *custody) setMail(s mailSettings, password string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.ph != open {
		return errLocked
	}
	if err := s.check(); err != nil {
		return err
	}
	if hasOtherKind(c.v, mailSettingsName, kindMailSettings) || hasOtherKind(c.v, mailPasswordName, kindMailPassword) {
		return errMailOtherKind
	}
	if !mailPassword(password) {
		return errWeakMailPassword
	}
	replacing := hasKind(c.v, mailSettingsName, kindMailSettings)
	rec, err := json.Marshal(mailRecord{mailSettings: s, SetAt: c.now().Unix()})
	if err != nil {
		return errInternal
	}
	if err := c.v.Put(mailPasswordName, kindMailPassword, []byte(password)); err != nil {
		return c.putErr(err)
	}
	if err := c.v.Put(mailSettingsName, kindMailSettings, rec); err != nil {
		return c.putErr(err)
	}
	if replacing {
		c.notify(noteMailReplaced)
	}
	return nil
}

func (c *custody) removeMail() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.ph != open {
		return errLocked
	}
	removed := false
	for _, n := range []struct{ name, kind string }{{mailSettingsName, kindMailSettings}, {mailPasswordName, kindMailPassword}} {
		if !hasKind(c.v, n.name, n.kind) {
			continue
		}
		if err := c.v.Delete(n.name); err != nil {
			return c.putErr(err)
		}
		removed = true
	}
	if removed {
		c.notify(noteMailRemoved)
	}
	return nil
}

// mailAccount reads the account. Caller holds mu.
func (c *custody) mailAccount() (mailRecord, string, error) {
	if c.ph != open {
		return mailRecord{}, "", mailsock.ErrLocked
	}
	if !hasKind(c.v, mailSettingsName, kindMailSettings) || !hasKind(c.v, mailPasswordName, kindMailPassword) {
		return mailRecord{}, "", mailsock.ErrNotConnected
	}
	raw, ok1 := c.v.Secret(mailSettingsName)
	pw, ok2 := c.v.Secret(mailPasswordName)
	var rec mailRecord
	if !ok1 || !ok2 || json.Unmarshal([]byte(raw.Reveal()), &rec) != nil {
		return mailRecord{}, "", mailsock.ErrNotConnected
	}
	return rec, pw.Reveal(), nil
}

func (c *custody) mailStatus() (mailStatusReply, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	rec, _, err := c.mailAccount()
	switch {
	case errors.Is(err, mailsock.ErrLocked):
		return mailStatusReply{}, errLocked
	case err != nil:
		return mailStatusReply{}, nil
	}
	return mailStatusReply{Set: true, Settings: rec.mailSettings}, nil
}

// mailSource is the account as mail.sock serves it: a Store over the
// owner's servers whose password is read from the vault for each
// connection it opens, so a lock or a removal takes effect at once.
func (c *custody) mailSource() (mailsock.Account, error) {
	c.mu.Lock()
	rec, _, err := c.mailAccount()
	plain := c.mailPlain
	c.mu.Unlock()
	if err != nil {
		return mailsock.Account{}, err
	}
	imapSec, smtpSec := imapsmtp.TLS, imapsmtp.TLS
	if rec.StartTLS {
		smtpSec = imapsmtp.StartTLS
	}
	if plain {
		imapSec, smtpSec = imapsmtp.Plain, imapsmtp.Plain
	}
	user := rec.User
	if user == "" {
		user = rec.Address
	}
	st, err := imapsmtp.New(imapsmtp.Config{IMAP: rec.IMAP, SMTP: rec.SMTP, IMAPSec: imapSec, SMTPSec: smtpSec, From: rec.Address,
		Credential: func(context.Context) (imapsmtp.Login, error) {
			c.mu.Lock()
			defer c.mu.Unlock()
			now, pw, err := c.mailAccount()
			if err != nil || now.mailSettings != rec.mailSettings {
				return imapsmtp.Login{}, mailsock.ErrNotConnected
			}
			return imapsmtp.Login{User: user, Secret: pw}, nil
		}})
	if err != nil {
		return mailsock.Account{}, mailsock.ErrFailed
	}
	return mailsock.Account{Store: st, Address: rec.Address}, nil
}

// serveMail opens mail.sock in dir for the broker's uid and serves it
// until the returned closer is closed.
func serveMail(dir string, c *custody, brokerUID int) (io.Closer, error) {
	if err := runDir(dir); err != nil {
		return nil, err
	}
	ln, err := listen(dir, mailsock.Socket, brokerUID)
	if err != nil {
		return nil, err
	}
	go func() {
		sem := make(chan struct{}, mailConns)
		for {
			conn, err := ln.Accept()
			if errors.Is(err, net.ErrClosed) {
				return
			}
			if err != nil {
				time.Sleep(50 * time.Millisecond)
				continue
			}
			sem <- struct{}{}
			go func() {
				defer func() { <-sem }()
				mailsock.ServeConn(conn, c.mailSource)
			}()
		}
	}()
	return ln, nil
}

// mailRoutes adds the mail account's setup to the unlock socket.
func mailRoutes(mux *http.ServeMux, c *custody, read func(http.ResponseWriter, *http.Request, any) bool,
	reply func(http.ResponseWriter, int, any), fail func(http.ResponseWriter, error)) {
	mux.HandleFunc("/mail", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			mailSettings
			Password string `json:"password"`
		}
		if !read(w, r, &req) {
			return
		}
		if err := c.setMail(req.mailSettings, req.Password); err != nil {
			fail(w, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("/mail/status", func(w http.ResponseWriter, r *http.Request) {
		st, err := c.mailStatus()
		if err != nil {
			fail(w, err)
			return
		}
		reply(w, http.StatusOK, st)
	})
	mux.HandleFunc("/mail/remove", func(w http.ResponseWriter, r *http.Request) {
		var req struct{}
		if !read(w, r, &req) {
			return
		}
		if err := c.removeMail(); err != nil {
			fail(w, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
}
