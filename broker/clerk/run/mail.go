package run

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	netmail "net/mail"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"unicode"

	"github.com/ghbmrk/agentos/broker/clerk"
	"github.com/ghbmrk/agentos/broker/clerk/inbox"
	"github.com/ghbmrk/agentos/broker/clerk/inbox/imapsmtp"
	"github.com/ghbmrk/agentos/broker/netguard"
)

// The mail clerk's process (MIG-4-mail-run, #2655). Its directory holds the
// account's settings, which are not secret, and its Secrets file, whose one
// static slot holds the mailbox password. The password is opened inside
// broker/clerk at each connection (clerk.Secrets.Login), so a removal or a
// replacement takes effect at the next one, and no file or answer of this
// process carries it.
const (
	mailSlot     = "mail-password"
	mailSettings = "mail.json"
	maxSettings  = 4 << 10
)

// MailSettings is the account as the owner enters it. IMAP is implicit TLS;
// SMTP is implicit TLS, or STARTTLS when StartTLS is set. A password or app
// password only: OAuth is not set up here.
type MailSettings struct {
	Address  string `json:"address"`
	IMAP     string `json:"imap"` // host:port
	SMTP     string `json:"smtp"` // host:port
	StartTLS bool   `json:"starttls,omitempty"`
	User     string `json:"user,omitempty"` // sign-in name; empty is Address
}

// Setup refusals: one fixed reason per field, never the value entered. The
// wording is the old setup's (cmd/agentos-egress/mailaccount.go), kept as is.
var (
	ErrMailAddress      = errors.New("Enter the mailbox's own address, like you@example.com, with no name around it.")
	ErrMailServer       = errors.New("Enter each server as name:port, like imap.example.com:993 and smtp.example.com:465, from your provider's settings page.")
	ErrMailUser         = errors.New("Enter the sign-in name on one line, or leave it empty to sign in with the address.")
	ErrWeakMailPassword = errors.New("Paste the mailbox password or app password from your provider, 12 to 256 characters on one line.")
	// ErrNoMailAccount is OpenMail's refusal when no account is set up.
	ErrNoMailAccount = errors.New("run: no mail account is set up")
)

func (s MailSettings) check() error {
	if a, err := netmail.ParseAddress(s.Address); err != nil || a.Name != "" || a.Address != s.Address {
		return ErrMailAddress
	}
	for _, hp := range []string{s.IMAP, s.SMTP} {
		if !hostPort(hp) {
			return ErrMailServer
		}
	}
	if len(s.User) > 256 || strings.IndexFunc(s.User, func(r rune) bool { return !unicode.IsPrint(r) }) >= 0 {
		return ErrMailUser
	}
	return nil
}

func (s MailSettings) login() string {
	if s.User != "" {
		return s.User
	}
	return s.Address
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
	return len(p) >= 12 && len(p) <= 256 && strings.IndexFunc(p, func(r rune) bool { return !unicode.IsPrint(r) }) < 0
}

// SetMail sets up or replaces the account in dir, the mail clerk's own
// directory: the password goes to sec's static slot, sealed, and the settings
// beside it. A refusal writes nothing. The password is written first, so a
// crash between the two leaves the old settings, whose next connection signs
// in with the new password and is refused, not a new server given the old
// password.
func SetMail(dir string, sec *clerk.Secrets, s MailSettings, password string) error {
	if err := s.check(); err != nil {
		return err
	}
	if !mailPassword(password) {
		return ErrWeakMailPassword
	}
	if err := private(dir, true); err != nil {
		return err
	}
	b, err := json.Marshal(s)
	if err != nil {
		return err
	}
	if err := sec.Put(mailSlot, clerk.KindStatic, []byte(password)); err != nil {
		return err
	}
	return writeAtomic(dir, mailSettings, b, nil)
}

// RemoveMail removes the account from dir: the password first, so the next
// connection has nothing to sign in with, then the settings.
func RemoveMail(dir string, sec *clerk.Secrets) error {
	if err := private(dir, true); err != nil {
		return err
	}
	if err := sec.Remove(mailSlot); err != nil {
		return err
	}
	if err := os.Remove(filepath.Join(dir, mailSettings)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return syncDir(dir)
}

// readMail loads dir's settings under the same custody checks as the Secrets
// file.
func readMail(dir string) (MailSettings, error) {
	var s MailSettings
	if err := private(dir, true); err != nil {
		return s, err
	}
	f, err := os.OpenFile(filepath.Join(dir, mailSettings), os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if errors.Is(err, os.ErrNotExist) {
		return s, ErrNoMailAccount
	}
	if err != nil {
		return s, err
	}
	defer f.Close()
	if err := privateFile(f); err != nil {
		return s, err
	}
	b, err := io.ReadAll(io.LimitReader(f, maxSettings+1))
	if err != nil {
		return s, err
	}
	if len(b) > maxSettings || json.Unmarshal(b, &s) != nil || s.check() != nil {
		return s, fmt.Errorf("run: %s does not load", mailSettings)
	}
	return s, nil
}

// MailConfig is what the mail clerk's process is given besides its directory.
type MailConfig struct {
	Anchors []ed25519.PublicKey
	// HandleSecret keys the sender handles the planner sees (inbox.NewAccount).
	HandleSecret []byte
	// Ask is the quarantined read that classes each mail (inbox.Read).
	Ask           inbox.Ask
	World         func() inbox.World
	RetentionDays int
	OneClickBody  string
	TLS           *tls.Config      // nil: system roots, the server's name
	Guard         *netguard.Policy // nil: imapsmtp's default policy

	plain bool // the loopback test server only (imapsmtp refuses it elsewhere)
}

// OpenMail is the mail clerk over the account in dir: it reads the newest
// inbox mails through the owner's mailbox, classes them with c.Ask, and
// returns the clerk to serve with ServeClerk. Every connection signs in with
// the password sealed in sec, opened at that connection.
func OpenMail(ctx context.Context, dir string, sec *clerk.Secrets, c MailConfig) (*inbox.Account, error) {
	s, err := readMail(dir)
	if err != nil {
		return nil, err
	}
	cfg := imapsmtp.Config{IMAP: s.IMAP, SMTP: s.SMTP, IMAPSec: imapsmtp.TLS, SMTPSec: imapsmtp.TLS, TLS: c.TLS,
		Credential: sec.Login(mailSlot, s.login()), From: s.Address, Guard: c.Guard}
	if s.StartTLS {
		cfg.SMTPSec = imapsmtp.StartTLS
	}
	if c.plain {
		cfg.IMAPSec, cfg.SMTPSec = imapsmtp.Plain, imapsmtp.Plain
	}
	st, err := imapsmtp.New(cfg)
	if err != nil {
		return nil, err
	}
	box := inbox.NewLive(st)
	ms, err := box.Read(ctx)
	if err != nil {
		return nil, err
	}
	return inbox.NewAccount(c.Anchors, c.HandleSecret, c.World, inbox.Read(ctx, c.Ask, ms), box, c.RetentionDays, c.OneClickBody)
}
