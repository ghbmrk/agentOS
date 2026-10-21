package run

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
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
// account's settings, which are not secret, and its Secrets file, where the
// mailbox password sits in a static slot named for those settings (slotOf).
// The password is opened inside broker/clerk at each connection
// (clerk.Secrets.Login), so a removal or a replacement takes effect at the
// next one, and no file or answer of this process carries it. A clerk opened
// on one account asks for that account's slot only, so once the account is
// replaced or removed it has no password to send anywhere.
const (
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

// slotOf names the password's slot for these settings. It covers every field,
// so a replacement that keeps the address but changes a server or the
// sign-in name is another slot, and the old account's clerk cannot open it
// (the old setup's MAIL-gen).
func slotOf(s MailSettings) string {
	b, _ := json.Marshal(s)
	h := sha256.Sum256(b)
	return clerk.MailSlots + hex.EncodeToString(h[:16])
}

// mailRecord is the settings file: the account, and the slot of the account
// it replaced while that slot may still be in the Secrets file.
type mailRecord struct {
	MailSettings
	Prev string `json:"prev,omitempty"`
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
// directory: the password goes, sealed, to the slot named for the settings,
// and the settings beside it. A refusal writes nothing. The steps are: drop a
// slot an earlier crash left, put the new slot, write the settings naming the
// replaced slot, drop the replaced slot. A crash at any point leaves the
// settings file naming an account whose own slot holds its own password, so
// no password is sent to another account's servers; a crash after the put
// can leave the new slot sealed and unnamed until the next SetMail of that
// account replaces it (ASSUMPTIONS MIG-4-run-j).
func SetMail(dir string, sec *clerk.Secrets, s MailSettings, password string) error {
	if err := s.check(); err != nil {
		return err
	}
	if !mailPassword(password) {
		return ErrWeakMailPassword
	}
	old, err := readMail(dir)
	switch {
	case errors.Is(err, ErrNoMailAccount):
	case err != nil:
		return err
	}
	cur := slotOf(s)
	rec := mailRecord{MailSettings: s}
	if err == nil {
		if old.Prev != "" && old.Prev != cur {
			if err := sec.Remove(old.Prev); err != nil {
				return err
			}
		}
		if p := slotOf(old.MailSettings); p != cur {
			rec.Prev = p
		}
	}
	b, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	if err := sec.Put(cur, clerk.KindStatic, []byte(password)); err != nil {
		return err
	}
	if err := writeAtomic(dir, mailSettings, b, nil); err != nil {
		return err
	}
	if rec.Prev != "" {
		return sec.Remove(rec.Prev)
	}
	return nil
}

// RemoveMail removes the account from dir: its password and any replaced
// one first, so the next connection has nothing to sign in with, then the
// settings. Settings that do not load are removed all the same.
func RemoveMail(dir string, sec *clerk.Secrets) error {
	rec, err := readMail(dir)
	switch {
	case errors.Is(err, ErrNoMailAccount):
		return nil
	case err == nil:
		for _, slot := range []string{slotOf(rec.MailSettings), rec.Prev} {
			if slot == "" {
				continue
			}
			if err := sec.Remove(slot); err != nil {
				return err
			}
		}
	case private(dir, true) != nil:
		return err
	}
	if err := os.Remove(filepath.Join(dir, mailSettings)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return syncDir(dir)
}

// readMail loads dir's settings file under the same custody checks as the
// Secrets file.
func readMail(dir string) (mailRecord, error) {
	var r mailRecord
	if err := private(dir, true); err != nil {
		return r, err
	}
	f, err := os.OpenFile(filepath.Join(dir, mailSettings), os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if errors.Is(err, os.ErrNotExist) {
		return r, ErrNoMailAccount
	}
	if err != nil {
		return r, err
	}
	defer f.Close()
	if err := privateFile(f); err != nil {
		return r, err
	}
	b, err := io.ReadAll(io.LimitReader(f, maxSettings+1))
	if err != nil {
		return r, err
	}
	if len(b) > maxSettings || json.Unmarshal(b, &r) != nil || r.check() != nil {
		return r, fmt.Errorf("run: %s does not load", mailSettings)
	}
	return r, nil
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
	r, err := readMail(dir)
	if err != nil {
		return nil, err
	}
	s := r.MailSettings
	cfg := imapsmtp.Config{IMAP: s.IMAP, SMTP: s.SMTP, IMAPSec: imapsmtp.TLS, SMTPSec: imapsmtp.TLS, TLS: c.TLS,
		Credential: sec.Login(slotOf(s), s.login()), From: s.Address, Guard: c.Guard}
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
