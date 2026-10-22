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
	"sync"
	"syscall"
	"time"
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

// mailMu serializes SetMail and RemoveMail, so two of them cannot leave a
// slot that neither's settings name.
var mailMu sync.Mutex

// SetMail sets up or replaces the account in dir, the mail clerk's own
// directory: the password goes, sealed, to the slot named for the settings,
// and the settings beside it. A refusal writes nothing. The steps are: put the
// new slot, write the settings, drop another account's record of read mail,
// drop every other mail slot. A crash at any
// point leaves the settings naming an account whose own slot holds its own
// password, so no password goes to another account's servers, and the next
// SetMail or RemoveMail drops whatever slot the crash left.
func SetMail(dir string, sec *clerk.Secrets, s MailSettings, password string) error {
	return setMail(dir, sec, s, password, nil)
}

// setMail is SetMail; stop, for tests only, ends it after step i as a crash
// would.
func setMail(dir string, sec *clerk.Secrets, s MailSettings, password string, stop func(i int) bool) error {
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
	mailMu.Lock()
	defer mailMu.Unlock()
	cur := slotOf(s)
	prev, perr := readMail(dir)
	same := perr == nil && slotOf(prev) == cur
	steps := []func() error{
		func() error { return sec.Put(cur, clerk.KindStatic, []byte(password)) },
		func() error { return writeAtomic(dir, mailSettings, b, nil) },
		func() error {
			// Another account's record of read mail does not load under this
			// one; dropping it makes the restart a new account's, not a loss.
			if same {
				return nil
			}
			return removeFiles(dir, seenFile)
		},
		func() error { return sec.RemovePrefix(clerk.MailSlots, cur) },
	}
	for i, step := range steps {
		if err := step(); err != nil {
			return err
		}
		if stop != nil && stop(i) {
			return errStopped
		}
	}
	return nil
}

// RemoveMail removes the account from dir: every mail password first, so the
// next connection has nothing to sign in with and no crash-left slot stays
// sealed, then the settings and any temporary a crashed write left.
func RemoveMail(dir string, sec *clerk.Secrets) error {
	if err := private(dir, true); err != nil {
		return err
	}
	mailMu.Lock()
	defer mailMu.Unlock()
	if err := sec.RemovePrefix(clerk.MailSlots, ""); err != nil {
		return err
	}
	// A temporary a crashed write left may hold a sealed password or the
	// settings; it is never read, and it goes too, with the record of read
	// mail.
	return removeFiles(dir, secretsName+".tmp", mailSettings+".tmp", mailSettings, seenFile, seenFile+".tmp")
}

// removeFiles removes the named files from dir, if there, and syncs it.
func removeFiles(dir string, names ...string) error {
	for _, name := range names {
		if err := os.Remove(filepath.Join(dir, name)); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	return syncDir(dir)
}

// readMail loads dir's settings file under the same custody checks as the
// Secrets file.
func readMail(dir string) (MailSettings, error) {
	var r MailSettings
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
	// Sealer seals the record of read mail, as it does the Secrets file.
	Sealer clerk.Sealer

	plain bool // the loopback test server only (imapsmtp refuses it elsewhere)
}

// Mail is the mail clerk a process serves, and what it tells the owner.
type Mail struct {
	*inbox.Account
	Status MailStatus
	world  func() inbox.World // the world the account judges VRB-2 in
	mark   inbox.Mark         // the mailbox's Mark before the read; nil: none
	day    string             // the read's date
}

// OpenMail is the mail clerk over the account in dir: it reads the newest
// inbox mails, classes them with c.Ask, and returns the clerk to serve with
// ServeClerk. Every connection signs in with the password sealed in sec,
// opened at that connection. LastOpened in the world VRB-2 reads is the
// clerk's own, from the account's read mail and its sealed record
// (lastOpened); the rest of the world is c.World's, and its Today dates the
// read. The mailbox's Mark is taken before the read, so mail arriving
// during it moves the next one.
func OpenMail(ctx context.Context, dir string, sec *clerk.Secrets, c MailConfig) (*Mail, error) {
	box, s, err := mailBox(dir, sec, c)
	if err != nil {
		return nil, err
	}
	mark, _ := box.Mark(ctx) // nil on any error: the next read is not skipped
	ms, err := box.Read(ctx)
	if err != nil {
		return nil, err
	}
	today := c.today()
	opened, status := lastOpened(ctx, box, dir, c.Sealer, slotOf(s), today, ms)
	m := &Mail{Status: status, mark: mark, day: today, world: func() inbox.World {
		w := c.World()
		w.LastOpened = opened
		return w
	}}
	if m.Account, err = inbox.NewAccount(c.Anchors, c.HandleSecret, m.world, inbox.Read(ctx, c.Ask, ms), box, c.RetentionDays, c.OneClickBody); err != nil {
		return nil, err
	}
	return m, nil
}

// Unchanged reports whether a read now would find what m's read found: the
// same day, which Opened also moves with, and a Mark the same as the one m
// was read under (#2742 item 1). A server whose STATUS leaves an item out
// is read again the next day, not at every listing; any other error reads
// again, so a failure such as a refused sign-in is found and told. A read
// with no Mark, or whose record of read mail may yet come out otherwise
// (MailStatus.again), is read again at once.
func (m *Mail) Unchanged(ctx context.Context, dir string, sec *clerk.Secrets, c MailConfig) bool {
	today := c.today()
	if m.day != today || m.Status.again {
		return false
	}
	box, _, err := mailBox(dir, sec, c)
	if err != nil {
		return false
	}
	now, err := box.Mark(ctx)
	return unchanged(m, today, now, err)
}

// unchanged is Unchanged's answer for m, given today and the Mark now with
// the error taking it.
func unchanged(m *Mail, today string, now inbox.Mark, err error) bool {
	if m.day != today || m.Status.again {
		return false
	}
	return errors.Is(err, imapsmtp.ErrPartialStatus) || m.mark.Same(now)
}

// mailBox is the mailbox of the account in dir, and its settings.
func mailBox(dir string, sec *clerk.Secrets, c MailConfig) (*inbox.Live, MailSettings, error) {
	s, err := readMail(dir)
	if err != nil {
		return nil, s, err
	}
	if c.Sealer == nil || c.World == nil {
		return nil, s, errors.New("run: a mail clerk needs its sealer and its world")
	}
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
		return nil, s, err
	}
	return inbox.NewLive(st), s, nil
}

// today is the date c's world gives, or UTC's.
func (c MailConfig) today() string {
	if t := c.World().Today; t != "" {
		return t
	}
	return time.Now().UTC().Format(time.DateOnly)
}
