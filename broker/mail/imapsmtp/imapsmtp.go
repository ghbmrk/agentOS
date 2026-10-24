// Package imapsmtp is the old mail adapter's Store over the mail clerk's
// IMAP and SMTP transport (broker/clerk/inbox/imapsmtp). It only converts
// between the transport's raw messages and mail.Store's parsed ones, so the
// transport has one copy. It is transitional: MIG-4-mail's delete (2574b,
// #2574) removes it with broker/mail.
package imapsmtp

import (
	"context"
	"errors"
	"time"

	"github.com/ghbmrk/agentos/broker/clerk/inbox/imapconn"
	transport "github.com/ghbmrk/agentos/broker/clerk/inbox/imapsmtp"
	"github.com/ghbmrk/agentos/broker/mail"
)

// The transport's configuration, as the adapter's callers name it.
type (
	Login    = transport.Login
	Security = transport.Security
	Config   = transport.Config
)

const (
	TLS      = transport.TLS
	StartTLS = transport.StartTLS
	Plain    = transport.Plain
)

// ErrInsecure is returned for a Plain connection to a non-loopback host.
var ErrInsecure = transport.ErrInsecure

// Store is a mail.Store over the transport.
type Store struct{ t *transport.Store }

var _ mail.Store = (*Store)(nil)

// New checks cfg.
func New(cfg Config) (*Store, error) {
	if cfg.Conn == nil {
		// The old core serves its IMAP connections in-process (#2937 gap 2).
		cfg.Conn = imapconn.Pipe()
	}
	t, err := transport.New(cfg)
	if err != nil {
		return nil, err
	}
	return &Store{t}, nil
}

// validityErr gives mail.ErrValidity for the transport's, which mailsock and
// the adapter match.
func validityErr(err error) error {
	if errors.Is(err, transport.ErrValidity) {
		return mail.ErrValidity
	}
	return err
}

func (s *Store) Folders(ctx context.Context) ([]mail.Folder, error) {
	fs, err := s.t.Folders(ctx)
	var out []mail.Folder
	for _, f := range fs {
		out = append(out, mail.Folder{Name: f.Name, Role: mail.Role(f.Role)})
	}
	return out, err
}

func (s *Store) UIDs(ctx context.Context, folder string) (uint32, []uint32, error) {
	return s.t.UIDs(ctx, folder)
}

// parse is the adapter's reading of one fetched message; one that does
// not parse keeps only its place and flags.
func parse(m transport.Message) mail.Message {
	msg, err := mail.Parse(m.Raw)
	if err != nil {
		msg = mail.Message{}
	}
	msg.Folder, msg.Validity, msg.UID, msg.Flags = m.Folder, m.Validity, m.UID, m.Flags
	return msg
}

func (s *Store) Fetch(ctx context.Context, folder string, validity uint32, uids []uint32) ([]mail.Message, error) {
	ms, err := s.t.Fetch(ctx, folder, validity, uids)
	out := make([]mail.Message, 0, len(ms))
	for _, m := range ms {
		out = append(out, parse(m))
	}
	if len(out) == 0 {
		out = nil
	}
	return out, validityErr(err)
}

// Find returns the messages in folder whose Message-ID is exactly id.
func (s *Store) Find(ctx context.Context, folder, id string) ([]mail.Message, error) {
	ms, err := s.t.Find(ctx, folder, id, func(m transport.Message) bool { return parse(m).MessageID == id })
	var out []mail.Message
	for _, m := range ms {
		out = append(out, parse(m))
	}
	return out, err
}

func ref(m mail.Ref) transport.Ref {
	return transport.Ref{Folder: m.Folder, Validity: m.Validity, UID: m.UID}
}

func (s *Store) SetFlags(ctx context.Context, m mail.Ref, add, remove []string) error {
	return validityErr(s.t.SetFlags(ctx, ref(m), add, remove))
}

func (s *Store) Move(ctx context.Context, m mail.Ref, to string) error {
	return validityErr(s.t.Move(ctx, ref(m), to))
}

func (s *Store) Ensure(ctx context.Context, folder string) error { return s.t.Ensure(ctx, folder) }

func (s *Store) Append(ctx context.Context, folder string, flags []string, date time.Time, raw []byte) error {
	return s.t.Append(ctx, folder, flags, date, raw)
}

func (s *Store) Submit(ctx context.Context, rcpt []string, raw []byte) error {
	return s.t.Submit(ctx, rcpt, raw)
}
