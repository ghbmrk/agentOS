package inbox

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"

	"github.com/ghbmrk/agentos/broker/clerk/inbox/imapsmtp"
)

// Mailbox is where the clerk's effects land. Do calls it only after the
// step passed the clerk's one check (clerk.Check) and the clerk's own rules,
// so nothing reaches a mailbox that the kernel did not dispatch. Each method
// acts on one mail by the id the clerk read it under and confirms the effect
// before it returns nil. A NotDone error means nothing changed; any other
// error means the effect may have happened and was not confirmed.
type Mailbox interface {
	Label(ctx context.Context, mail, label string) error
	Trash(ctx context.Context, mail string) error
	Post(ctx context.Context, p Post) error
}

// NotDone is a mailbox's refusal before acting, as the clerk's reason.
type NotDone string

func (e NotDone) Error() string { return "inbox: not done: " + string(e) }

// The reasons a mailbox refuses before acting.
const (
	nUnknown    NotDone = "unknown-mail"    // not a mail this mailbox read
	nRenumbered NotDone = "renumbered"      // the folder's UID validity changed
	nNoMove     NotDone = "no-move"         // the server cannot MOVE without EXPUNGE
	nNoTrash    NotDone = "no-trash-folder" // the account has no folder with the trash role
	nNoPoster   NotDone = "no-poster"       // no one-click POSTer is wired (#2601)
	nBadFlag    NotDone = "bad-flag"        // a label that is not an IMAP keyword
)

// Synthetic is the eval's mailbox (MIG-3-1): every effect is accepted and
// lands nowhere; the clerk's own record (Effects, Posts) is the outcome.
type Synthetic struct{}

func (Synthetic) Label(context.Context, string, string) error { return nil }
func (Synthetic) Trash(context.Context, string) error         { return nil }
func (Synthetic) Post(context.Context, Post) error            { return nil }

// readMax is how many of the newest inbox mails Live reads: a day's worth
// of the clerk's organize and trash effects (DailyCap), so what is read is
// what one day can act on, and memory stays bounded by readMax times the
// transport's MaxFetch.
const readMax = DailyCap

// fetchBatch is how many mails one fetch asks for.
const fetchBatch = 50

// Live is the owner's mailbox over IMAP and SMTP (SPEC: the mail clerk
// supports any IMAP and SMTP provider). It reads the inbox without marking
// anything read and acts only on the mails it read, by their full reference:
// a label is an IMAP keyword, a trash is a UID MOVE to the account's trash
// folder, never an EXPUNGE. Each effect is read back before it counts.
type Live struct {
	st *imapsmtp.Store

	mu    sync.Mutex
	refs  map[string]liveMail
	trash string // the trash folder's name, "" when the account has none
}

type liveMail struct {
	ref imapsmtp.Ref
	id  string // the Message-ID header, for the trash read-back
}

// NewLive is a mailbox over st.
func NewLive(st *imapsmtp.Store) *Live { return &Live{st: st, refs: map[string]liveMail{}} }

// Read fetches the newest readMax inbox mails with BODY.PEEK, unclassified:
// a class comes from a reader, not from the mailbox. It replaces what an
// earlier Read found.
func (l *Live) Read(ctx context.Context) ([]Mail, error) {
	fs, err := l.st.Folders(ctx)
	if err != nil {
		return nil, err
	}
	inbox, trash := "", ""
	for _, f := range fs {
		switch f.Role {
		case imapsmtp.Inbox:
			inbox = f.Name
		case imapsmtp.Trash:
			if trash == "" {
				trash = f.Name
			}
		}
	}
	if inbox == "" {
		return nil, errors.New("inbox: the account lists no inbox")
	}
	validity, uids, err := l.st.UIDs(ctx, inbox)
	if err != nil {
		return nil, err
	}
	if len(uids) > readMax {
		uids = newest(uids, readMax)
	}
	refs := map[string]liveMail{}
	var out []Mail
	for i := 0; i < len(uids); i += fetchBatch {
		ms, err := l.st.Fetch(ctx, inbox, validity, uids[i:min(i+fetchBatch, len(uids))])
		if err != nil {
			return nil, err
		}
		for _, m := range ms {
			id := fmt.Sprintf("imap-%d-%d", m.Validity, m.UID)
			refs[id] = liveMail{ref: m.Ref, id: messageID(m.Raw)}
			out = append(out, Mail{ID: id, Raw: m.Raw})
		}
	}
	l.mu.Lock()
	l.refs, l.trash = refs, trash
	l.mu.Unlock()
	return out, nil
}

// newest is the n highest UIDs, in ascending order.
func newest(uids []uint32, n int) []uint32 {
	s := append([]uint32(nil), uids...)
	slices.Sort(s)
	return s[len(s)-n:]
}

func (l *Live) mail(id string) (liveMail, string, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	m, ok := l.refs[id]
	if !ok {
		return liveMail{}, "", nUnknown
	}
	return m, l.trash, nil
}

// before maps a transport error from a change: one the server refused before
// acting is NotDone, anything else may have acted.
func before(err error) error {
	switch {
	case errors.Is(err, imapsmtp.ErrValidity):
		return nRenumbered
	case errors.Is(err, imapsmtp.ErrNoMove):
		return nNoMove
	case errors.Is(err, imapsmtp.ErrBadFlag):
		return nBadFlag
	}
	return err
}

// errUnconfirmed: the effect was asked for but the read-back does not show it.
var errUnconfirmed = errors.New("inbox: the mailbox does not show the effect")

// Label adds label to the mail as an IMAP keyword and reads it back.
func (l *Live) Label(ctx context.Context, id, label string) error {
	m, _, err := l.mail(id)
	if err != nil {
		return err
	}
	if err := l.st.SetFlags(ctx, m.ref, []string{label}, nil); err != nil {
		return before(err)
	}
	got, err := l.st.Fetch(ctx, m.ref.Folder, m.ref.Validity, []uint32{m.ref.UID})
	if err != nil {
		return err
	}
	if len(got) != 1 || !hasFlag(got[0].Flags, label) {
		return errUnconfirmed
	}
	return nil
}

// Trash moves the mail to the account's trash folder and reads it back: it
// is gone from where it was and its Message-ID is in the trash. A mail with
// no Message-ID cannot be found there, so its trash is never confirmed.
func (l *Live) Trash(ctx context.Context, id string) error {
	m, trash, err := l.mail(id)
	if err != nil {
		return err
	}
	if trash == "" {
		return nNoTrash
	}
	if err := l.st.Move(ctx, m.ref, trash); err != nil {
		return before(err)
	}
	left, err := l.st.Fetch(ctx, m.ref.Folder, m.ref.Validity, []uint32{m.ref.UID})
	if err != nil {
		return err
	}
	if len(left) != 0 || m.id == "" {
		return errUnconfirmed
	}
	there, err := l.st.Find(ctx, trash, m.id, func(x imapsmtp.Message) bool { return messageID(x.Raw) == m.id })
	if err != nil {
		return err
	}
	if len(there) == 0 {
		return errUnconfirmed
	}
	return nil
}

// Post refuses: the one-click POSTer and its egress rules are #2601, so a
// live unsubscribe is not sent and not reported as sent.
func (l *Live) Post(context.Context, Post) error { return nNoPoster }

func hasFlag(flags []string, f string) bool {
	for _, x := range flags {
		if strings.EqualFold(x, f) {
			return true
		}
	}
	return false
}

// messageID is the message's Message-ID header value, trimmed, or "".
func messageID(raw []byte) string {
	hs, _ := splitMessage(raw)
	for _, h := range hs {
		if h.key() == "message-id" {
			return strings.TrimSpace(string(h.value))
		}
	}
	return ""
}
