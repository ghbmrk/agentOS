package main

import (
	"bytes"
	"context"
	"fmt"
	"net/mail"
	"slices"
	"strings"

	"github.com/ghbmrk/agentos/broker/clerk"
	"github.com/ghbmrk/agentos/broker/clerk/inbox"
	"github.com/ghbmrk/agentos/broker/clerk/inbox/gmailtest"
	"github.com/ghbmrk/agentos/broker/clerk/inbox/imapsmtp"
	"github.com/ghbmrk/agentos/broker/clerk/inbox/imapsmtp/imaptest"
)

// The mailboxes a run can land on: the synthetic one (the default), or a
// fake account read and changed through the clerk's real mailbox for it, so
// A21 runs on both: IMAP (inbox.Live) and the Gmail API (inbox.Gmail).
const (
	boxIMAP  = "imap"
	boxGmail = "gmail"
)

// account is a fake account loaded with a run's mails and the clerk's real
// mailbox over it. It answers to the input's mail ids, so the run's outcome
// and log are the synthetic run's, and the mails the clerk reads are the
// ones the mailbox read back.
type account struct {
	box   inbox.Mailbox
	ids   map[string]string // the input's id to the mailbox's
	mails []inbox.Mail      // as the mailbox read them, under the input's ids
	check func(effects []inbox.Effect) error
	stop  func()
}

func (a *account) Label(ctx context.Context, m, label string) error {
	id, ok := a.ids[m]
	if !ok {
		return inbox.NotDone("unknown-mail")
	}
	return a.box.Label(ctx, id, label)
}

func (a *account) Trash(ctx context.Context, m string) error {
	id, ok := a.ids[m]
	if !ok {
		return inbox.NotDone("unknown-mail")
	}
	return a.box.Trash(ctx, id)
}

// Post is recorded by the clerk and lands nowhere, as on the synthetic
// mailbox: a one-click POST goes to the sender's endpoint through the
// Poster, which is the same whichever mailbox the mail was read from.
func (a *account) Post(context.Context, inbox.Post) error { return nil }

// header is a raw mail's header, "" when it has none.
func header(raw []byte, name string) string {
	m, err := mail.ReadMessage(bytes.NewReader(raw))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(m.Header.Get(name))
}

// openAccount delivers mails to a fake account of kind and reads them back
// through the clerk's mailbox for it. Every mail must carry its own
// Message-ID, which is how a read mail is matched to the input's.
func openAccount(kind string, mails []inbox.Mail) (*account, error) {
	byMID := map[string]inbox.Mail{}
	for _, m := range mails {
		mid := header(m.Raw, "Message-ID")
		if _, dup := byMID[mid]; mid == "" || dup {
			return nil, fmt.Errorf("slice: mail %s has no Message-ID of its own", m.ID)
		}
		byMID[mid] = m
	}
	a := &account{ids: map[string]string{}}
	var read func(context.Context) ([]inbox.Mail, error)
	switch kind {
	case boxIMAP:
		srv, stop, err := imaptest.Run()
		if err != nil {
			return nil, err
		}
		a.stop = stop
		for _, m := range mails {
			// The fake writes CRLF line ends itself.
			srv.Deliver("INBOX", strings.ReplaceAll(string(m.Raw), "\r\n", "\n"))
		}
		st, err := imapsmtp.New(imapsmtp.Config{IMAP: srv.IMAP, SMTP: srv.SMTP, IMAPSec: imapsmtp.Plain, SMTPSec: imapsmtp.Plain,
			From: imaptest.User, Credential: func(context.Context) (imapsmtp.Login, error) {
				return imapsmtp.Login{User: imaptest.User, Secret: imaptest.Password}, nil
			}})
		if err != nil {
			stop()
			return nil, err
		}
		live := inbox.NewLive(st)
		a.box, read = live, live.Read
		a.check = func(effects []inbox.Effect) error { return checkIMAP(srv, byMID, effects) }
	case boxGmail:
		srv := gmailtest.New()
		a.stop = srv.Close
		gid := map[string]string{}
		for mid, m := range byMID {
			gid[mid] = srv.Deliver(m.Raw)
		}
		sl, err := clerk.NewAESSealer(make([]byte, 32))
		if err != nil {
			srv.Close()
			return nil, err
		}
		sec := clerk.NewSecrets(sl, nil)
		if err := sec.Put("gmail", clerk.KindGrant, gmailtest.Grant()); err != nil {
			srv.Close()
			return nil, err
		}
		api, err := clerk.NewAPI(inbox.GmailDeclaration(srv.Base(), srv.Token(), "gmail", srv.Guard(), nil), sec, srv.Roots())
		if err != nil {
			srv.Close()
			return nil, err
		}
		g := inbox.NewGmail(api)
		a.box, read = g, g.Read
		a.check = func(effects []inbox.Effect) error { return checkGmail(srv, byMID, gid, effects) }
	default:
		return nil, fmt.Errorf("slice: no mailbox %q", kind)
	}
	got, err := read(context.Background())
	if err != nil {
		a.stop()
		return nil, err
	}
	for _, m := range got {
		in, ok := byMID[header(m.Raw, "Message-ID")]
		if !ok {
			a.stop()
			return nil, fmt.Errorf("slice: the %s mailbox read a mail the run did not deliver", kind)
		}
		a.ids[in.ID] = m.ID
		a.mails = append(a.mails, inbox.Mail{ID: in.ID, Raw: m.Raw, Class: in.Class})
	}
	if len(a.mails) != len(mails) {
		a.stop()
		return nil, fmt.Errorf("slice: the %s mailbox read %d of %d mails", kind, len(a.mails), len(mails))
	}
	// The clerk reads the mails in the input's order, as on the synthetic
	// mailbox, so the plans and the log are the same.
	order := map[string]int{}
	for i, m := range mails {
		order[m.ID] = i
	}
	slices.SortFunc(a.mails, func(x, y inbox.Mail) int { return order[x.ID] - order[y.ID] })
	return a, nil
}

// effectsOf is, for each input id, whether the run trashed it and the labels
// it added.
func effectsOf(effects []inbox.Effect) (map[string]bool, map[string][]string) {
	trashed, labels := map[string]bool{}, map[string][]string{}
	for _, e := range effects {
		switch e.Verb {
		case "trash":
			trashed[e.Mail] = true
		case "organize":
			labels[e.Mail] = append(labels[e.Mail], e.Label)
		}
	}
	return trashed, labels
}

// checkIMAP is the account after the run: each trashed mail in Trash and
// every other in INBOX, each with exactly the run's keywords and none read.
func checkIMAP(srv *imaptest.Server, byMID map[string]inbox.Mail, effects []inbox.Effect) error {
	trashed, labels := effectsOf(effects)
	for mid, m := range byMID {
		folder, flags, ok := srv.Find(mid)
		want := "INBOX"
		if trashed[m.ID] {
			want = "Trash"
		}
		if !ok || folder != want {
			return fmt.Errorf("slice: imap: %s is in %q, want %s", m.ID, folder, want)
		}
		var kept []string
		for _, f := range flags {
			if strings.EqualFold(f, `\Seen`) {
				return fmt.Errorf("slice: imap: %s was marked read", m.ID)
			}
			if strings.HasPrefix(strings.ToLower(f), "agentos/") {
				kept = append(kept, strings.ToLower(f))
			}
		}
		if !sameLabels(kept, labels[m.ID]) {
			return fmt.Errorf("slice: imap: %s has labels %v, the run added %v", m.ID, kept, labels[m.ID])
		}
	}
	return nil
}

// checkGmail is checkIMAP for the Gmail fake, which also refused nothing
// the clerk asked for.
func checkGmail(srv *gmailtest.Server, byMID map[string]inbox.Mail, gid map[string]string, effects []inbox.Effect) error {
	if r := srv.Refused(); len(r) != 0 {
		return fmt.Errorf("slice: gmail: the clerk asked for what the account refuses: %v", r)
	}
	trashed, labels := effectsOf(effects)
	for mid, m := range byMID {
		g, ok := srv.Get(gid[mid])
		if !ok {
			return fmt.Errorf("slice: gmail: %s is gone", m.ID)
		}
		if !slices.Contains(g.Labels, "UNREAD") {
			return fmt.Errorf("slice: gmail: %s was marked read", m.ID)
		}
		if got, want := slices.Contains(g.Labels, "TRASH"), trashed[m.ID]; got != want || slices.Contains(g.Labels, "INBOX") == want {
			return fmt.Errorf("slice: gmail: %s has %v, trashed %v", m.ID, g.Labels, want)
		}
		var kept []string
		for _, l := range g.Labels {
			if n := srv.LabelName(l); strings.HasPrefix(n, "agentOS/") {
				kept = append(kept, strings.ToLower(n))
			}
		}
		if !sameLabels(kept, labels[m.ID]) {
			return fmt.Errorf("slice: gmail: %s has labels %v, the run added %v", m.ID, kept, labels[m.ID])
		}
	}
	return nil
}

func sameLabels(got, added []string) bool {
	want := map[string]bool{}
	for _, l := range added {
		want[strings.ToLower(l)] = true
	}
	have := map[string]bool{}
	for _, l := range got {
		have[l] = true
	}
	if len(have) != len(want) {
		return false
	}
	for l := range want {
		if !have[l] {
			return false
		}
	}
	return true
}
