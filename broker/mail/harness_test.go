package mail_test

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/journal"
	"github.com/ghbmrk/agentos/broker/mail"
	"github.com/ghbmrk/agentos/broker/mail/imapsmtp"
	"github.com/ghbmrk/agentos/broker/mail/mailtest"
)

var ctx = context.Background()

const me = mailtest.User

// h is one account on the local test server, with the adapter over the
// real IMAP and SMTP backend.
type h struct {
	t     *testing.T
	srv   *mailtest.Server
	store *imapsmtp.Store
	a     *mail.Adapter
	cfg   mail.Config
	now   time.Time
	n     int
}

func newH(t *testing.T, edit func(*mail.Config)) *h {
	t.Helper()
	srv := mailtest.Start(t)
	st, err := imapsmtp.New(imapsmtp.Config{IMAP: srv.IMAP, SMTP: srv.SMTP, IMAPSec: imapsmtp.Plain, SMTPSec: imapsmtp.Plain,
		From: me, Credential: func(context.Context) (imapsmtp.Login, error) {
			return imapsmtp.Login{User: mailtest.User, Secret: mailtest.Password}, nil
		}})
	if err != nil {
		t.Fatal(err)
	}
	x := &h{t: t, srv: srv, store: st, now: time.Date(2026, 10, 5, 9, 0, 0, 0, time.UTC)}
	x.cfg = mail.Config{Account: "mail", Address: me, Store: st, AuthServ: "mx.example.test",
		SecuritySenders: []string{"security@provider.example"}, Folders: []string{"Receipts"},
		Labels: []string{"Family"}, Shared: []string{"Team"}, Retention: []string{"Legal"},
		InUse: func(string, time.Time) []journal.Use { return nil },
		Now:   func() time.Time { return x.now }}
	srv.AddFolder("Receipts", "")
	srv.AddFolder("Team", "")
	srv.AddFolder("Legal", "")
	if edit != nil {
		edit(&x.cfg)
	}
	if x.a, err = mail.New(x.cfg); err != nil {
		t.Fatal(err)
	}
	return x
}

// msg is a synthetic message. Extra header lines go before the body.
type msg struct {
	id, from, to, cc, subject, body, inReplyTo, refs string
	extra                                            []string
}

func (m msg) raw() string {
	s := ""
	for _, e := range m.extra {
		s += e + "\n"
	}
	s += "From: " + m.from + "\nTo: " + m.to + "\n"
	if m.cc != "" {
		s += "Cc: " + m.cc + "\n"
	}
	s += "Subject: " + m.subject + "\nDate: Mon, 05 Oct 2026 08:00:00 +0000\nMessage-ID: " + m.id + "\n"
	if m.inReplyTo != "" {
		s += "In-Reply-To: " + m.inReplyTo + "\n"
	}
	if m.refs != "" {
		s += "References: " + m.refs + "\n"
	}
	return s + "Content-Type: text/plain; charset=utf-8\n\n" + m.body + "\n"
}

func (x *h) deliver(folder string, m msg, flags ...string) {
	x.srv.Deliver(folder, m.raw(), flags...)
}

// news delivers a plain newsletter to the inbox and returns its ID.
func (x *h) news(i int) string {
	id := fmt.Sprintf("<news-%d@shop.example>", i)
	x.deliver("INBOX", msg{id: id, from: "Shop <deals@shop.example>", to: me, subject: fmt.Sprintf("Autumn sale %d", i), body: "Twenty percent off boots."})
	return id
}

func (x *h) intent(action string, params map[string]any, recips ...string) journal.Intent {
	x.n++
	return journal.Intent{ID: fmt.Sprintf("agent/%d", x.n), Origin: "guest:agent", Account: "mail", Action: action,
		Params: params, Recipients: recips, Executor: "mail"}
}

// run executes in as the journal does after the gate: the dispatch
// recheck's Escalate (which pins what it judged), then Execute.
func (x *h) run(in journal.Intent) journal.Outcome {
	x.t.Helper()
	x.a.Escalate(ctx, in)
	return x.a.Execute(ctx, in, 1)
}

// uses wraps intents as the journal's places in use.
func uses(xs []journal.Intent) []journal.Use {
	out := make([]journal.Use, len(xs))
	for i, x := range xs {
		out[i] = journal.Use{Intent: x}
	}
	return out
}

func (x *h) mustRun(in journal.Intent) journal.Outcome {
	x.t.Helper()
	out := x.run(in)
	if out.Result != journal.ResultSucceeded {
		x.t.Fatalf("%s: %s %s", in.Action, out.Result, out.Evidence)
	}
	return out
}

func change(t *testing.T, out journal.Outcome) mail.Change {
	t.Helper()
	c, err := mail.ParseChange(out.Evidence)
	if err != nil {
		t.Fatalf("evidence %q: %v", out.Evidence, err)
	}
	return c
}

func outgoing(t *testing.T, out journal.Outcome) mail.Outgoing {
	t.Helper()
	var o mail.Outgoing
	if err := json.Unmarshal([]byte(out.Evidence), &o); err != nil {
		t.Fatal(err)
	}
	return o
}

func rec(id string) map[string]any { return map[string]any{mail.ParamRecord: id} }
