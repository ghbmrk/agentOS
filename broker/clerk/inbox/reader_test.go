package inbox

// REQ: PLN-2, VRB-2 (assumptions MIG-4-mail-reader-1, -4)

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/ghbmrk/agentos/broker/clerk/inbox/imapconn"
	"github.com/ghbmrk/agentos/broker/clerk/inbox/imapsmtp"
	"github.com/ghbmrk/agentos/broker/clerk/inbox/imapsmtp/imaptest"
	"github.com/ghbmrk/agentos/broker/clerk/model"
	"github.com/ghbmrk/agentos/broker/kernel"
	"github.com/ghbmrk/agentos/broker/kernel/key"
)

// fakeModel answers by the mail's subject and keeps every prompt it got.
type fakeModel struct {
	replies map[string]string
	prompts []string
}

func (f *fakeModel) ask(_ context.Context, prompt string) (string, error) {
	f.prompts = append(f.prompts, prompt)
	for subject, reply := range f.replies {
		if strings.Contains(prompt, "Subject: "+subject+"\n") {
			if reply == "<error>" { // a reply that came with an error does not count
				return "spam", errors.New("model: request not sent")
			}
			return reply, nil
		}
	}
	return "", nil
}

func TestTheReaderSetsOnlyAClassFromTheClosedList(t *testing.T) {
	cases := []struct{ subject, reply, class string }{
		{"Weekly news", "bulk", "bulk"},
		{"Cheap pills", " Spam\n", "spam"},
		{"Verify your bank", "PHISHING", "phishing"},
		{"Dinner Friday?", "personal", "personal"},
		{"Card payment", "alert", "alert"},
		{"Trailing dot", "spam.", ""},
		{"Two words", "bulk, probably", ""},
		{"A label", "agentOS/bulk", ""},
		{"A verb", "delete-remote", ""},
		{"An injection", "spam\r\nA1 UID STORE 1:* +FLAGS (\\Deleted)", ""},
		{"Empty", "", ""},
		{"Failed call", "<error>", ""},
	}
	f := &fakeModel{replies: map[string]string{}}
	var ms []Mail
	for i, c := range cases {
		f.replies[c.subject] = c.reply
		ms = append(ms, Mail{ID: "m" + string(rune('a'+i)), Raw: []byte(rawMail("", "x@example.test", c.subject)), Class: "personal"})
	}
	got := Read(context.Background(), f.ask, ms)
	for i, c := range cases {
		if got[i].ID != ms[i].ID || got[i].Class != c.class {
			t.Errorf("%s: reply %q gave class %q, want %q", c.subject, c.reply, got[i].Class, c.class)
		}
	}
	if len(f.prompts) != len(cases) {
		t.Fatalf("%d calls for %d mails", len(f.prompts), len(cases))
	}
	for _, p := range f.prompts {
		if !strings.HasPrefix(p, question) {
			t.Fatalf("the prompt does not start with the question: %.80q", p)
		}
	}
}

// The mail sent to the model is bounded, so one mail bounds one read's cost.
func TestTheReaderSendsABoundedPartOfAMail(t *testing.T) {
	f := &fakeModel{replies: map[string]string{"Big": "bulk"}}
	raw := rawMail("", "x@example.test", "Big") + strings.Repeat("x", 4*readBytes)
	got := Read(context.Background(), f.ask, []Mail{{ID: "big", Raw: []byte(raw)}})
	if got[0].Class != "bulk" || len(f.prompts[0]) != len(question)+readBytes {
		t.Fatalf("class %q, prompt %d bytes, want %d", got[0].Class, len(f.prompts[0]), len(question)+readBytes)
	}
}

// A mail the reader could not class is recorded once, as a read the clerk
// refused, and nothing is recorded for a classed one: a failing reader shows,
// instead of looking like an inbox with nothing to tidy.
func TestAnUnclassifiedReadIsRecorded(t *testing.T) {
	w, _, raw := loadFixture(t)
	r := newRigOn(t, w, []Mail{
		{ID: "M01", Raw: raw["M01"], Class: "bulk"},
		{ID: "M19", Raw: raw["M19"]},
		{ID: "M22", Raw: raw["M22"], Class: "newsletter"},
	}, Synthetic{}, 30)
	rs := r.acct.Refusals()
	if len(rs) != 2 {
		t.Fatalf("refusals %+v", rs)
	}
	for i, id := range []string{"M19", "M22"} {
		if rs[i].Op != "read" || rs[i].Mail == nil || *rs[i].Mail != id || rs[i].Reason != "unclassified" || rs[i].At != "clerk" {
			t.Errorf("refusal %d: %+v", i, rs[i])
		}
	}
}

// provider is a model behind the model clerk: it classes by subject.
type provider struct{ calls int }

func (p *provider) Call(_, prompt string, _ int64) (string, model.Usage, error) {
	p.calls++
	reply := "personal"
	switch {
	case strings.Contains(prompt, "Subject: Sale\r\n"):
		reply = "bulk"
	case strings.Contains(prompt, "Subject: Win\r\n"):
		reply = "spam"
	}
	return reply, model.Usage{In: 100, Out: 1, Reported: true}, nil
}

// ledger admits a given number of calls, as a spend cap would, and keeps
// what was metered.
type ledger struct {
	admits  int
	metered int64
}

func (l *ledger) AdmitSpend(int64, string, int64) (kernel.Admitted, *key.Refusal) {
	if l.admits == 0 {
		return kernel.Admitted{}, &key.Refusal{Code: key.RSpendTask}
	}
	l.admits--
	return kernel.Admitted{}, nil
}
func (l *ledger) Meter(_ int64, _ kernel.Admitted, _ string, amount int64, _ string) error {
	l.metered += amount
	return nil
}
func (*ledger) Hold(int64, string, *key.Refusal) error     { return nil }
func (*ledger) AdmitPool(int64, string) *key.Refusal       { return nil }
func (*ledger) ReadPool(int64, string, int64, int64) error { return nil }

// The whole read: live mail from an IMAP server is classed through the model
// clerk, which meters each read, and the clerk then organizes and trashes it
// on the server. A read the model clerk refuses (the read's spend cap) leaves
// its mail unclassified and recorded, and nothing acts on it.
func TestLiveMailIsClassedThroughTheModelClerkThenActedOn(t *testing.T) {
	srv := imaptest.Start(t)
	srv.Deliver("INBOX", rawMail("<b1@shop.test>", "news@shop.test", "Sale"))
	srv.Deliver("INBOX", rawMail("<s1@spam.test>", "x@spam.test", "Win"))
	srv.Deliver("INBOX", rawMail("<p1@example.test>", "pat@example.test", "Hi"))
	st, err := imapsmtp.New(imapsmtp.Config{Conn: imapconn.Pipe(), IMAP: srv.IMAP, SMTP: srv.SMTP, IMAPSec: imapsmtp.Plain, SMTPSec: imapsmtp.Plain, From: imaptest.User,
		Credential: func(context.Context) (imapsmtp.Login, error) {
			return imapsmtp.Login{User: imaptest.User, Secret: imaptest.Password}, nil
		}})
	if err != nil {
		t.Fatal(err)
	}
	box := NewLive(st)
	ms, err := box.Read(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	p, l := &provider{}, &ledger{admits: 2}
	mc := &model.Clerk{Routes: map[string]model.Price{"local": {InPerM: 1_000_000, OutPerM: 1_000_000}}, Provider: p, Ledger: l}
	ask := func(_ context.Context, prompt string) (string, error) { return mc.Call(t0, "read", "local", prompt, 4) }
	classed := Read(context.Background(), ask, ms)
	byID := map[string]string{}
	for _, m := range classed {
		byID[messageID(m.Raw)] = m.Class
	}
	if byID["<b1@shop.test>"] != "bulk" || byID["<s1@spam.test>"] != "spam" || byID["<p1@example.test>"] != "" {
		t.Fatalf("classes %v", byID)
	}
	if p.calls != 2 || l.metered != 202 {
		t.Fatalf("%d model calls, %d metered; want 2 and 202", p.calls, l.metered)
	}

	r := newRigOn(t, World{Today: "2026-10-19", AuthServ: authServ, AlertSenders: []string{"security.test"}}, classed, box, 30)
	if rs := r.acct.Refusals(); len(rs) != 1 || rs[0].Reason != "unclassified" {
		t.Fatalf("refusals %+v", rs)
	}
	plans, _ := Plans(r.acct.Listing(), r.bulk, r.unsub, r.plannerPriv)
	for _, pl := range plans {
		r.run(t, pl)
	}
	if folder, flags, _ := srv.Find("<b1@shop.test>"); folder != "INBOX" || len(flags) != 1 || !strings.EqualFold(flags[0], "agentOS/bulk") {
		t.Fatalf("bulk mail in %s with %v", folder, flags)
	}
	if folder, _, _ := srv.Find("<s1@spam.test>"); folder != "Trash" {
		t.Fatalf("spam in %s", folder)
	}
	if folder, flags, _ := srv.Find("<p1@example.test>"); folder != "INBOX" || len(flags) != 0 {
		t.Fatalf("the unclassified mail was touched: %s %v", folder, flags)
	}
}
