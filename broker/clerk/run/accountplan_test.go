package run

// REQ: TN-account-plan-6, CLK-9, CLK-14, DEV-8, A22

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/ghbmrk/agentos/broker/clerk/accounts"
	"github.com/ghbmrk/agentos/broker/clerk/inbox"
	"github.com/ghbmrk/agentos/broker/clerk/inbox/gmailtest"
	"github.com/ghbmrk/agentos/broker/clerk/inbox/imapsmtp"
	"github.com/ghbmrk/agentos/broker/clerk/inbox/imapsmtp/imaptest"
)

// planCanary is in every mail field the plan must drop.
const planCanary = "canary-plan-7f3a"

// googleMail is a welcome mail from Google, DKIM-authenticated by Gmail's
// own Authentication-Results in the shape Gmail writes it (header.i, no
// header.d), with the canary in the name, the local part and the subject.
func googleMail(authServ string) []byte {
	return []byte("Authentication-Results: " + authServ + ";\r\n       dkim=pass header.i=@accounts.google.com header.s=s1 header.b=AbCd;\r\n" +
		"       spf=pass smtp.mailfrom=bounce@accounts.google.com\r\n" +
		"From: " + planCanary + " <" + planCanary + "@accounts.google.com>\r\nTo: " + gmailtest.User + "\r\nSubject: Welcome " + planCanary +
		"\r\nMessage-ID: <" + planCanary + "@accounts.google.com>\r\n\r\nsynthetic body " + planCanary + "\r\n")
}

// planConfig is gmailConfig with Gmail's authserv-id as the world's.
func planConfig(srv *gmailtest.Server) MailConfig {
	c := gmailConfig(srv)
	c.World = func() inbox.World { return inbox.World{Today: "2026-10-21", AuthServ: "mx.google.com"} }
	return c
}

// planIDs is the plan's item IDs, in order.
func planIDs(p AccountPlanned) []string {
	var ids []string
	for _, it := range p.Items {
		ids = append(ids, it.ID)
	}
	return ids
}

// TN-account-plan-6: the mail clerk's accountplan answers only plan items:
// table IDs, the table's wording and a source tag. A sender Gmail
// authenticated adds its entry, found in mail; a sender another server
// vouched for adds nothing; no byte of any mail crosses the socket.
func TestAccountPlanOpSendsOnlyItems(t *testing.T) {
	srv, dir, sec := newGmailAccount(t)
	srv.Deliver(googleMail("mx.google.com"))
	srv.Deliver(googleMail("mx.evil.test"))
	owner := MailOwner{serveMail(t, NewMailHost(context.Background(), dir, sec, planConfig(srv)), MailOwnerSide)}
	var raw json.RawMessage
	if err := owner.Call("accountplan", nil, &raw); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte(planCanary)) || bytes.Contains(raw, []byte(gmailtest.User)) {
		t.Fatalf("the plan carries mail bytes: %s", raw)
	}
	var p AccountPlanned
	if err := json.Unmarshal(raw, &p); err != nil || p.Reason != "" {
		t.Fatalf("plan %s: %v", raw, err)
	}
	if want := []string{accounts.CardID, accounts.WalletID, accounts.MailboxID, "gmail"}; !slices.Equal(planIDs(p), want) {
		t.Fatalf("plan %v, want %v", planIDs(p), want)
	}
	g := p.Items[3]
	if g.Source != string(accounts.FromMail) || !g.Connected || g.Label != accounts.LabelNarrower || g.Advice != accounts.AdviceNarrower {
		t.Fatalf("the Gmail item %+v", g)
	}
	tbl, err := accounts.Known()
	if err != nil {
		t.Fatal(err)
	}
	for _, it := range p.Items {
		e, ok := tbl.Entry(it.ID)
		if !ok || it.Name != e.Name || it.Kind != e.Kind || it.Group != e.Group {
			t.Fatalf("item %+v is not its table entry's", it)
		}
		if it.ID != "gmail" && it.Connected {
			t.Fatalf("item %+v marked connected", it)
		}
	}
	// Only the item fields cross: a field added to the answer fails here.
	var keys []map[string]any
	var outer map[string]json.RawMessage
	json.Unmarshal(raw, &outer)
	json.Unmarshal(outer["items"], &keys)
	allowed := []string{"id", "name", "kind", "group", "source", "preselected", "label", "advice", "connected"}
	for k := range outer {
		if k != "items" && k != "reason" {
			t.Fatalf("the answer carries %q", k)
		}
	}
	for _, m := range keys {
		for k := range m {
			if !slices.Contains(allowed, k) {
				t.Fatalf("an item carries %q", k)
			}
		}
	}
	if n := reflect.TypeOf(PlanItem{}).NumField(); n != len(allowed) {
		t.Fatalf("PlanItem has %d fields, the test allows %d", n, len(allowed))
	}
}

// A verdict another server wrote, or a pass under another authserv-id than
// the world's, adds nothing: the mailbox's own verdict alone counts.
func TestAccountPlanTakesOnlyTheProvidersVerdict(t *testing.T) {
	for _, authServ := range []string{"mx.evil.test", ""} {
		srv, dir, sec := newGmailAccount(t)
		srv.Deliver(googleMail("mx.evil.test"))
		c := planConfig(srv)
		if authServ == "" {
			srv.Deliver(googleMail("mx.google.com"))
			c.World = func() inbox.World { return inbox.World{Today: "2026-10-21"} } // fails closed
		}
		owner := MailOwner{serveMail(t, NewMailHost(context.Background(), dir, sec, c), MailOwnerSide)}
		p, err := owner.AccountPlan()
		if want := []string{accounts.CardID, accounts.WalletID, accounts.MailboxID}; err != nil || !slices.Equal(planIDs(p), want) {
			t.Fatalf("authserv %q: %v %v, want %v", authServ, planIDs(p), err, want)
		}
	}
}

// The lifecycle on the clerk's side: the plan is built once and served from
// memory, built again by a new process for the same result, and dropped
// with the account it was read from.
func TestAccountPlanIsKeptForTheAccountAndRebuiltAfterARestart(t *testing.T) {
	srv, dir, sec := newGmailAccount(t)
	srv.Deliver(googleMail("mx.google.com"))
	owner := MailOwner{serveMail(t, NewMailHost(context.Background(), dir, sec, planConfig(srv)), MailOwnerSide)}
	first, err := owner.AccountPlan()
	if err != nil {
		t.Fatal(err)
	}
	n := len(srv.Requests())
	again, err := owner.AccountPlan()
	if err != nil || !reflect.DeepEqual(again, first) || len(srv.Requests()) != n {
		t.Fatalf("reopened: %+v %v, %d requests after %d", again, err, len(srv.Requests()), n)
	}
	restarted := MailOwner{serveMail(t, NewMailHost(context.Background(), dir, sec, planConfig(srv)), MailOwnerSide)}
	if p, err := restarted.AccountPlan(); err != nil || !reflect.DeepEqual(p, first) {
		t.Fatalf("after a restart: %+v %v, want %+v", p, err, first)
	}
	if err := owner.RemoveMail(); err != nil {
		t.Fatal(err)
	}
	p, err := owner.AccountPlan()
	if want := []string{accounts.CardID, accounts.WalletID, accounts.MailboxID}; err != nil || !slices.Equal(planIDs(p), want) {
		t.Fatalf("with no account: %v %v, want %v", planIDs(p), err, want)
	}
	if p.Items[0].Preselected != true || p.Items[2].Preselected || p.Items[2].Label != accounts.LabelFull {
		t.Fatalf("the card or mailbox: %+v", p.Items)
	}
}

// A22's Gmail clause: a grant Gmail refuses at refresh is grant death. The
// answer is the typed reason and no plan, never a part of one, and no
// further call goes to Google until the owner signs in again.
func TestAccountPlanReportsGrantDeath(t *testing.T) {
	srv, dir, sec := newGmailAccount(t)
	srv.Deliver(googleMail("mx.google.com"))
	h := NewMailHost(context.Background(), dir, sec, planConfig(srv))
	if _, stop := h.clerk(); stop != nil {
		t.Fatalf("the account did not open: %v", stop)
	}
	owner := MailOwner{serveMail(t, h, MailOwnerSide)}
	srv.RefuseGrant()
	srv.Expire()
	p, err := owner.AccountPlan()
	if err != nil || p.Reason != DReconnect || len(p.Items) != 0 {
		t.Fatalf("grant refused: %+v %v", p, err)
	}
	if _, stop := h.clerk(); !errors.Is(stop, inbox.ErrReconnect) {
		t.Fatalf("the clerk goes on calling Google: stop %v", stop)
	}
	if st, err := owner.Status(); err != nil || len(st.Lines) == 0 || !strings.Contains(st.Lines[0], "I stopped working in your mailbox") {
		t.Fatalf("the clerk stopped but STATUS does not say so: %q %v", st.Lines, err)
	}
	n := len(srv.Requests())
	if p, err = owner.AccountPlan(); err != nil || p.Reason != DReconnect || len(p.Items) != 0 || len(srv.Requests()) != n {
		t.Fatalf("again: %+v %v, %d requests after %d", p, err, len(srv.Requests()), n)
	}
}

// imapPlanHost is a mail host over r's IMAP account, in a world whose
// mailbox provider is declared with authServ.
func imapPlanHost(t *testing.T, r *mailRig, authServ string) (*MailHost, MailOwner) {
	c := mailConfig()
	c.World = func() inbox.World { return inbox.World{Today: "2026-10-21", AuthServ: authServ} }
	h := NewMailHost(context.Background(), r.dir, r.sec, c)
	return h, MailOwner{serveMail(t, h, MailOwnerSide)}
}

// imapMail is m as the IMAP test server takes it (it writes each LF as CRLF).
func imapMail(m []byte) string { return strings.ReplaceAll(string(m), "\r\n", "\n") }

// The lifecycle's "Mailbox over IMAP" (#3220, A22): the same rule reads the
// same two fields over IMAP. A sender the declared provider authenticated
// adds its entry, found in mail, from any folder but spam and trash; a
// verdict another server wrote, or any verdict with no authserv-id
// declared, adds nothing; no byte of mail crosses; and no item is marked
// connected, since an IMAP account is Full power whoever serves it.
func TestAccountPlanReadsSendersOverIMAP(t *testing.T) {
	fixed := []string{accounts.CardID, accounts.WalletID, accounts.MailboxID}
	for _, c := range []struct {
		name, authServ, folder, verdict string
		want                            []string
	}{
		{"authenticated", "mx.google.com", "Archive", "mx.google.com", append(slices.Clone(fixed), "gmail")},
		{"forged verdict", "mx.google.com", "INBOX", "mx.evil.test", fixed},
		{"no authserv-id declared", "", "INBOX", "mx.google.com", fixed},
		{"in spam", "mx.google.com", "Junk", "mx.google.com", fixed},
		{"in trash", "mx.google.com", "Trash", "mx.google.com", fixed},
	} {
		r := newMailRig(t, "<a@shop.test>")
		r.srv.Deliver(c.folder, imapMail(googleMail(c.verdict)))
		_, owner := imapPlanHost(t, r, c.authServ)
		var raw json.RawMessage
		if err := owner.Call("accountplan", nil, &raw); err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if bytes.Contains(raw, []byte(planCanary)) || bytes.Contains(raw, []byte("shop.test")) {
			t.Fatalf("%s: the plan carries mail bytes: %s", c.name, raw)
		}
		var p AccountPlanned
		if err := json.Unmarshal(raw, &p); err != nil || p.Reason != "" || !slices.Equal(planIDs(p), c.want) {
			t.Fatalf("%s: %v %q %v, want %v", c.name, planIDs(p), p.Reason, err, c.want)
		}
		for _, it := range p.Items {
			if it.Connected {
				t.Fatalf("%s: IMAP item %+v marked connected", c.name, it)
			}
			if it.ID == accounts.MailboxID && it.Label != accounts.LabelFull {
				t.Fatalf("%s: the mailbox %+v", c.name, it)
			}
			if it.ID == "gmail" && it.Source != string(accounts.FromMail) {
				t.Fatalf("%s: the Gmail item %+v", c.name, it)
			}
		}
	}
}

// A sign-in the IMAP server refuses while the plan is read is that
// account's grant death: the typed reason and no plan, and the clerk stops
// signing in until the owner sets the account up again.
func TestAccountPlanOverIMAPReportsARefusedSignIn(t *testing.T) {
	r := newMailRig(t, "<a@shop.test>")
	r.srv.Deliver("INBOX", imapMail(googleMail("mx.google.com")))
	h, owner := imapPlanHost(t, r, "mx.google.com")
	if _, stop := h.clerk(); stop != nil {
		t.Fatalf("the account did not open: %v", stop)
	}
	if err := SetMail(r.dir, r.sec, MailSettings{Address: imaptest.User, IMAP: r.srv.IMAP, SMTP: r.srv.SMTP}, "a-wrong-password-1"); err != nil {
		t.Fatal(err)
	}
	p, err := owner.AccountPlan()
	if err != nil || p.Reason != DSignInRefused || len(p.Items) != 0 {
		t.Fatalf("sign-in refused: %+v %v", p, err)
	}
	if _, stop := h.clerk(); !errors.Is(stop, imapsmtp.ErrLoginRefused) {
		t.Fatalf("the clerk goes on signing in: stop %v", stop)
	}
}
