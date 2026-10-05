package mail_test

// REQ: CH-20, CRED-7

import (
	"slices"
	"strings"
	"testing"

	"github.com/ghbmrk/agentos/broker/journal"
	"github.com/ghbmrk/agentos/broker/mail"
	"github.com/ghbmrk/agentos/broker/verb"
)

func deliverIntent(x *h, body string, recips ...string) journal.Intent {
	in := x.intent(mail.OpDeliver, map[string]any{mail.ParamBody: body}, recips...)
	in.Origin = "broker:evidence"
	return in
}

// TestDeliverSendsTheReplyToTheOwnersOwnAddress: the evidence route's one
// operation is a share to the owner (CH-20), with a fixed subject, and it
// reconciles like any sent message.
func TestDeliverSendsTheReplyToTheOwnersOwnAddress(t *testing.T) {
	if mail.Declared()[mail.OpDeliver] != verb.Share {
		t.Fatalf("mail.deliver declares %q, want share", mail.Declared()[mail.OpDeliver])
	}
	x := newH(t, func(c *mail.Config) { c.AppendSent = true })
	in := deliverIntent(x, "The full reply.\nSecond line.", me)
	o := outgoing(t, x.mustRun(in))
	subs := x.srv.Submitted()
	if len(subs) != 1 || !slices.Equal(subs[0].Rcpt, []string{me}) {
		t.Fatalf("submitted %+v", subs)
	}
	raw := string(subs[0].Raw)
	for _, want := range []string{"To: " + me + "\r\n", "Subject: " + mail.DeliverSubject + "\r\n", "The full reply.\r\nSecond line."} {
		if !strings.Contains(raw, want) {
			t.Fatalf("message lacks %q:\n%s", want, raw)
		}
	}
	if o.Op != mail.OpDeliver || o.Folder != "Sent" {
		t.Fatalf("evidence %+v", o)
	}
	if out := x.a.Reconcile(ctx, in, 1); out.Result != journal.ResultSucceeded {
		t.Fatalf("reconcile: %+v", out)
	}
	if out := x.a.Reconcile(ctx, in, 2); out.Result != journal.ResultUnknown {
		t.Fatalf("reconcile of an attempt never made: %+v", out)
	}
}

// TestDeliverGoesToNoOneElse: the executor re-checks that the one
// recipient is the account's own address, so even an intent the gate let
// through by mistake cannot mail a third party, and it takes no subject.
func TestDeliverGoesToNoOneElse(t *testing.T) {
	x := newH(t, func(c *mail.Config) { c.Aliases = []string{"alias@example.test"} })
	for _, rc := range [][]string{{"sam@example.com"}, {me, "sam@example.com"}, {"Owner <" + me + ">"}, nil} {
		if out := x.run(deliverIntent(x, "b", rc...)); out.Result != journal.ResultNotApplied {
			t.Fatalf("recipients %q: %+v", rc, out)
		}
	}
	if out := x.run(x.intent(mail.OpDeliver, map[string]any{mail.ParamBody: "b"}, me)); out.Result != journal.ResultNotApplied {
		t.Fatalf("an agent delivered: %+v", out)
	}
	in := deliverIntent(x, "b", me)
	in.Params[mail.ParamSubject] = "Click here"
	if out := x.run(in); out.Result != journal.ResultNotApplied {
		t.Fatalf("subject taken: %+v", out)
	}
	if n := len(x.srv.Submitted()); n != 0 {
		t.Fatalf("submitted %d", n)
	}
	x.mustRun(deliverIntent(x, "b", "alias@example.test"))
	if !x.a.Owns(me) || !x.a.Owns("ALIAS@example.test") || x.a.Owns("sam@example.com") || x.a.Owns("not an address") {
		t.Fatal("Owns")
	}
}

// TestDeliverRedactsVaultValues: CRED-7 applies to evidence. The vault
// process runs the store and passes its redactor; a canary never leaves.
func TestDeliverRedactsVaultValues(t *testing.T) {
	const canary = "CANARY-ch20-0f3a"
	x := newH(t, func(c *mail.Config) {
		c.Redact = func(s string) string { return strings.ReplaceAll(s, canary, "[REDACTED]") }
	})
	x.mustRun(deliverIntent(x, "The key is "+canary+".", me))
	raw := string(x.srv.Submitted()[0].Raw)
	if strings.Contains(raw, canary) || !strings.Contains(raw, "The key is [REDACTED].") {
		t.Fatalf("not redacted:\n%s", raw)
	}
}
