package mail_test

import (
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/ghbmrk/agentos/broker/journal"
	"github.com/ghbmrk/agentos/broker/mail"
)

// thread puts a three-message thread in the account: the owner wrote to
// sam, sam replied, and then sam replied again copying bob.
func thread(x *h) {
	x.deliver("Sent", msg{id: "<t1@example.test>", from: me, to: "sam@example.com", subject: "Lunch", body: "Lunch next week?"})
	x.deliver("INBOX", msg{id: "<t2@example.com>", from: "Sam <sam@example.com>", to: me, subject: "Re: Lunch",
		body: "Sure. Private note: my door code is behind the plant.", inReplyTo: "<t1@example.test>", refs: "<t1@example.test>"})
	x.deliver("INBOX", msg{id: "<t3@example.com>", from: "sam@example.com", to: me, cc: "Bob <bob@example.com>", subject: "Re: Lunch",
		body: "Adding Bob.", inReplyTo: "<t2@example.com>", refs: "<t1@example.test> <t2@example.com>"})
}

func reply(id, body string) map[string]any {
	return map[string]any{mail.ParamRecord: id, mail.ParamBody: body}
}

// REQ: ADP-11, CH-10, OP-1, OP-2

// TestReplyIsVerifiedFromTheSource: a reply's recipients are the thread's
// participants as the source headers name them, never the agent's, and
// the thread counts as verified only when the owner (as Sent shows) or an
// authenticated contact started it and every recipient was on a message
// the owner sent or that contact's first one.
func TestReplyIsVerifiedFromTheSource(t *testing.T) {
	x := newH(t, func(c *mail.Config) { c.AppendSent = true })
	thread(x)
	v, err := x.a.Verify(ctx, x.intent(mail.OpReply, reply("<t2@example.com>", "Works for me."), "sam@example.com"))
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(v.Recipients, []string{"sam@example.com"}) || v.Record != "<t2@example.com>" ||
		!v.ThreadVerified || v.Attachments || v.Item.Recipient != "sam@example.com" ||
		v.Item.Object != `reply to "Re: Lunch"` || !v.Item.Facts.RecipientChecked {
		t.Fatalf("verified %+v", v)
	}
	// Sam copied Bob in: a reply goes to both, but the thread no longer
	// counts as verified, since the owner never wrote to Bob.
	v, err = x.a.Verify(ctx, x.intent(mail.OpReply, reply("<t3@example.com>", "Works for me."), "sam@example.com", "bob@example.com"))
	if err != nil || !slices.Equal(v.Recipients, []string{"bob@example.com", "sam@example.com"}) || v.ThreadVerified {
		t.Fatalf("third party's Cc: %+v %v", v, err)
	}
	// Reply-To cannot redirect a reply.
	x.deliver("INBOX", msg{id: "<cold@x.example>", from: "stranger@x.example", to: me, subject: "Hi",
		body: "hello", extra: []string{"Reply-To: attacker@evil.example"}})
	v, err = x.a.Verify(ctx, x.intent(mail.OpReply, reply("<cold@x.example>", "Hi"), "stranger@x.example"))
	if err != nil || !slices.Equal(v.Recipients, []string{"stranger@x.example"}) || v.ThreadVerified {
		t.Fatalf("cold message: %+v %v", v, err)
	}
	// A contact's thread verifies only with an aligned DMARC pass from
	// the provider: anyone can put a contact's address in From.
	y := newH(t, func(c *mail.Config) { c.Contacts = func(a string) bool { return a == "stranger@x.example" } })
	y.deliver("INBOX", msg{id: "<cold@x.example>", from: "stranger@x.example", to: me, subject: "Hi", body: "hello",
		extra: []string{"Authentication-Results: mx.example.test; dmarc=pass header.from=x.example"}})
	if v, _ := y.a.Verify(ctx, y.intent(mail.OpReply, reply("<cold@x.example>", "Hi"), "stranger@x.example")); !v.ThreadVerified || !v.Item.Facts.RecipientExists {
		t.Fatalf("contact's thread: %+v", v)
	}
	y.deliver("INBOX", msg{id: "<spoof@x.example>", from: "stranger@x.example", to: me, subject: "Hi", body: "hello"})
	if v, _ := y.a.Verify(ctx, y.intent(mail.OpReply, reply("<spoof@x.example>", "Hi"), "stranger@x.example")); v.ThreadVerified {
		t.Fatal("an unauthenticated contact's thread verified")
	}
	// A new message has no source record: the gate shows it unverified.
	if _, err := x.a.Verify(ctx, x.intent(mail.OpSend, map[string]any{"subject": "s", "body": "b"}, "sam@example.com")); !errors.Is(err, mail.ErrUnverifiable) {
		t.Fatalf("new message verified: %v", err)
	}
}

// TestReplySendsToTheThreadAndReconciles: the executor re-reads the
// thread, refuses recipients that are not exactly its participants, and
// sends a threaded reply whose Message-ID Reconcile finds in Sent.
func TestReplySendsToTheThreadAndReconciles(t *testing.T) {
	x := newH(t, func(c *mail.Config) { c.AppendSent = true })
	thread(x)
	if out := x.run(x.intent(mail.OpReply, reply("<t3@example.com>", "Works."), "sam@example.com")); out.Result != journal.ResultNotApplied || len(x.srv.Submitted()) != 0 {
		t.Fatalf("narrower recipients sent: %+v", out)
	}
	if out := x.run(x.intent(mail.OpReply, reply("<t3@example.com>", "Works."), "sam@example.com", "bob@example.com", "eve@example.net")); out.Result != journal.ResultNotApplied {
		t.Fatalf("added recipient sent: %+v", out)
	}
	in := x.intent(mail.OpReply, reply("<t3@example.com>", "Works for me.\nSee you then."), "SAM@example.com", "bob@example.com")
	o := outgoing(t, x.mustRun(in))
	subs := x.srv.Submitted()
	if len(subs) != 1 {
		t.Fatalf("submitted %d", len(subs))
	}
	s := subs[0]
	raw := string(s.Raw)
	if s.From != me || !slices.Equal(sortedCopy(s.Rcpt), []string{"bob@example.com", "sam@example.com"}) || s.Auth != "PLAIN" {
		t.Fatalf("envelope %+v", s)
	}
	for _, want := range []string{"To: sam@example.com\r\n", "Cc: bob@example.com\r\n", "Subject: Re: Lunch\r\n",
		"In-Reply-To: <t3@example.com>\r\n", "References: <t1@example.test> <t2@example.com> <t3@example.com>\r\n",
		"Message-ID: " + o.MessageID + "\r\n", "Works for me.\r\nSee you then."} {
		if !strings.Contains(raw, want) {
			t.Fatalf("message lacks %q:\n%s", want, raw)
		}
	}
	if o.Folder != "Sent" || !strings.HasSuffix(o.MessageID, "@example.test>") {
		t.Fatalf("evidence %+v", o)
	}
	if out := x.a.Reconcile(ctx, in, 1); out.Result != journal.ResultSucceeded {
		t.Fatalf("reconcile: %+v", out)
	}
	if out := x.a.Reconcile(ctx, in, 2); out.Result != journal.ResultUnknown {
		t.Fatalf("reconcile of an attempt never made: %+v", out)
	}
}

// TestSendFailureIsUnknownUntilReconciled: a refused submission is
// unknown, not "not applied", and with no copy in Sent stays unknown.
func TestSendFailureIsUnknownUntilReconciled(t *testing.T) {
	x := newH(t, nil)
	x.srv.FailSMTP(true)
	in := x.intent(mail.OpSend, map[string]any{"subject": "Hello", "body": "Hi"}, "sam@example.com")
	if out := x.run(in); out.Result != journal.ResultUnknown || strings.Contains(out.Evidence, "try again") {
		t.Fatalf("failed send: %+v", out)
	}
	if out := x.a.Reconcile(ctx, in, 1); out.Result != journal.ResultUnknown {
		t.Fatalf("reconcile: %+v", out)
	}
}

// TestNewMessagesTakeBareRecipientsOnly: no display names or lists in a
// recipient, never the owner's own address, and no header added through
// the subject.
func TestNewMessagesTakeBareRecipientsOnly(t *testing.T) {
	x := newH(t, nil)
	for _, rc := range [][]string{{"Sam <sam@example.com>"}, {"sam@example.com, eve@example.net"}, {me}, {"not an address"}, nil} {
		if out := x.run(x.intent(mail.OpSend, map[string]any{"subject": "s", "body": "b"}, rc...)); out.Result != journal.ResultNotApplied {
			t.Fatalf("recipients %q: %+v", rc, out)
		}
	}
	x.mustRun(x.intent(mail.OpSend, map[string]any{"subject": "Hi\r\nBcc: eve@example.net", "body": "b"}, "sam@example.com"))
	s := x.srv.Submitted()[0]
	if strings.Contains(string(s.Raw), "\r\nBcc:") || !slices.Equal(s.Rcpt, []string{"sam@example.com"}) {
		t.Fatalf("subject added a header:\n%s", s.Raw)
	}
}

// TestDraftsAreSavedNotSent: a draft goes to the drafts folder only.
func TestDraftsAreSavedNotSent(t *testing.T) {
	x := newH(t, nil)
	thread(x)
	in := x.intent(mail.OpDraft, map[string]any{"record": "<t3@example.com>", "body": "Draft reply"}, "sam@example.com")
	o := outgoing(t, x.mustRun(in))
	ds := x.srv.Messages("Drafts")
	if len(ds) != 1 || ds[0].ID != o.MessageID || !slices.Contains(ds[0].Flags, mail.Draft) || len(x.srv.Submitted()) != 0 ||
		!strings.Contains(ds[0].Raw, "Subject: Re: Lunch") || !strings.Contains(ds[0].Raw, "In-Reply-To: <t3@example.com>") {
		t.Fatalf("drafts %+v, submitted %d", ds, len(x.srv.Submitted()))
	}
	if out := x.a.Reconcile(ctx, in, 1); out.Result != journal.ResultSucceeded {
		t.Fatalf("reconcile: %+v", out)
	}
	if out := x.a.Reconcile(ctx, in, 2); out.Result != journal.ResultNotApplied {
		t.Fatalf("reconcile of an unsaved draft: %+v", out)
	}
}

// TestComposerSeesOnlyWhatEveryRecipientSaw: an ADP-11 composer gets the
// thread messages whose participants include every recipient of the
// reply. Bob was not on the first two, so neither reaches a reply that
// copies him.
func TestComposerSeesOnlyWhatEveryRecipientSaw(t *testing.T) {
	x := newH(t, nil)
	thread(x)
	ms, err := x.a.Thread(ctx, "<t3@example.com>")
	if err != nil {
		t.Fatal(err)
	}
	if len(ms) != 1 || ms[0].MessageID != "<t3@example.com>" {
		t.Fatalf("composer got %d messages", len(ms))
	}
	ms, err = x.a.Thread(ctx, "<t2@example.com>")
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, m := range ms {
		got = append(got, m.MessageID)
	}
	if !slices.Equal(got, []string{"<t1@example.test>", "<t2@example.com>"}) {
		t.Fatalf("composer got %v", got)
	}
}

func sortedCopy(l []string) []string {
	out := slices.Clone(l)
	slices.Sort(out)
	return out
}

// TestForgedThreadsDoNotVerify: References and In-Reply-To are the
// sender's to write. A cold sender naming a message the owner sent to
// someone else does not verify, and a second message forging that
// message's Message-ID makes the record ambiguous.
func TestForgedThreadsDoNotVerify(t *testing.T) {
	x := newH(t, nil)
	thread(x)
	x.deliver("INBOX", msg{id: "<f1@evil.example>", from: "eve@evil.example", to: me, subject: "Re: Lunch",
		body: "Me too", inReplyTo: "<t1@example.test>", refs: "<t1@example.test>"})
	v, err := x.a.Verify(ctx, x.intent(mail.OpReply, reply("<f1@evil.example>", "ok"), "eve@evil.example"))
	if err != nil || v.ThreadVerified {
		t.Fatalf("forged thread verified: %+v %v", v, err)
	}
	// Sam's reply in the real thread still verifies.
	if v, _ := x.a.Verify(ctx, x.intent(mail.OpReply, reply("<t2@example.com>", "ok"), "sam@example.com")); !v.ThreadVerified {
		t.Fatal("the real thread no longer verifies")
	}
	// References alone, pointing at the owner's message, from a new
	// sender: the message starts its own thread, which is cold.
	x.deliver("INBOX", msg{id: "<f2@evil.example>", from: "eve@evil.example", to: me, subject: "Re: Lunch",
		body: "Me too", refs: "<t1@example.test>"})
	if v, _ := x.a.Verify(ctx, x.intent(mail.OpReply, reply("<f2@evil.example>", "ok"), "eve@evil.example")); v.ThreadVerified {
		t.Fatal("a References header verified a new sender")
	}
	// A starter with the owner's address in From, planted in the inbox,
	// is not one the owner sent.
	x.deliver("INBOX", msg{id: "<s1@example.test>", from: me, to: "eve@evil.example", subject: "Plan", body: "x"})
	x.deliver("INBOX", msg{id: "<f3@evil.example>", from: "eve@evil.example", to: me, subject: "Re: Plan",
		body: "ok", inReplyTo: "<s1@example.test>", refs: "<s1@example.test>"})
	if v, _ := x.a.Verify(ctx, x.intent(mail.OpReply, reply("<f3@evil.example>", "ok"), "eve@evil.example")); v.ThreadVerified {
		t.Fatal("a spoofed owner starter verified")
	}
	// A participant copying someone new on their own message: the reply
	// would reach them, so the thread does not verify, and the executor
	// refuses a recipient set other than the source's.
	x.deliver("INBOX", msg{id: "<t4@example.com>", from: "sam@example.com", to: me, cc: "eve@evil.example", subject: "Re: Lunch",
		body: "ok", inReplyTo: "<t2@example.com>", refs: "<t1@example.test> <t2@example.com>"})
	if v, _ := x.a.Verify(ctx, x.intent(mail.OpReply, reply("<t4@example.com>", "ok"), "eve@evil.example", "sam@example.com")); v.ThreadVerified {
		t.Fatal("an added Cc verified")
	}
	if out := x.run(x.intent(mail.OpReply, reply("<t4@example.com>", "ok"), "sam@example.com")); out.Result != journal.ResultNotApplied || len(x.srv.Submitted()) != 0 {
		t.Fatalf("reply without the added Cc ran: %+v", out)
	}
	// A forged copy of the owner's starter makes it ambiguous: the chain
	// through it no longer verifies, and the record is refused.
	x.deliver("INBOX", msg{id: "<t1@example.test>", from: "eve@evil.example", to: me, subject: "Lunch", body: "forged"})
	if v, _ := x.a.Verify(ctx, x.intent(mail.OpReply, reply("<t2@example.com>", "ok"), "sam@example.com")); v.ThreadVerified {
		t.Fatal("a chain through an ambiguous message verified")
	}
	if _, err := x.a.Verify(ctx, x.intent(mail.OpReply, reply("<t1@example.test>", "ok"), "sam@example.com")); !errors.Is(err, mail.ErrAmbiguous) {
		t.Fatalf("ambiguous record: %v", err)
	}
}

// TestOwnerPlusAddressesAreTheOwner: a plus-address variant of the
// owner's address is never a reply recipient.
func TestOwnerPlusAddressesAreTheOwner(t *testing.T) {
	g := newH(t, func(c *mail.Config) { c.Aliases = []string{"first.last@gmail.com"} })
	g.deliver("INBOX", msg{id: "<g1@example.com>", from: "sam@example.com", to: "FirstLast+news@googlemail.com", subject: "Hi", body: "x"})
	if v, err := g.a.Verify(ctx, g.intent(mail.OpReply, reply("<g1@example.com>", "ok"), "sam@example.com")); err != nil || !slices.Equal(v.Recipients, []string{"sam@example.com"}) {
		t.Fatalf("Gmail variant of the owner: %+v %v", v.Recipients, err)
	}
	x := newH(t, nil)
	x.deliver("INBOX", msg{id: "<p1@example.com>", from: "sam@example.com", to: "owner+lists@example.test", cc: "bob@example.com", subject: "Hi", body: "x"})
	v, err := x.a.Verify(ctx, x.intent(mail.OpReply, reply("<p1@example.com>", "ok"), "sam@example.com", "bob@example.com"))
	if err != nil || !slices.Equal(v.Recipients, []string{"bob@example.com", "sam@example.com"}) {
		t.Fatalf("recipients %+v %v", v.Recipients, err)
	}
	if out := x.run(x.intent(mail.OpSend, map[string]any{"subject": "s", "body": "b"}, "owner+x@example.test")); out.Result != journal.ResultNotApplied {
		t.Fatalf("sent to the owner's plus-address: %+v", out)
	}
}

// TestPlantedOwnerCopiesDoNotVerify: a copy of the owner's reply delivered
// to the inbox with its In-Reply-To stripped (so the chain would seem to
// start at the owner) makes the ID ambiguous, and the composer never gets
// a planted copy as the owner's text (L3 B1 probe).
func TestPlantedOwnerCopiesDoNotVerify(t *testing.T) {
	x := newH(t, nil)
	x.deliver("INBOX", msg{id: "<c1@evil.example>", from: "eve@evil.example", to: me, subject: "Invoice", body: "Please pay."})
	x.deliver("Sent", msg{id: "<o1@example.test>", from: me, to: "eve@evil.example", subject: "Re: Invoice", body: "Who are you?",
		inReplyTo: "<c1@evil.example>", refs: "<c1@evil.example>"})
	x.deliver("INBOX", msg{id: "<o1@example.test>", from: me, to: "eve@evil.example", subject: "Re: Invoice", body: "Who are you?"})
	x.deliver("INBOX", msg{id: "<e2@evil.example>", from: "eve@evil.example", to: me, subject: "Re: Invoice", body: "Me.",
		inReplyTo: "<o1@example.test>", refs: "<o1@example.test>"})
	if v, _ := x.a.Verify(ctx, x.intent(mail.OpReply, reply("<e2@evil.example>", "ok"), "eve@evil.example")); v.ThreadVerified {
		t.Fatal("a planted copy of the owner's reply verified the thread")
	}
	if _, err := x.a.Verify(ctx, x.intent(mail.OpReply, reply("<o1@example.test>", "ok"), "eve@evil.example")); !errors.Is(err, mail.ErrAmbiguous) {
		t.Fatalf("copies differing in In-Reply-To: %v", err)
	}
	// An owner message held only outside Sent never vouches for anyone,
	// even in the middle of a chain that starts in Sent.
	x.deliver("Sent", msg{id: "<s1@example.test>", from: me, to: "sam@example.com", subject: "Plan", body: "x"})
	x.deliver("INBOX", msg{id: "<p1@example.test>", from: me, to: "sam@example.com", cc: "bob@example.com", subject: "Re: Plan",
		body: "y", inReplyTo: "<s1@example.test>", refs: "<s1@example.test>"})
	x.deliver("INBOX", msg{id: "<p2@example.com>", from: "sam@example.com", to: me, cc: "bob@example.com", subject: "Re: Plan",
		body: "z", inReplyTo: "<p1@example.test>", refs: "<s1@example.test> <p1@example.test>"})
	if v, _ := x.a.Verify(ctx, x.intent(mail.OpReply, reply("<p2@example.com>", "ok"), "bob@example.com", "sam@example.com")); v.ThreadVerified {
		t.Fatal("an owner message outside Sent vouched for a recipient")
	}
	// A planted copy with other text never reaches the composer.
	x.deliver("INBOX", msg{id: "<o2@example.test>", from: me, to: "eve@evil.example", subject: "Re: Invoice", body: "Yes, I agree to pay."})
	x.deliver("Sent", msg{id: "<o2@example.test>", from: me, to: "eve@evil.example", subject: "Re: Invoice", body: "No."})
	x.deliver("INBOX", msg{id: "<e3@evil.example>", from: "eve@evil.example", to: me, subject: "Re: Invoice", body: "Sure?",
		inReplyTo: "<o2@example.test>", refs: "<o2@example.test>"})
	ms, err := x.a.Thread(ctx, "<e3@evil.example>")
	for _, m := range ms {
		if strings.Contains(m.Text, "agree") {
			t.Fatalf("composer got the planted copy (err %v)", err)
		}
	}
}

// TestEveryChainLinkIsAParticipant: a message in the chain whose sender
// was not on the message it answers breaks the chain, even when every
// reply recipient was on the owner's message.
func TestEveryChainLinkIsAParticipant(t *testing.T) {
	x := newH(t, nil)
	x.deliver("Sent", msg{id: "<s1@example.test>", from: me, to: "sam@example.com", subject: "Plan", body: "x"})
	x.deliver("INBOX", msg{id: "<x1@evil.example>", from: "eve@evil.example", to: me, cc: "sam@example.com", subject: "Re: Plan",
		body: "y", inReplyTo: "<s1@example.test>", refs: "<s1@example.test>"})
	x.deliver("INBOX", msg{id: "<x2@example.com>", from: "sam@example.com", to: me, subject: "Re: Plan",
		body: "z", inReplyTo: "<x1@evil.example>", refs: "<s1@example.test> <x1@evil.example>"})
	if v, _ := x.a.Verify(ctx, x.intent(mail.OpReply, reply("<x2@example.com>", "ok"), "sam@example.com")); v.ThreadVerified {
		t.Fatal("a chain through an outsider's message verified")
	}
}

// TestComposerNeverGetsAnOwnerRecordOutsideSent: a record with the
// owner's address in From that exists only outside Sent is not the
// owner's, so the composer gets nothing for it.
func TestComposerNeverGetsAnOwnerRecordOutsideSent(t *testing.T) {
	x := newH(t, nil)
	x.deliver("INBOX", msg{id: "<fake@example.test>", from: me, to: "eve@evil.example", subject: "Deal", body: "I agree."})
	if ms, err := x.a.Thread(ctx, "<fake@example.test>"); err == nil || len(ms) != 0 {
		t.Fatalf("composer got %d messages, err %v", len(ms), err)
	}
}
