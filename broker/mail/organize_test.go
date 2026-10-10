package mail_test

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/journal"
	"github.com/ghbmrk/agentos/broker/mail"
	"github.com/ghbmrk/agentos/broker/verb"
)

// REQ: ADP-1, ADP-2

// TestDeclarationUsesTheFixedVerbList: every operation maps to one verb
// of the broker's list; organize only with a declared inverse; filters,
// forwarding, auto-reply settings and emptying trash are not declared, so
// they do not exist for agents.
func TestDeclarationUsesTheFixedVerbList(t *testing.T) {
	if err := mail.Validate(mail.Ops()); err != nil {
		t.Fatal(err)
	}
	d := mail.Declared()
	for name, v := range d {
		if !verb.Valid(v) {
			t.Fatalf("%s: %s", name, v)
		}
	}
	want := map[string]string{
		mail.OpReply: verb.Send, mail.OpSend: verb.Send, mail.OpDraft: verb.Draft,
		mail.OpArchive: verb.Organize, mail.OpMarkRead: verb.Organize, mail.OpLabel: verb.Organize,
		mail.OpDelete: verb.DeleteRemote, mail.OpReportSpam: verb.DeleteRemote,
	}
	for op, v := range want {
		if d[op] != v {
			t.Fatalf("%s maps to %q, want %q", op, d[op], v)
		}
	}
	for op := range d {
		for _, bad := range []string{"filter", "forward", "auto", "expunge", "empty", "vacation"} {
			if strings.Contains(op, bad) {
				t.Fatalf("%s is declared", op)
			}
		}
	}
	if c, _ := verb.ClassOf(verb.Organize); c != verb.Reversible {
		t.Fatal("organize is not reversible")
	}
	for _, bad := range [][]mail.Op{
		{{Name: "x.archive", Verb: verb.Organize}},
		{{Name: "x.archive", Verb: verb.Organize, Inverse: "x.unarchive"}, {Name: "x.unarchive", Verb: verb.Send}},
		{{Name: "x.do", Verb: "tidy"}},
	} {
		if mail.Validate(bad) == nil {
			t.Fatalf("accepted %+v", bad)
		}
	}
}

// REQ: ADP-2, REV-2, OP-2

// TestOrganizeJournalsPriorStateAndLabels: an archive moves the message,
// labels it AgentOS, and its evidence holds the state before.
func TestOrganizeJournalsPriorStateAndLabels(t *testing.T) {
	x := newH(t, nil)
	id := x.news(1)
	if e, err := x.a.Escalate(ctx, x.intent(mail.OpArchive, rec(id))); err != nil || e.Verb != "" || e.Ask {
		t.Fatalf("plain archive escalated: %+v %v", e, err)
	}
	c := change(t, x.mustRun(x.intent(mail.OpArchive, rec(id))))
	if c.From != "INBOX" || c.To != "Archive" || c.Record != id || c.Sender != "deals@shop.example" || !hasFlag(c.Added, mail.Keyword) {
		t.Fatalf("change %+v", c)
	}
	folder, flags, _ := x.srv.Find(id)
	if folder != "Archive" || !hasFlag(flags, mail.Keyword) || slices.Contains(flags, mail.Seen) {
		t.Fatalf("now in %s with %v", folder, flags)
	}
	// Labels and stars; the evidence lists only what changed.
	c = change(t, x.mustRun(x.intent(mail.OpLabel, map[string]any{"record": id, "label": "Family"})))
	if !slices.Equal(c.Added, []string{"Family"}) || c.From != "Archive" {
		t.Fatalf("label change %+v", c)
	}
	x.mustRun(x.intent(mail.OpStar, rec(id)))
	if _, flags, _ := x.srv.Find(id); !slices.Contains(flags, mail.Flagged) {
		t.Fatalf("not starred: %v", flags)
	}
	// Reconcile sees the state the effect set.
	if out := x.a.Reconcile(ctx, x.intent(mail.OpStar, rec(id)), 1); out.Result != journal.ResultSucceeded {
		t.Fatalf("reconcile: %+v", out)
	}
	if out := x.a.Reconcile(ctx, x.intent(mail.OpUnstar, rec(id)), 1); out.Result != journal.ResultNotApplied {
		t.Fatalf("reconcile of an effect not made: %+v", out)
	}
	// A param the operation does not take is refused, not ignored.
	if out := x.run(x.intent(mail.OpArchive, map[string]any{"record": id, "to": "Legal"})); out.Result != journal.ResultNotApplied {
		t.Fatalf("extra param: %+v", out)
	}
}

// TestOrganizeTargetsAreGuarded: moves and labels go only to system
// states, owner-confirmed folders and labels, or the AgentOS/ namespace;
// trash, junk and retention folders never; shared ones are share.
func TestOrganizeTargetsAreGuarded(t *testing.T) {
	x := newH(t, nil)
	id := x.news(1)
	move := func(to string) (string, error) {
		e, err := x.a.Escalate(ctx, x.intent(mail.OpMove, map[string]any{"record": id, "to": to}))
		return e.Verb, err
	}
	for _, to := range []string{"Trash", "Junk", "Legal", "Unconfirmed", "Deleted Items"} {
		if _, err := move(to); !errors.Is(err, mail.ErrTarget) {
			t.Fatalf("move to %s: %v", to, err)
		}
	}
	for to, want := range map[string]string{"Receipts": "", "AgentOS/Shopping": "", "Archive": "", "Team": verb.Share} {
		if v, err := move(to); err != nil || v != want {
			t.Fatalf("move to %s: %q %v", to, v, err)
		}
	}
	if e, _ := x.a.Escalate(ctx, x.intent(mail.OpMove, map[string]any{"record": id, "to": "Team"})); e.Reason != "into shared folder Team" {
		t.Fatalf("share reason %q", e.Reason)
	}
	label := func(l string) (string, error) {
		e, err := x.a.Escalate(ctx, x.intent(mail.OpLabel, map[string]any{"record": id, "label": l}))
		return e.Verb, err
	}
	for _, l := range []string{`\Deleted`, "Random", "Spam", "a b"} {
		if _, err := label(l); !errors.Is(err, mail.ErrTarget) {
			t.Fatalf("label %q: %v", l, err)
		}
	}
	for l, want := range map[string]string{"Family": "", "AgentOS/later": "", "Team": verb.Share} {
		if v, err := label(l); err != nil || v != want {
			t.Fatalf("label %s: %q %v", l, v, err)
		}
	}
	// The executor checks again and creates the namespace folder.
	if out := x.run(x.intent(mail.OpMove, map[string]any{"record": id, "to": "Trash"})); out.Result != journal.ResultNotApplied {
		t.Fatalf("executor moved to trash: %+v", out)
	}
	c := change(t, x.mustRun(x.intent(mail.OpMove, map[string]any{"record": id, "to": "AgentOS/Shopping"})))
	if folder, _, _ := x.srv.Find(id); folder != "AgentOS/Shopping" || c.To != "AgentOS/Shopping" {
		t.Fatalf("now in %s", folder)
	}
	// Trash and spam are delete-remote and go to the account's own folders.
	x.mustRun(x.intent(mail.OpDelete, rec(id)))
	if folder, _, _ := x.srv.Find(id); folder != "Trash" {
		t.Fatalf("delete put it in %s", folder)
	}
}

// TestAlertsAskBeforeTheyAreHidden: archiving, moving out of the inbox
// or marking read an alert is change-account; labelling and starring it
// run and are marked for the digest. A sender is trusted only through the
// provider's own, topmost Authentication-Results header.
func TestAlertsAskBeforeTheyAreHidden(t *testing.T) {
	x := newH(t, func(c *mail.Config) {
		c.AccountSenders = func() []string { return []string{"bank.example"} }
		c.Financial = []string{"payroll@work.example"}
	})
	pass := func(domain string) string {
		return "Authentication-Results: mx.example.test; spf=pass smtp.mailfrom=" + domain + "; dmarc=pass (p=reject) header.from=" + domain
	}
	mk := func(id, from, subject string, extra ...string) string {
		x.deliver("INBOX", msg{id: id, from: from, to: me, subject: subject, body: "Hello.", extra: extra})
		return id
	}
	alerts := []string{
		mk("<a1@provider.example>", "security@provider.example", "Hello", pass("provider.example")),
		mk("<a2@bank.example>", "statements@mail.bank.example", "Your statement", pass("mail.bank.example")),
		mk("<a3@work.example>", "payroll@work.example", "October", pass("work.example")),
		// Wording alone, whoever sent it.
		mk("<a4@x.example>", "someone@x.example", "New sign-in on your account"),
		mk("<a5@x.example>", "someone@x.example", "Your verification code is 482913"),
		// RFC 8601 allows comments and spacing around "=".
		mk("<a7@bank.example>", "statements@bank.example", "Your statement",
			`Authentication-Results: mx.example.test (mta 2); dmarc = pass (p=reject) header.from = "bank.example"`),
	}
	quiet := []string{
		// A known domain without the provider's DMARC pass on top.
		mk("<q1@bank.example>", "statements@bank.example", "Your statement",
			"Authentication-Results: mx.example.test; dmarc=fail header.from=bank.example",
			pass("bank.example")),
		// A pass the sender wrote itself (another authserv-id).
		mk("<q2@bank.example>", "statements@bank.example", "Your statement",
			"Authentication-Results: evil.example; dmarc=pass header.from=bank.example"),
		// Aligned to another domain.
		mk("<q3@bank.example>", "statements@bank.example", "Your statement", pass("evil.example")),
		// A pass inside a comment, or inside a quoted string, is not a
		// result (Security C2).
		mk("<q4@bank.example>", "statements@bank.example", "Your statement",
			"Authentication-Results: mx.example.test; dmarc=fail (x; dmarc=pass header.from=bank.example ) header.from=bank.example"),
		mk("<q7@bank.example>", "statements@bank.example", "Your statement",
			"Authentication-Results: mx.example.test; spf=pass (x; dmarc=pass header.from=bank.example ) smtp.mailfrom=bank.example"),
		mk("<q5@bank.example>", "statements@bank.example", "Your statement",
			`Authentication-Results: mx.example.test; spf=pass smtp.mailfrom="x; dmarc=pass header.from=bank.example"`),
		mk("<q6@bank.example>", "statements@bank.example", "Your statement",
			"Authentication-Results: mx.example.test (; dmarc=pass header.from=bank.example); dmarc=none header.from=bank.example"),
		x.news(1),
	}
	for _, id := range alerts {
		for _, op := range []string{mail.OpArchive, mail.OpMarkRead} {
			e, err := x.a.Escalate(ctx, x.intent(op, rec(id)))
			if err != nil || e.Verb != verb.ChangeAccount || !strings.HasPrefix(e.Reason, "hides an alert from ") {
				t.Fatalf("%s %s: %+v %v", op, id, e, err)
			}
			// The reason names the sender's domain, never the subject.
			if strings.Contains(e.Reason, "@") || len([]rune(e.Reason)) > 40 {
				t.Fatalf("reason %q", e.Reason)
			}
		}
		e, err := x.a.Escalate(ctx, x.intent(mail.OpMove, map[string]any{"record": id, "to": "Receipts"}))
		if err != nil || e.Verb != verb.ChangeAccount {
			t.Fatalf("move %s: %+v %v", id, e, err)
		}
		for _, op := range []string{mail.OpStar, mail.OpLabel} {
			p := rec(id)
			if op == mail.OpLabel {
				p["label"] = "Family"
			}
			if e, err := x.a.Escalate(ctx, x.intent(op, p)); err != nil || e.Verb != "" {
				t.Fatalf("%s on an alert escalated: %+v %v", op, e, err)
			}
		}
		if c := change(t, x.mustRun(x.intent(mail.OpStar, rec(id)))); !c.Alert {
			t.Fatalf("star on %s not marked for the digest", id)
		}
		if folder, flags, _ := x.srv.Find(id); folder != "INBOX" || slices.Contains(flags, mail.Seen) {
			t.Fatalf("starring moved or read it: %s %v", folder, flags)
		}
	}
	for _, id := range quiet {
		if e, err := x.a.Escalate(ctx, x.intent(mail.OpArchive, rec(id))); err != nil || e.Verb != "" {
			t.Fatalf("archive %s escalated: %+v %v", id, e, err)
		}
	}
	// Marking an already-read alert read hides nothing.
	x.deliver("INBOX", msg{id: "<a6@x.example>", from: "someone@x.example", to: me, subject: "Password reset", body: "x"}, mail.Seen)
	if e, _ := x.a.Escalate(ctx, x.intent(mail.OpMarkRead, rec("<a6@x.example>"))); e.Verb != "" {
		t.Fatalf("read alert: %+v", e)
	}
}

// TestOrganizeBoundAsksPastTheDailyLimit: beyond 200 organize effects a
// day (counted from the journal) the owner is asked once; the rest are
// held while that ask is open or after a NO; a YES lifts the bound for the
// day to 2000, past which each is asked; the guards still run on every
// effect; without the journal count none runs unasked (UX-69-1).
func TestOrganizeBoundAsksPastTheDailyLimit(t *testing.T) {
	var authorized int
	var approved []string // intents the owner approved past the bound
	var since time.Time
	x := newH(t, func(c *mail.Config) {
		c.InUse = func(action string, s time.Time) []journal.Use {
			since = s
			if action != mail.OpArchive {
				return nil
			}
			var out []journal.Intent
			for i := 0; i < authorized; i++ {
				out = append(out, journal.Intent{ID: fmt.Sprint("earlier/", i), Account: "mail"})
			}
			for _, a := range approved {
				out = append(out, journal.Intent{ID: a, Account: "mail"})
			}
			return uses(out)
		}
	})
	id := x.news(1)
	in := x.intent(mail.OpArchive, rec(id))
	authorized = mail.DefaultDailyLimit - 1
	if e, _ := x.a.Escalate(ctx, in); e.Ask {
		t.Fatal("asked under the bound")
	}
	if !since.Equal(x.now.Add(-24 * time.Hour)) {
		t.Fatalf("counted since %v", since)
	}
	// The recheck of the same intent keeps its place.
	if e, _ := x.a.Escalate(ctx, in); e.Ask {
		t.Fatal("the recheck lost its place")
	}
	// That place counts at once, before the journal authorizes it, so the
	// next effect is past the bound: the one ask.
	first := x.intent(mail.OpArchive, rec(id))
	if e, err := x.a.Escalate(ctx, first); err != nil || !e.Ask || e.Verb != "" || e.Reason != "past 200, YES allows 2000" {
		t.Fatalf("past the bound: %+v %v", e, err)
	}
	// While it is open (or after a NO) the rest are held, not asked, with
	// a reason that says they may be tried again.
	if e, err := x.a.Escalate(ctx, x.intent(mail.OpArchive, rec(id))); err != nil || !e.Held || e.Ask || e.Reason != "held past today's 200" {
		t.Fatalf("second past the bound: %+v %v", e, err)
	}
	if e, err := x.a.Escalate(ctx, first); err != nil || !e.Ask {
		t.Fatalf("the asked effect's recheck: %+v %v", e, err)
	}
	// Other owner approvals (a share, an alert) can take the count past
	// the bound: that is no YES to this ask, and nothing is lifted.
	authorized = mail.DefaultDailyLimit + 5
	if e, err := x.a.Escalate(ctx, x.intent(mail.OpArchive, rec(id))); err != nil || !e.Held {
		t.Fatalf("count past the bound without a YES: %+v %v", e, err)
	}
	// YES: the journal authorized the asked effect, so the rest of the day
	// runs unasked up to the ceiling.
	approved = []string{first.ID}
	if e, err := x.a.Escalate(ctx, x.intent(mail.OpArchive, rec(id))); err != nil || e.Ask {
		t.Fatalf("after YES: %+v %v", e, err)
	}
	// The YES lifts only the count: an alert is still asked.
	x.deliver("INBOX", msg{id: "<al@x.example>", from: "someone@x.example", to: me, subject: "New sign-in", body: "x"})
	if e, err := x.a.Escalate(ctx, x.intent(mail.OpArchive, rec("<al@x.example>"))); err != nil || e.Verb != verb.ChangeAccount {
		t.Fatalf("alert after YES: %+v %v", e, err)
	}
	authorized = mail.DefaultDailyCeiling
	if e, err := x.a.Escalate(ctx, x.intent(mail.OpArchive, rec(id))); err != nil || !e.Ask || e.Reason != "past 2000 today" {
		t.Fatalf("past the ceiling: %+v %v", e, err)
	}
	if e, err := x.a.Escalate(ctx, x.intent(mail.OpArchive, rec(id))); err != nil || !e.Ask || e.Held {
		t.Fatalf("past the ceiling, asked again: %+v %v", e, err)
	}
	// The lift lasts the day the ask was made.
	x.now = x.now.Add(25 * time.Hour)
	authorized, approved = mail.DefaultDailyLimit, nil
	if e, err := x.a.Escalate(ctx, x.intent(mail.OpArchive, rec(id))); err != nil || e.Reason != "past 200, YES allows 2000" {
		t.Fatalf("next day: %+v %v", e, err)
	}
	// The ceiling is the owner's to set.
	zj := []journal.Intent{{ID: "a", Account: "mail"}, {ID: "b", Account: "mail"}}
	z := newH(t, func(c *mail.Config) {
		c.DailyLimit, c.DailyCeiling = 2, 3
		c.InUse = func(action string, _ time.Time) []journal.Use {
			if action != mail.OpArchive {
				return nil
			}
			return uses(zj)
		}
	})
	id = z.news(1)
	zin := z.intent(mail.OpArchive, rec(id))
	if e, _ := z.a.Escalate(ctx, zin); !e.Ask || e.Reason != "past 2, YES allows 3" {
		t.Fatalf("owner's ceiling, ask: %+v", e)
	}
	zj = append(zj, journal.Intent{ID: zin.ID, Account: "mail"})
	if e, _ := z.a.Escalate(ctx, z.intent(mail.OpArchive, rec(id))); !e.Ask || e.Reason != "past 3 today" {
		t.Fatalf("owner's ceiling: %+v", e)
	}
	y := newH(t, func(c *mail.Config) { c.InUse = nil })
	id = y.news(1)
	if e, _ := y.a.Escalate(ctx, y.intent(mail.OpArchive, rec(id))); !e.Ask {
		t.Fatal("no journal count, not asked")
	}
}

// TestUndoRestoresOnlyWhatIsUnchanged: UNDO restores each item whose
// state still matches what the agent set and skips the rest; the digest
// line counts by action, names senders, and states the UNDO's lapse.
func TestUndoRestoresOnlyWhatIsUnchanged(t *testing.T) {
	x := newH(t, nil)
	var changes []mail.Change
	var ids []string
	for i := 0; i < 3; i++ {
		id := x.news(i)
		ids = append(ids, id)
		changes = append(changes, change(t, x.mustRun(x.intent(mail.OpArchive, rec(id)))))
	}
	x.deliver("INBOX", msg{id: "<s@x.example>", from: "someone@x.example", to: me, subject: "Security alert", body: "x"})
	changes = append(changes, change(t, x.mustRun(x.intent(mail.OpStar, rec("<s@x.example>")))))
	// Since then the owner read one archived message (no conflict), moved
	// another elsewhere, and took the AgentOS label off a third.
	x.srv.SetFlags(ids[0], mail.Seen, mail.Keyword)
	moved, _ := x.store.Find(ctx, "Archive", ids[1])
	if err := x.store.Move(ctx, moved[0].Ref(), "Receipts"); err != nil {
		t.Fatal(err)
	}
	x.srv.SetFlags(ids[2])
	r := x.a.Undo(ctx, changes)
	if r.Restored != 2 || r.Skipped != 2 || r.Text() != "Restored 2; 2 skipped (changed since)." {
		t.Fatalf("undo: %+v %q", r, r.Text())
	}
	if folder, flags, _ := x.srv.Find(ids[0]); folder != "INBOX" || !slices.Equal(flags, []string{mail.Seen}) {
		t.Fatalf("restored: %s %v", folder, flags)
	}
	if folder, _, _ := x.srv.Find(ids[1]); folder != "Receipts" {
		t.Fatal("undo overrode a move made since")
	}
	if folder, _, _ := x.srv.Find(ids[2]); folder != "Archive" {
		t.Fatal("undo overrode a label change made since")
	}
	if _, flags, _ := x.srv.Find("<s@x.example>"); slices.Contains(flags, mail.Flagged) {
		t.Fatal("star not undone")
	}
	d := mail.Summarize(changes)
	line := d.Line("U7", x.now.Add(mail.UndoWindow))
	if d.Total != 4 || d.GuardHits != 1 || d.TopSenders[0] != "shop.example" ||
		line != "Mail organized: 4 (1 star, 3 archive). Most from shop.example, x.example. 1 security alerts labelled but left in the inbox. UNDO U7 until Mon Oct 12. MORE U7 lists them." {
		t.Fatalf("digest %+v %q", d, line)
	}
	// The longest line still fits CH-12's three text segments.
	long := strings.Repeat("a", 60) + ".example"
	var many []mail.Change
	for i, op := range []string{mail.OpArchive, mail.OpUnarchive, mail.OpMove, mail.OpLabel, mail.OpUnlabel, mail.OpMarkRead, mail.OpMarkUnread, mail.OpStar, mail.OpUnstar} {
		for j := 0; j < 1000; j++ {
			many = append(many, mail.Change{Op: op, Record: "<r>", From: "INBOX", Sender: fmt.Sprintf("x@%d%s", i%4, long), Alert: true})
		}
	}
	if l := mail.Summarize(many).Line("U12345678", x.now); len(l) > 3*153 {
		t.Fatalf("digest line is %d characters: %q", len(l), l)
	}
}

func hasFlag(l []string, f string) bool {
	return slices.ContainsFunc(l, func(x string) bool { return strings.EqualFold(x, f) })
}

// TestOrganizeSourcesAreGuarded: nothing is organized out of trash, junk
// or a retention folder (unarchiving from junk would put phishing in the
// inbox), and an effect in a shared folder is share.
func TestOrganizeSourcesAreGuarded(t *testing.T) {
	x := newH(t, nil)
	x.deliver("Junk", msg{id: "<phish@evil.example>", from: "eve@evil.example", to: me, subject: "Invoice", body: "x"})
	x.deliver("Legal", msg{id: "<hold@law.example>", from: "a@law.example", to: me, subject: "Hold", body: "x"})
	x.deliver("Team", msg{id: "<team@work.example>", from: "a@work.example", to: me, subject: "Plan", body: "x"})
	for _, c := range [][2]string{{"<phish@evil.example>", "Junk"}, {"<hold@law.example>", "Legal"}} {
		for _, op := range []string{mail.OpUnarchive, mail.OpStar, mail.OpMarkRead} {
			if _, err := x.a.Escalate(ctx, x.intent(op, map[string]any{"record": c[0], "folder": c[1]})); !errors.Is(err, mail.ErrTarget) {
				t.Fatalf("%s from %s: %v", op, c[1], err)
			}
		}
		if out := x.run(x.intent(mail.OpUnarchive, map[string]any{"record": c[0], "folder": c[1]})); out.Result != journal.ResultNotApplied {
			t.Fatalf("executor moved out of %s: %+v", c[1], out)
		}
	}
	e, err := x.a.Escalate(ctx, x.intent(mail.OpStar, map[string]any{"record": "<team@work.example>", "folder": "Team"}))
	if err != nil || e.Verb != verb.Share || e.Reason != "in shared folder Team" {
		t.Fatalf("star in a shared folder: %+v %v", e, err)
	}
}

// TestUndoSkipsReconciledEvidence: a reconciliation sees no prior state,
// so its evidence is skipped rather than reported restored.
func TestUndoSkipsReconciledEvidence(t *testing.T) {
	x := newH(t, nil)
	id := x.news(1)
	in := x.intent(mail.OpArchive, rec(id))
	x.mustRun(in)
	out := x.a.Reconcile(ctx, in, 1)
	if out.Result != journal.ResultSucceeded {
		t.Fatalf("reconcile %+v", out)
	}
	if r := x.a.Undo(ctx, []mail.Change{change(t, out)}); r.Restored != 0 || r.Skipped != 1 {
		t.Fatalf("undo of reconciled evidence: %+v", r)
	}
	if folder, _, _ := x.srv.Find(id); folder != "Archive" {
		t.Fatal("moved")
	}
}

// TestReasonsFitTheDetailCap: every combination of share, alert and the
// bound fits the owner channel's 40-character detail, the bound clause
// comes first so a cut never loses it, and the cut uses ASCII (UX-69-3).
func TestReasonsFitTheDetailCap(t *testing.T) {
	const long = "Projects/Client-Accounts-Quarterly-Review"
	for _, lim := range [][2]int{{1, 1}, {200, 2000}, {50000, 100000}} {
		for _, bound := range []string{"", "once", "each"} {
			for _, share := range []bool{false, true} {
				for _, alert := range []bool{false, true} {
					var journaled []journal.Intent
					x := newH(t, func(c *mail.Config) {
						c.Shared = append(c.Shared, long)
						c.DailyLimit, c.DailyCeiling = lim[0], lim[1]
						c.InUse = func(action string, _ time.Time) []journal.Use {
							if action != mail.OpMove && action != mail.OpArchive {
								return nil
							}
							return uses(journaled)
						}
					})
					x.srv.AddFolder(long, "")
					m := msg{id: "<m@notifications.security.verylongbank.example>", from: "alerts@notifications.security.verylongbank.example",
						to: me, subject: "Hello", body: "Twenty percent off."}
					if alert {
						m.subject = "New sign-in on your account"
					}
					x.deliver("INBOX", m)
					p := map[string]any{mail.ParamRecord: m.id, mail.ParamTo: "Receipts"}
					if share {
						p[mail.ParamTo] = long
					}
					earlier := func(n int) []journal.Intent {
						out := make([]journal.Intent, n)
						for i := range out {
							out[i] = journal.Intent{ID: fmt.Sprint("earlier/", i), Account: "mail"}
						}
						return out
					}
					switch bound {
					case "once":
						journaled = earlier(lim[0])
					case "each":
						journaled = earlier(lim[0])
						asked := x.intent(mail.OpMove, p)
						x.a.Escalate(ctx, asked)
						journaled = append(earlier(lim[1]), journal.Intent{ID: asked.ID, Account: "mail"})
					}
					e, err := x.a.Escalate(ctx, x.intent(mail.OpMove, p))
					if err != nil {
						t.Fatal(err)
					}
					name := fmt.Sprintf("bounds=%v bound=%s share=%v alert=%v", lim, bound, share, alert)
					if n := len(e.Reason); n > 40 || strings.Contains(e.Reason, "…") || alert != strings.Contains(e.Reason, "alert") {
						t.Fatalf("%s: %q (%d)", name, e.Reason, n)
					}
					if (bound == "once") != strings.HasPrefix(e.Reason, fmt.Sprintf("past %d, YES allows %d", lim[0], lim[1])) ||
						(bound == "each") != strings.HasPrefix(e.Reason, fmt.Sprintf("past %d today", lim[1])) {
						t.Fatalf("%s: bound clause not first: %q", name, e.Reason)
					}
					if (share || alert || bound != "") != (e.Reason != "") || share && !alert && !strings.Contains(e.Reason, "shared") {
						t.Fatalf("%s: reason %q", name, e.Reason)
					}
				}
			}
		}
	}
}

// TestOrganizeActsOnItsOwnCopy: an organize effect judges and moves the
// copy it acts on, never a Sent twin sharing its Message-ID: an inbox
// alert reusing the ID of the owner's sent mail is still an alert; with
// no folder named, the copy outside Sent moves and the thread still
// resolves; and spam spoofing the owner, with no Sent copy, can be
// archived or reported.
func TestOrganizeActsOnItsOwnCopy(t *testing.T) {
	x := newH(t, nil)
	thread(x)
	x.deliver("INBOX", msg{id: "<t1@example.test>", from: "someone@x.example", to: me, subject: "New sign-in, code 482913", body: "x"})
	e, err := x.a.Escalate(ctx, x.intent(mail.OpArchive, rec("<t1@example.test>")))
	if err != nil || e.Verb != verb.ChangeAccount {
		t.Fatalf("alert sharing a Sent ID: %+v %v", e, err)
	}
	v, err := x.a.Verify(ctx, x.intent(mail.OpArchive, rec("<t1@example.test>")))
	if err != nil || !strings.Contains(v.Item.Object, `"New sign-in, code 482913" from someone@x.example`) {
		t.Fatalf("line shows another copy: %+v %v", v.Item, err)
	}
	// With no folder named, the Sent copy alone is never acted on; naming
	// Sent acts on it.
	if _, err := x.a.Escalate(ctx, x.intent(mail.OpStar, rec("<t2@example.com>"))); err != nil {
		t.Fatalf("inbox message: %v", err)
	}
	x.deliver("Sent", msg{id: "<solo@example.test>", from: me, to: "sam@example.com", subject: "Note", body: "x"})
	if out := x.run(x.intent(mail.OpStar, rec("<solo@example.test>"))); out.Result != journal.ResultNotApplied {
		t.Fatalf("Sent copy acted on without a hint: %+v", out)
	}
	x.mustRun(x.intent(mail.OpStar, map[string]any{mail.ParamRecord: "<solo@example.test>", mail.ParamFolder: "Sent"}))

	// A benign twin cannot launder an alert: archiving the benign inbox
	// copy still asks, since a same-ID copy elsewhere is an alert.
	w := newH(t, nil)
	w.deliver("INBOX", msg{id: "<tw@x.example>", from: "someone@x.example", to: me, subject: "Hello", body: "x"})
	w.deliver("Receipts", msg{id: "<tw@x.example>", from: "someone@x.example", to: me, subject: "Password reset", body: "x"})
	if e, err := w.a.Escalate(ctx, w.intent(mail.OpArchive, map[string]any{mail.ParamRecord: "<tw@x.example>", mail.ParamFolder: "INBOX"})); err != nil || e.Verb != verb.ChangeAccount {
		t.Fatalf("laundered alert: %+v %v", e, err)
	}
	// A non-owner copy reusing the owner's ID, in the named folder, is
	// organized as itself; the Sent copy is untouched.
	w.deliver("Sent", msg{id: "<own@example.test>", from: me, to: "sam@example.com", subject: "Plan", body: "x"})
	w.deliver("Receipts", msg{id: "<own@example.test>", from: "eve@evil.example", to: me, subject: "Plan", body: "y"})
	w.mustRun(w.intent(mail.OpArchive, map[string]any{mail.ParamRecord: "<own@example.test>", mail.ParamFolder: "Receipts"}))
	if len(w.srv.Messages("Sent")) != 1 || len(w.srv.Messages("Archive")) != 1 {
		t.Fatal("organized the wrong copy")
	}

	y := newH(t, nil)
	thread(y)
	y.deliver("INBOX", msg{id: "<t1@example.test>", from: me, to: "sam@example.com", subject: "Lunch",
		body: "Lunch next week?\r\n--\r\nlist footer"})
	y.mustRun(y.intent(mail.OpArchive, rec("<t1@example.test>")))
	if n := len(y.srv.Messages("Sent")); n != 1 {
		t.Fatalf("archive moved the Sent copy: %d left in Sent", n)
	}
	if v, err := y.a.Verify(ctx, y.intent(mail.OpReply, reply("<t2@example.com>", "ok"), "sam@example.com")); err != nil || !v.ThreadVerified {
		t.Fatalf("thread after archive: %+v %v", v, err)
	}

	z := newH(t, nil)
	z.deliver("INBOX", msg{id: "<spam1@example.test>", from: me, to: me, subject: "Win", body: "x"})
	z.deliver("INBOX", msg{id: "<spam2@example.test>", from: me, to: me, subject: "Win", body: "x"})
	z.mustRun(z.intent(mail.OpArchive, rec("<spam1@example.test>")))
	z.mustRun(z.intent(mail.OpReportSpam, rec("<spam2@example.test>")))
	if f, _, _ := z.srv.Find("<spam2@example.test>"); f != "Junk" {
		t.Fatalf("spoofed spam reported to %q", f)
	}
}
