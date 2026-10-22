package inbox

// REQ: CLK-2, VRB-2, OWN-13, KRN-8

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/ghbmrk/agentos/broker/clerk/inbox/imapsmtp"
	"github.com/ghbmrk/agentos/broker/clerk/inbox/imapsmtp/imaptest"
	"github.com/ghbmrk/agentos/broker/kernel"
	"github.com/ghbmrk/agentos/broker/kernel/key"
)

// rawMail is a synthetic message as the test server stores it.
func rawMail(id, from, subject string) string {
	h := "From: " + from + "\nTo: owner@example.test\nSubject: " + subject + "\n"
	if id != "" {
		h += "Message-ID: " + id + "\n"
	}
	return h + "\nsynthetic body\n"
}

type liveRig struct {
	*rig
	srv  *imaptest.Server
	box  *Live
	mail map[string]string // Message-ID to the clerk's mail id
}

// newLiveRig delivers the given mails to a local IMAP server, reads them
// through Live and boots the clerk over them, classed by Message-ID.
func newLiveRig(t *testing.T, retention int, classes map[string]string, raws ...string) *liveRig {
	t.Helper()
	srv := imaptest.Start(t)
	for _, raw := range raws {
		srv.Deliver("INBOX", raw)
	}
	st, err := imapsmtp.New(imapsmtp.Config{IMAP: srv.IMAP, SMTP: srv.SMTP, IMAPSec: imapsmtp.Plain, SMTPSec: imapsmtp.Plain, From: imaptest.User,
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
	lr := &liveRig{srv: srv, box: box, mail: map[string]string{}}
	for i := range ms {
		id := messageID(ms[i].Raw)
		ms[i].Class = classes[id]
		lr.mail[id] = ms[i].ID
	}
	lr.rig = newRigOn(t, World{Today: "2026-10-19"}, ms, box, retention)
	return lr
}

// flagsOf is a message's folder and flags on the server.
func (lr *liveRig) flagsOf(t *testing.T, id string) (string, []string) {
	t.Helper()
	folder, flags, ok := lr.srv.Find(id)
	if !ok {
		t.Fatalf("%s is not on the server", id)
	}
	return folder, flags
}

// A dispatched organize sets the clerk's keyword and a dispatched trash moves
// the mail to the account's trash folder; both are read back before they
// count, and reading the inbox marked nothing read.
func TestLiveOrganizeAndTrashLandOnTheServerAndAreReadBack(t *testing.T) {
	lr := newLiveRig(t, 30, map[string]string{"<b1@shop.test>": "bulk", "<s1@spam.test>": "spam"},
		rawMail("<b1@shop.test>", "news@shop.test", "Sale"), rawMail("<s1@spam.test>", "x@spam.test", "Win"))
	lr.run(t, lr.step("o", key.Organize, map[string]string{"target": lr.mail["<b1@shop.test>"], "label": "agentOS/bulk"}))
	lr.run(t, lr.step("t", key.Trash, map[string]string{"target": lr.mail["<s1@spam.test>"]}))

	// IMAP keywords are case-insensitive; the test server folds them.
	if folder, flags := lr.flagsOf(t, "<b1@shop.test>"); folder != "INBOX" || !slices.ContainsFunc(flags, func(f string) bool { return strings.EqualFold(f, "agentOS/bulk") }) {
		t.Fatalf("organized mail is in %s with %v, want INBOX with agentOS/bulk", folder, flags)
	}
	if folder, _ := lr.flagsOf(t, "<s1@spam.test>"); folder != "Trash" {
		t.Fatalf("trashed mail is in %s, want Trash", folder)
	}
	for _, id := range []string{"<b1@shop.test>", "<s1@spam.test>"} {
		if _, flags := lr.flagsOf(t, id); slices.Contains(flags, `\Seen`) {
			t.Fatalf("%s was marked read by the clerk", id)
		}
	}
	if n := len(lr.acct.Effects()); n != 2 {
		t.Fatalf("%d effects recorded, want 2: %+v %+v", n, lr.acct.Effects(), lr.acct.Refusals())
	}
}

// Nothing reaches the server but a step the kernel dispatched and the clerk's
// one check passed: a direct call, a forged step and a verb outside the key
// all leave the mailbox as it was.
func TestLiveStepsOutsideTheCheckNeverReachTheServer(t *testing.T) {
	const spam = "<s1@spam.test>"
	lr := newLiveRig(t, 30, map[string]string{spam: "spam"}, rawMail(spam, "x@spam.test", "Win"))
	target := map[string]string{"target": lr.mail[spam]}

	// Not dispatched: called directly, with no log entry.
	lr.acct.Do(kernel.Request{Plan: lr.step("direct", key.Trash, target)}, lr.k.State())
	if got := lr.lastRefusal(t).Reason; got != "not-dispatched" {
		t.Fatalf("direct call refused as %q", got)
	}
	// Forged: the logged step was an organize, the request a trash.
	lr.run(t, lr.step("real", key.Organize, map[string]string{"target": lr.mail[spam], "label": "agentOS/spam"}))
	lr.acct.Do(kernel.Request{Plan: lr.step("real", key.Trash, target)}, lr.k.State())
	if got := lr.lastRefusal(t).Reason; got != "not-dispatched" {
		t.Fatalf("forged step refused as %q", got)
	}
	// Outside the key: a planner key that carries organize only.
	only, err := key.Derive(lr.planner, lr.plannerPriv, lr.plannerPriv.Public().(ed25519.PublicKey), key.LimitVerbs(key.Organize))
	if err != nil {
		t.Fatal(err)
	}
	_ = lr.k.Submit(t0, lr.onKey(only, "narrow", key.Trash, target))
	_ = lr.tick(t0)

	if folder, _ := lr.flagsOf(t, spam); folder != "INBOX" {
		t.Fatalf("a step outside the check moved the mail to %s", folder)
	}
	for _, e := range lr.acct.Effects() {
		if e.Verb == string(key.Trash) {
			t.Fatalf("trash recorded: %+v", e)
		}
	}
}

// A mail no reader has classed is filed under nothing: the planner skips it
// and the clerk refuses a step that names it.
func TestLiveUnclassifiedMailIsNotActedOn(t *testing.T) {
	const m = "<u1@example.test>"
	lr := newLiveRig(t, 30, nil, rawMail(m, "pat@example.test", "Hello"))
	plans, _ := Plans(lr.acct.Listing(), lr.bulk, lr.unsub, lr.plannerPriv)
	if len(plans) != 0 {
		t.Fatalf("the planner made %d plans for unclassified mail", len(plans))
	}
	lr.run(t, lr.step("o", key.Organize, map[string]string{"target": lr.mail[m], "label": "agentOS/"}))
	if got := lr.lastRefusal(t).Reason; got != "unclassified" {
		t.Fatalf("refusal %q, want unclassified", got)
	}
	if _, flags := lr.flagsOf(t, m); len(flags) != 0 {
		t.Fatalf("unclassified mail got flags %v", flags)
	}
}

// A folder renumbered since the clerk read it is refused before acting: the
// UID the clerk holds may now name another mail.
func TestLiveRenumberedInboxIsRefusedBeforeActing(t *testing.T) {
	const spam = "<s1@spam.test>"
	lr := newLiveRig(t, 30, map[string]string{spam: "spam"}, rawMail(spam, "x@spam.test", "Win"))
	lr.srv.Renumber("INBOX")
	lr.run(t, lr.step("t", key.Trash, map[string]string{"target": lr.mail[spam]}))
	if got := lr.lastRefusal(t).Reason; got != "renumbered" {
		t.Fatalf("refusal %q, want renumbered", got)
	}
	if folder, _ := lr.flagsOf(t, spam); folder != "INBOX" {
		t.Fatalf("mail moved to %s under a stale UID", folder)
	}
}

// An account with no trash-role folder has no restore point to trash into,
// so a trash is refused, never emulated with a delete.
func TestLiveTrashWithoutATrashFolderIsRefused(t *testing.T) {
	const spam = "<s1@spam.test>"
	lr := newLiveRig(t, 30, map[string]string{spam: "spam"}, rawMail(spam, "x@spam.test", "Win"))
	// The provider drops the role and the clerk reads again: the mail ids
	// are the same, the trash folder is gone.
	lr.srv.SetAttr("Trash", "")
	if _, err := lr.box.Read(context.Background()); err != nil {
		t.Fatal(err)
	}
	lr.run(t, lr.step("t", key.Trash, map[string]string{"target": lr.mail[spam]}))
	if got := lr.lastRefusal(t).Reason; got != "no-trash-folder" {
		t.Fatalf("refusal %q, want no-trash-folder", got)
	}
	if folder, _ := lr.flagsOf(t, spam); folder != "INBOX" {
		t.Fatalf("mail moved to %s", folder)
	}
}

// A trash the read-back cannot confirm (the mail has no Message-ID to find in
// the trash) is unknown, not ok: no effect is recorded and the kernel is left
// to probe and park it (OWN-13, KRN-8).
func TestLiveUnconfirmedTrashIsUnknownAndNotRecorded(t *testing.T) {
	lr := newLiveRig(t, 30, nil, rawMail("", "x@spam.test", "Win"))
	var id string
	for _, it := range lr.acct.Listing() {
		id = it.Mail
	}
	lr.acct.mails[id] = Mail{ID: id, Raw: lr.acct.mails[id].Raw, Class: "spam"}
	p := lr.step("t", key.Trash, map[string]string{"target": id})
	if err := lr.k.Submit(t0, p); err != nil {
		t.Fatal(err)
	}
	_ = lr.tick(t0)
	if n := len(lr.acct.Effects()); n != 0 {
		t.Fatalf("an unconfirmed trash was recorded: %+v", lr.acct.Effects())
	}
	if res := lr.acct.Probe(kernel.Request{Plan: p}, lr.k.State()); res != "notdone" {
		t.Fatalf("probe %q after an unconfirmed trash", res)
	}
}

// A live unsubscribe is not sent and not reported as sent until the
// one-click POSTer and its egress rules exist (#2601).
func TestLiveUnsubscribeIsRefusedWithoutAPoster(t *testing.T) {
	var nd NotDone
	if err := (&Live{}).Post(context.Background(), Post{URL: "https://shop.test/u"}); !errors.As(err, &nd) || nd != nNoPoster {
		t.Fatalf("Post = %v, want %v", err, nNoPoster)
	}
}

// The clerk reads only the newest day's worth of inbox mail.
func TestLiveReadsTheNewestReadMax(t *testing.T) {
	var raws []string
	for i := range readMax + 5 {
		raws = append(raws, rawMail("<n"+strconv.Itoa(i)+"@example.test>", "a@example.test", "n"))
	}
	lr := newLiveRig(t, 30, nil, raws...)
	got := lr.acct.Listing()
	if len(got) != readMax {
		t.Fatalf("read %d mails, want %d", len(got), readMax)
	}
	if _, ok := lr.mail["<n0@example.test>"]; ok {
		t.Fatal("the oldest mail was read")
	}
}

// Each read-back is what makes an effect count: a server that answers OK
// but keeps no keyword, leaves the mail in place, or puts it nowhere gives an
// unknown step and no recorded effect (OWN-13, SPEC "Read back").
func TestLiveReadBackCatchesAnEffectTheServerDidNotKeep(t *testing.T) {
	const bulk, spam = "<b1@shop.test>", "<s1@spam.test>"
	for _, c := range []struct {
		name    string
		breakIt func(*imaptest.Server)
		verb    key.Verb
	}{
		{"keyword dropped", func(s *imaptest.Server) { s.DropKeywords(true) }, key.Organize},
		{"move copies and keeps the mail", func(s *imaptest.Server) { s.SetMove(imaptest.MoveKeeps) }, key.Trash},
		{"move loses the mail", func(s *imaptest.Server) { s.SetMove(imaptest.MoveLoses) }, key.Trash},
	} {
		t.Run(c.name, func(t *testing.T) {
			lr := newLiveRig(t, 30, map[string]string{bulk: "bulk", spam: "spam"},
				rawMail(bulk, "news@shop.test", "Sale"), rawMail(spam, "x@spam.test", "Win"))
			c.breakIt(lr.srv)
			args := map[string]string{"target": lr.mail[spam]}
			if c.verb == key.Organize {
				args = map[string]string{"target": lr.mail[bulk], "label": "agentOS/bulk"}
			}
			p := lr.step("s", c.verb, args)
			lr.run(t, p)
			if n := len(lr.acct.Effects()); n != 0 {
				t.Fatalf("an effect the server did not keep was recorded: %+v", lr.acct.Effects())
			}
			if len(lr.acct.Refusals()) != 0 {
				t.Fatalf("an unconfirmed effect was recorded as a refusal: %+v", lr.acct.Refusals())
			}
			if got := lr.acct.Probe(kernel.Request{Plan: p}, lr.k.State()); got != "notdone" {
				t.Fatalf("probe %q, want notdone (an idempotent effect may be sent again)", got)
			}
		})
	}
}

// A transport refusal before acting is the clerk's NotDone, by its reason.
func TestLiveRefusalsBeforeActingKeepTheirReason(t *testing.T) {
	for err, want := range map[error]NotDone{imapsmtp.ErrValidity: nRenumbered, imapsmtp.ErrNoMove: nNoMove,
		imapsmtp.ErrLoginRefused: nSignInRefused, fmt.Errorf("%w: no route", imapsmtp.ErrUnreachable): nUnreachable} {
		if got := before(err); got != want {
			t.Fatalf("before(%v) = %v, want %v", err, got, want)
		}
	}
	if got := before(errors.New("connection reset")); errors.As(got, new(NotDone)) {
		t.Fatalf("a transport failure became a refusal before acting: %v", got)
	}
}

// failingBox never confirms anything and counts its calls.
type failingBox struct{ calls int }

func (f *failingBox) Label(context.Context, string, string) error { f.calls++; return errUnconfirmed }
func (f *failingBox) Trash(context.Context, string) error         { f.calls++; return errUnconfirmed }
func (f *failingBox) Post(context.Context, Post) error            { f.calls++; return errUnconfirmed }

// An effect that is never confirmed is sent at most MaxChecks times and then
// parked, not resent forever (KRN-8).
func TestAnUnconfirmedOrganizeIsParkedAfterMaxChecks(t *testing.T) {
	w, mails, raw := loadFixture(t)
	var ms []Mail
	for _, m := range mails {
		ms = append(ms, Mail{ID: m.ID, Raw: raw[m.ID], Class: m.Class})
	}
	box := &failingBox{}
	r := newRigOn(t, w, ms, box, 30)
	ticks := []int64{}
	for i := int64(1); i <= 3*kernel.MaxChecks; i++ {
		ticks = append(ticks, t0+i*kernel.ProbeEvery)
	}
	r.run(t, r.step("o", key.Organize, map[string]string{"target": "M22", "label": "agentOS/personal"}), ticks...)
	if box.calls > kernel.MaxChecks {
		t.Fatalf("%d mailbox calls, want at most %d", box.calls, kernel.MaxChecks)
	}
	st := r.k.State().Status()
	if len(st) != 1 || st[0].Phase != kernel.PParked {
		t.Fatalf("step is %+v, want parked", st)
	}
}

// An unconfirmed unsubscribe is never sent again: a one-click POST is not
// idempotent, so Probe says unknown at once.
func TestAnUnconfirmedUnsubscribeIsNeverResent(t *testing.T) {
	w, mails, raw := loadFixture(t)
	var ms []Mail
	for _, m := range mails {
		ms = append(ms, Mail{ID: m.ID, Raw: raw[m.ID], Class: m.Class})
	}
	box := &failingBox{}
	r := newRigOn(t, w, ms, box, 30)
	p := r.step("u", key.Unsubscribe, map[string]string{"to": handleOfMail(t, r, "M01")})
	r.run(t, p, t0+kernel.ProbeEvery, t0+2*kernel.ProbeEvery, t0+3*kernel.ProbeEvery)
	if box.calls != 1 {
		t.Fatalf("%d POSTs, want exactly 1", box.calls)
	}
	if got := r.acct.Probe(kernel.Request{Plan: p}, r.k.State()); got != "unknown" {
		t.Fatalf("probe %q, want unknown", got)
	}
}

// A class outside the reader's closed list leaves the mail unclassified, so a
// class can never carry a space or a line break into a label (Security 1).
func TestAClassOutsideTheListCannotReachTheMailbox(t *testing.T) {
	const m = "<b1@shop.test>"
	lr := newLiveRig(t, 30, map[string]string{m: "bulk \\Deleted"}, rawMail(m, "news@shop.test", "Sale"))
	lr.run(t, lr.step("o", key.Organize, map[string]string{"target": lr.mail[m], "label": "agentOS/bulk \\Deleted"}))
	if got := lr.lastRefusal(t).Reason; got != "unclassified" {
		t.Fatalf("refusal %q, want unclassified", got)
	}
	if _, flags := lr.flagsOf(t, m); len(flags) != 0 {
		t.Fatalf("mail got flags %v", flags)
	}
}

// The mailbox refuses a label that is not an IMAP keyword before acting,
// whoever asks: a line break cannot end the command and start another.
func TestLiveRefusesALabelThatIsNotAKeyword(t *testing.T) {
	const m, other = "<b1@shop.test>", "<p1@example.test>"
	lr := newLiveRig(t, 30, nil, rawMail(m, "news@shop.test", "Sale"), rawMail(other, "pat@example.test", "Hi"))
	for _, label := range []string{"agentOS/bulk\r\nA1 UID STORE 1:* +FLAGS (\\Deleted)", "\\Deleted", "\\Seen", "NonJunk"} {
		err := lr.box.Label(context.Background(), lr.mail[m], label)
		var nd NotDone
		if !errors.As(err, &nd) || nd != nBadFlag {
			t.Fatalf("Label(%q) = %v, want %v", label, err, nBadFlag)
		}
	}
	for _, id := range []string{m, other} {
		if _, flags := lr.flagsOf(t, id); len(flags) != 0 {
			t.Fatalf("%s got flags %v", id, flags)
		}
	}
}
