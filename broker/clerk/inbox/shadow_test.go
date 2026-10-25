package inbox

// REQ: EVL-2
import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/clerk"
	"github.com/ghbmrk/agentos/broker/clerk/inbox/gmailtest"
	"github.com/ghbmrk/agentos/broker/kernel/key"
)

var shadowStart = time.Date(2026, 10, 26, 8, 0, 0, 0, time.UTC)

// readOnlyGmail is a Gmail mailbox over srv under the shadow week's
// declaration, as OpenGmail builds one under the full one.
func readOnlyGmail(t *testing.T, srv *gmailtest.Server) *Gmail {
	t.Helper()
	sl, err := clerk.NewAESSealer(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	sec := clerk.NewSecrets(sl, nil)
	if err := sec.Put("gmail", clerk.KindGrant, gmailtest.Grant()); err != nil {
		t.Fatal(err)
	}
	api, err := clerk.NewAPI(clerk.APIDeclaration{Name: Name, Calls: GmailReadCalls(srv.Base(), "gmail"), Guard: srv.Guard(),
		Refresh: srv.Token()}, sec, srv.Roots())
	if err != nil {
		t.Fatal(err)
	}
	return NewGmail(api)
}

// TN-shadow-a: under the read-only declaration every write is refused before
// a request leaves, and a shadow run (the clerk over Synthetic, the mails
// read through that declaration) records its effects and leaves every mail
// as it was.
func TestShadowRunChangesNothing(t *testing.T) {
	for _, c := range GmailReadCalls("https://gmail.test", "gmail") {
		if c.Method != "GET" {
			t.Fatalf("the read-only declaration has %s %s", c.Method, c.Name)
		}
	}
	srv := gmailtest.New()
	t.Cleanup(srv.Close)
	ro := readOnlyGmail(t, srv)
	b := srv.Deliver([]byte(crlfMail("<b1@shop.test>", "news@shop.test", "Sale")))
	s := srv.Deliver([]byte(crlfMail("<s1@spam.test>", "x@spam.test", "Win")))
	ms, err := ro.Read(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	ids := map[string]string{}
	for i := range ms {
		ms[i].Class = map[string]string{"<b1@shop.test>": "bulk", "<s1@spam.test>": "spam"}[messageID(ms[i].Raw)]
		ids[messageID(ms[i].Raw)] = ms[i].ID
	}
	before := map[string][]string{}
	for _, id := range []string{b, s} {
		m, _ := srv.Get(id)
		before[id] = m.Labels
	}

	r := newRigOn(t, World{Today: "2026-10-19", AuthServ: authServ, AlertSenders: []string{"security.test"}}, ms, Synthetic{}, 30)
	r.run(t, r.step("o", key.Organize, map[string]string{"target": ids["<b1@shop.test>"], "label": "agentOS/bulk"}))
	r.run(t, r.step("t", key.Trash, map[string]string{"target": ids["<s1@spam.test>"]}))
	if n := len(r.acct.Effects()); n != 2 {
		t.Fatalf("%d effects recorded, want 2: %+v", n, r.acct.Refusals())
	}

	ctx := context.Background()
	for name, err := range map[string]error{
		"label":       ro.Label(ctx, ids["<b1@shop.test>"], "agentOS/bulk"),
		"trash":       ro.Trash(ctx, ids["<s1@spam.test>"]),
		"untrash":     ro.Untrash(ctx, ids["<s1@spam.test>"]),
		"unsubscribe": ro.Post(ctx, Post{Method: "POST", URL: "https://shop.test/u"}),
	} {
		if !errors.As(err, new(NotDone)) {
			t.Fatalf("read-only %s = %v, want a refusal before acting", name, err)
		}
	}
	// A label's write first reads the account's labels; only reads reach
	// the API.
	for _, c := range srv.Calls() {
		if !strings.HasPrefix(c, "GET ") {
			t.Fatalf("the shadow run made %s", c)
		}
	}
	for _, id := range []string{b, s} {
		if m, _ := srv.Get(id); !slices.Equal(m.Labels, before[id]) {
			t.Fatalf("%s's labels went from %v to %v", id, before[id], m.Labels)
		}
	}
}

// TN-shadow-b: one proposal per mail, under the strongest effect on it or
// leave; a mail read again keeps its first proposal; nothing is proposed
// before the week or after it.
func TestShadowProposesOncePerMail(t *testing.T) {
	s := &Shadow{Start: shadowStart}
	listing := []Item{{Mail: "m1", Class: "spam"}, {Mail: "m2", Class: "bulk"}, {Mail: "m3", Class: "personal"}}
	s.Propose(shadowStart.Add(time.Hour), listing, []Effect{
		{Verb: "organize", Mail: "m1", Label: "agentOS/spam"}, {Verb: "trash", Mail: "m1"},
		{Verb: "organize", Mail: "m2", Label: "agentOS/bulk"}, {Verb: "unsubscribe", Mail: "m2"},
	})
	s.Propose(shadowStart.Add(2*time.Hour), append(listing, Item{Mail: "m4", Class: "bulk"}),
		[]Effect{{Verb: "trash", Mail: "m3"}, {Verb: "organize", Mail: "m4", Label: "agentOS/bulk"}})
	s.Propose(shadowStart.Add(-time.Minute), []Item{{Mail: "early", Class: "spam"}}, nil)
	s.Propose(shadowStart.Add(ShadowWeek), []Item{{Mail: "late", Class: "spam"}}, nil)

	var got []string
	for _, p := range s.Proposals {
		got = append(got, p.Mail+":"+p.Class+":"+p.Verb+":"+p.At.Sub(shadowStart).String())
	}
	want := []string{"m1:spam:trash:1h0m0s", "m2:bulk:unsubscribe:1h0m0s", "m3:personal:leave:1h0m0s", "m4:bulk:organize:2h0m0s"}
	if !slices.Equal(got, want) {
		t.Fatalf("proposals %v, want %v", got, want)
	}
	b, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	var back Shadow
	if err := json.Unmarshal(b, &back); err != nil || !back.Start.Equal(s.Start) || len(back.Proposals) != len(s.Proposals) {
		t.Fatalf("the log does not round-trip: %s", b)
	}
}

// TN-shadow-c: a day after each proposal, and not before, the owner's action
// is read from Gmail's labels: trash, spam and gone are removed, out of the
// inbox is archived, else read or unread. Each is read once.
func TestShadowReadsBackTheOwnersActionADayLater(t *testing.T) {
	srv := gmailtest.New()
	t.Cleanup(srv.Close)
	ro := readOnlyGmail(t, srv)
	gid := map[string]string{}
	for _, n := range []string{"trashed", "spammed", "erased", "archived", "read", "unread", "later"} {
		gid[n] = srv.Deliver([]byte(crlfMail("<"+n+"@x.test>", "a@x.test", n)))
	}
	ms, err := ro.Read(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	mail := map[string]string{}
	var listing []Item
	for _, m := range ms {
		n := strings.TrimSuffix(strings.TrimPrefix(messageID(m.Raw), "<"), "@x.test>")
		mail[n] = m.ID
		if n != "later" {
			listing = append(listing, Item{Mail: m.ID, Class: "bulk"})
		}
	}
	s := &Shadow{Start: shadowStart}
	s.Propose(shadowStart, listing, nil)
	s.Propose(shadowStart.Add(6*time.Hour), []Item{{Mail: mail["later"], Class: "bulk"}}, nil)

	srv.Move(gid["trashed"], "TRASH")
	srv.Move(gid["spammed"], "SPAM", "UNREAD")
	srv.Erase(gid["erased"])
	srv.Move(gid["archived"], "UNREAD")
	srv.Open(gid["read"])

	if err := s.ReadBack(context.Background(), shadowStart.Add(ShadowDelay-time.Second), ro); err != nil || s.Waiting() != 7 {
		t.Fatalf("read back before a day: %v, %d waiting", err, s.Waiting())
	}
	if err := s.ReadBack(context.Background(), shadowStart.Add(ShadowDelay), ro); err != nil {
		t.Fatal(err)
	}
	want := map[string]string{"trashed": OwnerRemoved, "spammed": OwnerRemoved, "erased": OwnerRemoved,
		"archived": OwnerArchived, "read": OwnerRead, "unread": OwnerUnread, "later": ""}
	for n, w := range want {
		for _, p := range s.Proposals {
			if p.Mail == mail[n] && p.Owner != w {
				t.Fatalf("%s read back as %q, want %q", n, p.Owner, w)
			}
		}
	}
	srv.Open(gid["unread"]) // read after its read-back: the read-back stands
	calls := len(srv.Calls())
	if err := s.ReadBack(context.Background(), shadowStart.Add(ShadowDelay+6*time.Hour), ro); err != nil {
		t.Fatal(err)
	}
	if n := len(srv.Calls()) - calls; n != 1 || s.Waiting() != 0 || s.Done(shadowStart.Add(ShadowDelay+6*time.Hour)) {
		t.Fatalf("second pass made %d calls, %d waiting", n, s.Waiting())
	}
	if !s.Done(shadowStart.Add(ShadowWeek)) {
		t.Fatal("the week is over and every proposal read back, but not done")
	}
	for _, p := range s.Proposals {
		if p.Mail == mail["unread"] && p.Owner != OwnerUnread {
			t.Fatalf("a read-back was read again: %q", p.Owner)
		}
	}
}

// TN-shadow-c: a read the API fails stays for the next pass, and a dead
// grant ends the pass.
func TestShadowRetriesAFailedReadBack(t *testing.T) {
	srv := gmailtest.New()
	t.Cleanup(srv.Close)
	ro := readOnlyGmail(t, srv)
	id := srv.Deliver([]byte(crlfMail("<a@x.test>", "a@x.test", "a")))
	ms, err := ro.Read(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	s := &Shadow{Start: shadowStart}
	s.Propose(shadowStart, []Item{{Mail: ms[0].ID, Class: "bulk"}, {Mail: "imap-7", Class: "bulk"}}, nil)
	srv.Fail("/messages/"+id, http.StatusInternalServerError)
	if err := s.ReadBack(context.Background(), shadowStart.Add(ShadowDelay), ro); err == nil || s.Waiting() != 2 {
		t.Fatalf("a failed read-back: %v, %d waiting", err, s.Waiting())
	}
	r := &stubOwner{owner: OwnerRead}
	if err := s.ReadBack(context.Background(), shadowStart.Add(ShadowDelay), r); err != nil || r.n != 2 || s.Waiting() != 0 {
		t.Fatalf("the retry: %v after %d reads, %d waiting", err, r.n, s.Waiting())
	}

	s.Proposals = []Proposal{{Mail: "m1", At: shadowStart}, {Mail: "m2", At: shadowStart}}
	r = &stubOwner{err: ErrReconnect}
	if err := s.ReadBack(context.Background(), shadowStart.Add(ShadowDelay), r); !errors.Is(err, ErrReconnect) || r.n != 1 {
		t.Fatalf("a dead grant: %v after %d reads", err, r.n)
	}
	r = &stubOwner{owner: "starred"}
	if err := s.ReadBack(context.Background(), shadowStart.Add(ShadowDelay), r); err == nil || s.Waiting() != 2 {
		t.Fatalf("an action outside the four: %v, %d waiting", err, s.Waiting())
	}
}

type stubOwner struct {
	owner string
	err   error
	n     int
}

func (s *stubOwner) Owner(context.Context, string) (string, error) { s.n++; return s.owner, s.err }

// TN-shadow-d: agreement counts only mails the owner dealt with, by the
// verb's rule, and STATUS gives it by class.
func TestShadowAgreementByClass(t *testing.T) {
	for _, c := range []struct {
		verb, owner    string
		agree, counted bool
	}{
		{"trash", OwnerRemoved, true, true}, {"trash", OwnerArchived, false, true}, {"trash", OwnerRead, false, true},
		{"unsubscribe", OwnerRemoved, true, true}, {"unsubscribe", OwnerArchived, true, true}, {"unsubscribe", OwnerRead, false, true},
		{"organize", OwnerRemoved, false, true}, {"organize", OwnerArchived, true, true}, {"organize", OwnerRead, true, true},
		{Leave, OwnerRemoved, false, true}, {Leave, OwnerRead, true, true},
		{"trash", OwnerUnread, false, false}, {Leave, OwnerUnread, false, false}, {"trash", "", false, false},
	} {
		if a, ok := Agrees(c.verb, c.owner); a != c.agree || ok != c.counted {
			t.Fatalf("Agrees(%s, %s) = %v, %v; want %v, %v", c.verb, c.owner, a, ok, c.agree, c.counted)
		}
	}
	s := &Shadow{Start: shadowStart, Proposals: []Proposal{
		{Class: "spam", Verb: "trash", Owner: OwnerRemoved},
		{Class: "spam", Verb: "trash", Owner: OwnerRemoved},
		{Class: "bulk", Verb: "unsubscribe", Owner: OwnerRead},
		{Class: "bulk", Verb: "organize", Owner: OwnerArchived},
		{Class: "personal", Verb: Leave, Owner: OwnerRead},
		{Class: "", Verb: Leave, Owner: OwnerRemoved},
		{Class: "personal", Verb: Leave, Owner: OwnerUnread},
		{Class: "alert", Verb: Leave},
	}}
	want := "Shadow week: I matched what you did with 4 of the 6 mails you dealt with " +
		"(spam 2 of 2, bulk 1 of 2, personal 1 of 1, unclassified 0 of 1); 2 you have not looked at yet. " +
		"I changed nothing in your mailbox."
	if got := s.Line(); got != want {
		t.Fatalf("STATUS line\n got %q\nwant %q", got, want)
	}
}
