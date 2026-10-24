package inbox

// REQ: CLK-9, CLK-3, CLK-1, CLK-4, VRB-3

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/ghbmrk/agentos/broker/clerk"
	"github.com/ghbmrk/agentos/broker/clerk/inbox/gmailtest"
	"github.com/ghbmrk/agentos/broker/kernel"
	"github.com/ghbmrk/agentos/broker/kernel/key"
)

// crlfMail is rawMail with the CRLF line ends a mail API returns.
func crlfMail(id, from, subject string) string {
	return strings.ReplaceAll(rawMail(id, from, subject), "\n", "\r\n")
}

// newGmail is a Gmail mailbox over a fresh fake, its grant sealed in the
// clerk's one slot.
func newGmail(t *testing.T) (*Gmail, *gmailtest.Server) {
	t.Helper()
	srv := gmailtest.New()
	t.Cleanup(srv.Close)
	g, err := OpenGmail(srv.Base(), srv.Token(), gmailtest.Grant(), srv.Guard(), srv.Roots())
	if err != nil {
		t.Fatal(err)
	}
	return g, srv
}

type gmailRig struct {
	*rig
	srv  *gmailtest.Server
	box  *Gmail
	mail map[string]string // Message-ID to the clerk's mail id
	gid  map[string]string // Message-ID to Gmail's id
}

// newGmailRig delivers the mails to the fake, reads them through Gmail and
// boots the clerk over them, classed by Message-ID.
func newGmailRig(t *testing.T, classes map[string]string, raws ...string) *gmailRig {
	t.Helper()
	box, srv := newGmail(t)
	gr := &gmailRig{srv: srv, box: box, mail: map[string]string{}, gid: map[string]string{}}
	for _, raw := range raws {
		gr.gid[messageID([]byte(raw))] = srv.Deliver([]byte(raw))
	}
	ms, err := box.Read(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for i := range ms {
		id := messageID(ms[i].Raw)
		ms[i].Class = classes[id]
		gr.mail[id] = ms[i].ID
	}
	gr.rig = newRigOn(t, World{Today: "2026-10-19", AuthServ: authServ, AlertSenders: []string{"security.test"}}, ms, box, 30)
	return gr
}

func (gr *gmailRig) labels(t *testing.T, mid string) []string {
	t.Helper()
	m, ok := gr.srv.Get(gr.gid[mid])
	if !ok {
		t.Fatalf("%s is not in the account", mid)
	}
	var names []string
	for _, l := range m.Labels {
		names = append(names, gr.srv.LabelName(l))
	}
	return names
}

// A dispatched organize adds the agentOS/ label and a dispatched trash moves
// the mail to Gmail's trash; both are read back, reading marked nothing
// read, and the clerk asked for nothing the fake refused.
func TestGmailOrganizeAndTrashLandAndAreReadBack(t *testing.T) {
	gr := newGmailRig(t, map[string]string{"<b1@shop.test>": "bulk", "<s1@spam.test>": "spam"},
		crlfMail("<b1@shop.test>", "news@shop.test", "Sale"), crlfMail("<s1@spam.test>", "x@spam.test", "Win"))
	gr.run(t, gr.step("o", key.Organize, map[string]string{"target": gr.mail["<b1@shop.test>"], "label": "agentOS/bulk"}))
	gr.run(t, gr.step("t", key.Trash, map[string]string{"target": gr.mail["<s1@spam.test>"]}))

	if got := gr.labels(t, "<b1@shop.test>"); !slices.Contains(got, "agentOS/bulk") || !slices.Contains(got, "INBOX") {
		t.Fatalf("organized mail has %v, want INBOX and agentOS/bulk", got)
	}
	if got := gr.labels(t, "<s1@spam.test>"); !slices.Contains(got, "TRASH") || slices.Contains(got, "INBOX") {
		t.Fatalf("trashed mail has %v, want TRASH and not INBOX", got)
	}
	for _, id := range []string{"<b1@shop.test>", "<s1@spam.test>"} {
		if !slices.Contains(gr.labels(t, id), "UNREAD") {
			t.Fatalf("%s was marked read by the clerk", id)
		}
	}
	if n := len(gr.acct.Effects()); n != 2 {
		t.Fatalf("%d effects recorded, want 2: %+v %+v", n, gr.acct.Effects(), gr.acct.Refusals())
	}
	if r := gr.srv.Refused(); len(r) != 0 {
		t.Fatalf("the clerk asked for what the fake refuses: %v", r)
	}
}

// Nothing reaches the API but a step the kernel dispatched and the clerk's
// check passed.
func TestGmailStepsOutsideTheCheckNeverReachTheAPI(t *testing.T) {
	const spam = "<s1@spam.test>"
	gr := newGmailRig(t, map[string]string{spam: "spam"}, crlfMail(spam, "x@spam.test", "Win"))
	before := len(gr.srv.Calls())
	gr.acct.Do(kernel.Request{Plan: gr.step("direct", key.Trash, map[string]string{"target": gr.mail[spam]})}, gr.k.State())
	if got := gr.lastRefusal(t).Reason; got != "not-dispatched" {
		t.Fatalf("direct call refused as %q", got)
	}
	if calls := gr.srv.Calls()[before:]; len(calls) != 0 {
		t.Fatalf("an undispatched step reached the API: %v", calls)
	}
}

// Gmail's declaration holds no permanent deletion, no settings write and no
// label removal: an operation not declared does not exist (CLK-3, CLK-9).
func TestGmailDeclarationRefusesDeleteAndSettingsWrites(t *testing.T) {
	calls := GmailCalls(GmailBase, "gmail")
	for _, c := range calls {
		path := strings.TrimPrefix(c.URL, GmailBase)
		if c.Method == "DELETE" || strings.Contains(strings.ToLower(path), "delete") {
			t.Errorf("%s deletes: %s %s", c.Name, c.Method, path)
		}
		if strings.HasPrefix(path, "/settings") && c.Method != "GET" {
			t.Errorf("%s writes a setting: %s %s", c.Name, c.Method, path)
		}
		for f := range c.Body {
			if f == "removeLabelIds" {
				t.Errorf("%s removes labels, which could mark mail read", c.Name)
			}
		}
		if c.Slot != "gmail" || c.Prefix != "Bearer " || !strings.HasPrefix(c.URL, GmailBase+"/") {
			t.Errorf("%s is not a bearer call on the account's own root: %+v", c.Name, c)
		}
	}
	if len(calls) != 18 {
		t.Fatalf("%d calls, want the 16 TN-gmail-api names and the read-mail list (#2925)", len(calls))
	}
	// And the declaration builds: each shape passes the exit's checks.
	box, _ := newGmail(t)
	if ans, bad := box.api.Call(context.Background(), "messages.delete", map[string]string{"id": "abc"}); bad != clerk.DUndeclared {
		t.Fatalf("an undeclared delete answered %+v %q", ans, bad)
	}
}

// The fake refuses what the box's grant cannot do, as the real API does
// (A22 Fences), and records it.
func TestGmailFakeRefusesDeleteAndSettingsWrites(t *testing.T) {
	env := fakeEnv(t)
	gmailContract(t, env)
	if got := len(env.srv.Refused()); got < 4 {
		t.Fatalf("the fake recorded %d refusals, want each attempt", got)
	}
}

// A write the API answered but did not keep is not confirmed.
func TestGmailReadBackCatchesAWriteTheAPIDidNotKeep(t *testing.T) {
	gr := newGmailRig(t, map[string]string{"<b@x.test>": "bulk", "<s@x.test>": "spam"},
		crlfMail("<b@x.test>", "n@x.test", "a"), crlfMail("<s@x.test>", "s@x.test", "b"))
	gr.srv.Lie(true)
	ctx := context.Background()
	if err := gr.box.Label(ctx, gr.mail["<b@x.test>"], "agentOS/bulk"); !errors.Is(err, errUnconfirmed) {
		t.Fatalf("Label = %v, want unconfirmed", err)
	}
	if err := gr.box.Trash(ctx, gr.mail["<s@x.test>"]); !errors.Is(err, errUnconfirmed) {
		t.Fatalf("Trash = %v, want unconfirmed", err)
	}
}

// A refusal before acting is NotDone with its reason; a server error may
// have acted and is not.
func TestGmailRefusalsBeforeActingKeepTheirReason(t *testing.T) {
	for _, c := range []struct {
		status int
		want   NotDone
	}{{http.StatusForbidden, nRefused}, {http.StatusNotFound, nRefused}, {http.StatusTooManyRequests, nBusy}, {http.StatusInternalServerError, ""}} {
		gr := newGmailRig(t, nil, crlfMail("<s@x.test>", "s@x.test", "b"))
		gr.srv.Fail("/trash", c.status)
		err := gr.box.Trash(context.Background(), gr.mail["<s@x.test>"])
		var nd NotDone
		if got := errors.As(err, &nd); got != (c.want != "") || nd != c.want {
			t.Fatalf("http %d: Trash = %v, want NotDone %q", c.status, err, c.want)
		}
	}
}

// A refused refresh is grant death: the owner signs in again (A22 Gmail).
func TestGmailRefusedRefreshIsGrantDeath(t *testing.T) {
	box, srv := newGmail(t)
	srv.RefuseGrant()
	if _, err := box.Read(context.Background()); !errors.Is(err, nReconnect) {
		t.Fatalf("Read = %v, want %v", err, nReconnect)
	}
}

// An access token the API stops taking is redeemed once more and the call
// made again.
func TestGmailExpiredTokenIsRedeemedAgain(t *testing.T) {
	box, srv := newGmail(t)
	srv.Deliver([]byte(crlfMail("<a@x.test>", "a@x.test", "a")))
	if _, err := box.Read(context.Background()); err != nil {
		t.Fatal(err)
	}
	srv.Expire()
	if ms, err := box.Read(context.Background()); err != nil || len(ms) != 1 {
		t.Fatalf("Read after expiry = %d, %v", len(ms), err)
	}
	if n := srv.Tokens(); n != 2 {
		t.Fatalf("%d tokens redeemed, want 2", n)
	}
}

// An API that echoes the bearer token gets it back redacted, in its JSON
// and inside the raw message the reader would see (CLK-1, CLK-4).
func TestGmailEchoedTokenNeverReachesTheMail(t *testing.T) {
	box, srv := newGmail(t)
	srv.Deliver([]byte(crlfMail("<a@x.test>", "a@x.test", "a")))
	srv.Echo(true)
	ms, err := box.Read(context.Background())
	if err != nil || len(ms) != 1 {
		t.Fatalf("Read = %d, %v", len(ms), err)
	}
	if bytes.Contains(ms[0].Raw, []byte("canary-gmailtest-access")) || !bytes.Contains(ms[0].Raw, []byte("X-Echo: [redacted]")) {
		t.Fatalf("the token reached the mail: %q", ms[0].Raw)
	}
}

// An agentOS/ label the API answers with a system label's id is refused, so
// no answer turns a label into a read-state change.
func TestGmailNeverAddsASystemLabel(t *testing.T) {
	gr := newGmailRig(t, nil, crlfMail("<b@x.test>", "n@x.test", "a"))
	gr.srv.AddLabel(gmailtest.Label{ID: "UNREAD", Name: "agentOS/bulk", Type: "user"})
	err := gr.box.Label(context.Background(), gr.mail["<b@x.test>"], "agentOS/bulk")
	if !errors.Is(err, nBadLabel) {
		t.Fatalf("Label = %v, want %v", err, nBadLabel)
	}
	if calls := gr.srv.Calls(); slices.ContainsFunc(calls, func(c string) bool { return strings.HasSuffix(c, "/modify") }) {
		t.Fatalf("a modify was sent: %v", calls)
	}
}

// A mail whose answer passes the bound is not read, and the newest readMax
// are.
func TestGmailReadsTheNewestReadMaxAndSkipsWhatItCannotHold(t *testing.T) {
	box, srv := newGmail(t)
	for i := range readMax + 3 {
		srv.Deliver([]byte(crlfMail(fmt.Sprintf("<m%d@x.test>", i), "a@x.test", "m")))
	}
	ms, err := box.Read(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(ms) != readMax || messageID(ms[0].Raw) != fmt.Sprintf("<m%d@x.test>", readMax+2) {
		t.Fatalf("read %d, want the newest %d", len(ms), readMax)
	}

	box, srv = newGmail(t)
	srv.Deliver([]byte(crlfMail("<big@x.test>", "a@x.test", "big") + strings.Repeat("x", gRawMax)))
	srv.Deliver([]byte(crlfMail("<s@x.test>", "a@x.test", "s")))
	ms, err = box.Read(context.Background())
	if err != nil || len(ms) != 1 || messageID(ms[0].Raw) != "<s@x.test>" {
		t.Fatalf("Read = %d, %v; want only the mail it can hold", len(ms), err)
	}
}

// The account's doors are read, never written, and history marks a change.
func TestGmailDoorsAndHistory(t *testing.T) {
	gr := newGmailRig(t, nil, crlfMail("<b@x.test>", "n@x.test", "a"))
	gr.srv.SetDoors(2, []string{"elsewhere@x.test"}, "elsewhere@x.test")
	ctx := context.Background()
	d, err := gr.box.Doors(ctx)
	if err != nil || d.Filters != 2 || !slices.Equal(d.Forwarding, []string{"elsewhere@x.test"}) || d.AutoForward != "elsewhere@x.test" {
		t.Fatalf("Doors = %+v, %v", d, err)
	}
	mark, err := gr.box.History(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if changed, err := gr.box.Changed(ctx, mark); err != nil || changed {
		t.Fatalf("Changed with nothing new = %v, %v", changed, err)
	}
	if err := gr.box.Label(ctx, gr.mail["<b@x.test>"], "agentOS/bulk"); err != nil {
		t.Fatal(err)
	}
	if changed, err := gr.box.Changed(ctx, mark); err != nil || !changed {
		t.Fatalf("Changed after a label = %v, %v", changed, err)
	}
	if changed, _ := gr.box.Changed(ctx, "1"); !changed {
		t.Fatal("a mark Gmail keeps no history for is not changed")
	}
}

// A Gmail mailbox with no Poster refuses an unsubscribe.
func TestGmailUnsubscribeIsRefusedWithoutAPoster(t *testing.T) {
	box, _ := newGmail(t)
	if err := box.Post(context.Background(), Post{URL: "https://shop.test/u"}); !errors.Is(err, nNoPoster) {
		t.Fatalf("Post = %v, want %v", err, nNoPoster)
	}
}

// gmailEnv is one account the contract cases run against: the fake, or a
// real test account (A22).
type gmailEnv struct {
	box *Gmail
	srv *gmailtest.Server // nil for a real account
	// deliver puts a mail in the inbox and returns its Message-ID.
	deliver func(t *testing.T, raw string)
	// attempt makes a request outside the declaration under the box's own
	// grant, and returns its status.
	attempt func(t *testing.T, method, path, body string) int
}

func fakeEnv(t *testing.T) gmailEnv {
	box, srv := newGmail(t)
	return gmailEnv{box: box, srv: srv,
		deliver: func(t *testing.T, raw string) { srv.Deliver([]byte(raw)) },
		attempt: func(t *testing.T, method, path, body string) int {
			return srv.Attempt(method, path, body)
		}}
}

// gmailContract is the cases a fake and a real account must agree on.
func gmailContract(t *testing.T, env gmailEnv) {
	ctx := context.Background()
	mid := "<contract-" + strings.ReplaceAll(t.Name(), "/", "-") + "@agentos.test>"
	env.deliver(t, crlfMail(mid, "contract@agentos.test", "agentOS contract"))
	ms, err := env.box.Read(ctx)
	if err != nil {
		t.Fatal(err)
	}
	id := ""
	for _, m := range ms {
		if messageID(m.Raw) == mid {
			id = m.ID
		}
	}
	if id == "" {
		t.Fatalf("the delivered mail was not read (%d read)", len(ms))
	}
	gid, _ := env.box.mail(id)
	unread := func() bool {
		l, err := env.box.labelsOf(ctx, gid)
		if err != nil {
			t.Fatal(err)
		}
		return slices.Contains(l, "UNREAD")
	}
	was := unread()
	if err := env.box.Label(ctx, id, "agentOS/contract"); err != nil {
		t.Fatalf("Label: %v", err)
	}
	if err := env.box.Label(ctx, id, "Work"); !errors.Is(err, nBadFlag) {
		t.Fatalf("a label outside agentOS/ = %v", err)
	}
	if err := env.box.Trash(ctx, id); err != nil {
		t.Fatalf("Trash: %v", err)
	}
	if err := env.box.Untrash(ctx, id); err != nil {
		t.Fatalf("Untrash: %v", err)
	}
	if unread() != was {
		t.Fatal("the clerk changed the read state")
	}
	if _, err := env.box.Doors(ctx); err != nil {
		t.Fatalf("Doors: %v", err)
	}
	// Under the box's grant, permanent deletion and settings changes are
	// refused, and the mail is still there.
	for _, a := range []struct{ method, path, body string }{
		{"DELETE", "/messages/" + gid, ""},
		{"POST", "/messages/batchDelete", `{"ids":["` + gid + `"]}`},
		{"PUT", "/settings/autoForwarding", `{"enabled":false}`},
		{"POST", "/settings/filters", `{"criteria":{"from":"x@agentos.test"},"action":{"addLabelIds":["TRASH"]}}`},
	} {
		if got := env.attempt(t, a.method, a.path, a.body); got != http.StatusForbidden {
			t.Errorf("%s %s under the box's grant = %d, want 403", a.method, a.path, got)
		}
	}
	if _, err := env.box.labelsOf(ctx, gid); err != nil {
		t.Fatalf("the mail is gone after the refused deletes: %v", err)
	}
}
