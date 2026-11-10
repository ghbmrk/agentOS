package run

// REQ: CLK-9, CLK-1, CLK-4

import (
	"bytes"
	"context"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/ghbmrk/agentos/broker/clerk"
	"github.com/ghbmrk/agentos/broker/clerk/inbox/gmailtest"
	"github.com/ghbmrk/agentos/broker/clerk/inbox/imapsmtp/imaptest"
	"github.com/ghbmrk/agentos/broker/kernel"
)

// signInConfig is gmailConfig with the fake's consent page and revocation
// endpoint.
func signInConfig(srv *gmailtest.Server) MailConfig {
	c := gmailConfig(srv)
	c.gmail.consent, c.gmail.revoke = srv.Consent(), srv.Revoke()
	return c
}

var fakeClient = &clerk.Registration{ID: gmailtest.Client, Secret: gmailtest.Secret}

// signIn runs the owner's sign-in for use over the owner's socket, with
// reg, and returns Finish's detail.
func signIn(t *testing.T, srv *gmailtest.Server, owner MailOwner, use string, reg *clerk.Registration) string {
	t.Helper()
	consent, detail, err := owner.GmailBegin(use, reg)
	if err != nil || detail != "" {
		t.Fatalf("GmailBegin = %q, %v", detail, err)
	}
	landing, ok := srv.Approve(consent)
	if !ok {
		t.Fatalf("the fake refused the consent address %s", consent)
	}
	detail, err = owner.GmailFinish(use, landing)
	if err != nil {
		t.Fatal(err)
	}
	return detail
}

// noFileHolds fails if any file in dir holds one of the canaries in the clear.
func noFileHolds(t *testing.T, dir string, canaries ...string) {
	t.Helper()
	ents, _ := os.ReadDir(dir)
	for _, e := range ents {
		b, _ := os.ReadFile(filepath.Join(dir, e.Name()))
		for _, c := range canaries {
			if bytes.Contains(b, []byte(c)) {
				t.Fatalf("%s holds a canary in the clear", e.Name())
			}
		}
	}
}

// The owner's socket runs a first Gmail sign-in end to end (#3009): the
// consent address comes out, the paste goes in, and the account Google's
// profile names is set up with its grant sealed in its own slot, the
// registration sealed with it, and nothing secret in a file in the clear.
func TestTheOwnerSignsInToGmailOverTheMailSocket(t *testing.T) {
	srv := gmailtest.New()
	t.Cleanup(srv.Close)
	srv.Deliver(gmailMail("news@shop.test", "<a@shop.test>"))
	dir := shortDir(t)
	sec, err := OpenSecrets(dir, testSealer())
	if err != nil {
		t.Fatal(err)
	}
	h := NewMailHost(context.Background(), dir, sec, signInConfig(srv))
	owner := MailOwner{serveMail(t, h, MailOwnerSide)}
	if d := signIn(t, srv, owner, "watch", fakeClient); d != clerk.DSignedIn+" watch" {
		t.Fatalf("GmailFinish = %q", d)
	}
	a, err := owner.Account()
	if err != nil || !a.Set || a.Settings != (MailSettings{Address: gmailtest.User, API: APIGmail}) {
		t.Fatalf("Account = %+v, %v", a, err)
	}
	if sec.Len() != 1 || !sec.Has(GmailSlot(gmailtest.User)) {
		t.Fatalf("%d slots after the sign-in; want the Gmail grant only", sec.Len())
	}
	if ls, err := h.listing(false); err != nil || len(ls) != 1 {
		t.Fatalf("listing = %v, %v", ls, err)
	}
	noFileHolds(t, dir, gmailtest.Refresh, gmailtest.Secret)
}

// Begin answers a typed detail, with no value, for a sign-in that cannot
// start, and Finish for a paste with no sign-in waiting (CLK-4).
func TestGmailSignInDetails(t *testing.T) {
	srv := gmailtest.New()
	t.Cleanup(srv.Close)
	dir := shortDir(t)
	sec, err := OpenSecrets(dir, testSealer())
	if err != nil {
		t.Fatal(err)
	}
	owner := MailOwner{serveMail(t, NewMailHost(context.Background(), dir, sec, signInConfig(srv)), MailOwnerSide)}
	for _, c := range []struct {
		use  string
		reg  *clerk.Registration
		want string
	}{
		{"watch", nil, clerk.DNoAccount}, // no Gmail account to sign in again with
		{"delete", fakeClient, clerk.DUndeclared},
		{"watch", &clerk.Registration{ID: gmailtest.Client, Secret: "a\nb"}, clerk.DRegistered},
	} {
		if consent, d, err := owner.GmailBegin(c.use, c.reg); err != nil || d != c.want || consent != "" {
			t.Fatalf("GmailBegin(%q) = %q, %q, %v; want %q", c.use, consent, d, err, c.want)
		}
	}
	if d, err := owner.GmailFinish("watch", "http://127.0.0.1:8521/agentos?state=x&code=y"); err != nil || d != clerk.DNoSignIn {
		t.Fatalf("GmailFinish with none waiting = %q, %v", d, err)
	}
	if d, err := owner.GmailRevoke(); err != nil || d != DNotGmail {
		t.Fatalf("GmailRevoke with no account = %q, %v", d, err)
	}
}

// A first sign-in that finishes is a change of account whose settings
// write has ended; it wipes the grant it held and leaves no sign-in
// waiting, so a later paste finds none (#3023 Security). Its store was
// sealed under a key drawn for it, never a fixed one.
func TestAFinishedSignInLeavesNothingBehind(t *testing.T) {
	srv := gmailtest.New()
	t.Cleanup(srv.Close)
	dir := shortDir(t)
	sec, err := OpenSecrets(dir, testSealer())
	if err != nil {
		t.Fatal(err)
	}
	h := NewMailHost(context.Background(), dir, sec, signInConfig(srv))
	consent := h.gmailBegin("watch", fakeClient).Consent
	h.signMu.Lock()
	g := h.signing
	h.signMu.Unlock()
	landing, ok := srv.Approve(consent)
	if g == nil || !ok {
		t.Fatalf("no sign-in waiting (%v) or the fake refused %s", g == nil, consent)
	}
	h.mu.Lock()
	before := h.changes
	h.mu.Unlock()
	if d, err := h.gmailFinish("watch", landing); err != nil || d != clerk.DSignedIn+" watch" {
		t.Fatalf("gmailFinish = %q, %v", d, err)
	}
	h.mu.Lock()
	changes := h.changes
	h.mu.Unlock()
	h.ws.mu.Lock()
	writes := h.ws.writes
	h.ws.mu.Unlock()
	if changes != before+1 || writes != 0 {
		t.Fatalf("%d changes after %d, %d settings writes in flight; want one change and none", changes, before, writes)
	}
	if len(g.grant) == 0 || bytes.Count(g.grant, []byte{0}) != len(g.grant) {
		t.Fatal("the finished sign-in still holds its grant")
	}
	if d, err := h.gmailFinish("watch", "https://example.test/"); err != nil || d != clerk.DNoSignIn {
		t.Fatalf("a paste after the finish = %q, %v; want %q", d, err, clerk.DNoSignIn)
	}
	b, err := g.sec.MarshalBinary()
	if err != nil || g.sec.Len() != 1 {
		t.Fatalf("the sign-in's store: %d slots, %v", g.sec.Len(), err)
	}
	zero, err := clerk.NewAESSealer(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	if clerk.NewSecrets(zero, nil).UnmarshalBinary(b) == nil {
		t.Fatal("the sign-in's store opens under the zero key")
	}
}

// A profile address the clerk cannot set up is refused like no address:
// the grant is given back and nothing is set up.
func TestAProfileAddressThatIsNoMailAddressIsGivenBack(t *testing.T) {
	srv := gmailtest.New()
	t.Cleanup(srv.Close)
	dir := shortDir(t)
	sec, err := OpenSecrets(dir, testSealer())
	if err != nil {
		t.Fatal(err)
	}
	owner := MailOwner{serveMail(t, NewMailHost(context.Background(), dir, sec, signInConfig(srv)), MailOwnerSide)}
	srv.As("Pat <pat@gmail.test>")
	if d := signIn(t, srv, owner, "watch", fakeClient); d != DGmailAddress {
		t.Fatalf("GmailFinish = %q, want %q", d, DGmailAddress)
	}
	if a, _ := owner.Account(); a.Set || sec.Len() != 0 || !slices.Equal(srv.Revoked(), []string{gmailtest.Issued(1)}) {
		t.Fatalf("account %+v, %d slots, revoked %v; want nothing set up and the grant given back", a, sec.Len(), srv.Revoked())
	}
}

// A sign-in the clerk cannot declare (its consent page is not plain https)
// starts nothing, and gmailrevoke then keeps the account and its grant.
// Nor can the clerk name the address with a Gmail root it cannot declare:
// the new grant is given back.
func TestAGmailSignInTheClerkCannotDeclare(t *testing.T) {
	t.Run("begin", func(t *testing.T) {
		srv, dir, sec := newGmailAccount(t)
		c := signInConfig(srv)
		c.gmail.consent = "http://" + gmailtest.Host + "/consent"
		h := NewMailHost(context.Background(), dir, sec, c)
		if b := h.gmailBegin("watch", fakeClient); b.Detail != clerk.DNoAccount || b.Consent != "" {
			t.Fatalf("gmailBegin = %+v; want %q", b, clerk.DNoAccount)
		}
		if d, err := h.gmailRevoke(); err != nil || d != clerk.DNoAccount {
			t.Fatalf("gmailRevoke = %q, %v; want %q", d, err, clerk.DNoAccount)
		}
		if !sec.Has(GmailSlot(gmailtest.User)) || srv.Revokes() != 0 {
			t.Fatalf("Gmail slot %v, %d revocations; want the account kept", sec.Has(GmailSlot(gmailtest.User)), srv.Revokes())
		}
	})
	t.Run("address", func(t *testing.T) {
		srv := gmailtest.New()
		t.Cleanup(srv.Close)
		dir := shortDir(t)
		sec, err := OpenSecrets(dir, testSealer())
		if err != nil {
			t.Fatal(err)
		}
		c := signInConfig(srv)
		c.gmail.base = "http://" + gmailtest.Host + "/gmail/v1/users/me"
		h := NewMailHost(context.Background(), dir, sec, c)
		landing, ok := srv.Approve(h.gmailBegin("watch", fakeClient).Consent)
		if !ok {
			t.Fatal("the fake refused the consent address")
		}
		if d, err := h.gmailFinish("watch", landing); err != nil || d != DGmailAddress {
			t.Fatalf("gmailFinish = %q, %v; want %q", d, err, DGmailAddress)
		}
		if sec.Len() != 0 || !slices.Equal(srv.Revoked(), []string{gmailtest.Issued(1)}) {
			t.Fatalf("%d slots, revoked %v; want the grant given back", sec.Len(), srv.Revoked())
		}
	})
}

// A sign-in again with no sealer to hold the grant's copy under starts
// nothing; one over a store that also holds a mail slot left behind signs
// in on a copy holding the account's grant only (CLK-1).
func TestASignInAgainNeedsASealerAndTheGrantAlone(t *testing.T) {
	t.Run("no sealer", func(t *testing.T) {
		srv, dir, sec := newGmailAccount(t)
		c := signInConfig(srv)
		c.Sealer = nil
		h := NewMailHost(context.Background(), dir, sec, c)
		if b := h.gmailBegin("watch", nil); b.Detail != clerk.DNoAccount || b.Consent != "" {
			t.Fatalf("gmailBegin = %+v; want %q", b, clerk.DNoAccount)
		}
	})
	t.Run("a mail slot left", func(t *testing.T) {
		srv, dir, sec := newGmailAccount(t)
		if err := sec.Put(clerk.MailSlots+"left", clerk.KindStatic, []byte("synthetic")); err != nil {
			t.Fatal(err)
		}
		h := NewMailHost(context.Background(), dir, sec, signInConfig(srv))
		b := h.gmailBegin("watch", nil)
		if b.Detail != "" || !strings.Contains(b.Consent, "login_hint="+url.QueryEscape(gmailtest.User)) {
			t.Fatalf("gmailBegin = %+v; want a sign-in again", b)
		}
		h.signMu.Lock()
		g := h.signing
		h.signMu.Unlock()
		if g.sec.Len() != 1 || !g.sec.Has(GmailSlot(gmailtest.User)) || sec.Len() != 2 {
			t.Fatalf("the copy holds %d slots, the account's store %d; want the grant alone in the copy", g.sec.Len(), sec.Len())
		}
	})
}

// The account removed while Google answers a sign-in again: the late grant
// is given back before it is used for anything, even the profile.
func TestASignInAgainYieldsToARemovalDuringFinish(t *testing.T) {
	srv, dir, sec := newGmailAccount(t)
	h := NewMailHost(context.Background(), dir, sec, signInConfig(srv))
	landing, ok := srv.Approve(h.gmailBegin("watch", nil).Consent)
	if !ok {
		t.Fatal("the fake refused the consent address")
	}
	h.signMu.Lock()
	g := h.signing
	h.signMu.Unlock()
	saved := g.in.Saved
	g.in.Saved = func(grant []byte) error {
		h.mu.Lock()
		defer h.mu.Unlock()
		if err := RemoveMail(h.dir, h.sec); err != nil {
			t.Error(err)
		}
		return saved(grant)
	}
	calls := len(srv.Calls())
	if d, err := h.gmailFinish("watch", landing); err != nil || d != clerk.DNoSignIn {
		t.Fatalf("gmailFinish = %q, %v; want %q", d, err, clerk.DNoSignIn)
	}
	if got := srv.Calls()[calls:]; len(got) != 0 || !slices.Equal(srv.Revoked(), []string{gmailtest.Issued(1)}) {
		t.Fatalf("calls %v, revoked %v; want the new grant given back unused", got, srv.Revoked())
	}
	if a, err := readMail(dir); err != ErrNoMailAccount || sec.Len() != 0 {
		t.Fatalf("account %+v, %v; want the removal to stand", a, err)
	}
}

// The account removed while the clerk asks Google's profile for the new
// grant's address, after the check during Finish: the removal stands, and
// the late grant is given back.
func TestASignInAgainYieldsToARemovalWhileNamingTheAddress(t *testing.T) {
	srv, dir, sec := newGmailAccount(t)
	h := NewMailHost(context.Background(), dir, sec, signInConfig(srv))
	landing, ok := srv.Approve(h.gmailBegin("watch", nil).Consent)
	if !ok {
		t.Fatal("the fake refused the consent address")
	}
	// A read in flight that this test ends: gmailFinish waits for it once
	// it has named the address, before it reads the account again.
	block := make(chan struct{})
	h.mu.Lock()
	h.idle()
	h.reading = block
	h.mu.Unlock()
	calls := len(srv.Calls())
	out := make(chan string, 1)
	go func() {
		d, err := h.gmailFinish("watch", landing)
		if err != nil {
			t.Error(err)
		}
		out <- d
	}()
	eventually(t, "the profile asked", func() bool { return len(srv.Calls()) > calls })
	h.mu.Lock()
	if err := RemoveMail(h.dir, h.sec); err != nil {
		t.Error(err)
	}
	h.reading = nil
	close(block)
	h.mu.Unlock()
	if d := <-out; d != clerk.DNoSignIn {
		t.Fatalf("gmailFinish = %q; want %q", d, clerk.DNoSignIn)
	}
	if a, err := readMail(dir); err != ErrNoMailAccount || sec.Len() != 0 || !slices.Equal(srv.Revoked(), []string{gmailtest.Issued(1)}) {
		t.Fatalf("account %+v, %v, %d slots, revoked %v; want the removal to stand and the new grant given back", a, err, sec.Len(), srv.Revoked())
	}
}

// A sign-in whose setup fails is no change of account: its settings write
// has ended, nothing tells the owner of a replacement, and its
// registration is not kept.
func TestAFailedSignInSetupChangesNothing(t *testing.T) {
	srv, dir, sec := newGmailAccount(t)
	h := NewMailHost(context.Background(), dir, sec, signInConfig(srv))
	owner := MailOwner{serveMail(t, h, MailOwnerSide)}
	blockSettings(t, dir)
	srv.As("other@gmail.test")
	h.mu.Lock()
	before := h.changes
	h.mu.Unlock()
	if _, err := finishSignIn(t, srv, owner, fakeClient); err == nil {
		t.Fatal("a sign-in whose setup failed answered no error")
	}
	h.mu.Lock()
	changes := h.changes
	h.mu.Unlock()
	h.ws.mu.Lock()
	writes := h.ws.writes
	h.ws.mu.Unlock()
	st, _ := owner.Status()
	if changes != before || writes != 0 || slices.Contains(st.Notices, noteMailReplaced) {
		t.Fatalf("%d changes after %d, %d settings writes in flight, notices %v; want no change told", changes, before, writes, st.Notices)
	}
	if _, ok := loadReg(dir, testSealer()); ok {
		t.Fatal("a failed setup kept its registration")
	}
}

// gmailrevoke is a change of account: the clerk the revoked account opened
// serves no step after it.
func TestARevokedGmailAccountServesNoStep(t *testing.T) {
	srv, dir, sec := newGmailAccount(t)
	h := NewMailHost(context.Background(), dir, sec, signInConfig(srv))
	if m, stop := h.clerk(); m == nil || stop != nil {
		t.Fatalf("before the revocation: clerk %v, stop %v", m, stop)
	}
	if d, err := h.gmailRevoke(); err != nil || d != clerk.DRevoked {
		t.Fatalf("gmailRevoke = %q, %v", d, err)
	}
	if res := h.Do(kernel.Request{}, nil); res.Detail != DNoAccount {
		t.Fatalf("a step after the revocation = %+v; want %q", res, DNoAccount)
	}
}

// giveBack called without h.mu takes it: it neither asks Google nor tells
// the owner while another change of the account holds it.
func TestAGiveBackWaitsForTheHostsLock(t *testing.T) {
	dir := shortDir(t)
	sec, err := OpenSecrets(dir, testSealer())
	if err != nil {
		t.Fatal(err)
	}
	h := NewMailHost(context.Background(), dir, sec, mailConfig())
	g, err := h.ownGmailSignIn() // holds no grant: Google keeps nothing, and the owner is told so
	if err != nil {
		t.Fatal(err)
	}
	h.mu.Lock()
	done := make(chan struct{})
	go func() { h.giveBack(g, false); close(done) }()
	wait, cancel := context.WithTimeout(context.Background(), 100e6) // 100 ms
	defer cancel()
	select {
	case <-done:
		h.mu.Unlock()
		t.Fatal("giveBack ran while h.mu was held")
	case <-wait.Done():
	}
	h.mu.Unlock()
	<-done
	h.mu.Lock()
	told := slices.ContainsFunc(h.notices, func(n notice) bool { return n.text == noteGmailKept })
	h.mu.Unlock()
	if !told {
		t.Fatal("the grant Google kept was not told")
	}
}

// What every Gmail sign-in runs on the mail account's own side (#5323):
// settings for a Gmail account name no servers and an address in plain
// form, and a directory others can reach holds no account, so SetGmail,
// RemoveMail and readMail refuse it.
func TestGmailSettingsRefuseWhatTheyCannotHold(t *testing.T) {
	if err := (MailSettings{Address: gmailtest.User, API: APIGmail, IMAP: "imap.example.test:993"}).check(); err != ErrMailAPI {
		t.Fatalf("Gmail settings naming a server: %v; want %v", err, ErrMailAPI)
	}
	_, dir, sec := newGmailAccount(t)
	const named = "Pat <pat@gmail.test>"
	if err := sec.Put(GmailSlot(named), clerk.KindGrant, gmailtest.Grant()); err != nil {
		t.Fatal(err)
	}
	if err := SetGmail(dir, sec, named); err != ErrMailAddress {
		t.Fatalf("SetGmail(%q) = %v; want %v", named, err, ErrMailAddress)
	}
	if s, err := readMail(dir); err != nil || s.Address != gmailtest.User {
		t.Fatalf("after a refused SetGmail: %+v, %v", s, err)
	}
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := SetGmail(dir, sec, gmailtest.User); err == nil {
		t.Fatal("SetGmail wrote into a directory others can reach")
	}
	if _, err := readMail(dir); err == nil {
		t.Fatal("readMail read settings from a directory others can reach")
	}
	if err := RemoveMail(dir, sec); err == nil || !sec.Has(GmailSlot(gmailtest.User)) {
		t.Fatalf("RemoveMail in a directory others can reach = %v, Gmail slot kept %v", err, sec.Has(GmailSlot(gmailtest.User)))
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
}

// readMail closes the settings file it reads.
func TestReadingTheSettingsClosesTheFile(t *testing.T) {
	_, dir, _ := newGmailAccount(t)
	open := func() int {
		fds, err := os.ReadDir("/proc/self/fd")
		if err != nil {
			t.Fatal(err)
		}
		return len(fds)
	}
	before := open()
	for range 64 {
		if s, err := readMail(dir); err != nil || s.Address != gmailtest.User {
			t.Fatalf("readMail = %+v, %v", s, err)
		}
	}
	if n := open(); n-before >= 32 {
		t.Fatalf("%d files open after 64 reads, %d before", n, before)
	}
}

// An account removed under the host, with no change told, is found gone at
// the next read: the clerk it opened stops serving, and the read counts as
// no account, not as a failure.
func TestARemovedAccountIsNoAccountAtTheNextRead(t *testing.T) {
	srv, dir, sec := newGmailAccount(t)
	h := NewMailHost(context.Background(), dir, sec, signInConfig(srv))
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.cur == nil {
		t.Fatalf("no clerk opened: %s", h.why)
	}
	if err := RemoveMail(dir, sec); err != nil {
		t.Fatal(err)
	}
	h.refresh()
	if h.cur != nil || h.why != "" || h.fails != 0 {
		t.Fatalf("after the removal: clerk %v, why %q, fails %d", h.cur, h.why, h.fails)
	}
}

// A change of account drops the senders record held for the old one and
// wakes the worker; the world's state starts over, and each settings write
// moves its generation at its start and its end (#3538).
func TestAChangeOfAccountStartsTheWorldOver(t *testing.T) {
	_, dir, sec := newGmailAccount(t)
	h := NewMailHost(context.Background(), dir, sec, mailConfig())
	h.mu.Lock()
	defer h.mu.Unlock()
	select {
	case <-h.kick:
	default:
	}
	h.srec = &sealedSenders{Over: true}
	h.ws.mu.Lock()
	h.ws.sread, h.ws.hist, h.ws.known, h.ws.contacts = sendersReading+1, slices.Grow(h.ws.hist, 1), []string{"a"}, []string{"b"}
	h.ws.mu.Unlock()
	h.changed()
	select {
	case <-h.kick:
	default:
		t.Fatal("a change of account did not wake the worker")
	}
	h.ws.mu.Lock()
	world := h.ws.sread == sendersReading && h.ws.hist == nil && h.ws.known == nil && h.ws.contacts == nil
	h.ws.mu.Unlock()
	if h.srec != nil || !world {
		t.Fatalf("after a change: senders record %v, world started over %v", h.srec, world)
	}
	gen := func() int64 {
		h.ws.mu.Lock()
		defer h.ws.mu.Unlock()
		return h.ws.gen
	}
	g0 := gen()
	end := h.ws.writing()
	g1 := gen()
	end()
	if g1 <= g0 || gen() <= g1 {
		t.Fatalf("generations %d, %d, %d across a write; want each later", g0, g1, gen())
	}
}

// The record of read mail's plaintext, which names senders, is wiped once
// saveSeen has sealed it.
func TestTheSeenRecordsPlaintextIsWiped(t *testing.T) {
	dir := shortDir(t)
	k := &gmailtest.Kept{Sealer: testSealer()}
	var rec sealedSeen
	rec.Log.Since = "2026-10-21"
	if err := saveSeen(dir, k, GmailSlot(gmailtest.User), rec, nil); err != nil {
		t.Fatal(err)
	}
	if n, wiped := k.Wiped(); n != 1 || !wiped {
		t.Fatalf("saveSeen left %d plaintexts, wiped %v", n, wiped)
	}
}

// A sign-in again, with the registration sealed in the account's grant,
// clears the reconnect stop: steps and reads run again, and the account
// keeps its record (#3009, the #3011 UX point).
func TestASignInAgainClearsTheReconnectStop(t *testing.T) {
	srv, dir, sec := newGmailAccount(t)
	srv.Deliver(gmailMail("news@shop.test", "<a@shop.test>"))
	srv.RefuseGrant()
	h := NewMailHost(context.Background(), dir, sec, signInConfig(srv))
	if res := h.Do(kernel.Request{}, nil); res.Detail != DReconnect {
		t.Fatalf("Do before the sign-in = %+v", res)
	}
	owner := MailOwner{serveMail(t, h, MailOwnerSide)}
	if d := signIn(t, srv, owner, "sort", nil); d != clerk.DSignedIn+" sort" {
		t.Fatalf("GmailFinish = %q", d)
	}
	if h.stop != nil || h.cur == nil {
		t.Fatalf("after the sign-in: stop %v, clerk %v", h.stop, h.cur)
	}
	if ls, err := h.listing(false); err != nil || len(ls) != 1 {
		t.Fatalf("listing = %v, %v", ls, err)
	}
	st, _ := owner.Status()
	if len(st.Lines) > 0 && strings.Contains(st.Lines[0], "Gmail stopped") || slices.Contains(st.Notices, noteMailReplaced) {
		t.Fatalf("status after a sign-in again = %+v", st)
	}
	if len(srv.Revoked()) != 0 {
		t.Fatalf("a sign-in again revoked %v; the new grant would die with the old", srv.Revoked())
	}
}

// A grant Google's profile names no usable address for is given back, and
// nothing is set up.
func TestAGrantWithNoAddressIsGivenBack(t *testing.T) {
	srv := gmailtest.New()
	t.Cleanup(srv.Close)
	dir := shortDir(t)
	sec, err := OpenSecrets(dir, testSealer())
	if err != nil {
		t.Fatal(err)
	}
	owner := MailOwner{serveMail(t, NewMailHost(context.Background(), dir, sec, signInConfig(srv)), MailOwnerSide)}
	srv.Fail("/profile", 500)
	if d := signIn(t, srv, owner, "watch", fakeClient); d != DGmailAddress {
		t.Fatalf("GmailFinish = %q, want %q", d, DGmailAddress)
	}
	if !slices.Equal(srv.Revoked(), []string{gmailtest.Issued(1)}) || sec.Len() != 0 {
		t.Fatalf("revoked %v, %d slots; want the grant given back and none kept", srv.Revoked(), sec.Len())
	}
	if a, _ := owner.Account(); a.Set {
		t.Fatalf("an account was set up: %+v", a)
	}
}

// Replacing or removing a Gmail account gives its grant back to Google
// before its slot is dropped (A22, #3009 issuecomment-6385928167); a setup
// the owner entered wrong is refused before anything is given back.
func TestReplacingOrRemovingGmailRevokesItsGrantFirst(t *testing.T) {
	imap := MailSettings{Address: imaptest.User, IMAP: "imap.example.test:993", SMTP: "smtp.example.test:465"}
	t.Run("replace", func(t *testing.T) {
		srv, dir, sec := newGmailAccount(t)
		owner := MailOwner{serveMail(t, NewMailHost(context.Background(), dir, sec, signInConfig(srv)), MailOwnerSide)}
		if err := owner.SetMail(imap, "short"); err == nil || len(srv.Revoked()) != 0 || !sec.Has(GmailSlot(gmailtest.User)) {
			t.Fatalf("a refused setup = %v; revoked %v", err, srv.Revoked())
		}
		if err := owner.SetMail(imap, imaptest.Password); err != nil {
			t.Fatal(err)
		}
		if !slices.Equal(srv.Revoked(), []string{gmailtest.Refresh}) || sec.Has(GmailSlot(gmailtest.User)) {
			t.Fatalf("revoked %v; Gmail slot kept %v", srv.Revoked(), sec.Has(GmailSlot(gmailtest.User)))
		}
		if st, _ := owner.Status(); slices.Contains(st.Notices, noteGmailKept) {
			t.Fatalf("a revoked grant was told as kept: %+v", st)
		}
	})
	t.Run("remove", func(t *testing.T) {
		srv, dir, sec := newGmailAccount(t)
		owner := MailOwner{serveMail(t, NewMailHost(context.Background(), dir, sec, signInConfig(srv)), MailOwnerSide)}
		if err := owner.RemoveMail(); err != nil {
			t.Fatal(err)
		}
		if !slices.Equal(srv.Revoked(), []string{gmailtest.Refresh}) || sec.Len() != 0 {
			t.Fatalf("revoked %v, %d slots", srv.Revoked(), sec.Len())
		}
	})
	// Google keeps the grant: the removal goes on, so the owner is never
	// stuck on Google's answer, and the owner is told the step that ends it.
	t.Run("kept", func(t *testing.T) {
		srv, dir, sec := newGmailAccount(t)
		c := signInConfig(srv)
		c.gmail.revoke = srv.Base() + "/revoke" // answers 401
		owner := MailOwner{serveMail(t, NewMailHost(context.Background(), dir, sec, c), MailOwnerSide)}
		if err := owner.RemoveMail(); err != nil || sec.Len() != 0 {
			t.Fatalf("RemoveMail = %v with %d slots", err, sec.Len())
		}
		st, _ := owner.Status()
		if !slices.Contains(st.Notices, noteGmailKept) || !strings.Contains(noteGmailKept, "myaccount.google.com/permissions") {
			t.Fatalf("notices = %v; want the kept grant told with its step", st.Notices)
		}
	})
}

// gmailrevoke gives the grant back and removes the account; a grant Google
// kept stays sealed with the account, so the owner can try again.
func TestGmailRevokeOverTheOwnerSocket(t *testing.T) {
	t.Run("revoked", func(t *testing.T) {
		srv, dir, sec := newGmailAccount(t)
		owner := MailOwner{serveMail(t, NewMailHost(context.Background(), dir, sec, signInConfig(srv)), MailOwnerSide)}
		if d, err := owner.GmailRevoke(); err != nil || d != clerk.DRevoked {
			t.Fatalf("GmailRevoke = %q, %v", d, err)
		}
		if a, _ := owner.Account(); a.Set || sec.Len() != 0 || !slices.Equal(srv.Revoked(), []string{gmailtest.Refresh}) {
			t.Fatalf("account %+v, %d slots, revoked %v", a, sec.Len(), srv.Revoked())
		}
		if st, _ := owner.Status(); !slices.Contains(st.Notices, noteGmailRevoked) {
			t.Fatalf("notices = %v", st.Notices)
		}
	})
	t.Run("kept", func(t *testing.T) {
		srv, dir, sec := newGmailAccount(t)
		c := signInConfig(srv)
		c.gmail.revoke = srv.Base() + "/revoke"
		owner := MailOwner{serveMail(t, NewMailHost(context.Background(), dir, sec, c), MailOwnerSide)}
		if d, err := owner.GmailRevoke(); err != nil || !strings.HasPrefix(d, clerk.DNoRevoke) {
			t.Fatalf("GmailRevoke = %q, %v", d, err)
		}
		if a, _ := owner.Account(); !a.Set || !sec.Has(GmailSlot(gmailtest.User)) {
			t.Fatalf("a kept grant removed the account: %+v", a)
		}
	})
}

// A sign-in again offers the account's own address first, and if the owner
// sets another account up while on Google's page, that setup stands and
// the late grant is given back.
func TestASignInAgainYieldsToALaterSetup(t *testing.T) {
	srv, dir, sec := newGmailAccount(t)
	owner := MailOwner{serveMail(t, NewMailHost(context.Background(), dir, sec, signInConfig(srv)), MailOwnerSide)}
	consent, d, err := owner.GmailBegin("watch", nil)
	if err != nil || d != "" || !strings.Contains(consent, "login_hint="+url.QueryEscape(gmailtest.User)) {
		t.Fatalf("GmailBegin = %q, %q, %v; want the account's address as the hint", consent, d, err)
	}
	imap := MailSettings{Address: imaptest.User, IMAP: "imap.example.test:993", SMTP: "smtp.example.test:465"}
	if err := owner.SetMail(imap, imaptest.Password); err != nil {
		t.Fatal(err)
	}
	landing, ok := srv.Approve(consent)
	if !ok {
		t.Fatal("the fake refused the consent address")
	}
	if d, err := owner.GmailFinish("watch", landing); err != nil || d != clerk.DNoSignIn {
		t.Fatalf("GmailFinish after a later setup = %q, %v", d, err)
	}
	if a, _ := owner.Account(); a.Settings != imap || sec.Has(GmailSlot(gmailtest.User)) || len(srv.Revoked()) != 1 {
		t.Fatalf("account %+v, Gmail slot %v, revoked %v; want the IMAP setup kept, the old grant given back and no code redeemed",
			a.Settings, sec.Has(GmailSlot(gmailtest.User)), srv.Revoked())
	}
}

// A sign-in that sets up another Gmail address gives the account it
// replaces its grant back first (A22, #3023 L3 1), and tells the owner the
// step when Google keeps it.
func TestASignInForAnotherAddressRevokesTheOldGrantFirst(t *testing.T) {
	const other = "other@gmail.test"
	for _, kept := range []bool{false, true} {
		srv, dir, sec := newGmailAccount(t)
		c := signInConfig(srv)
		if kept {
			c.gmail.revoke = srv.Base() + "/revoke" // answers 401
		}
		owner := MailOwner{serveMail(t, NewMailHost(context.Background(), dir, sec, c), MailOwnerSide)}
		srv.As(other)
		if d := signIn(t, srv, owner, "watch", fakeClient); d != clerk.DSignedIn+" watch" {
			t.Fatalf("kept %v: GmailFinish = %q", kept, d)
		}
		a, _ := owner.Account()
		if a.Settings.Address != other || sec.Has(GmailSlot(gmailtest.User)) || !sec.Has(GmailSlot(other)) || sec.Len() != 1 {
			t.Fatalf("kept %v: account %+v, %d slots; want the new address only", kept, a.Settings, sec.Len())
		}
		revoked := slices.Equal(srv.Revoked(), []string{gmailtest.Refresh})
		st, _ := owner.Status()
		if revoked == kept || slices.Contains(st.Notices, noteGmailKept) != kept || !slices.Contains(st.Notices, noteMailReplaced) {
			t.Fatalf("kept %v: revoked %v, notices %v", kept, srv.Revoked(), st.Notices)
		}
	}
}

// Two pastes at once finish the sign-in once: the other finds none
// waiting, and the account's grant works (#3023 Security).
func TestTwoPastesAtOnceFinishOnce(t *testing.T) {
	for i := 0; i < 20; i++ {
		srv, dir, sec := newGmailAccount(t)
		c := signInConfig(srv)
		c.gmail.revoke = srv.Base() + "/revoke" // keeps the fake's one refresh token alive for the check
		h := NewMailHost(context.Background(), dir, sec, c)
		const other = "other@gmail.test"
		srv.As(other)
		landing, ok := srv.Approve(h.gmailBegin("watch", fakeClient).Consent)
		if !ok {
			t.Fatal("the fake refused the consent address")
		}
		var wg sync.WaitGroup
		out := make([]string, 2)
		for j := range out {
			wg.Add(1)
			go func() { defer wg.Done(); out[j], _ = h.gmailFinish("watch", landing) }()
		}
		wg.Wait()
		slices.Sort(out)
		if !slices.Equal(out, []string{clerk.DNoSignIn, clerk.DSignedIn + " watch"}) {
			t.Fatalf("%d: details %q; want one finish and one nosignin", i, out)
		}
		box, err := gmailBox(sec, GmailSlot(other), h.cfg)
		if err == nil {
			_, err = box.Address(context.Background())
		}
		if err != nil {
			t.Fatalf("%d: the account's grant does not work: %v", i, err)
		}
	}
}

// A paste that is not the loopback address keeps the sign-in waiting.
func TestAWrongPasteKeepsTheSignInWaiting(t *testing.T) {
	srv, dir, sec := newGmailAccount(t)
	owner := MailOwner{serveMail(t, NewMailHost(context.Background(), dir, sec, signInConfig(srv)), MailOwnerSide)}
	consent, _, err := owner.GmailBegin("watch", fakeClient)
	if err != nil {
		t.Fatal(err)
	}
	if d, _ := owner.GmailFinish("watch", "https://example.test/"); d != clerk.DNotOurs {
		t.Fatalf("a wrong paste = %q", d)
	}
	landing, _ := srv.Approve(consent)
	if d, _ := owner.GmailFinish("watch", landing); d != clerk.DSignedIn+" watch" {
		t.Fatalf("the right paste after a wrong one = %q", d)
	}
}

// A sign-in again where the owner picks another Google account sets that
// account up and then gives the old account's grant back, which its Finish
// sealed only over a copy (#3023 Security R3, #3026).
func TestASignInAgainAsAnotherAccountGivesTheOldGrantBack(t *testing.T) {
	srv, dir, sec := newGmailAccount(t)
	owner := MailOwner{serveMail(t, NewMailHost(context.Background(), dir, sec, signInConfig(srv)), MailOwnerSide)}
	srv.As("other@gmail.test")
	if d := signIn(t, srv, owner, "watch", nil); d != clerk.DSignedIn+" watch" {
		t.Fatalf("GmailFinish = %q", d)
	}
	st, _ := owner.Status()
	if a, _ := owner.Account(); a.Settings.Address != "other@gmail.test" || sec.Len() != 1 || !sec.Has(GmailSlot("other@gmail.test")) ||
		!slices.Equal(srv.Revoked(), []string{gmailtest.Refresh}) || slices.Contains(st.Notices, noteGmailKept) || !slices.Contains(st.Notices, noteMailReplaced) {
		t.Fatalf("account %+v, %d slots, revoked %v, notices %v", a.Settings, sec.Len(), srv.Revoked(), st.Notices)
	}
}

// A new grant Google keeps when it is given back is told to the owner
// (#3023 Security R2).
func TestAKeptGiveBackIsTold(t *testing.T) {
	srv := gmailtest.New()
	t.Cleanup(srv.Close)
	dir := shortDir(t)
	sec, err := OpenSecrets(dir, testSealer())
	if err != nil {
		t.Fatal(err)
	}
	c := signInConfig(srv)
	c.gmail.revoke = srv.Base() + "/revoke" // answers 401
	owner := MailOwner{serveMail(t, NewMailHost(context.Background(), dir, sec, c), MailOwnerSide)}
	srv.Fail("/profile", 500)
	if d := signIn(t, srv, owner, "watch", fakeClient); d != DGmailAddress {
		t.Fatalf("GmailFinish = %q", d)
	}
	if st, _ := owner.Status(); !slices.Contains(st.Notices, noteGmailKept) || sec.Len() != 0 {
		t.Fatalf("notices %v, %d slots", st.Notices, sec.Len())
	}
}

// A wrong paste and the right one at once never wipe the grant the right
// one seals (#3023 Security delta).
func TestAWrongAndARightPasteAtOnce(t *testing.T) {
	for i := 0; i < 20; i++ {
		srv, dir, sec := newGmailAccount(t)
		c := signInConfig(srv)
		c.gmail.revoke = srv.Base() + "/revoke" // keeps the fake's one refresh token alive for the check
		h := NewMailHost(context.Background(), dir, sec, c)
		const other = "other@gmail.test"
		srv.As(other)
		landing, ok := srv.Approve(h.gmailBegin("watch", fakeClient).Consent)
		if !ok {
			t.Fatal("the fake refused the consent address")
		}
		var wg sync.WaitGroup
		out := make([]string, 2)
		for j, p := range []string{"https://example.test/", landing} {
			wg.Add(1)
			go func() { defer wg.Done(); out[j], _ = h.gmailFinish("watch", p) }()
		}
		wg.Wait()
		if out[1] != clerk.DSignedIn+" watch" {
			if out[1] != clerk.DNoSignIn {
				t.Fatalf("%d: the right paste = %q", i, out[1])
			}
			continue // the wrong one held the sign-in at that moment
		}
		box, err := gmailBox(sec, GmailSlot(other), h.cfg)
		if err == nil {
			_, err = box.Address(context.Background())
		}
		if err != nil {
			t.Fatalf("%d: the account's grant does not work: %v", i, err)
		}
	}
}

// blockSettings makes the next write of the account's settings fail, after
// any slot is put: its temporary is a directory that does not remove.
func blockSettings(t *testing.T, dir string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(dir, mailSettings+".tmp", "x"), 0o700); err != nil {
		t.Fatal(err)
	}
}

// finishSignIn is signIn that returns GmailFinish's error too.
func finishSignIn(t *testing.T, srv *gmailtest.Server, owner MailOwner, reg *clerk.Registration) (string, error) {
	t.Helper()
	consent, d, err := owner.GmailBegin("watch", reg)
	if err != nil || d != "" {
		t.Fatalf("GmailBegin = %q, %v", d, err)
	}
	landing, ok := srv.Approve(consent)
	if !ok {
		t.Fatal("the fake refused the consent address")
	}
	return owner.GmailFinish("watch", landing)
}

// readKept fails unless the grant sealed for gmailtest.User still reads.
func readKept(t *testing.T, srv *gmailtest.Server, sec *clerk.Secrets) {
	t.Helper()
	box, err := gmailBox(sec, GmailSlot(gmailtest.User), signInConfig(srv))
	if err == nil {
		_, err = box.Read(context.Background())
	}
	if err != nil {
		t.Fatalf("the kept grant does not read: %v", err)
	}
}

// A replaced Gmail account's grant is given back only once the new account
// is set up (#3026): when the setup fails, the account before stays set up
// with a grant that works, and only the new grant is given back (#3030).
func TestAFailedSetupKeepsTheReplacedGrant(t *testing.T) {
	const other = "other@gmail.test"
	imap := MailSettings{Address: imaptest.User, IMAP: "imap.example.test:993", SMTP: "smtp.example.test:465"}
	for _, again := range []bool{false, true} {
		srv, dir, sec := newGmailAccount(t)
		owner := MailOwner{serveMail(t, NewMailHost(context.Background(), dir, sec, signInConfig(srv)), MailOwnerSide)}
		blockSettings(t, dir)
		srv.As(other)
		reg := fakeClient
		if again {
			reg = nil
		}
		if _, err := finishSignIn(t, srv, owner, reg); err == nil {
			t.Fatalf("again %v: a sign-in whose setup failed answered no error", again)
		}
		a, _ := owner.Account()
		if a.Settings.Address != gmailtest.User || !sec.Has(GmailSlot(gmailtest.User)) || sec.Has(GmailSlot(other)) ||
			srv.Revokes() != 1 || !slices.Equal(srv.Revoked(), []string{gmailtest.Issued(1)}) {
			t.Fatalf("again %v: account %+v, %d slots, revoked %v; want the old account kept with its grant",
				again, a.Settings, sec.Len(), srv.Revoked())
		}
		readKept(t, srv, sec)
	}
	t.Run("setmail", func(t *testing.T) {
		srv, dir, sec := newGmailAccount(t)
		owner := MailOwner{serveMail(t, NewMailHost(context.Background(), dir, sec, signInConfig(srv)), MailOwnerSide)}
		blockSettings(t, dir)
		if err := owner.SetMail(imap, imaptest.Password); err == nil {
			t.Fatal("a setup whose write failed answered no error")
		}
		if a, _ := owner.Account(); a.Settings.API != APIGmail || !sec.Has(GmailSlot(gmailtest.User)) || len(srv.Revoked()) != 0 {
			t.Fatalf("account %+v, revoked %v; want the Gmail account kept with its grant", a.Settings, srv.Revoked())
		}
		readKept(t, srv, sec)
		if err := os.RemoveAll(filepath.Join(dir, mailSettings+".tmp")); err != nil {
			t.Fatal(err)
		}
		if err := owner.SetMail(imap, imaptest.Password); err != nil || !slices.Equal(srv.Revoked(), []string{gmailtest.Refresh}) {
			t.Fatalf("SetMail = %v, revoked %v", err, srv.Revoked())
		}
	})
	// A removal that fails once the slots are dropped has nothing left to
	// keep: the grant is given back all the same.
	t.Run("removemail", func(t *testing.T) {
		srv, dir, sec := newGmailAccount(t)
		owner := MailOwner{serveMail(t, NewMailHost(context.Background(), dir, sec, signInConfig(srv)), MailOwnerSide)}
		blockSettings(t, dir)
		if err := owner.RemoveMail(); err == nil {
			t.Fatal("a removal that failed answered no error")
		}
		if sec.Len() != 0 || !slices.Equal(srv.Revoked(), []string{gmailtest.Refresh}) {
			t.Fatalf("%d slots, revoked %v; want the dropped grant given back", sec.Len(), srv.Revoked())
		}
	})
}

// A first sign-in for the account's own address whose grant does not seal
// gives nothing back: Google's revocation of the new grant would end the
// account's own with it (#3026). One whose settings write fails has its
// grant sealed already, so the account is set up with it.
func TestAFailedSameAddressSetupGivesNothingBack(t *testing.T) {
	for _, block := range []string{secretsName, mailSettings} {
		srv, dir, sec := newGmailAccount(t)
		owner := MailOwner{serveMail(t, NewMailHost(context.Background(), dir, sec, signInConfig(srv)), MailOwnerSide)}
		if err := os.MkdirAll(filepath.Join(dir, block+".tmp", "x"), 0o700); err != nil {
			t.Fatal(err)
		}
		if _, err := finishSignIn(t, srv, owner, fakeClient); err == nil {
			t.Fatalf("%s: a sign-in whose write failed answered no error", block)
		}
		if a, _ := owner.Account(); a.Settings.Address != gmailtest.User || sec.Len() != 1 || len(srv.Revoked()) != 0 {
			t.Fatalf("%s: account %+v, %d slots, revoked %v", block, a.Settings, sec.Len(), srv.Revoked())
		}
	}
}

// A sign-in whose profile fails while a Gmail account is set up gives
// nothing back: the new grant may be that account's own, which Google's
// revocation would end. The account's grant keeps working, and the owner
// is told to end the new one only in another account (#3027 L3 1).
func TestASignInWithNoAddressKeepsTheAccountsGrantWorking(t *testing.T) {
	for _, reg := range []*clerk.Registration{nil, fakeClient} {
		srv, dir, sec := newGmailAccount(t)
		c := signInConfig(srv)
		owner := MailOwner{serveMail(t, NewMailHost(context.Background(), dir, sec, c), MailOwnerSide)}
		srv.Fail("/profile", 500)
		if d, err := finishSignIn(t, srv, owner, reg); err != nil || d != DGmailAddress {
			t.Fatalf("registration %v: GmailFinish = %q, %v", reg != nil, d, err)
		}
		box, err := gmailBox(sec, GmailSlot(gmailtest.User), c)
		if err == nil {
			_, err = box.Read(context.Background())
		}
		st, _ := owner.Status()
		if a, _ := owner.Account(); !a.Set || sec.Len() != 1 || srv.Revokes() != 0 || err != nil || !slices.Contains(st.Notices, noteGmailUnnamed) || slices.Contains(st.Notices, noteGmailKept) {
			t.Fatalf("registration %v: account %+v, %d slots, %d revocations, read %v, notices %v",
				reg != nil, a.Settings, sec.Len(), srv.Revokes(), err, st.Notices)
		}
	}
}

// Settings that do not read fail closed the same way: the box may still
// hold a Gmail grant the revocation would end (#3027 L3 delta 2).
func TestASignInWithNoAddressOverUnreadableSettingsGivesNothingBack(t *testing.T) {
	srv, dir, sec := newGmailAccount(t)
	owner := MailOwner{serveMail(t, NewMailHost(context.Background(), dir, sec, signInConfig(srv)), MailOwnerSide)}
	if err := os.WriteFile(filepath.Join(dir, mailSettings), []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	srv.Fail("/profile", 500)
	if d, err := finishSignIn(t, srv, owner, fakeClient); err != nil || d != DGmailAddress {
		t.Fatalf("GmailFinish = %q, %v", d, err)
	}
	if st, _ := owner.Status(); srv.Revokes() != 0 || !slices.Contains(st.Notices, noteGmailUnnamed) {
		t.Fatalf("%d revocations, notices %v", srv.Revokes(), st.Notices)
	}
}

// With an IMAP account set up, no Gmail grant is in use, so a new grant
// Google's profile names no address for is given back (#3027 Security
// delta 1).
func TestASignInWithNoAddressOverIMAPGivesTheGrantBack(t *testing.T) {
	srv, dir, sec := newGmailAccount(t)
	owner := MailOwner{serveMail(t, NewMailHost(context.Background(), dir, sec, signInConfig(srv)), MailOwnerSide)}
	imap := MailSettings{Address: imaptest.User, IMAP: "imap.example.test:993", SMTP: "smtp.example.test:465"}
	if err := owner.SetMail(imap, imaptest.Password); err != nil {
		t.Fatal(err)
	}
	before := srv.Revokes()
	srv.Fail("/profile", 500)
	if d, err := finishSignIn(t, srv, owner, fakeClient); err != nil || d != DGmailAddress {
		t.Fatalf("GmailFinish = %q, %v", d, err)
	}
	if st, _ := owner.Status(); srv.Revokes() != before+1 || slices.Contains(st.Notices, noteGmailUnnamed) {
		t.Fatalf("%d revocations after %d, notices %v", srv.Revokes(), before, st.Notices)
	}
}
