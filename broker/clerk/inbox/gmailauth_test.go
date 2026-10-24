package inbox

// REQ: CLK-9, CLK-1, CLK-4

import (
	"context"
	"crypto/rand"
	"errors"
	"net/url"
	"strings"
	"testing"

	"github.com/ghbmrk/agentos/broker/clerk"
	"github.com/ghbmrk/agentos/broker/clerk/inbox/gmailtest"
)

// signInRig is a Gmail account's sign-in on a fresh fake: the clerk's store,
// empty, and the sign-in and mailbox on it. out collects everything the clerk
// gave the owner side (the consent address and each detail), as the owner
// page's frames carry them (D-154).
type signInRig struct {
	srv *gmailtest.Server
	sec *clerk.Secrets
	in  *clerk.SignIn
	out []string
	// use is the last use begun, the one the owner page's confirm screen
	// shows and its Connect form carries.
	use string
}

func newSignIn(t *testing.T) *signInRig {
	t.Helper()
	srv := gmailtest.New()
	t.Cleanup(srv.Close)
	k := make([]byte, 32)
	rand.Read(k)
	sl, err := clerk.NewAESSealer(k)
	if err != nil {
		t.Fatal(err)
	}
	r := &signInRig{srv: srv, sec: clerk.NewSecrets(sl, nil)}
	r.in, err = clerk.NewSignIn(GmailSignIn(srv.Consent(), srv.Token(), srv.Revoke(), "gmail", srv.Guard(), nil), r.sec, srv.Roots())
	if err != nil {
		t.Fatal(err)
	}
	return r
}

var household = &clerk.Registration{ID: gmailtest.Client, Secret: gmailtest.Secret}

// begin starts a sign-in for use and returns the consent address.
func (r *signInRig) begin(t *testing.T, use string, reg *clerk.Registration) string {
	t.Helper()
	addr, err := r.in.Begin(use, reg)
	if err != nil {
		t.Fatalf("Begin(%s) = %v", use, err)
	}
	r.out = append(r.out, addr)
	r.use = use
	return addr
}

// finish pastes landing for the last use begun and returns the detail.
func (r *signInRig) finish(landing string) string { return r.finishAs(r.use, landing) }

// finishAs pastes landing on a confirm screen that named use.
func (r *signInRig) finishAs(use, landing string) string {
	d := r.in.Finish(context.Background(), use, landing)
	r.out = append(r.out, d)
	return d
}

// connect runs a whole sign-in for use: Begin, the owner's consent on their
// phone, and the paste.
func (r *signInRig) connect(t *testing.T, use string, reg *clerk.Registration) string {
	t.Helper()
	landing, ok := r.srv.Approve(r.begin(t, use, reg))
	if !ok {
		t.Fatal("the fake refused the consent address")
	}
	return r.finish(landing)
}

func (r *signInRig) mailbox(t *testing.T) *Gmail {
	t.Helper()
	api, err := clerk.NewAPI(GmailDeclaration(r.srv.Base(), r.srv.Token(), "gmail", r.srv.Guard(), nil), r.sec, r.srv.Roots())
	if err != nil {
		t.Fatal(err)
	}
	return NewGmail(api)
}

// A consent returned by paste yields a grant sealed in the mail clerk, with
// the scope the declared use needs and no wider, and the mailbox works on it
// (A22 Gmail).
func TestGmailSignInByPasteSealsTheGrantWithTheUsesScope(t *testing.T) {
	for use, scope := range GmailUses {
		r := newSignIn(t)
		addr := r.begin(t, use, household)
		u, _ := url.Parse(addr)
		q := u.Query()
		if u.Scheme+"://"+u.Host+u.Path != r.srv.Consent() || q.Get("scope") != scope || q.Get("redirect_uri") != GmailRedirect ||
			q.Get("code_challenge_method") != "S256" || q.Get("prompt") != "consent" {
			t.Fatalf("%s: consent address %s", use, addr)
		}
		landing, _ := r.srv.Approve(addr)
		if d := r.finish(landing); d != clerk.DSignedIn+" "+use {
			t.Fatalf("%s: Finish = %q", use, d)
		}
		if !r.sec.Has("gmail") || r.sec.Len() != 1 {
			t.Fatalf("%s: the grant is not sealed in the clerk's one slot", use)
		}
	}
	r := newSignIn(t)
	if d := r.connect(t, "sort", household); d != "signedin sort" {
		t.Fatal(d)
	}
	r.srv.Deliver([]byte(crlfMail("m1", "a@example.com", "hello")))
	if ms, err := r.mailbox(t).Read(context.Background()); err != nil || len(ms) != 1 {
		t.Fatalf("Read after sign-in = %d, %v", len(ms), err)
	}
}

// A grant wider than the use asked for is revoked and never sealed (CLK-9).
func TestGmailSignInRefusesAWiderGrantAndRevokesIt(t *testing.T) {
	r := newSignIn(t)
	r.srv.Wider(GmailUses["sort"])
	if d := r.connect(t, "watch", household); d != clerk.DScope {
		t.Fatalf("Finish = %q, want %q", d, clerk.DScope)
	}
	if r.sec.Has("gmail") {
		t.Fatal("a wider grant was sealed")
	}
	if rv := r.srv.Revoked(); len(rv) != 1 || rv[0] != gmailtest.Issued(1) {
		t.Fatalf("revoked %v", rv)
	}
}

// The paste is checked before anything is sent: only the declared loopback
// address, only this sign-in's state, once; a cancelled consent or a sign-in
// never begun redeems nothing.
func TestGmailSignInChecksThePasteBeforeRedeeming(t *testing.T) {
	r := newSignIn(t)
	if d := r.finish(GmailRedirect + "?state=x&code=y"); d != clerk.DNoSignIn {
		t.Fatalf("no sign-in: %q", d)
	}
	landing, _ := r.srv.Approve(r.begin(t, "watch", household))
	for _, bad := range []string{
		strings.Replace(landing, "127.0.0.1:8521", "127.0.0.1:8522", 1),
		strings.Replace(landing, "http://", "https://", 1),
		strings.Replace(landing, "/agentos", "/other", 1),
		"https://evil.example/agentos?" + landing[strings.Index(landing, "?")+1:],
	} {
		if d := r.finish(bad); d != clerk.DNotOurs {
			t.Fatalf("Finish(%s) = %q, want notours", bad, d)
		}
	}
	// A wrong state ends the sign-in, so the right paste after it is refused.
	q, _ := url.Parse(landing)
	forged := GmailRedirect + "?state=forged&code=" + q.Query().Get("code")
	if d := r.finish(forged); d != clerk.DState {
		t.Fatalf("forged state: %q", d)
	}
	if d := r.finish(landing); d != clerk.DNoSignIn {
		t.Fatalf("after a forged state: %q", d)
	}
	if d := r.finish(gmailtest.Deny(r.begin(t, "watch", household))); d != clerk.DRefused {
		t.Fatalf("cancelled consent: %q", d)
	}
	if r.srv.Tokens() != 0 || r.sec.Has("gmail") {
		t.Fatal("a code was redeemed")
	}
	// The verifier is the clerk's: a code redeemed with another fails.
	r2 := newSignIn(t)
	landing2, _ := r2.srv.Approve(r2.begin(t, "watch", household))
	_ = r2.begin(t, "watch", household) // a new Begin replaces the verifier and state
	if d := r2.finish(landing2); d != clerk.DState {
		t.Fatalf("stale state after a new Begin: %q", d)
	}
}

// Finish is bound to the use the owner confirmed (#3012, the #3008 Security
// path): with Watch begun in one tab and Sort in another, Sort's landing
// address pasted on Watch's confirm screen redeems nothing, seals nothing
// and ends the sign-in, so the paste cannot then be tried as Sort.
func TestGmailSignInIsBoundToTheConfirmedUse(t *testing.T) {
	r := newSignIn(t)
	_ = r.begin(t, "watch", household)
	landing, _ := r.srv.Approve(r.begin(t, "sort", household))
	if d := r.finishAs("watch", landing); d != clerk.DUse {
		t.Fatalf("Sort's landing on Watch's screen: %q", d)
	}
	if d := r.finishAs("sort", landing); d != clerk.DNoSignIn {
		t.Fatalf("after a use refused: %q", d)
	}
	for _, use := range []string{"", "everything"} {
		landing, _ := r.srv.Approve(r.begin(t, "watch", household))
		if d := r.finishAs(use, landing); d != clerk.DUse {
			t.Fatalf("use %q: %q", use, d)
		}
	}
	if r.srv.Tokens() != 0 || r.sec.Has("gmail") {
		t.Fatal("a code was redeemed for a use the owner did not confirm")
	}
	for _, o := range r.out {
		if strings.Contains(o, gmailtest.Secret) {
			t.Fatal("a detail carries the client secret")
		}
	}
}

// The box revokes its own grant: the provider drops it, the slot is
// emptied, and a refresh after it is grant death (A22 Gmail).
func TestGmailSignInRevokesItsOwnGrant(t *testing.T) {
	r := newSignIn(t)
	r.connect(t, "sort", household)
	box := r.mailbox(t)
	if _, err := box.Read(context.Background()); err != nil {
		t.Fatal(err)
	}
	if d := r.in.Revoke(context.Background()); d != clerk.DRevoked {
		t.Fatalf("Revoke = %q", d)
	}
	if r.sec.Has("gmail") {
		t.Fatal("the slot still holds the grant")
	}
	if rv := r.srv.Revoked(); len(rv) != 1 || rv[0] != gmailtest.Issued(1) {
		t.Fatalf("revoked %v", rv)
	}
	if d := r.in.Revoke(context.Background()); d != clerk.DNoAccount {
		t.Fatalf("second Revoke = %q", d)
	}
}

// A refused refresh is grant death: the mailbox reports reconnect, and the
// owner text names both causes, including a client left in Testing. A
// reconnect then needs no client secret from the owner side: it reuses the
// one sealed with the dead grant.
func TestGmailGrantDeathAndReconnectWithTheSealedClient(t *testing.T) {
	r := newSignIn(t)
	r.connect(t, "sort", household)
	box := r.mailbox(t)
	r.srv.RefuseGrant()
	r.srv.Expire()
	if _, err := box.Read(context.Background()); !errors.Is(err, nReconnect) {
		t.Fatalf("Read = %v, want reconnect", err)
	}
	for _, cause := range []string{"removed or ran out", "Testing", "7 days", "In production"} {
		if !strings.Contains(GmailReconnect, cause) {
			t.Fatalf("the reconnect text does not name %q", cause)
		}
	}
	api, err := clerk.NewAPI(GmailDeclaration(r.srv.Base(), r.srv.Token(), "gmail", r.srv.Guard(), nil), r.sec, r.srv.Roots())
	if err != nil {
		t.Fatal(err)
	}
	r.in.Saved = api.Reconnect
	if d := r.connect(t, "sort", nil); d != "signedin sort" {
		t.Fatalf("reconnect = %q", d)
	}
	if _, err := NewGmail(api).Read(context.Background()); err != nil {
		t.Fatalf("Read after reconnect = %v", err)
	}
}

// Keeper boundary (D-154): the client secret, the refresh token, the access
// tokens and the code's verifier never reach the owner side. Everything the
// clerk gave it across a connect, a reconnect and a revoke holds none of
// them; the owner side gives the secret once, at the first sign-in, and
// never again.
func TestGmailSignInGivesTheOwnerSideNoSecret(t *testing.T) {
	r := newSignIn(t)
	r.connect(t, "sort", household)
	box := r.mailbox(t)
	if _, err := box.Read(context.Background()); err != nil {
		t.Fatal(err)
	}
	r.srv.RefuseGrant()
	r.srv.Expire()
	_, err := box.Read(context.Background())
	r.out = append(r.out, err.Error())
	r.connect(t, "sort", nil)
	r.out = append(r.out, r.in.Revoke(context.Background()))
	held := strings.Join(r.out, "\n")
	// The code is not on the list: it comes from the owner's own paste.
	for _, c := range []string{gmailtest.Secret, gmailtest.Refresh, "canary-gmailtest-access"} {
		if strings.Contains(held, c) {
			t.Fatalf("the owner side holds %q:\n%s", c, held)
		}
	}
	if _, err := r.in.Begin("sort", &clerk.Registration{ID: "x", Secret: "bad\nsecret"}); err == nil || err.Error() != clerk.DRegistered {
		t.Fatalf("Begin with a bad registration = %v", err)
	}
	if _, err := r.in.Begin("send", household); err == nil {
		t.Fatal("Begin for an undeclared use")
	}
}
