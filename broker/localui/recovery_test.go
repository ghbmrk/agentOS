package localui

import (
	"bytes"
	"context"
	"encoding/base64"
	"html"
	"io"
	"math/rand"
	"mime/multipart"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ghbmrk/agentos/broker/card"
	"github.com/ghbmrk/agentos/broker/clerk/seal"
	"github.com/ghbmrk/agentos/broker/firstboot"
	"github.com/ghbmrk/agentos/broker/localapi"
	"github.com/ghbmrk/agentos/broker/modem"
)

// REQ: REC-4, BAK-1, STO-2

// fakeRecoveryOps is agentosd's passkey ops and recovery-key ops on one
// socket, as AgentosdPasskeys serves them.
type fakeRecoveryOps struct {
	*fakePasskeys
	begins  [][]byte
	rotates []localapi.RecoveryRotate
	beginErr,
	rotateErr error
	switched bool
	// The lost-card ops (lostcard_test.go).
	lost      []string
	lostState localapi.RecoveryLostState
	lostCard  []byte
	lostErr   error
	doneErr   error // RecoveryLostDone's answer
}

var testBegun = localapi.RecoveryBegun{Old: strings.Repeat("a1", 16), Next: strings.Repeat("b2", 16), Challenge: []byte("0123456789abcdef0123456789abcdef")}

func (f *fakeRecoveryOps) RecoveryBegin(_ context.Context, _ string, next []byte) (localapi.RecoveryBegun, error) {
	f.begins = append(f.begins, bytes.Clone(next))
	return testBegun, f.beginErr
}

func (f *fakeRecoveryOps) RecoveryRotate(_ context.Context, _, factor string, secret, next, ad, cd, sig []byte) (localapi.RecoveryDone, error) {
	f.rotates = append(f.rotates, localapi.RecoveryRotate{Factor: factor, Secret: bytes.Clone(secret), Next: bytes.Clone(next),
		AuthenticatorData: ad, ClientDataJSON: cd, Signature: sig})
	return localapi.RecoveryDone{Switched: f.switched}, f.rotateErr
}

func (f *fakeRecoveryOps) calls() int { return len(f.begins) + len(f.rotates) }

// recoveryRig is a set-up box whose passkey ops also serve the
// recovery-key ops; newKey is the recovery key of the last card the page
// made.
type recoveryRig struct {
	*rig
	f      *fakeRecoveryOps
	newKey string
}

func newRecoveryRig(t *testing.T) *recoveryRig {
	t.Helper()
	r := &recoveryRig{rig: newRig(t), f: &fakeRecoveryOps{fakePasskeys: &fakePasskeys{}, switched: true}}
	gen := func(rd io.Reader) (*card.Card, error) {
		c, err := card.Generate(rd)
		if err == nil {
			r.newKey = c.RecoveryKey
		}
		return c, err
	}
	s, err := New(Config{Page: testPage(), Hooks: r.hooks, SetupSecret: r.card.SetupSecret, Store: &MemStore{},
		Defaults: "spend cap $20 a day; payments need approval.", Passkeys: r.f, PasskeyRPID: DefaultPageName,
		RecoveryCard: gen, PageAuthority: testAuthority, Now: r.clock, Rand: rand.New(rand.NewSource(9))})
	if err != nil {
		t.Fatal(err)
	}
	r.srv = s
	r.runSetup()
	r.startChannel(modem.NewCarrier().Line(boxNum))
	return r
}

// factor posts the factor form as multipart, as the page sends it.
func (r *recoveryRig) factor(fields map[string]string) *http.Response {
	r.t.Helper()
	var b bytes.Buffer
	m := multipart.NewWriter(&b)
	for k, v := range fields {
		m.WriteField(k, v)
	}
	m.Close()
	w := r.do("POST", "/recovery/", nil, func(q *http.Request) {
		q.Body = io.NopCloser(bytes.NewReader(b.Bytes()))
		q.ContentLength = int64(b.Len())
		q.Header.Set("Content-Type", m.FormDataContentType())
	})
	return w.Result()
}

// confirm types back the asked group of the new card (or wrong, when bad).
func (r *recoveryRig) confirm(bad bool) *http.Response {
	r.t.Helper()
	_, g := r.srv.recovery.p.display.Asks()
	group := strings.Split(r.newKey, "-")[g-1]
	if bad {
		group = "ZZZZZ"
	}
	return r.post("/recovery/card", url.Values{"group": {group}}).Result()
}

var tapForm = url.Values{"step": {"rotate"}, "ad": {base64.StdEncoding.EncodeToString([]byte("ad"))},
	"cd": {base64.StdEncoding.EncodeToString([]byte("cd"))}, "sig": {base64.StdEncoding.EncodeToString([]byte("sig"))}}

// The page is served only with the recovery-key ops, behind sign-in,
// never without the passkey page's name; home lists it.
func TestRecoveryPageNeedsThePasskeyOps(t *testing.T) {
	p, _ := passkeyRig(t)
	p.signIn()
	if w := p.do("GET", "/recovery/", nil); w.Code != http.StatusNotFound {
		t.Fatalf("recovery page with passkey ops alone: %d", w.Code)
	}
	if _, err := New(Config{Page: testPage(), Recovery: &fakeRecoveryOps{fakePasskeys: &fakePasskeys{}}}); err == nil {
		t.Fatal("a Recovery key page without the passkey page's name")
	}
	var _ Recovery = AgentosdPasskeys{}
	r := newRecoveryRig(t)
	if w := r.do("GET", "/recovery/", nil); w.Code != http.StatusSeeOther {
		t.Fatalf("before sign-in: %d", w.Code)
	}
	if w := r.do("GET", "/recovery/card", nil); w.Code != http.StatusSeeOther {
		t.Fatalf("card before sign-in: %d", w.Code)
	}
	r.signIn()
	if !strings.Contains(r.get("/home"), "/recovery/") {
		t.Fatal("home does not link the Recovery key page")
	}
	if p := r.get("/recovery/"); !strings.Contains(p, `name="photo"`) || !strings.Contains(p, `name="recovery"`) {
		t.Fatal("no factor form")
	}
}

// Brief matrix, r4a: the owner gives the factor and sees the new card,
// and nothing reaches agentosd until the card is confirmed; a mismatch,
// a cancel or a lapse asks nothing.
func TestRecoveryAbandonedBeforeConfirmAsksNothing(t *testing.T) {
	r := newRecoveryRig(t)
	r.signIn()
	if res := r.factor(map[string]string{"passphrase": "alpha bravo charlie delta"}); res.Header.Get("Location") != "/recovery/card" {
		t.Fatalf("factor: %d", res.StatusCode)
	}
	if p := r.get("/recovery/card"); !strings.Contains(p, "new recovery key") {
		t.Fatalf("card page:\n%s", p)
	}
	if res := r.confirm(true); res.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("mismatch: %d", res.StatusCode)
	}
	if !strings.Contains(r.get("/recovery/"), "/recovery/card") {
		t.Fatal("the start page does not lead back to the waiting card")
	}
	if p := html.UnescapeString(r.post("/recovery/", url.Values{"step": {"cancel"}}).Body.String()); !strings.Contains(p, recoveryCancelText) {
		t.Fatal("no cancel line")
	}
	if r.srv.recovery.p != nil {
		t.Fatal("a cancelled replacement is kept")
	}
	r.factor(map[string]string{"passphrase": "alpha bravo charlie delta"})
	r.advance(RecoveryPendingFor)
	if w := r.do("GET", "/recovery/card", nil); w.Code != http.StatusSeeOther || r.srv.recovery.p != nil {
		t.Fatalf("a lapsed replacement: %d", w.Code)
	}
	if r.f.calls() != 0 {
		t.Fatalf("agentosd asked before a confirm: %d calls", r.f.calls())
	}
}

// The page's order: factor, card confirmed (agentosd's begin, with the
// new card's 32-byte key), the tap step showing the change and carrying
// the challenge, then one rotation call carrying the factor, the same key
// and the tap.
func TestRecoveryPageConfirmsThenTapsThenRotates(t *testing.T) {
	r := newRecoveryRig(t)
	r.signIn()
	r.factor(map[string]string{"passphrase": "  Alpha  BRAVO charlie\tdelta "})
	if res := r.confirm(false); res.Header.Get("Location") != "/recovery/" {
		t.Fatalf("confirm: %d", res.StatusCode)
	}
	want, err := card.StoreRecoveryKey(r.newKey)
	if err != nil || len(r.f.begins) != 1 || !bytes.Equal(r.f.begins[0], want) || len(r.f.rotates) != 0 {
		t.Fatalf("begin: %v %x", err, r.f.begins)
	}
	p := html.UnescapeString(r.get("/recovery/"))
	ch := base64.StdEncoding.EncodeToString(testBegun.Challenge)
	for _, s := range []string{`id="pk-finish"`, `data-rp="` + DefaultPageName + `"`, `data-challenge="` + ch + `"`, `id="pk-tap"`, testBegun.Old, testBegun.Next} {
		if !strings.Contains(p, s) {
			t.Errorf("tap step lacks %q", s)
		}
	}
	if w := r.do("GET", "/recovery/card", nil); w.Code != http.StatusSeeOther {
		t.Fatalf("the confirmed card is still served: %d", w.Code)
	}
	p = html.UnescapeString(r.post("/recovery/", tapForm).Body.String())
	if len(r.f.rotates) != 1 || !strings.Contains(p, recoveryDoneText) {
		t.Fatalf("rotate:\n%s", p)
	}
	got := r.f.rotates[0]
	if got.Factor != "passphrase" || string(got.Secret) != "alpha bravo charlie delta" || !bytes.Equal(got.Next, want) ||
		string(got.AuthenticatorData) != "ad" || string(got.Signature) != "sig" {
		t.Fatalf("rotated %+v", got)
	}
	if r.srv.recovery.p != nil {
		t.Fatal("a finished replacement is kept")
	}
}

// The #3412 Security finding on #3409: a recovery key with CR/LF (read
// from a file, pasted with a newline, or printed one group per line) reads
// as the card does, and opens the store's recovery slot.
func TestRecoveryKeyWithCRLFOpensTheSlot(t *testing.T) {
	c, err := card.Generate(rand.New(rand.NewSource(11)))
	if err != nil {
		t.Fatal(err)
	}
	clean, err := card.StoreRecoveryKey(c.RecoveryKey)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "store")
	st, err := seal.Create(path, seal.Recovery{Key: clean})
	if err != nil {
		t.Fatal(err)
	}
	st.Close()
	for _, typed := range []string{c.RecoveryKey + "\n", c.RecoveryKey + "\r\n", strings.ReplaceAll(c.RecoveryKey, "-", "\n"),
		strings.ReplaceAll(c.RecoveryKey, "-", "\r\n") + "\r\n"} {
		k, err := storeRecoveryKey(typed)
		if err != nil {
			t.Fatalf("%q: %v", typed, err)
		}
		st, err := seal.Unlock(path, seal.Recovery{Key: k})
		if err != nil {
			t.Fatalf("%q does not open the slot: %v", typed, err)
		}
		st.Close()
	}

	// And on the page: a recovery key typed one group per line is the
	// factor agentosd gets.
	r := newRecoveryRig(t)
	r.signIn()
	r.factor(map[string]string{"recovery": strings.ReplaceAll(c.RecoveryKey, "-", "\r\n") + "\r\n"})
	r.confirm(false)
	r.post("/recovery/", tapForm)
	if len(r.f.rotates) != 1 || r.f.rotates[0].Factor != "recovery" || !bytes.Equal(r.f.rotates[0].Secret, clean) {
		t.Fatalf("rotates %+v", r.f.rotates)
	}
	// A mistyped group is named, and starts nothing.
	bad := []byte(c.RecoveryKey)
	bad[0] ^= 1
	r.post("/recovery/", url.Values{"step": {"cancel"}})
	body, _ := io.ReadAll(r.factor(map[string]string{"recovery": string(bad)}).Body)
	if !strings.Contains(string(body), "group 1 of the recovery key looks mistyped") || r.srv.recovery.p != nil {
		t.Fatal("a mistyped key started a replacement")
	}
}

// Each refusal: a wrong tap, busy and no answer keep the replacement for
// another tap; factor and stale drop it; a begin agentosd refuses keeps the
// card on the display.
func TestRecoveryRefusalsKeepOrDrop(t *testing.T) {
	r := newRecoveryRig(t)
	r.signIn()
	start := func() {
		r.factor(map[string]string{"passphrase": "alpha bravo charlie delta"})
		r.confirm(false)
	}
	start()
	for e, want := range map[string]string{localapi.ErrRecoveryNotAnchor: "phone passkey", localapi.ErrRecoveryBusy: "Another replacement",
		localapi.ErrRecoveryUnavailable: recoveryUnsureText} {
		r.f.rotateErr = Refused(e)
		p := html.UnescapeString(r.post("/recovery/", tapForm).Body.String())
		if !strings.Contains(p, want) || !strings.Contains(p, `id="pk-tap"`) || r.srv.recovery.p == nil {
			t.Fatalf("%s:\n%s", e, p)
		}
	}
	for e, want := range map[string]string{localapi.ErrRecoveryFactor: "doesn't open my store", localapi.ErrRecoveryStale: "Something changed since you started"} {
		start()
		r.f.rotateErr = Refused(e)
		p := html.UnescapeString(r.post("/recovery/", tapForm).Body.String())
		if !strings.Contains(p, want) || !strings.Contains(p, recoveryKeepAll) || r.srv.recovery.p != nil {
			t.Fatalf("%s:\n%s", e, p)
		}
	}
	r.f.rotateErr, r.f.switched = nil, false
	start()
	if p := html.UnescapeString(r.post("/recovery/", tapForm).Body.String()); !strings.Contains(p, recoveryLaterText) {
		t.Fatalf("switch later:\n%s", p)
	}
	r.f.beginErr = Refused(localapi.ErrRecoveryUnavailable)
	r.factor(map[string]string{"passphrase": "alpha bravo charlie delta"})
	if res := r.confirm(false); res.StatusCode != http.StatusInternalServerError || r.srv.recovery.p.display == nil {
		t.Fatalf("begin refused: %d", res.StatusCode)
	}
}

// The replacement is the starting session's alone: another signed-in
// phone sees neither its card nor its tap step, and cannot send it.
func TestRecoveryIsBoundToItsSession(t *testing.T) {
	r := newRecoveryRig(t)
	r.signIn()
	r.factor(map[string]string{"passphrase": "alpha bravo charlie delta"})
	mine := r.jar
	r.jar, _ = cookiejar.New(nil)
	r.signIn()
	if w := r.do("GET", "/recovery/card", nil); w.Code != http.StatusSeeOther {
		t.Fatalf("another session's card: %d", w.Code)
	}
	r.jar = mine
	r.confirm(false)
	r.jar, _ = cookiejar.New(nil)
	r.signIn()
	if strings.Contains(r.get("/recovery/"), `id="pk-tap"`) {
		t.Fatal("another session sees the tap step")
	}
	r.post("/recovery/", tapForm)
	if len(r.f.rotates) != 0 {
		t.Fatal("another session sent the rotation")
	}
}

// The page never says which card is in effect but on Done (L3 6464454818,
// 6464542415 and 6464746705 on #3605): an earlier call whose answer was
// lost, from any phone, session or start of the page, may have rewritten
// the store, and nothing on the owner side records it. Every session
// (the one that tapped, a re-sign-in on the same phone, another phone,
// and a page restarted with its memory gone) crossed with every path
// after an unanswered tap: no page it is served claims nothing changed or
// says to destroy a card, and each line that ends a replacement short of
// Done says to keep all cards.
func TestRecoveryNoPageClaimsWhatIsInEffect(t *testing.T) {
	forbidden := []string{"Nothing changed", "nothing changed", "stays in effect", "Destroy the new card", "destroy its new card", "current card"}
	sessions := map[string]func(r *recoveryRig){
		"same session": func(*recoveryRig) {},
		"re-sign-in":   func(r *recoveryRig) { r.jar, _ = cookiejar.New(nil); r.signIn() },
		"other phone":  func(r *recoveryRig) { r.jar, _ = cookiejar.New(nil); r.ip = "10.42.0.77:5555"; r.signIn() },
		// A restart of the page process (or agentosd) loses every memory
		// of the call; the page holds no other state to lose.
		"page restarted": func(r *recoveryRig) { r.srv.recovery = recoveryState{} },
	}
	start := func(r *recoveryRig, factor string) {
		r.factor(map[string]string{factor: map[string]string{"recovery": r.card.RecoveryKey, "passphrase": "alpha bravo charlie delta"}[factor]})
		r.confirm(false)
	}
	paths := map[string]func(r *recoveryRig) string{
		"cancel": func(r *recoveryRig) string { return r.post("/recovery/", url.Values{"step": {"cancel"}}).Body.String() },
		"lapse": func(r *recoveryRig) string {
			r.advance(RecoveryPendingFor)
			return r.post("/recovery/", tapForm).Body.String()
		},
		"page": func(r *recoveryRig) string { return r.get("/recovery/") },
		"factor": func(r *recoveryRig) string {
			start(r, "recovery")
			r.f.rotateErr = Refused(localapi.ErrRecoveryFactor)
			return r.post("/recovery/", tapForm).Body.String()
		},
		"stale": func(r *recoveryRig) string {
			start(r, "passphrase")
			r.f.rotateErr = Refused(localapi.ErrRecoveryStale)
			return r.post("/recovery/", tapForm).Body.String()
		},
		"card cancel": func(r *recoveryRig) string {
			r.factor(map[string]string{"passphrase": "alpha bravo charlie delta"})
			r.post("/recovery/card", url.Values{"cancel": {"1"}})
			return r.do("GET", "/recovery/card", nil).Body.String() + r.get("/recovery/")
		},
		"wrong tap": func(r *recoveryRig) string {
			start(r, "passphrase")
			r.f.rotateErr = Refused(localapi.ErrRecoveryNotAnchor)
			return r.post("/recovery/", tapForm).Body.String()
		},
	}
	terminal := map[string]bool{"cancel": true, "lapse": true, "factor": true, "stale": true}
	for sn, session := range sessions {
		for pn, path := range paths {
			t.Run(sn+"/"+pn, func(t *testing.T) {
				r := newRecoveryRig(t)
				r.signIn()
				start(r, "recovery")
				r.f.rotateErr = Refused(localapi.ErrRecoveryUnavailable)
				r.post("/recovery/", tapForm)
				session(r)
				p := html.UnescapeString(path(r))
				if terminal[pn] && sn == "same session" && !strings.Contains(p, recoveryKeepAll) {
					t.Errorf("no keep-all line:\n%s", p)
				}
				for _, body := range r.seen {
					for _, f := range forbidden {
						if strings.Contains(html.UnescapeString(body), f) && strings.Contains(body, "<h1>Recovery key</h1>") {
							t.Fatalf("a page says %q:\n%s", f, body)
						}
					}
				}
			})
		}
	}
}

// The card's own cancel drops the replacement with it, so the page starts
// afresh rather than pointing at a card that is gone.
func TestRecoveryCardCancelDropsTheReplacement(t *testing.T) {
	r := newRecoveryRig(t)
	r.signIn()
	r.factor(map[string]string{"passphrase": "alpha bravo charlie delta"})
	if w := r.post("/recovery/card", url.Values{"cancel": {"1"}}); w.Header().Get("Location") != "/recovery/" {
		t.Fatalf("card cancel: %d", w.Code)
	}
	if r.srv.recovery.p != nil || !strings.Contains(r.get("/recovery/"), `name="photo"`) {
		t.Fatal("the replacement outlived its card")
	}
	if r.f.calls() != 0 {
		t.Fatal("a cancelled card reached agentosd")
	}
}

// REQ: REC-4, HW-1
//
// No authority, no new card: with no page authority the Recovery key
// page shows the fixed line, keeps no replacement (the factor goes) and
// asks agentosd nothing. It catches a new card printed without the
// fingerprint.
func TestRecoveryRefusesWithoutAuthority(t *testing.T) {
	r := newRecoveryRig(t)
	r.signIn()
	for _, auth := range []func() []byte{nil, func() []byte { return nil }} {
		r.srv.cfg.PageAuthority = auth
		res := r.factor(map[string]string{"passphrase": "alpha bravo charlie delta"})
		body, _ := io.ReadAll(res.Body)
		if res.Header.Get("Location") != "" || !strings.Contains(html.UnescapeString(string(body)), firstboot.ErrNoAuthority.Error()) {
			t.Fatalf("factor without an authority: %d %q", res.StatusCode, res.Header.Get("Location"))
		}
		if r.srv.recovery.p != nil || r.f.calls() != 0 {
			t.Fatalf("a replacement kept, or agentosd asked: %d calls", r.f.calls())
		}
	}
}
