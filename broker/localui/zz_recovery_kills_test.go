package localui

import (
	"bytes"
	"context"
	"html"
	"io"
	"math/rand"
	"mime/multipart"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/ghbmrk/agentos/broker/card"
	"github.com/ghbmrk/agentos/broker/localapi"
)

// REQ: REC-4

// recoveryEdges runs, as subtests of TestRecoveryKeyWithCRLFOpensTheSlot,
// the checks that kill #6000's mutgate survivors in recovery.go and
// setup.go. They are subtests, not top-level tests: localui has an init
// mutgate reads as order-dependent, so a new top-level test changes the run
// list and makes every localui test a changed test (#6000).
func recoveryEdges(t *testing.T) {
	t.Run("CancelWipesWhatItHeld", cancelWipesWhatItHeld)
	t.Run("CallsReleaseTheirContexts", callsReleaseTheirContexts)
	t.Run("FactorUnreadableForm", factorUnreadableForm)
	t.Run("FactorFromPhoto", factorFromPhoto)
	t.Run("TapRefusedBeforeConfirmOrMalformed", tapRefusedBeforeConfirmOrMalformed)
	t.Run("SetupDoneNamesNoStep", setupDoneNamesNoStep)
	t.Run("CodesUnavailableNamesItsCause", codesUnavailableNamesItsCause)
	t.Run("FormBytesRefusalHoldsNoBytes", formBytesRefusalHoldsNoBytes)
	survivorKills(t)
}

// ctxRecovery records the context each begin, rotate and lost-state call
// ran under, so a test can see that the page released it once the call
// returned.
type ctxRecovery struct {
	*fakeRecoveryOps
	ctxs map[string][]context.Context
}

func (c *ctxRecovery) RecoveryBegin(ctx context.Context, tok string, next []byte) (localapi.RecoveryBegun, error) {
	c.ctxs["begin"] = append(c.ctxs["begin"], ctx)
	return c.fakeRecoveryOps.RecoveryBegin(ctx, tok, next)
}

func (c *ctxRecovery) RecoveryRotate(ctx context.Context, tok, factor string, secret, next, ad, cd, sig []byte) (localapi.RecoveryDone, error) {
	c.ctxs["rotate"] = append(c.ctxs["rotate"], ctx)
	return c.fakeRecoveryOps.RecoveryRotate(ctx, tok, factor, secret, next, ad, cd, sig)
}

func (c *ctxRecovery) RecoveryLostState(ctx context.Context, tok string) (localapi.RecoveryLostState, error) {
	c.ctxs["lost"] = append(c.ctxs["lost"], ctx)
	return c.fakeRecoveryOps.RecoveryLostState(ctx, tok)
}

// A cancel wipes the held replacement: before the confirm its factor and
// card go, after it its factor and the confirmed key are zeroed.
func cancelWipesWhatItHeld(t *testing.T) {
	r := newRecoveryRig(t)
	r.signIn()
	r.factor(map[string]string{"passphrase": "alpha bravo charlie delta"})
	p := r.srv.recovery.p
	if p == nil || p.display == nil {
		t.Fatal("no replacement waiting on its card")
	}
	r.post("/recovery/", url.Values{"step": {"cancel"}})
	if p.display != nil || len(bytes.Trim(p.secret, "\x00")) != 0 {
		t.Fatalf("a cancelled replacement keeps its card or factor: %v %q", p.display != nil, p.secret)
	}

	r.factor(map[string]string{"passphrase": "alpha bravo charlie delta"})
	r.confirm(false)
	p = r.srv.recovery.p
	if p == nil || len(p.next) != card.StoreKeyLen || len(bytes.Trim(p.next, "\x00")) == 0 {
		t.Fatal("no confirmed key held")
	}
	next, secret := p.next, p.secret
	r.post("/recovery/", url.Values{"step": {"cancel"}})
	if len(bytes.Trim(next, "\x00")) != 0 || len(bytes.Trim(secret, "\x00")) != 0 {
		t.Fatalf("a cancel left the confirmed key or factor: %x %q", next, secret)
	}

	// A begin agentosd answers in-effect erases the card but keeps the
	// replacement; its cancel lets go of that card too, though the
	// display's own discard no longer runs.
	r.f.beginErr = card.ErrInEffect
	r.factor(map[string]string{"passphrase": "alpha bravo charlie delta"})
	p = r.srv.recovery.p
	r.confirm(false)
	if p == nil || r.srv.recovery.p != p || p.display == nil {
		t.Fatal("an in-effect begin did not keep the replacement and its card")
	}
	r.post("/recovery/", url.Values{"step": {"cancel"}})
	if p.display != nil || r.srv.recovery.p != nil {
		t.Fatal("a cancel after an in-effect begin keeps the card")
	}
}

// Each call to agentosd the page makes (the confirm's begin, the tap's
// rotate, the first step's lost-card read) has its context released when
// the call returns, not left to its timeout.
func callsReleaseTheirContexts(t *testing.T) {
	r := newRecoveryRig(t)
	c := &ctxRecovery{fakeRecoveryOps: r.f, ctxs: map[string][]context.Context{}}
	r.srv.cfg.Recovery = c
	r.signIn()
	r.get("/recovery/")
	r.factor(map[string]string{"passphrase": "alpha bravo charlie delta"})
	r.confirm(false)
	r.post("/recovery/", tapForm)
	for _, op := range []string{"lost", "begin", "rotate"} {
		if len(c.ctxs[op]) == 0 {
			t.Fatalf("no %s call", op)
		}
		for _, ctx := range c.ctxs[op] {
			if ctx.Err() == nil {
				t.Fatalf("a %s call's context is still live after the page answered", op)
			}
		}
	}
}

// A factor post that says multipart but carries no boundary is named, and
// starts nothing.
func factorUnreadableForm(t *testing.T) {
	r := newRecoveryRig(t)
	r.signIn()
	w := r.do("POST", "/recovery/", nil, func(q *http.Request) {
		q.Body = http.NoBody
		q.Header.Set("Content-Type", "multipart/form-data")
	})
	if !strings.Contains(w.Body.String(), "I could not read that form. Try again.") || r.srv.recovery.p != nil {
		t.Fatalf("unreadable form: %d\n%s", w.Code, w.Body.String())
	}
}

// A photo of the passphrase code alone is the factor.
func factorFromPhoto(t *testing.T) {
	r := newRecoveryRig(t)
	r.signIn()
	c, err := card.Generate(rand.New(rand.NewSource(5)))
	if err != nil {
		t.Fatal(err)
	}
	var b bytes.Buffer
	m := multipart.NewWriter(&b)
	fw, _ := m.CreateFormFile("photo", "IMG.png")
	fw.Write(qrPNG(t, c.VaultPassphrase))
	m.Close()
	w := r.do("POST", "/recovery/", nil, func(q *http.Request) {
		q.Body = io.NopCloser(bytes.NewReader(b.Bytes()))
		q.ContentLength = int64(b.Len())
		q.Header.Set("Content-Type", m.FormDataContentType())
	})
	p := r.srv.recovery.p
	if w.Header().Get("Location") != "/recovery/card" || p == nil || p.factor != localapi.RecoveryFactorPassphrase ||
		string(p.secret) != card.NormalizePassphrase(c.VaultPassphrase) {
		t.Fatalf("photo factor: %d %s", w.Code, w.Body.String())
	}
}

// A tap before the card is confirmed, or one whose fields do not decode,
// is refused on the page and never reaches agentosd.
func tapRefusedBeforeConfirmOrMalformed(t *testing.T) {
	r := newRecoveryRig(t)
	r.signIn()
	r.factor(map[string]string{"passphrase": "alpha bravo charlie delta"})
	p := html.UnescapeString(r.post("/recovery/", tapForm).Body.String())
	if !strings.Contains(p, "Confirm your new card first.") || len(r.f.rotates) != 0 {
		t.Fatalf("a tap before the confirm: %d rotates\n%s", len(r.f.rotates), p)
	}
	r.confirm(false)
	for _, field := range []string{"ad", "cd", "sig"} {
		f := url.Values{}
		for k, v := range tapForm {
			f[k] = v
		}
		f.Set(field, "not base64!")
		p = html.UnescapeString(r.post("/recovery/", f).Body.String())
		if !strings.Contains(p, recoveryText(Refused(localapi.ErrRecoveryBadAssertion))) || len(r.f.rotates) != 0 {
			t.Fatalf("a %s that does not decode: %d rotates\n%s", field, len(r.f.rotates), p)
		}
	}
	if r.srv.recovery.p == nil {
		t.Fatal("a malformed tap dropped the replacement")
	}
}

// A setup that is done has no unfinished step, whatever its other fields
// read (a state adopted from a finished Finish).
func setupDoneNamesNoStep(t *testing.T) {
	u := &setup{st: SetupState{Done: true}}
	if got := u.stepLocked(Progress{}); got != "done" {
		t.Fatalf("done setup's step: %q", got)
	}
}

// A vault that cannot add approval codes is named as the cause of a
// refused code, and the line stays with the phone when the vault answers
// again by the time the page reloads.
func codesUnavailableNamesItsCause(t *testing.T) {
	r := newRig(t)
	r.toCodes()
	r.hooks.mu.Lock()
	r.hooks.unavailable = true
	r.hooks.mu.Unlock()
	r.post("/setup/codes", url.Values{"code": {"123456"}})
	r.hooks.mu.Lock()
	r.hooks.unavailable = false
	r.hooks.mu.Unlock()
	if got := r.setupErr(); got != cannotFinish || r.srv.setup.st.Codes {
		t.Fatalf("codes %v, said %q", r.srv.setup.st.Codes, got)
	}
}

// A refused field gives no bytes: an empty one, or one longer than any
// encoding of max bytes, is refused before it is decoded.
func formBytesRefusalHoldsNoBytes(t *testing.T) {
	for _, v := range []string{"", "QUFBQUFB", strings.Repeat("A", 1<<12)} {
		if b, ok := formBytes(v, 3); ok || b != nil {
			t.Fatalf("formBytes(%.12q, 3) = %q, %v", v, b, ok)
		}
	}
	if b, ok := formBytes("QUFB", 3); !ok || string(b) != "AAA" {
		t.Fatalf("formBytes of 3 bytes: %q %v", b, ok)
	}
}
