package localui

import (
	"context"
	"encoding/base64"
	"errors"
	"html"
	"math/rand"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/ghbmrk/agentos/broker/localapi"
	"github.com/ghbmrk/agentos/broker/modem"
)

// REQ: LOG-4, CH-7, CH-26

// fakeForgetOps is agentosd's passkey ops and erase ops on one socket, as
// AgentosdPasskeys serves them.
type fakeForgetOps struct {
	*fakePasskeys
	found    localapi.EraseFound
	result   string
	finds    []string
	confirms []localapi.EraseConfirm
	err      error // every op answers it
}

func (f *fakeForgetOps) ForgetFind(_ context.Context, _, name string) (localapi.EraseFound, error) {
	f.finds = append(f.finds, name)
	return f.found, f.err
}

func (f *fakeForgetOps) ForgetConfirm(_ context.Context, _, handle string, ad, cd, sig []byte) (string, error) {
	f.confirms = append(f.confirms, localapi.EraseConfirm{Handle: handle, AuthenticatorData: ad, ClientDataJSON: cd, Signature: sig})
	if f.err != nil {
		return "", f.err
	}
	return f.result, nil
}

const forgetHandle = "0123456789abcdef0123456789abcdef"

var forgetChallenge = []byte("0123456789abcdef0123456789abcdef")

// forgetRig is a set-up box whose passkey ops also serve the erase ops.
func forgetRig(t *testing.T) (*rig, *fakeForgetOps) {
	t.Helper()
	r := newRig(t)
	ff := &fakeForgetOps{fakePasskeys: &fakePasskeys{},
		found:  localapi.EraseFound{Text: "Found 3 items named Alice (message 3). Confirm to forget them.", Handle: forgetHandle, Challenge: forgetChallenge},
		result: "Forgot everything named Alice (3 items). It can no longer be read. Agent L1 went back to before it read them."}
	s, err := New(Config{Page: testPage(), Hooks: r.hooks, SetupSecret: r.card.SetupSecret, Store: &MemStore{},
		Defaults: "spend cap $20 a day; payments need approval.", Passkeys: ff, PasskeyRPID: DefaultPageName,
		Now: r.clock, Rand: rand.New(rand.NewSource(9))})
	if err != nil {
		t.Fatal(err)
	}
	r.srv = s
	r.runSetup()
	r.startChannel(modem.NewCarrier().Line(boxNum))
	return r, ff
}

// tapStep looks Alice up and returns the confirm form the tap step
// carries, with a tap's answer filled in.
func (r *rig) forgetTapStep(t *testing.T) (url.Values, string) {
	t.Helper()
	p := html.UnescapeString(r.post("/forget/", url.Values{"step": {"find"}, "name": {" Alice "}}).Body.String())
	v := url.Values{"step": {"confirm"}}
	for _, k := range []string{"handle", "ch", "name", "found", "tok"} {
		i := strings.Index(p, `name="`+k+`" value="`)
		if i < 0 {
			t.Fatalf("tap step lacks %s:\n%s", k, p)
		}
		rest := p[i+len(`name="`+k+`" value="`):]
		v.Set(k, rest[:strings.Index(rest, `"`)])
	}
	enc := base64.StdEncoding.EncodeToString
	v.Set("ad", enc([]byte("ad")))
	v.Set("cd", enc([]byte("cd")))
	v.Set("sig", enc([]byte("sig")))
	return v, p
}

// The page is served only when agentosd's passkey ops also serve the
// erase ops, behind sign-in, and never without the passkey page's name.
func TestForgetPageNeedsThePasskeyOps(t *testing.T) {
	r, _ := passkeyRig(t)
	r.signIn()
	if w := r.do("GET", "/forget/", nil); w.Code != http.StatusNotFound {
		t.Fatalf("forget page with passkey ops alone: %d", w.Code)
	}
	if _, err := New(Config{Page: testPage(), Forget: &fakeForgetOps{fakePasskeys: &fakePasskeys{}}}); err == nil {
		t.Fatal("a Forget page without the passkey page's name")
	}
	var _ Forget = AgentosdPasskeys{}
	f, ff := forgetRig(t)
	if w := f.do("GET", "/forget/", nil); w.Code != http.StatusSeeOther {
		t.Fatalf("forget page before sign-in: %d", w.Code)
	}
	if w := f.post("/forget/", url.Values{"step": {"find"}, "name": {"Alice"}}); w.Code != http.StatusSeeOther || len(ff.finds) != 0 {
		t.Fatalf("a find without sign-in: %d %v", w.Code, ff.finds)
	}
	f.signIn()
	if !strings.Contains(f.get("/home"), `href="/forget/"`) {
		t.Fatal("home does not link the Forget page")
	}
	if w := f.do("GET", "/forget/ask", nil); w.Code != http.StatusNotFound {
		t.Fatalf("GET /forget/ask: %d", w.Code)
	}
}

// Look up, readback, passkey tap, result: the name goes to agentosd
// trimmed, the tap step shows agentosd's readback unchanged and carries
// its challenge for any of the owner's passkeys, the tap's answer goes to
// agentosd as sent, and the result is agentosd's text unchanged.
func TestForgetPageForgetsOnAPasskeyTap(t *testing.T) {
	r, ff := forgetRig(t)
	r.signIn()
	form, p := r.forgetTapStep(t)
	if len(ff.finds) != 1 || ff.finds[0] != "Alice" {
		t.Fatalf("finds %q", ff.finds)
	}
	ch := base64.StdEncoding.EncodeToString(forgetChallenge)
	for _, s := range []string{"<p>" + ff.found.Text + "</p>", `id="pk-finish"`, `data-rp="` + DefaultPageName + `"`, `data-challenge="` + ch + `"`,
		`data-any="1"`, `id="pk-tap"`, `name="handle" value="` + forgetHandle + `"`, "cannot be undone"} {
		if !strings.Contains(p, s) {
			t.Errorf("tap step lacks %q", s)
		}
	}
	if len(ff.confirms) != 0 {
		t.Fatal("a find confirmed")
	}
	p = html.UnescapeString(r.post("/forget/", form).Body.String())
	if len(ff.confirms) != 1 {
		t.Fatalf("confirms %+v", ff.confirms)
	}
	c := ff.confirms[0]
	if c.Handle != forgetHandle || string(c.AuthenticatorData) != "ad" || string(c.ClientDataJSON) != "cd" || string(c.Signature) != "sig" {
		t.Fatalf("confirmed %+v", c)
	}
	if !strings.Contains(p, `<p class="ok">`+ff.result+`</p>`) || strings.Contains(p, `id="pk-tap"`) {
		t.Fatalf("result:\n%s", p)
	}
	// The script's tap asks for any passkey on this page, a hardware key
	// on the others.
	if !strings.Contains(passkeyJS, `if (any) pk.hints = [];`) || !strings.Contains(passkeyJS, `f.dataset.any === "1"`) {
		t.Fatal("the tap does not offer any passkey")
	}
}

// Nothing to confirm offers no tap: agentosd's words, and the name form
// again with the typed name.
func TestForgetPageWithNothingFound(t *testing.T) {
	r, ff := forgetRig(t)
	r.signIn()
	ff.found = localapi.EraseFound{Text: "Nothing named Carol was found."}
	p := html.UnescapeString(r.post("/forget/", url.Values{"step": {"find"}, "name": {"Carol"}}).Body.String())
	if !strings.Contains(p, ff.found.Text) || strings.Contains(p, `id="pk-tap"`) || !strings.Contains(p, `name="name" maxlength="256" required value="Carol"`) {
		t.Fatalf("nothing found:\n%s", p)
	}
	// A challenge out of shape offers no tap either.
	ff.found = localapi.EraseFound{Text: "Found 1 item named Bob.", Handle: forgetHandle, Challenge: []byte{1}}
	if p = r.post("/forget/", url.Values{"step": {"find"}, "name": {"Bob"}}).Body.String(); strings.Contains(p, `id="pk-tap"`) {
		t.Fatalf("a short challenge:\n%s", p)
	}
}

// A tap that did not match stays on the tap step with the same find, but
// only as this UI gave it: a challenge, handle or readback the form made
// up is never shown back.
func TestForgetPageWrongTapStaysOnlyOnItsOwnFind(t *testing.T) {
	r, ff := forgetRig(t)
	r.signIn()
	form, _ := r.forgetTapStep(t)
	ff.err = Refused(localapi.ErrEraseBadAssertion)
	p := html.UnescapeString(r.post("/forget/", form).Body.String())
	if !strings.Contains(p, ForgetTapAgainText) || !strings.Contains(p, `id="pk-tap"`) || !strings.Contains(p, ff.found.Text) ||
		!strings.Contains(p, `data-challenge="`+form.Get("ch")+`"`) {
		t.Fatalf("wrong tap:\n%s", p)
	}
	made := base64.StdEncoding.EncodeToString([]byte("fedcba9876543210fedcba9876543210"))
	for k, bad := range map[string]string{"ch": made, "found": "Found 0 items. Tap to continue.", "handle": strings.Repeat("f", 32), "name": "Bob", "tok": ""} {
		forged := url.Values{}
		for kk, vv := range form {
			forged[kk] = vv
		}
		forged.Set(k, bad)
		p = html.UnescapeString(r.post("/forget/", forged).Body.String())
		if strings.Contains(p, `id="pk-tap"`) || strings.Contains(p, made) || strings.Contains(p, "Tap to continue") || !strings.Contains(p, ForgetTapAgainText) {
			t.Fatalf("forged %s was shown back:\n%s", k, p)
		}
	}
	// An assertion past its bound never reaches agentosd.
	n := len(ff.confirms)
	form.Set("sig", base64.StdEncoding.EncodeToString(make([]byte, localapi.MaxPasskeyAssertion+1)))
	r.post("/forget/", form)
	if len(ff.confirms) != n {
		t.Fatal("an unbounded tap reached agentosd")
	}
}

// Every refusal shows fixed words that say nothing was forgotten, and no
// kernel text; a cross-origin confirm is refused before anything runs.
func TestForgetPageWordsEachRefusal(t *testing.T) {
	r, ff := forgetRig(t)
	r.signIn()
	form, _ := r.forgetTapStep(t)
	seen := map[string]bool{}
	codes := append(append([]string{}, localapi.EraseCodes...), localapi.ErrBadArgs, localapi.ErrLimited, localapi.ErrUnauthorized)
	for _, c := range append(codes, "kernel: content closed") {
		ff.err = Refused(c)
		txt := forgetText(Refused(c))
		for _, step := range []url.Values{{"step": {"find"}, "name": {"Alice"}}, form} {
			p := html.UnescapeString(r.post("/forget/", step).Body.String())
			want := txt
			if step.Get("step") == "confirm" && !forgetRefusedBefore(Refused(c)) {
				// A confirm may have erased (TestForgetPageNeverSaysNothingWhenItCannotTell).
				want = ForgetUnknownText
			}
			if !strings.Contains(p, want) || strings.Contains(p, "kernel:") || strings.Contains(p, ff.result) {
				t.Fatalf("%s (%s):\n%s", c, step.Get("step"), p)
			}
		}
		if !strings.Contains(txt, "nothing was forgotten") && c != localapi.ErrBadArgs && c != localapi.ErrLimited {
			t.Errorf("%s: %q does not say nothing was forgotten", c, txt)
		}
		seen[txt] = true
	}
	// The stranger reads as ErrEraseUnavailable does.
	if len(seen) != len(codes) {
		t.Fatalf("%d texts for %d codes and one stranger", len(seen), len(codes))
	}
	ff.err = nil
	n := len(ff.confirms)
	w := r.do("POST", "/forget/", form, func(q *http.Request) {
		q.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		q.Header.Set("Origin", "http://evil.example")
	})
	if w.Code != http.StatusForbidden || len(ff.confirms) != n {
		t.Fatalf("a cross-origin confirm: %d", w.Code)
	}
}

// A confirm that went out but got no refusal back (a timeout, a dropped
// socket, agentosd's own failure) may have erased, since agentosd's
// confirm runs to the end: the page never says nothing was forgotten then
// (Potency on #5092).
func TestForgetPageNeverSaysNothingWhenItCannotTell(t *testing.T) {
	r, ff := forgetRig(t)
	r.signIn()
	form, _ := r.forgetTapStep(t)
	for _, e := range []error{context.DeadlineExceeded, errors.New("bridgeclient: connection reset"), Refused("request failed")} {
		ff.err = e
		p := html.UnescapeString(r.post("/forget/", form).Body.String())
		if !strings.Contains(p, ForgetUnknownText) || strings.Contains(p, "nothing was forgotten") {
			t.Fatalf("%v:\n%s", e, p)
		}
	}
	// A refusal agentosd gives before any erase still says nothing went.
	ff.err = Refused(localapi.ErrEraseStale)
	if p := html.UnescapeString(r.post("/forget/", form).Body.String()); !strings.Contains(p, "nothing was forgotten") || strings.Contains(p, ForgetUnknownText) {
		t.Fatalf("stale:\n%s", p)
	}
}
