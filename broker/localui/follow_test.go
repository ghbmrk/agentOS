package localui

// REQ: OSS-10, CH-7

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"html"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/grants"
	"github.com/ghbmrk/agentos/broker/localapi"
	"github.com/ghbmrk/agentos/broker/localsrv"
	"github.com/ghbmrk/agentos/broker/modem"
	"github.com/ghbmrk/agentos/broker/owner"
)

var followDigest = strings.Repeat("ab", 32)

const approvalsButton = `class="button" href="/approvals/"`

// followRig is a signed-in phone on a box whose follow ops are stubs.
type followRig struct {
	*rig
	mu       sync.Mutex
	shown    [][]byte
	chains   [][][]byte
	asked    []string
	reply    string
	describe func([]byte) (localapi.RootSummary, error)
}

func newFollowRig(t *testing.T) *followRig {
	t.Helper()
	f := &followRig{rig: newRig(t), reply: "Asked. Approve it on the Approvals page."}
	f.runSetup()
	ch, err := owner.New(owner.Config{Owner: ownerNum, Modem: modem.NewCarrier().Line(boxNum), Engine: f.eng, Store: &owner.MemStore{},
		Secrets: owner.Secrets{TOTPSeed: f.hooks.seed, GridSeed: f.card.GridSeed}, Now: f.clock, Location: time.UTC})
	if err != nil {
		t.Fatal(err)
	}
	f.ch = ch
	f.describe = func([]byte) (localapi.RootSummary, error) {
		return localapi.RootSummary{Version: 3, Digest: followDigest, Expires: time.Date(2027, 3, 1, 0, 0, 0, 0, time.UTC),
			Keys:       map[string][]string{"root": {"k1", "k2", "k3"}, "targets": {"k1", "k2"}},
			Thresholds: map[string]int{"root": 2, "targets": 2}}, nil
	}
	f.srv.SetOwner(f.pageWith(ch, localsrv.Config{
		DescribeRoot: func(_ context.Context, b []byte, chain [][]byte) (localapi.RootSummary, error) {
			f.mu.Lock()
			f.shown = append(f.shown, b)
			f.chains = append(f.chains, chain)
			d := f.describe
			f.mu.Unlock()
			return d(b)
		},
		Follow: func(_ context.Context, name, digest string) (string, error) {
			f.mu.Lock()
			defer f.mu.Unlock()
			f.asked = append(f.asked, name+"@"+digest)
			return f.reply, nil
		},
	}))
	f.signIn()
	return f
}

func (f *followRig) calls() (shown int, asked []string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.shown), append([]string(nil), f.asked...)
}

// upload posts roots as the page's file form.
func (f *followRig) upload(roots ...[]byte) string {
	f.t.Helper()
	var b bytes.Buffer
	mw := multipart.NewWriter(&b)
	for i, root := range roots {
		fw, err := mw.CreateFormFile("root", fmt.Sprintf("%d.root.json", i))
		if err != nil {
			f.t.Fatal(err)
		}
		fw.Write(root)
	}
	mw.WriteField("step", "show")
	mw.Close()
	w := f.do("POST", "/follow/", nil, func(r *http.Request) {
		r.Body, r.ContentLength = io.NopCloser(bytes.NewReader(b.Bytes())), int64(b.Len())
		r.Header.Set("Content-Type", mw.FormDataContentType())
	})
	if w.Code != 200 {
		f.t.Fatalf("upload: %d", w.Code)
	}
	return html.UnescapeString(w.Body.String())
}

var followFormRe = regexp.MustCompile(`name="digest" value="([^"]+)"><input type="hidden" name="tok" value="([^"]+)"`)

func (f *followRig) askForm(page string) url.Values {
	f.t.Helper()
	m := followFormRe.FindStringSubmatch(page)
	if m == nil {
		f.t.Fatalf("no ask form in %s", page)
	}
	return url.Values{"digest": {m[1]}, "tok": {m[2]}, "step": {"ask"}}
}

func (f *followRig) ask(v url.Values) string {
	f.t.Helper()
	w := f.post("/follow/", v)
	if w.Code != 200 {
		f.t.Fatalf("ask: %d", w.Code)
	}
	return html.UnescapeString(w.Body.String())
}

// The follow page (OSS-10): the owner brings a root file, sees what
// following it means (its version, keys, expiry and fingerprint, and that
// its keys can change any software on the box), names it and asks; the
// request is then approved with a code on the Approvals page.
func TestOSS10w2FollowPage(t *testing.T) {
	f := newFollowRig(t)
	if !strings.Contains(f.get("/home"), `href="/follow/"`) {
		t.Fatal("home does not link the follow page")
	}
	p := html.UnescapeString(f.get("/follow/"))
	for _, want := range []string{`enctype="multipart/form-data"`, `type="file" name="root"`, "Nothing changes until you approve it"} {
		if !strings.Contains(p, want) {
			t.Fatalf("no %q in %s", want, p)
		}
	}
	p = f.upload([]byte(`{"signed":"synthetic"}`))
	for _, want := range []string{"version 3", "1 March 2027", followDigest, "abab-abab", "2 of 3 keys", "can change any software on this box", `name="name"`} {
		if !strings.Contains(p, want) {
			t.Fatalf("no %q in %s", want, p)
		}
	}
	// A fork's root is never offered as switching back (WF1, UX lens).
	if strings.Contains(p, "witch back") {
		t.Fatalf("a fork's root offers switching back: %s", p)
	}
	if shown, asked := f.calls(); shown != 1 || len(asked) != 0 {
		t.Fatalf("shown %d asked %v", shown, asked)
	}
	form := f.askForm(p)
	if p := f.ask(with(form, "name", "Acme Fork")); !strings.Contains(p, "Asked. Approve it on the Approvals page.") || !strings.Contains(p, approvalsButton) {
		t.Fatalf("%s", p)
	}
	// A fork's root needs a name, and not one that reads as the
	// project's (security 323-1); the page says so without asking.
	for name, want := range map[string]string{"": followNoName, "The AgentOS project again": followReservedName} {
		if p := f.ask(with(form, "name", name)); !strings.Contains(p, want) || strings.Contains(p, approvalsButton) {
			t.Fatalf("%q: %s", name, p)
		}
	}
	if _, asked := f.calls(); len(asked) != 1 || asked[0] != "Acme Fork@"+followDigest {
		t.Fatalf("%v", asked)
	}
}

func with(v url.Values, k, x string) url.Values {
	out := url.Values{k: {x}}
	for kk, xx := range v {
		out[kk] = xx
	}
	return out
}

// WF1 at describe time (UX lens): only a root with the project's own keys
// is offered as switching back, with no name to give, and the offer is
// bound into the form's token, so a fork's form cannot be turned into a
// switch back nor the project's into a named follow.
func TestOSS10w2FollowSwitchBackOnlyForTheProject(t *testing.T) {
	f := newFollowRig(t)
	fork := f.askForm(f.upload([]byte("fork")))
	f.mu.Lock()
	f.describe = func([]byte) (localapi.RootSummary, error) {
		return localapi.RootSummary{Version: 9, Digest: followDigest, Project: true,
			Keys: map[string][]string{"root": {"k1", "k2"}}, Thresholds: map[string]int{"root": 2}}, nil
	}
	f.mu.Unlock()
	p := f.upload([]byte("project"))
	if !strings.Contains(p, "Switch back to the AgentOS project") || strings.Contains(p, `name="name"`) || !strings.Contains(p, `name="project" value="1"`) {
		t.Fatalf("%s", p)
	}
	proj := f.askForm(p)
	proj["project"] = []string{"1"}
	for _, v := range []url.Values{
		with(fork, "project", "1"),                       // a fork's form as switching back
		with(proj, "name", "Acme"),                       // the project's form with a name
		with(with(proj, "project", "0"), "name", "Acme"), // or without its flag
	} {
		if p := f.ask(v); !strings.Contains(p, followStale) {
			t.Fatalf("%v: %s", v, p)
		}
	}
	if p := f.ask(proj); !strings.Contains(p, "Asked. Approve it on the Approvals page.") {
		t.Fatalf("%s", p)
	}
	if _, asked := f.calls(); len(asked) != 1 || asked[0] != "@"+followDigest {
		t.Fatalf("%v", asked)
	}
}

// A request the box refused is said as a failure, not as asked.
func TestOSS10w2FollowNotAskedIsAnError(t *testing.T) {
	f := newFollowRig(t)
	form := f.askForm(f.upload([]byte("root")))
	f.mu.Lock()
	f.reply = "Not asked: I refused this request."
	f.mu.Unlock()
	if p := f.ask(with(form, "name", "Acme")); !strings.Contains(p, `class="err">Not asked: I refused this request.`) || strings.Contains(p, approvalsButton) {
		t.Fatalf("%s", p)
	}
}

// The ask form is bound to this phone's sign-in and the root it was
// shown: another digest, a forged token, or a token from another phone is
// refused before agentosd is asked.
func TestOSS10w2FollowFormIsBound(t *testing.T) {
	f := newFollowRig(t)
	form := f.askForm(f.upload([]byte("root")))
	other := newFollowRig(t)
	for _, v := range []url.Values{
		{"digest": {strings.Repeat("cd", 32)}, "tok": form["tok"], "step": {"ask"}, "name": {"A"}},
		{"digest": form["digest"], "tok": {strings.Repeat("0", 64)}, "step": {"ask"}, "name": {"A"}},
		{"digest": form["digest"], "step": {"ask"}, "name": {"A"}},
		{"digest": form["digest"], "tok": form["tok"], "name": {"A"}},
	} {
		if p := f.ask(v); !strings.Contains(p, followStale) {
			t.Fatalf("%v: %s", v, p)
		}
		if p := other.ask(v); !strings.Contains(p, followStale) {
			t.Fatalf("other phone %v: %s", v, p)
		}
	}
	_, a1 := f.calls()
	_, a2 := other.calls()
	if len(a1)+len(a2) != 0 {
		t.Fatalf("asked %v %v", a1, a2)
	}
	// Signed out, the page is not served.
	f.post("/signout", url.Values{})
	if w := f.do("GET", "/follow/", nil); w.Code != http.StatusSeeOther || !strings.HasPrefix(w.Header().Get("Location"), "/unlock") {
		t.Fatalf("signed out: %d %s", w.Code, w.Header().Get("Location"))
	}
}

// OSS-10w L3 decision: a refused root says its coarse cause in the
// owner's words, and offers nothing to ask.
func TestOSS10w2FollowRefusedRootWording(t *testing.T) {
	f := newFollowRig(t)
	for reason, want := range map[string]string{
		localapi.RootExpired:    rootExpiredText,
		localapi.RootSignatures: rootSignaturesText,
		localapi.RootThreshold:  rootThresholdText,
		"":                      rootUnreadText,
	} {
		f.mu.Lock()
		f.describe = func([]byte) (localapi.RootSummary, error) {
			return localapi.RootSummary{Reason: reason}, errors.New("synthetic refusal")
		}
		f.mu.Unlock()
		p := f.upload([]byte("root"))
		if !strings.Contains(p, want) || followFormRe.MatchString(p) {
			t.Fatalf("%q: %s", reason, p)
		}
	}
	// Too big a file never reaches agentosd.
	n, _ := f.calls()
	if p := f.upload(make([]byte, localapi.MaxRoot+1)); !strings.Contains(p, rootTooBigText) {
		t.Fatalf("too big: %s", p)
	}
	if m, _ := f.calls(); m != n {
		t.Fatal("a too-big root was sent")
	}
}

// Key IDs come from the brought file: shown escaped and with any unusual
// character as its code point.
func TestOSS10w2FollowShowsKeysAsCodePoints(t *testing.T) {
	f := newFollowRig(t)
	f.describe = func([]byte) (localapi.RootSummary, error) {
		return localapi.RootSummary{Version: 1, Digest: followDigest, Keys: map[string][]string{"root": {"<b>CANARY</b>", "k‮1"}},
			Thresholds: map[string]int{"root": 2}}, nil
	}
	f.upload([]byte("root"))
	raw := f.seen[len(f.seen)-1]
	if strings.Contains(raw, "<b>CANARY") || !strings.Contains(html.UnescapeString(raw), "k[U+202E]1") {
		t.Fatalf("%s", raw)
	}
}

// Without the follow ops wired in agentosd, the page says so and changes
// nothing.
func TestOSS10w2FollowUnwired(t *testing.T) {
	a := newApprovalRig(t)
	if p := html.UnescapeString(a.upload(t, []byte("root"))); !strings.Contains(p, followOffText) {
		t.Fatalf("%s", p)
	}
}

func (a *approvalRig) upload(t *testing.T, root []byte) string {
	f := &followRig{rig: a.rig}
	return f.upload(root)
}

// The page mirrors the gate's reserved name and fingerprint (localui does
// not import grants), so the page and the approval card always agree.
func TestOSS10w2FollowMirrorsTheGate(t *testing.T) {
	if reservedName != grants.ReservedFollowName {
		t.Fatalf("%q != %q", reservedName, grants.ReservedFollowName)
	}
	for _, d := range []string{followDigest, strings.Repeat("0123456789", 6) + "abcd", ""} {
		if followPrint(d) != grants.FollowPrint(d) {
			t.Fatalf("%q: %q != %q", d, followPrint(d), grants.FollowPrint(d))
		}
	}
}

// OSS-10w-r: the owner may bring several root files, the project's
// rotations from the one this box last trusted; the newest version is the
// root shown and the rest go with it, in the order brought, as its chain.
// One over the bound is refused on the page.
func TestOSS10wrPageSendsTheChain(t *testing.T) {
	f := newFollowRig(t)
	if page := f.get("/follow/"); !strings.Contains(page, `type="file" name="root" accept=".json,application/json" multiple required`) {
		t.Fatalf("the file input takes one file: %s", page)
	}
	v := func(n int) []byte {
		return []byte(fmt.Sprintf(`{"signatures":[],"signed":{"_type":"root","version":%d}}`, n))
	}
	f.upload(v(2), v(4), []byte("not json"), v(3))
	f.mu.Lock()
	shown, chain := f.shown[0], f.chains[0]
	f.mu.Unlock()
	if string(shown) != string(v(4)) || len(chain) != 3 || string(chain[0]) != string(v(2)) ||
		string(chain[1]) != "not json" || string(chain[2]) != string(v(3)) {
		t.Fatalf("root %s chain %q", shown, chain)
	}
	many := make([][]byte, localapi.MaxRootChain+2)
	for i := range many {
		many[i] = v(i + 1)
	}
	if page := f.upload(many...); !strings.Contains(page, rootTooManyText) {
		t.Fatalf("%s", page)
	}
	if shown, _ := f.calls(); shown != 1 {
		t.Fatalf("shown %d", shown)
	}
}
