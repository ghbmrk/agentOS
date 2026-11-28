package localui

import (
	"context"
	"encoding/base64"
	"html"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/localapi"
	"github.com/ghbmrk/agentos/broker/owner"
)

// REQ: KEY-4, REC-3, CH-7, CH-10

// localui4Kills runs the checks that kill MUT-kill-localui-4's (#6768)
// mutgate survivors in passkeys.go and approvals.go. Each drives the
// handler or helper itself on a bare Server, so the lines it runs stay
// those two files' own.
func localui4Kills(t *testing.T) {
	t.Run("PasskeyRefusalsHaveTheirOwnWords", passkeyRefusalsHaveTheirOwnWords)
	t.Run("FormBytesBoundsTheText", formBytesBoundsTheText)
	t.Run("FindPasskeyNeedsAnID", findPasskeyNeedsAnID)
	t.Run("AlgNamesEachAlgorithm", algNamesEachAlgorithm)
	t.Run("PasskeyPageRefusesOtherPathsAndMethods", passkeyPageRefusesOtherPathsAndMethods)
	t.Run("PasskeyPageReleasesItsContext", passkeyPageReleasesItsContext)
	t.Run("PasskeyPageShowsAListRefusal", passkeyPageShowsAListRefusal)
	t.Run("PasskeyPageBoundsItsBody", passkeyPageBoundsItsBody)
	t.Run("PasskeyBeginRefusals", passkeyBeginRefusals)
	t.Run("PasskeyFinishRefusals", passkeyFinishRefusals)
	t.Run("PasskeyCutOffRefusals", passkeyCutOffRefusals)
	t.Run("PasskeyPageRendersOnce", passkeyPageRendersOnce)
	t.Run("AnswerNamesEachRefusal", answerNamesEachRefusal)
	t.Run("WrongAnswersKeepTheirSlot", wrongAnswersKeepTheirSlot)
	t.Run("TryPageForgetsAfterAMinute", tryPageForgetsAfterAMinute)
	t.Run("ReleaseGivesBackOneSlot", releaseGivesBackOneSlot)
}

// ctxPasskeys is Passkeys with a refusal per op, keeping every context
// it was called with.
type ctxPasskeys struct {
	list                                 localapi.PasskeyList
	listErr, beginErr, finishErr, cutErr error
	ctxs                                 []context.Context
	calls                                int
}

func (p *ctxPasskeys) List(ctx context.Context, _ string) (localapi.PasskeyList, error) {
	p.ctxs = append(p.ctxs, ctx)
	return p.list, p.listErr
}

func (p *ctxPasskeys) Begin(ctx context.Context, _ string, _ []byte) ([]byte, error) {
	p.ctxs = append(p.ctxs, ctx)
	p.calls++
	return []byte("0123456789abcdef0123456789abcdef"), p.beginErr
}

func (p *ctxPasskeys) Finish(ctx context.Context, _ string, _, _, _ []byte) error {
	p.ctxs = append(p.ctxs, ctx)
	p.calls++
	return p.finishErr
}

func (p *ctxPasskeys) CutOff(ctx context.Context, _, _ string, _, _, _ []byte) error {
	p.ctxs = append(p.ctxs, ctx)
	p.calls++
	return p.cutErr
}

// bareServer is a Server with only its config, pages and form key, for
// calling a handler or helper directly without New's routes.
func bareServer(t *testing.T, p Passkeys, now func() time.Time) *Server {
	t.Helper()
	if now == nil {
		now = time.Now
	}
	cfg := Config{Page: testPage(), Now: now}
	if p != nil {
		cfg.Passkeys, cfg.PasskeyRPID = p, DefaultPageName
	}
	return &Server{cfg: cfg, pages: pagesFor(cfg.Page.pageName()), formKey: []byte("localui-4 form key, tests only..")}
}

// passkeyPost is passkeysPage's answer to method with form as its body.
func passkeyPost(s *Server, method, path string, form url.Values) *httptest.ResponseRecorder {
	var q *http.Request
	if form == nil {
		q = httptest.NewRequest(method, "http://10.42.0.1"+path, nil)
	} else {
		q = httptest.NewRequest(method, "http://10.42.0.1"+path, strings.NewReader(form.Encode()))
		q.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	w := httptest.NewRecorder()
	s.passkeysPage(w, q)
	return w
}

func pkList() localapi.PasskeyList {
	return localapi.PasskeyList{Anchors: []localapi.Passkey{anchorKey}, Enrolled: []localapi.Passkey{phoneKey}}
}

func pkTap() url.Values {
	enc := base64.StdEncoding.EncodeToString
	return url.Values{"ad": {enc([]byte("ad"))}, "cd": {enc([]byte("cd"))}, "sig": {enc([]byte("sig"))}}
}

func passkeyRefusalsHaveTheirOwnWords(t *testing.T) {
	for code, want := range map[string]string{
		localapi.ErrPasskeyAnchor:       AnchorReply,
		localapi.ErrPasskeyNotAnchor:    "That tap was a phone passkey's. Only one of your hardware keys can add or cut off a passkey. Start again and tap a hardware key when asked.",
		localapi.ErrPasskeyBadAssertion: "That tap didn't match. Start again, and tap one of your hardware keys when asked.",
		localapi.ErrPasskeyRefused:      "I couldn't add that passkey. A passkey you cut off can't come back: make a new one on the phone and start again.",
		localapi.ErrPasskeyStale:        "That took too long, or this page is out of date. Start again.",
		localapi.ErrPasskeySetup:        "Finish setup first.",
		localapi.ErrLimited:             "Too many tries. Wait a minute, then start again.",
		localapi.ErrUnauthorized:        "Your sign-in ended. Sign in again, then start again.",
		"kernel: something else":        "I couldn't reach the part of me that keeps your passkeys. Try again in a minute.",
	} {
		if got := passkeyText(Refused(code)); got != want {
			t.Errorf("%s: %q", code, got)
		}
	}
}

func formBytesBoundsTheText(t *testing.T) {
	enc := base64.StdEncoding.EncodeToString
	// Decoding skips newlines, so only the length check refuses text past
	// the bound whose bytes are within it.
	if _, ok := formBytes(enc([]byte("abc"))+"\n\n", 3); ok {
		t.Fatal("text past its bound was read")
	}
	if b, ok := formBytes(enc([]byte("abc")), 3); !ok || string(b) != "abc" {
		t.Fatalf("formBytes: %q %v", b, ok)
	}
	if _, ok := formBytes("", 3); ok {
		t.Fatal("empty text was read")
	}
}

func findPasskeyNeedsAnID(t *testing.T) {
	l := localapi.PasskeyList{Enrolled: []localapi.Passkey{{Fingerprint: "no id"}}}
	if k, ok := findPasskey(l, ""); ok {
		t.Fatalf("an empty id found %v", k)
	}
	if k, ok := findPasskey(pkList(), phoneKey.ID); !ok || k.ID != phoneKey.ID {
		t.Fatal("a listed key was not found")
	}
}

func algNamesEachAlgorithm(t *testing.T) {
	for alg, want := range map[string]string{"es256": "ES256", "ed25519": "Ed25519", "rsa": "unknown"} {
		if got := algName(alg); got != want {
			t.Errorf("%s: %q", alg, got)
		}
	}
}

func passkeyPageRefusesOtherPathsAndMethods(t *testing.T) {
	p := &ctxPasskeys{list: pkList()}
	s := bareServer(t, p, nil)
	if w := passkeyPost(s, "GET", "/other", nil); w.Code != http.StatusNotFound || len(p.ctxs) != 0 {
		t.Fatalf("another path: %d, %d calls", w.Code, len(p.ctxs))
	}
	w := passkeyPost(s, "PUT", "/", url.Values{"step": {"begin"}})
	if w.Code != http.StatusMethodNotAllowed || w.Header().Get("Allow") != "GET, POST" || len(p.ctxs) != 0 ||
		strings.Contains(w.Body.String(), "<h1>Passkeys</h1>") {
		t.Fatalf("PUT: %d %q, %d calls\n%s", w.Code, w.Header().Get("Allow"), len(p.ctxs), w.Body.String())
	}
	w = passkeyPost(s, "GET", "/", nil)
	if w.Code != http.StatusOK || w.Header().Get("Allow") != "" || strings.Contains(w.Body.String(), "Method not allowed") {
		t.Fatalf("GET: %d %q", w.Code, w.Header().Get("Allow"))
	}
}

func passkeyPageReleasesItsContext(t *testing.T) {
	p := &ctxPasskeys{list: pkList()}
	s := bareServer(t, p, nil)
	passkeyPost(s, "GET", "/", nil)
	if len(p.ctxs) != 1 || p.ctxs[0].Err() == nil {
		t.Fatal("the page's call bound outlived the page")
	}
}

func passkeyPageShowsAListRefusal(t *testing.T) {
	p := &ctxPasskeys{list: pkList(), listErr: Refused(localapi.ErrUnauthorized)}
	s := bareServer(t, p, nil)
	if b := html.UnescapeString(passkeyPost(s, "GET", "/", nil).Body.String()); !strings.Contains(b, passkeyText(p.listErr)) {
		t.Fatalf("a list refusal was not shown:\n%s", b)
	}
	// A step's own refusal stands over the list's.
	b := html.UnescapeString(passkeyPost(s, "POST", "/", url.Values{"step": {"begin"}, "point": {"AAAA"}}).Body.String())
	if !strings.Contains(b, "That passkey isn't one I can use. Try again.") || strings.Contains(b, passkeyText(p.listErr)) {
		t.Fatalf("the step's refusal was not kept:\n%s", b)
	}
}

func passkeyPageBoundsItsBody(t *testing.T) {
	p := &ctxPasskeys{list: pkList()}
	s := bareServer(t, p, nil)
	w := passkeyPost(s, "POST", "/", url.Values{"step": {"begin"}, "pad": {strings.Repeat("a", 16<<10)}})
	if w.Code != http.StatusBadRequest || p.calls != 0 || strings.Count(w.Body.String(), "Bad request") != 1 {
		t.Fatalf("an oversized body: %d\n%s", w.Code, w.Body.String())
	}
}

func passkeyBeginRefusals(t *testing.T) {
	p := &ctxPasskeys{list: pkList(), beginErr: Refused(localapi.ErrPasskeySetup)}
	s := bareServer(t, p, nil)
	enc := base64.StdEncoding.EncodeToString
	b := html.UnescapeString(passkeyPost(s, "POST", "/", url.Values{"step": {"begin"}, "point": {enc(make([]byte, 64))}}).Body.String())
	if !strings.Contains(b, "That passkey isn't one I can use. Try again.") || p.calls != 0 {
		t.Fatalf("a short point:\n%s", b)
	}
	b = html.UnescapeString(passkeyPost(s, "POST", "/", url.Values{"step": {"begin"}, "point": {enc(append([]byte{4}, make([]byte, 64)...))}}).Body.String())
	if p.calls != 1 || !strings.Contains(b, "Finish setup first.") || strings.Contains(b, `id="pk-tap"`) {
		t.Fatalf("a refused begin:\n%s", b)
	}
}

func passkeyFinishRefusals(t *testing.T) {
	p := &ctxPasskeys{list: pkList(), finishErr: Refused(localapi.ErrPasskeyStale)}
	s := bareServer(t, p, nil)
	f := pkTap()
	f.Set("step", "finish")
	b := html.UnescapeString(passkeyPost(s, "POST", "/", f).Body.String())
	if p.calls != 1 || !strings.Contains(b, passkeyText(p.finishErr)) || strings.Contains(b, "passkey is added") {
		t.Fatalf("a refused finish:\n%s", b)
	}
	// The page after a step lists the keys afresh.
	p.finishErr = nil
	b = html.UnescapeString(passkeyPost(s, "POST", "/", f).Body.String())
	if !strings.Contains(b, "passkey is added") || !strings.Contains(b, anchorKey.Fingerprint) || !strings.Contains(b, phoneKey.Fingerprint) {
		t.Fatalf("the finished page lists no keys:\n%s", b)
	}
}

func passkeyCutOffRefusals(t *testing.T) {
	p := &ctxPasskeys{list: pkList(), cutErr: Refused(localapi.ErrPasskeyRefused)}
	s := bareServer(t, p, nil)
	b := html.UnescapeString(passkeyPost(s, "POST", "/", url.Values{"step": {"cutoff"}, "id": {strings.Repeat("c3", 32)}}).Body.String())
	if p.calls != 0 || !strings.Contains(b, passkeyText(Refused(localapi.ErrPasskeyStale))) {
		t.Fatalf("an unlisted key:\n%s", b)
	}
	b = html.UnescapeString(passkeyPost(s, "POST", "/", url.Values{"step": {"cutoff"}, "id": {anchorKey.ID}}).Body.String())
	if p.calls != 1 || !strings.Contains(b, passkeyText(p.cutErr)) || strings.Contains(b, "cut off for good") {
		t.Fatalf("a refused cut-off:\n%s", b)
	}
}

// A step that renders its own page renders it once.
func passkeyPageRendersOnce(t *testing.T) {
	p := &ctxPasskeys{list: pkList(), finishErr: Refused(localapi.ErrPasskeyBadAssertion), cutErr: Refused(localapi.ErrPasskeyNotAnchor)}
	s := bareServer(t, p, nil)
	once := func(what string, w *httptest.ResponseRecorder) {
		t.Helper()
		if n := strings.Count(w.Body.String(), "<h1>Passkeys</h1>"); n != 1 {
			t.Fatalf("%s rendered %d pages", what, n)
		}
	}
	once("the list", passkeyPost(s, "GET", "/", nil))
	ch := base64.StdEncoding.EncodeToString([]byte("0123456789abcdef0123456789abcdef"))
	f := pkTap()
	f.Set("step", "finish")
	f.Set("ch", ch)
	f.Set("tok", s.passkeyToken("", ch))
	w := passkeyPost(s, "POST", "/", f)
	if !strings.Contains(html.UnescapeString(w.Body.String()), TapAgainText) {
		t.Fatalf("a wrong tap:\n%s", w.Body.String())
	}
	once("a wrong tap", w)
	f = pkTap()
	f.Set("step", "cutoff")
	f.Set("id", phoneKey.ID)
	w = passkeyPost(s, "POST", "/", f)
	if !strings.Contains(html.UnescapeString(w.Body.String()), TapAgainText) {
		t.Fatalf("a wrong cut-off tap:\n%s", w.Body.String())
	}
	once("a wrong cut-off tap", w)
}

// scriptOwner answers OpAnswer with answered, or err.
type scriptOwner struct {
	answered localapi.Answered
	err      error
	calls    int
}

func (o *scriptOwner) Call(_ context.Context, op string, _, out any) error {
	if op != localapi.OpAnswer {
		return Refused("unexpected op " + op)
	}
	o.calls++
	if o.err != nil {
		return o.err
	}
	*out.(*localapi.Answered) = o.answered
	return nil
}

// approveForm is the Approvals form for request id as sess was shown it.
func approveForm(s *Server, sess, id string) map[string][]string {
	return map[string][]string{"id": {id}, "sum": {"sum"}, "tok": {s.formToken(sess, id, "sum")},
		"answer": {"approve"}, "code": {"123456"}}
}

func answerNamesEachRefusal(t *testing.T) {
	cases := []struct {
		answered localapi.Answered
		err      error
		want     string
	}{
		{err: Refused(localapi.ErrLimited), want: "Too many wrong codes from this phone. Wait a minute, then try again."},
		{answered: localapi.Answered{Refusal: localapi.RefusedTooMany}, want: "Too many tries on my Wi-Fi in the last day, so approving here is paused for up to 24 hours. Deny still works here, and NO by text."},
		{answered: localapi.Answered{Refusal: localapi.RefusedWrongCode}, want: wrongCodeText},
		{answered: localapi.Answered{Refusal: localapi.RefusedTextedCode}, want: owner.ErrTextedCode.Error()},
		{answered: localapi.Answered{Refusal: localapi.RefusedNoRequest, Text: "the channel's words"}, want: stalePage},
		{answered: localapi.Answered{Refusal: localapi.RefusedChanged, Text: "the channel's words"}, want: stalePage},
	}
	for i, c := range cases {
		s := bareServer(t, nil, nil)
		s.SetOwner(&scriptOwner{answered: c.answered, err: c.err})
		sess := "phone"
		if _, got := s.answer(context.Background(), "tok", sess, approveForm(s, sess, "req")); got != c.want {
			t.Errorf("case %d: %q", i, got)
		}
	}
}

// A wrong or texted code holds its slot, so the phone's bound stops the
// next try before it reaches agentosd.
func wrongAnswersKeepTheirSlot(t *testing.T) {
	for _, r := range []string{localapi.RefusedWrongCode, localapi.RefusedTextedCode} {
		s := bareServer(t, nil, nil)
		o := &scriptOwner{answered: localapi.Answered{Refusal: r}}
		s.SetOwner(o)
		for i := 0; i < PageWrongPerMinute; i++ {
			s.answer(context.Background(), "tok", "phone", approveForm(s, "phone", "req"))
		}
		_, got := s.answer(context.Background(), "tok", "phone", approveForm(s, "phone", "req"))
		if o.calls != PageWrongPerMinute || got != "Too many wrong codes from this phone. Wait a minute, then try again." {
			t.Fatalf("%s: %d calls, %q", r, o.calls, got)
		}
	}
}

func tryPageForgetsAfterAMinute(t *testing.T) {
	now := time.Date(2026, 11, 28, 10, 0, 0, 0, time.UTC)
	s := bareServer(t, nil, func() time.Time { return now })
	for _, sess := range []string{"old", "old", "old", "old", "old", "both"} {
		if rel, ok := s.tryPage(sess); !ok {
			t.Fatal("a slot was refused")
		} else {
			rel(true)
		}
	}
	now = now.Add(40 * time.Second)
	if rel, ok := s.tryPage("both"); ok {
		rel(true)
	}
	now = now.Add(30 * time.Second)
	// "old" is past its minute and forgotten; "both" keeps only its later
	// try.
	if rel, ok := s.tryPage("both"); !ok {
		t.Fatal("a slot was refused")
	} else {
		rel(true)
	}
	if _, ok := s.pageWrong["old"]; ok || len(s.pageWrong["both"]) != 2 || len(s.pageWrong) != 1 {
		t.Fatalf("after a minute: %v", s.pageWrong)
	}
	if rel, ok := s.tryPage("old"); !ok {
		t.Fatal("a phone past its minute is still bounded")
	} else {
		rel(true)
	}
}

func releaseGivesBackOneSlot(t *testing.T) {
	now := time.Date(2026, 11, 28, 10, 0, 0, 0, time.UTC)
	s := bareServer(t, nil, func() time.Time { return now })
	rel, _ := s.tryPage("phone")
	rel(false)
	if _, ok := s.pageWrong["phone"]; ok {
		t.Fatalf("a right code kept its slot: %v", s.pageWrong)
	}
	// Two tries at one instant: giving one back keeps the other.
	wrong, _ := s.tryPage("phone")
	right, _ := s.tryPage("phone")
	wrong(true)
	right(false)
	if len(s.pageWrong["phone"]) != 1 {
		t.Fatalf("giving one slot back left %d", len(s.pageWrong["phone"]))
	}
}
