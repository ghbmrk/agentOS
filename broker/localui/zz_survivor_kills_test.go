package localui

import (
	"bytes"
	"context"
	"errors"
	"html"
	"image"
	"image/color"
	"image/png"
	"io"
	"math"
	"math/rand"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"testing/iotest"
	"time"

	"github.com/ghbmrk/agentos/broker/card"
	"github.com/ghbmrk/agentos/broker/localapi"
	"rsc.io/qr"
)

// survivorKills runs, as subtests of TestRecoveryKeyWithCRLFOpensTheSlot
// (through recoveryEdges), the checks that kill #6000's second set of
// mutgate survivors in recovery.go, scan.go, setup.go, vault.go and
// server.go. They are subtests for the reason recoveryEdges gives: a new
// top-level test in localui widens mutgate's targets to the whole package.
func survivorKills(t *testing.T) {
	t.Run("RestartAndCancelEraseTheCard", restartAndCancelEraseTheCard)
	t.Run("DisplayCancelWipesTheFactor", displayCancelWipesTheFactor)
	t.Run("RefusedBeginWipesTheKey", refusedBeginWipesTheKey)
	t.Run("BeginOvertakenKeepsNothing", beginOvertakenKeepsNothing)
	t.Run("TapWipesWhatItSent", tapWipesWhatItSent)
	t.Run("BadAssertionWording", badAssertionWording)
	t.Run("EachAnswerWrittenOnce", eachAnswerWrittenOnce)
	t.Run("FormBodiesAreBounded", formBodiesAreBounded)
	t.Run("PagesCarryTheirHeaders", pagesCarryTheirHeaders)
	t.Run("FactorWaitsForTheScanner", factorWaitsForTheScanner)
	t.Run("FactorUploadHasADeadline", factorUploadHasADeadline)
	t.Run("FactorCutShortIsNamed", factorCutShortIsNamed)
	t.Run("FactorPassphraseTooLong", factorPassphraseTooLong)
	t.Run("ScanSameCodeTwice", scanSameCodeTwice)
	t.Run("ScanStopsAtTheFirstSize", scanStopsAtTheFirstSize)
	t.Run("ScanFallsBackToOneCode", scanFallsBackToOneCode)
	t.Run("GrayReducesAndKeepsLuma", grayReducesAndKeepsLuma)
	t.Run("ReadPhotoRefusesOneByteOver", readPhotoRefusesOneByteOver)
	t.Run("ScanPanicReadsAsNotAPhoto", scanPanicReadsAsNotAPhoto)
	t.Run("CodesStepNamesEachRefusal", codesStepNamesEachRefusal)
	t.Run("DoneSetupRefusesAnAnswer", doneSetupRefusesAnAnswer)
	t.Run("SignInNamesEachRefusal", signInNamesEachRefusal)
}

// keepRecovery keeps the very slices the page passes to begin and rotate
// (not copies), so a test can see that the page wiped them once the call
// returned; onBegin runs inside the begin.
type keepRecovery struct {
	*fakeRecoveryOps
	next, secret [][]byte
	onBegin      func()
}

func (k *keepRecovery) RecoveryBegin(ctx context.Context, tok string, next []byte) (localapi.RecoveryBegun, error) {
	k.next = append(k.next, next)
	if k.onBegin != nil {
		k.onBegin()
	}
	return k.fakeRecoveryOps.RecoveryBegin(ctx, tok, next)
}

func (k *keepRecovery) RecoveryRotate(ctx context.Context, tok, factor string, secret, next, ad, cd, sig []byte) (localapi.RecoveryDone, error) {
	k.secret, k.next = append(k.secret, secret), append(k.next, next)
	return k.fakeRecoveryOps.RecoveryRotate(ctx, tok, factor, secret, next, ad, cd, sig)
}

func zeroed(b []byte) bool { return len(bytes.Trim(b, "\x00")) == 0 }

// keepCards has the page's card maker record each card it makes.
func keepCards(r *recoveryRig) *[]*card.Card {
	var cards []*card.Card
	gen := r.srv.cfg.RecoveryCard
	r.srv.cfg.RecoveryCard = func(rd io.Reader) (*card.Card, error) {
		c, err := gen(rd)
		if err == nil {
			cards = append(cards, c)
		}
		return c, err
	}
	return &cards
}

// A second start erases the first replacement's card and factor, and a
// cancel erases the card the replacement waits on.
func restartAndCancelEraseTheCard(t *testing.T) {
	r := newRecoveryRig(t)
	cards := keepCards(r)
	r.signIn()
	r.factor(map[string]string{"passphrase": "alpha bravo charlie delta"})
	first := r.srv.recovery.p
	r.factor(map[string]string{"passphrase": "echo foxtrot golf hotel"})
	if len(*cards) != 2 || first == nil || r.srv.recovery.p == first {
		t.Fatalf("two starts made %d cards", len(*cards))
	}
	if c := (*cards)[0]; c.RecoveryKey != "" || c.VaultPassphrase != "" || !zeroed(first.secret) || first.display != nil {
		t.Fatalf("a second start left the first card or factor: %q %q", c.RecoveryKey, first.secret)
	}
	r.post("/recovery/", url.Values{"step": {"cancel"}})
	if c := (*cards)[1]; c.RecoveryKey != "" || c.VaultPassphrase != "" {
		t.Fatal("a cancel left the waiting card unerased")
	}
}

// The display's own cancel drops the replacement with its factor.
func displayCancelWipesTheFactor(t *testing.T) {
	r := newRecoveryRig(t)
	r.signIn()
	r.factor(map[string]string{"passphrase": "alpha bravo charlie delta"})
	p := r.srv.recovery.p
	w := r.post("/recovery/card", url.Values{"cancel": {"1"}})
	if w.Code != http.StatusSeeOther || r.srv.recovery.p != nil || p.display != nil || !zeroed(p.secret) {
		t.Fatalf("the card's cancel: %d, kept %v, display %v, factor %q", w.Code, r.srv.recovery.p != nil, p.display != nil, p.secret)
	}
}

// A confirm agentosd refuses wipes the key it sent.
func refusedBeginWipesTheKey(t *testing.T) {
	r := newRecoveryRig(t)
	k := &keepRecovery{fakeRecoveryOps: r.f}
	r.srv.cfg.Recovery = k
	r.signIn()
	r.f.beginErr = Refused(localapi.ErrRecoveryBusy)
	r.factor(map[string]string{"passphrase": "alpha bravo charlie delta"})
	r.confirm(false)
	if len(k.next) != 1 || len(k.next[0]) != card.StoreKeyLen || !zeroed(k.next[0]) {
		t.Fatalf("a refused begin left its key: %x", k.next)
	}
}

// A begin whose replacement was cancelled while it ran keeps nothing: the
// key is wiped and the replacement never reaches the tap.
func beginOvertakenKeepsNothing(t *testing.T) {
	r := newRecoveryRig(t)
	k := &keepRecovery{fakeRecoveryOps: r.f}
	r.srv.cfg.Recovery = k
	k.onBegin = func() {
		r.srv.recovery.mu.Lock()
		r.srv.recovery.p = nil
		r.srv.recovery.mu.Unlock()
	}
	r.signIn()
	r.factor(map[string]string{"passphrase": "alpha bravo charlie delta"})
	p := r.srv.recovery.p
	r.confirm(false)
	if len(k.next) != 1 || !zeroed(k.next[0]) || p.next != nil || p.begun != nil {
		t.Fatalf("an overtaken begin kept its key: %x %x %v", k.next, p.next, p.begun != nil)
	}
}

// The factor and key copies a tap sends are wiped once the rotate returns.
func tapWipesWhatItSent(t *testing.T) {
	r := newRecoveryRig(t)
	k := &keepRecovery{fakeRecoveryOps: r.f}
	r.srv.cfg.Recovery = k
	r.signIn()
	r.factor(map[string]string{"passphrase": "alpha bravo charlie delta"})
	r.confirm(false)
	r.post("/recovery/", tapForm)
	if len(k.secret) != 1 || len(k.next) != 2 || len(k.secret[0]) == 0 || len(k.next[1]) != card.StoreKeyLen {
		t.Fatalf("tap sent %d factors, %d keys", len(k.secret), len(k.next))
	}
	if !zeroed(k.secret[0]) || !zeroed(k.next[1]) {
		t.Fatalf("a tap left what it sent: %q %x", k.secret[0], k.next[1])
	}
}

// A tap that does not verify has its own wording.
func badAssertionWording(t *testing.T) {
	if got := recoveryText(Refused(localapi.ErrRecoveryBadAssertion)); got != "That tap didn't match. Tap again with one of your hardware keys." {
		t.Fatalf("bad assertion reads %q", got)
	}
}

// Each answer of the recovery page is written once: the first step, the
// card page, a refused method, a started replacement's redirect and a refused factor
// carry nothing after their own answer.
func eachAnswerWrittenOnce(t *testing.T) {
	r := newRecoveryRig(t)
	r.signIn()
	if b := r.do("GET", "/recovery/", nil).Body.String(); strings.Contains(b, "Bad request") {
		t.Fatalf("the first step ends with a second answer:\n%s", b)
	}
	w := r.do("PUT", "/recovery/", url.Values{"step": {"cancel"}})
	if w.Code != http.StatusMethodNotAllowed || w.Body.String() != "Method not allowed\n" {
		t.Fatalf("PUT: %d %q", w.Code, w.Body.String())
	}
	if w := r.factor(map[string]string{"passphrase": " "}); w.StatusCode != http.StatusOK || strings.Contains(readAll(w.Body), "Bad request") {
		t.Fatalf("a refused factor: %d", w.StatusCode)
	}
	w2 := r.factor(map[string]string{"passphrase": "alpha bravo charlie delta"})
	if b := readAll(w2.Body); w2.StatusCode != http.StatusSeeOther || b != "" {
		t.Fatalf("a started replacement: %d %q", w2.StatusCode, b)
	}
	if b := r.do("GET", "/recovery/card", nil).Body.String(); strings.Contains(b, "404 page not found") {
		t.Fatalf("the card page ends with a second answer:\n%s", b)
	}
}

func readAll(rd io.Reader) string {
	b, _ := io.ReadAll(rd)
	return string(b)
}

// A step post over 16 KiB, and a factor upload over the photo bound and its
// slack, are refused before they are read whole.
func formBodiesAreBounded(t *testing.T) {
	r := newRecoveryRig(t)
	r.signIn()
	if w := r.post("/recovery/", url.Values{"step": {"cancel"}, "pad": {strings.Repeat("a", 16<<10)}}); w.Code != http.StatusBadRequest {
		t.Fatalf("a 16 KiB step post: %d", w.Code)
	}
	var b bytes.Buffer
	m := multipart.NewWriter(&b)
	fw, _ := m.CreateFormField("pad")
	fw.Write(make([]byte, MaxPhotoBytes+64<<10))
	m.WriteField("passphrase", "alpha bravo charlie delta")
	m.Close()
	w := r.do("POST", "/recovery/", nil, multipartBody(b.Bytes(), m.FormDataContentType()))
	if !strings.Contains(w.Body.String(), "too large or did not arrive whole") || r.srv.recovery.p != nil {
		t.Fatalf("an upload past its bound: %d, started %v", w.Code, r.srv.recovery.p != nil)
	}
}

func multipartBody(b []byte, ct string) func(*http.Request) {
	return func(q *http.Request) {
		q.Body = io.NopCloser(bytes.NewReader(b))
		q.ContentLength = int64(len(b))
		q.Header.Set("Content-Type", ct)
	}
}

// Every recovery page is no-store under the vault page's policy, and the
// tap step under the passkey page's.
func pagesCarryTheirHeaders(t *testing.T) {
	r := newRecoveryRig(t)
	r.signIn()
	w := r.do("GET", "/recovery/", nil)
	if w.Header().Get("Cache-Control") != "no-store" || w.Header().Get("Content-Security-Policy") != vaultCSP {
		t.Fatalf("first step headers: %v", w.Header())
	}
	r.factor(map[string]string{"passphrase": "alpha bravo charlie delta"})
	r.confirm(false)
	w = r.do("GET", "/recovery/", nil)
	if w.Header().Get("Cache-Control") != "no-store" || w.Header().Get("Content-Security-Policy") != passkeyCSP || passkeyCSP == vaultCSP {
		t.Fatalf("tap step headers: %v", w.Header())
	}
}

// While another photo is being read, a factor post is turned away and
// starts nothing.
func factorWaitsForTheScanner(t *testing.T) {
	r := newRecoveryRig(t)
	r.signIn()
	r.srv.scanning <- struct{}{}
	w := r.factor(map[string]string{"passphrase": "alpha bravo charlie delta"})
	<-r.srv.scanning
	if b := html.UnescapeString(readAll(w.Body)); !strings.Contains(b, scanText(ErrScanBusy)) || r.srv.recovery.p != nil {
		t.Fatalf("a factor while the scanner is busy started %v", r.srv.recovery.p != nil)
	}
}

// deadlineWriter records the read deadline a handler sets.
type deadlineWriter struct {
	*httptest.ResponseRecorder
	at time.Time
}

func (d *deadlineWriter) SetReadDeadline(t time.Time) error { d.at = t; return nil }

// A factor upload is read under the upload window's deadline.
func factorUploadHasADeadline(t *testing.T) {
	r := newRecoveryRig(t)
	r.signIn()
	var b bytes.Buffer
	m := multipart.NewWriter(&b)
	m.WriteField("passphrase", "alpha bravo charlie delta")
	m.Close()
	req := httptest.NewRequest("POST", "http://10.42.0.1/recovery/", nil)
	req.RemoteAddr = r.ip
	for _, c := range r.jar.Cookies(req.URL) {
		req.AddCookie(c)
	}
	multipartBody(b.Bytes(), m.FormDataContentType())(req)
	w := &deadlineWriter{ResponseRecorder: httptest.NewRecorder()}
	before := time.Now()
	r.srv.ServeHTTP(w, reaching(req))
	if w.Code != http.StatusSeeOther || w.at.Before(before.Add(uploadWindow)) || w.at.After(time.Now().Add(uploadWindow)) {
		t.Fatalf("upload deadline %v (now %v), %d", w.at, before, w.Code)
	}
}

// An upload whose body ends inside a part is named, and starts nothing.
func factorCutShortIsNamed(t *testing.T) {
	r := newRecoveryRig(t)
	r.signIn()
	var b bytes.Buffer
	m := multipart.NewWriter(&b)
	m.WriteField("passphrase", "alpha bravo charlie delta")
	m.Close()
	cut := b.Bytes()[:b.Len()-len(m.Boundary())-8]
	w := r.do("POST", "/recovery/", nil, multipartBody(cut, m.FormDataContentType()))
	if !strings.Contains(w.Body.String(), "did not arrive whole") || r.srv.recovery.p != nil {
		t.Fatalf("a cut upload: %d, started %v", w.Code, r.srv.recovery.p != nil)
	}
}

// A passphrase longer than any card's is refused on the page.
func factorPassphraseTooLong(t *testing.T) {
	r := newRecoveryRig(t)
	r.signIn()
	long := strings.TrimSpace(strings.Repeat("alpha ", localapi.MaxRecoveryPassphrase/6+2))
	w := r.factor(map[string]string{"passphrase": long})
	if b := html.UnescapeString(readAll(w.Body)); !strings.Contains(b, "That passphrase is longer than any card's.") || r.f.calls() != 0 || r.srv.recovery.p != nil {
		t.Fatalf("a long passphrase started %v", r.srv.recovery.p != nil)
	}
}

// drawQR draws payload's code into img at (x0, y0), mod pixels a module.
func drawQR(t *testing.T, img *image.Gray, payload string, x0, y0, mod int) {
	t.Helper()
	c, err := qr.Encode(payload, qr.M)
	if err != nil {
		t.Fatal(err)
	}
	for y := 0; y < c.Size*mod; y++ {
		for x := 0; x < c.Size*mod; x++ {
			if c.Black(x/mod, y/mod) {
				img.SetGray(x0+x, y0+y, color.Gray{10})
			}
		}
	}
}

func whiteGray(w, h int) *image.Gray {
	img := image.NewGray(image.Rect(0, 0, w, h))
	for i := range img.Pix {
		img.Pix[i] = 255
	}
	return img
}

func pngBytes(t *testing.T, img image.Image) []byte {
	t.Helper()
	var b bytes.Buffer
	if err := png.Encode(&b, img); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

// Two copies of the one passphrase code in a photo are one passphrase.
func scanSameCodeTwice(t *testing.T) {
	img := whiteGray(1200, 600)
	drawQR(t, img, "alpha bravo charlie delta", 50, 50, 10)
	drawQR(t, img, "alpha bravo charlie delta", 650, 50, 10)
	if got := decodeQR(gray(img, scanEdge)); len(got) != 2 {
		t.Fatalf("the decoder found %q, not both copies", got)
	}
	if p, err := ScanPassphrase(pngBytes(t, img)); p != "alpha bravo charlie delta" || err != nil {
		t.Fatalf("two copies: %q %v", p, err)
	}
}

// The search stops at the first size that finds a passphrase: a second
// code that only a coarser size reads does not make the photo ambiguous.
func scanStopsAtTheFirstSize(t *testing.T) {
	img := whiteGray(3072, 1400)
	drawQR(t, img, "alpha bravo charlie delta", 40, 40, 40)
	drawQR(t, img, "echo foxtrot golf hotel", 2400, 600, 3)
	if got := decodeQR(gray(img, scanEdge)); len(got) != 1 {
		t.Fatalf("the first size found %q", got)
	}
	if got := decodeQR(gray(img, scanEdge/2)); len(got) != 2 {
		t.Fatalf("the coarser size found %q, not both codes", got)
	}
	if p, err := ScanPassphrase(pngBytes(t, img)); p != "alpha bravo charlie delta" || err != nil {
		t.Fatalf("a code only a later size reads: %q %v", p, err)
	}
}

// A noisy, turned code the multi-code reader misses is read by the
// single-code reader.
func scanFallsBackToOneCode(t *testing.T) {
	rng := rand.New(rand.NewSource(63))
	mod := 2 + rng.Intn(4)
	base := whiteGray(41*mod, 41*mod)
	drawQR(t, base, "alpha bravo charlie delta", 8*mod, 8*mod, mod)
	ang, noise := rng.Float64()*math.Pi/2, rng.Intn(120)
	b := base.Bounds()
	n := int(float64(b.Dx()) * 1.5)
	img := whiteGray(n, n)
	c, s := math.Cos(ang), math.Sin(ang)
	for y := 0; y < n; y++ {
		for x := 0; x < n; x++ {
			dx, dy := float64(x)-float64(n)/2, float64(y)-float64(n)/2
			u, v := int(c*dx+s*dy+float64(b.Dx())/2), int(-s*dx+c*dy+float64(b.Dy())/2)
			val := 255
			if u >= 0 && v >= 0 && u < b.Dx() && v < b.Dy() {
				val = int(base.Pix[v*base.Stride+u])
			}
			val += rng.Intn(2*noise+1) - noise
			img.Pix[y*img.Stride+x] = uint8(min(255, max(0, val)))
		}
	}
	if p, err := ScanPassphrase(pngBytes(t, img)); p != "alpha bravo charlie delta" || err != nil {
		t.Fatalf("a code only the single reader reads: %q %v", p, err)
	}
}

// gray reduces a photo to the edge it is given, and takes a JPEG's luma
// from its Y plane as it stands.
func grayReducesAndKeepsLuma(t *testing.T) {
	if g := gray(whiteGray(2000, 1000), 500); g.Bounds().Dx() != 500 || g.Bounds().Dy() != 250 {
		t.Fatalf("2000x1000 to 500: %v", g.Bounds())
	}
	yc := image.NewYCbCr(image.Rect(0, 0, 4, 4), image.YCbCrSubsampleRatio444)
	for i := range yc.Y {
		yc.Y[i], yc.Cb[i], yc.Cr[i] = 40, 255, 255
	}
	if g := gray(yc, 8); g.Pix[0] != 40 {
		t.Fatalf("the Y plane's 40 reads %d", g.Pix[0])
	}
}

// A photo of exactly the bound is read; one byte more, or a read that
// fails, is refused.
func readPhotoRefusesOneByteOver(t *testing.T) {
	if b, err := readPhoto(bytes.NewReader(make([]byte, MaxPhotoBytes))); err != nil || len(b) != MaxPhotoBytes {
		t.Fatalf("a photo of the bound: %d %v", len(b), err)
	}
	if b, err := readPhoto(bytes.NewReader(make([]byte, MaxPhotoBytes+1))); !errors.Is(err, ErrPhotoSize) || b != nil {
		t.Fatalf("one byte over: %d %v", len(b), err)
	}
	cut := errors.New("upload cut")
	if b, err := readPhoto(io.MultiReader(bytes.NewReader([]byte("\x89PNG")), iotest.ErrReader(cut))); !errors.Is(err, cut) || b != nil {
		t.Fatalf("a photo cut short: %d %v", len(b), err)
	}
}

// A decoder that panics on a hostile file reads as no photo, not a crash.
func scanPanicReadsAsNotAPhoto(t *testing.T) {
	const magic = "agentos-panicking-format-6000"
	boom := func(io.Reader) (image.Image, error) { panic("decoder bug") }
	image.RegisterFormat("agentospanic", magic, boom, func(io.Reader) (image.Config, error) { panic("decoder bug") })
	if p, err := scanSafe([]byte(magic + "rest")); p != "" || !errors.Is(err, ErrNotPhoto) {
		t.Fatalf("a panicking decoder: %q %v", p, err)
	}
}

// codeHooks answers the code enrollment's calls with fixed errors.
type codeHooks struct {
	*fakeHooks
	enrollErr, confirmErr error
	enrollLink            string // EnrollCode's link beside enrollErr
}

func (h *codeHooks) EnrollCode() (string, error) {
	if h.enrollErr != nil {
		return h.enrollLink, h.enrollErr
	}
	return h.fakeHooks.EnrollCode()
}

func (h *codeHooks) ConfirmCode(code string) (bool, error) {
	if h.confirmErr != nil {
		return false, h.confirmErr
	}
	return h.fakeHooks.ConfirmCode(code)
}

// The codes step names each refusal the vault gives: too many new codes
// on the page, any other failure as a 500; and on a typed code, a key no
// longer waiting, too many wrong codes, and a check that failed.
func codesStepNamesEachRefusal(t *testing.T) {
	r := newRig(t)
	h := &codeHooks{fakeHooks: r.hooks, enrollErr: ErrCodesLimited}
	r.srv.cfg.Hooks = h
	if p := r.toCodes(); !strings.Contains(p, "Too many new codes in a minute. Wait a minute, then reload this page.") {
		t.Fatalf("limited enroll:\n%s", p)
	}
	// A failed enroll is a 500 even beside a link that reads as a key.
	h.enrollErr, h.enrollLink = errors.New("vault gone"), "otpauth://totp/agentOS:agentOS?secret=JBSWY3DPEHPK3PXP&issuer=agentOS&algorithm=SHA1&digits=6&period=30"
	if w := r.do("GET", "/setup", nil); w.Code != http.StatusInternalServerError || !strings.Contains(w.Body.String(), "Setup could not start this step.") {
		t.Fatalf("failed enroll: %d %s", w.Code, w.Body.String())
	}
	h.enrollErr, h.enrollLink = nil, ""
	r.get("/setup")
	for _, c := range []struct {
		err  error
		want string
	}{
		{ErrNoCodeEnrollment, "That key is no longer waiting. Add the new one below."},
		{ErrCodesLimited, "Too many wrong codes. Wait a few minutes, then try again."},
		{errors.New("vault gone"), "Could not check the code. Try again."},
	} {
		h.confirmErr = c.err
		w := r.post("/setup/codes", url.Values{"code": {"123456"}})
		if b := html.UnescapeString(w.Body.String() + r.setupErr()); !strings.Contains(b, c.want) {
			t.Fatalf("%v: %d\n%s", c.err, w.Code, b)
		}
	}
}

// A setup already done refuses an AI answer before anything else.
func doneSetupRefusesAnAnswer(t *testing.T) {
	u := &setup{st: SetupState{Done: true}, finishing: true, busy: map[string]bool{"x": true}}
	if err := u.begin("x"); !errors.Is(err, errSetupDone) {
		t.Fatalf("done setup's begin: %v", err)
	}
}

// signInOwner fails agentosd's sign-in call with err.
type signInOwner struct {
	Owner
	err error
}

func (o signInOwner) Call(ctx context.Context, op string, args, out any) error {
	if op == localapi.OpSignIn {
		return o.err
	}
	return o.Owner.Call(ctx, op, args, out)
}

// Sign-in names a limited agentosd and a failed check apart.
func signInNamesEachRefusal(t *testing.T) {
	r := newRecoveryRig(t)
	o := r.srv.getOwner()
	for _, c := range []struct {
		err  error
		want string
	}{
		{Refused(localapi.ErrLimited), limitedText},
		{errors.New("socket gone"), "Could not check the code. Try again."},
	} {
		r.srv.SetOwner(signInOwner{Owner: o, err: c.err})
		w := r.post("/unlock", url.Values{"code": {r.code()}, "next": {"/home"}})
		if b := html.UnescapeString(w.Body.String()); !strings.Contains(b, c.want) {
			t.Fatalf("%v: %d\n%s", c.err, w.Code, b)
		}
	}
}
