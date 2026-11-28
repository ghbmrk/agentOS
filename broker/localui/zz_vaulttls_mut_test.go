package localui

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"image"
	"image/color"
	"io"
	"log"
	"mime/multipart"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/localapi"
	"github.com/ghbmrk/agentos/broker/pageca"
)

// REQ: CH-6, CH-7, CH-9

// vaultTLSKills runs, as subtests of TestScanSafeRecovers, the checks that
// kill the mutgate survivors in vault.go and tls.go (#6763). They are
// subtests, not top-level tests, for the reason recoveryEdges gives: a new
// top-level test changes localui's run list and makes every test a
// changed test.
func vaultTLSKills(t *testing.T) {
	t.Run("UnlockClientWire", unlockClientWire)
	t.Run("UnlockClientClosesEachReply", unlockClientClosesEachReply)
	t.Run("VaultPageStates", vaultPageStates)
	t.Run("VaultPendingForgottenOnceEnded", vaultPendingForgottenOnceEnded)
	t.Run("VaultPassphraseFormBounds", vaultPassphraseFormBounds)
	t.Run("VaultPassphraseOutcomes", vaultPassphraseOutcomes)
	t.Run("VaultPINOutcomes", vaultPINOutcomes)
	t.Run("VaultBudgetPrunes", vaultBudgetPrunes)
	t.Run("VaultTextsNameEachRefusal", vaultTextsNameEachRefusal)
	t.Run("ScanSafeRecoversADecoderPanic", scanSafeRecoversADecoderPanic)
	t.Run("PageTLSDefaultLog", pageTLSDefaultLog)
	t.Run("PageTLSRefusesBadAnswers", pageTLSRefusesBadAnswers)
	t.Run("PageTLSRunStops", pageTLSRunStops)
}

// unixVault serves h on a unix socket, as the vault process's unlock
// socket, and returns a client for it.
func unixVault(t *testing.T, h http.HandlerFunc) (*UnlockClient, *http.Server) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "u.sock")
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: h}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })
	return NewUnlockClient(path), srv
}

func unlockClientWire(t *testing.T) {
	var mu sync.Mutex
	ctypes := map[string]string{}
	reply := func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		ctypes[r.Method+" "+r.URL.Path] = r.Header.Get("Content-Type")
		mu.Unlock()
		switch r.URL.Path {
		case "/status":
			w.Write([]byte(`{"state":"locked"}`))
		case "/unlock":
			w.Write([]byte(`{"state":"pending","ticket":"tkt"}`))
		case "/unlock-pin":
			// A refusal with no body: the client names it itself.
			w.WriteHeader(http.StatusForbidden)
		case "/confirm":
			w.Write([]byte("not json"))
		}
	}
	u, _ := unixVault(t, reply)
	ctx := context.Background()
	if st, err := u.Status(ctx); err != nil || st.State != "locked" {
		t.Fatalf("status %+v, %v", st, err)
	}
	if _, tk, err := u.Unlock(ctx, "words"); err != nil || tk != "tkt" {
		t.Fatalf("unlock %q, %v", tk, err)
	}
	mu.Lock()
	if g, p := ctypes["GET /status"], ctypes["POST /unlock"]; g != "" || p != "application/json" {
		t.Errorf("Content-Type: GET %q, POST %q", g, p)
	}
	mu.Unlock()
	var ve *VaultError
	if _, err := u.UnlockPIN(ctx, "0000"); !errors.As(err, &ve) || ve.Status != http.StatusForbidden || ve.Msg != "the vault process refused the request" {
		t.Errorf("bodiless refusal: %v", err)
	}
	if _, err := u.Confirm(ctx, "tkt", "123456", false); err == nil || errors.As(err, &ve) {
		t.Errorf("unreadable reply: %v", err)
	}
	// A request that cannot be made, and a socket nobody serves, are
	// errors, not panics.
	var none context.Context
	if _, err := u.Status(none); err == nil {
		t.Error("a nil context made a request")
	}
	gone := NewUnlockClient(filepath.Join(t.TempDir(), "none.sock"))
	if _, err := gone.Status(ctx); err == nil {
		t.Error("no socket, no error")
	}
}

// The client closes each reply's body: a reply with more bytes than the
// decoder reads leaves its connection open until the body is closed.
func unlockClientClosesEachReply(t *testing.T) {
	closed := make(chan struct{}, 1)
	u, srv := unixVault(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"state":"locked"}`))
		w.Write(bytes.Repeat([]byte(" "), 32<<10))
	})
	srv.ConnState = func(_ net.Conn, s http.ConnState) {
		if s == http.StateClosed {
			select {
			case closed <- struct{}{}:
			default:
			}
		}
	}
	if _, err := u.Status(context.Background()); err != nil {
		t.Fatal(err)
	}
	select {
	case <-closed:
	case <-time.After(5 * time.Second):
		t.Fatal("the reply's connection stayed open: its body was never closed")
	}
}

// vaultDo sends one request to the vault page from ip, with no cookies
// unless jar holds some, through w (a recorder unless given).
func vaultDo(r *rig, ip, method string, body []byte, ctype string, w http.ResponseWriter) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, "http://10.42.0.1/unlock/vault", bytes.NewReader(body))
	req.RemoteAddr = ip
	if ctype != "" {
		req.Header.Set("Content-Type", ctype)
	}
	rec, _ := w.(*httptest.ResponseRecorder)
	if w == nil {
		rec = httptest.NewRecorder()
		w = rec
	}
	r.srv.ServeHTTP(w, reaching(req))
	return rec
}

func vaultPageStates(t *testing.T) {
	r, fv := vaultRig(t)
	fv.down = true
	if n := strings.Count(r.get("/unlock/vault"), "<!doctype html>"); n != 1 {
		t.Errorf("down: %d pages in one reply", n)
	}
	fv.down, fv.state = false, "opening"
	if p := r.get("/unlock/vault"); !strings.Contains(p, `http-equiv="refresh" content="2"`) {
		t.Errorf("opening: no reload\n%s", p)
	}
}

// Once the vault says the unlock is no longer pending, the page forgets
// its ticket: a code from that phone later is not sent with it.
func vaultPendingForgottenOnceEnded(t *testing.T) {
	r, fv := vaultRig(t)
	r.upload(nil, r.card.VaultPassphrase)
	if fv.state != "pending" {
		t.Fatalf("state %q", fv.state)
	}
	ticket := fv.ticket
	fv.state = "locked"
	r.get("/unlock/vault")
	fv.state, fv.ticket = "pending", ticket
	w := r.post("/unlock/vault", url.Values{"step": {"code"}, "code": {fv.code}})
	if !strings.Contains(w.Body.String(), "This unlock was started on another phone.") || len(fv.confirms) != 0 {
		t.Fatalf("a forgotten ticket was used: %v\n%s", fv.confirms, w.Body)
	}
}

func vaultForm(parts ...[2]string) ([]byte, string) {
	var b bytes.Buffer
	mw := multipart.NewWriter(&b)
	for _, p := range parts {
		fw, _ := mw.CreateFormField(p[0])
		fw.Write([]byte(p[1]))
	}
	mw.Close()
	return b.Bytes(), mw.FormDataContentType()
}

func vaultPassphraseFormBounds(t *testing.T) {
	r, fv := vaultRig(t)
	// A form post is read to 16 KiB at most: a longer one is not read.
	pad := url.Values{"step": {"pin"}, "pin": {"0000"}, "pad": {strings.Repeat("a", 20<<10)}}
	w := vaultDo(r, "10.42.0.60:1", "POST", []byte(pad.Encode()), "application/x-www-form-urlencoded", nil)
	if len(fv.pins) != 0 || w.Code != http.StatusOK {
		t.Errorf("an oversized form was read: %v", fv.pins)
	}
	// A multipart post with no boundary is refused, not read.
	w = vaultDo(r, "10.42.0.61:1", "POST", []byte("x"), "multipart/form-data", nil)
	if !strings.Contains(w.Body.String(), "I could not read that form.") {
		t.Errorf("no boundary:\n%s", w.Body)
	}
	// The upload's read deadline is set on the connection.
	body, ct := vaultForm([2]string{"passphrase", "wrong words"})
	dw := &deadlineWriter{ResponseRecorder: httptest.NewRecorder()}
	before := time.Now()
	vaultDo(r, "10.42.0.62:1", "POST", body, ct, dw)
	if dw.at.Before(before.Add(uploadWindow)) || dw.at.After(time.Now().Add(uploadWindow)) {
		t.Errorf("read deadline %v, want %v after the post", dw.at, uploadWindow)
	}
	// The body is bounded: a part past the bound ends the read, so the
	// words after it never reach the vault.
	body, ct = vaultForm([2]string{"junk", strings.Repeat("j", MaxPhotoBytes+128<<10)}, [2]string{"passphrase", r.card.VaultPassphrase})
	w = vaultDo(r, "10.42.0.63:1", "POST", body, ct, nil)
	if len(fv.unlocks) != 1 || !strings.Contains(w.Body.String(), "did not arrive whole") {
		t.Errorf("past the bound: %d unlocks\n%.300s", len(fv.unlocks), w.Body)
	}
	// An oversized photo ends the read too, though typed words follow.
	var b bytes.Buffer
	mw := multipart.NewWriter(&b)
	fw, _ := mw.CreateFormFile("photo", "IMG.jpg")
	fw.Write(make([]byte, MaxPhotoBytes+1))
	mw.WriteField("passphrase", r.card.VaultPassphrase)
	mw.Close()
	w = vaultDo(r, "10.42.0.64:1", "POST", b.Bytes(), mw.FormDataContentType(), nil)
	if len(fv.unlocks) != 1 || !strings.Contains(w.Body.String(), "too large") {
		t.Errorf("oversized photo: %d unlocks\n%.300s", len(fv.unlocks), w.Body)
	}
}

func vaultPassphraseOutcomes(t *testing.T) {
	r, fv := vaultRig(t)
	// An unreadable photo gets its own line, and only that.
	res := r.upload([]byte("not an image"), "")
	if !strings.Contains(res.Body, "I cannot read that file.") || strings.Contains(res.Body, "Take a photo of the passphrase code, or type the words.") {
		t.Errorf("unreadable photo:\n%s", res.Body)
	}
	// Wrong words leave nothing pending.
	r.upload(nil, "wrong words entirely here now please")
	r.srv.mu.Lock()
	pend := r.srv.vaultPend
	r.srv.mu.Unlock()
	if pend != nil {
		t.Errorf("wrong words left a pending unlock %+v", pend)
	}
	// The right words: a redirect alone, and a cookie that ends with the
	// pending unlock.
	r.advance(VaultTryGap)
	body, ct := vaultForm([2]string{"passphrase", r.card.VaultPassphrase})
	w := vaultDo(r, phoneIP, "POST", body, ct, nil)
	if w.Code != http.StatusSeeOther || w.Body.Len() != 0 {
		t.Errorf("unlock: %d, body %q", w.Code, w.Body)
	}
	var c *http.Cookie
	for _, k := range w.Result().Cookies() {
		if k.Name == vaultCookie {
			c = k
		}
	}
	if c == nil || !c.Expires.Equal(fv.expires) {
		t.Errorf("cookie %+v, want expiry %v", c, fv.expires)
	}
}

func vaultPINOutcomes(t *testing.T) {
	r, fv := vaultRig(t)
	fv.pin, fv.wantPIN = true, "4711"
	w := r.post("/unlock/vault", url.Values{"step": {"pin"}, "pin": {"0000"}})
	if w.Code != http.StatusOK || w.Header().Get("Location") != "" {
		t.Errorf("wrong PIN: %d to %q", w.Code, w.Header().Get("Location"))
	}
	// Inside the gap, the PIN never reaches the vault.
	r.post("/unlock/vault", url.Values{"step": {"pin"}, "pin": {"4711"}})
	if len(fv.pins) != 1 {
		t.Errorf("inside the gap the vault saw %v", fv.pins)
	}
}

// The attempt budget forgets what is over an hour old: phones that last
// tried then, and Wi-Fi-wide tries then.
func vaultBudgetPrunes(t *testing.T) {
	r, _ := vaultRig(t)
	pin := func(ip string) string {
		body := []byte(url.Values{"step": {"pin"}, "pin": {"0000"}}.Encode())
		return vaultDo(r, ip, "POST", body, "application/x-www-form-urlencoded", nil).Body.String()
	}
	for i := 0; i < 60; i++ {
		pin(fmt.Sprintf("10.42.1.%d:1", i))
	}
	r.advance(40 * time.Minute)
	for i := 0; i < 60; i++ {
		pin(fmt.Sprintf("10.42.2.%d:1", i))
	}
	r.advance(21 * time.Minute)
	pin("10.42.3.1:1")
	if b := pin("10.42.3.2:1"); strings.Contains(b, "Too many tries") {
		t.Errorf("61 tries in the last hour refused:\n%.300s", b)
	}
	r.srv.mu.Lock()
	_, stale := r.srv.vaultTries["10.42.1.0"]
	_, fresh := r.srv.vaultTries["10.42.2.0"]
	r.srv.mu.Unlock()
	if stale || !fresh {
		t.Errorf("per-phone tries: stale kept %v, fresh kept %v", stale, fresh)
	}
}

func vaultTextsNameEachRefusal(t *testing.T) {
	for err, want := range map[error]string{
		ErrManyQR:    "That photo holds more than one passphrase-like code.",
		ErrPhotoSize: "That photo is too large for me.",
	} {
		if got := scanText(err); !strings.HasPrefix(got, want) {
			t.Errorf("scanText(%v) = %q", err, got)
		}
	}
	for msg, want := range map[string]string{
		"wait a moment before trying again": "Wait a moment, then try again.",
		"  ":                                "I refused that. Try again.",
	} {
		if got := vaultText(&VaultError{403, msg}); got != want {
			t.Errorf("vaultText(%q) = %q", msg, got)
		}
	}
}

// A decoder that panics on a photo makes it an unreadable photo. The
// format is registered here, under a magic no real photo starts with,
// since no stdlib decoder is known to panic.
func scanSafeRecoversADecoderPanic(t *testing.T) {
	image.RegisterFormat("synthetic-panic", "SYNTHPANIC", func(io.Reader) (image.Image, error) {
		panic("synthetic decoder panic")
	}, func(io.Reader) (image.Config, error) {
		return image.Config{ColorModel: color.RGBAModel, Width: 8, Height: 8}, nil
	})
	if pass, err := scanSafe([]byte("SYNTHPANIC")); pass != "" || err != ErrNotPhoto {
		t.Errorf("a panicking decoder: %q, %v", pass, err)
	}
}

// With no log func given, renewal failures go to the standard logger.
func pageTLSDefaultLog(t *testing.T) {
	var buf bytes.Buffer
	prev, flags := log.Writer(), log.Flags()
	log.SetOutput(&buf)
	log.SetFlags(0)
	defer func() { log.SetOutput(prev); log.SetFlags(flags) }()
	p, err := NewPageTLS(context.Background(), DefaultPageName, newCertifier(t), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	p.log(LogRenewFailed)
	if buf.String() != LogRenewFailed+"\n" {
		t.Errorf("logged %q", buf.String())
	}
}

// certOwner answers OpCertify with what answer makes of the request's
// public key.
type certOwner func(pub []byte) (localapi.Certified, error)

func (f certOwner) Call(_ context.Context, _ string, args, out any) error {
	c, err := f(args.(localapi.CertifyArgs).Pub)
	if err == nil {
		*out.(*localapi.Certified) = c
	}
	return err
}

func pageTLSRefusesBadAnswers(t *testing.T) {
	ctx := context.Background()
	lost := errors.New("synthetic socket loss")
	if _, err := NewPageTLS(ctx, DefaultPageName, certOwner(func([]byte) (localapi.Certified, error) {
		return localapi.Certified{}, lost
	}), nil, nil); !errors.Is(err, lost) {
		t.Errorf("a failed call: %v", err)
	}
	a, err := pageca.New(DefaultPageName, testBuilt, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewPageTLS(ctx, DefaultPageName, certOwner(func([]byte) (localapi.Certified, error) {
		return localapi.Certified{Leaf: []byte("not a certificate"), Authority: a.Certificate()}, nil
	}), nil, nil); err == nil {
		t.Error("took an unreadable leaf")
	}
	if _, err := NewPageTLS(ctx, DefaultPageName, certOwner(func(pub []byte) (localapi.Certified, error) {
		leaf, err := a.Issue(pub, testBuilt.Add(time.Hour), rand.Reader)
		return localapi.Certified{Leaf: leaf, Authority: []byte("not a certificate")}, err
	}), nil, nil); err == nil {
		t.Error("took an unreadable authority")
	}
}

// Run returns once its context ends: while it waits, and when a renewal
// fails because the context ended (which logs nothing).
func pageTLSRunStops(t *testing.T) {
	f := newCertifier(t)
	var mu sync.Mutex
	var logged []string
	p, err := NewPageTLS(context.Background(), DefaultPageName, f, nil, func(s string) { mu.Lock(); logged = append(logged, s); mu.Unlock() })
	if err != nil {
		t.Fatal(err)
	}
	returns := func(ctx context.Context) bool {
		done := make(chan struct{})
		go func() { p.Run(ctx); close(done) }()
		select {
		case <-done:
			return true
		case <-time.After(5 * time.Second):
			return false
		}
	}
	p.after = func(time.Duration) <-chan time.Time { return nil }
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if !returns(ctx) {
		t.Fatal("Run kept waiting after its context ended")
	}
	ctx, cancel = context.WithCancel(context.Background())
	defer cancel()
	tick := make(chan time.Time, 1)
	tick <- time.Time{}
	p.after = func(time.Duration) <-chan time.Time { return tick }
	p.owner = certOwner(func([]byte) (localapi.Certified, error) {
		cancel()
		return localapi.Certified{}, context.Canceled
	})
	if !returns(ctx) {
		t.Fatal("Run kept going after a renewal its context ended")
	}
	mu.Lock()
	defer mu.Unlock()
	if len(logged) != 0 {
		t.Errorf("an ended context logged %q", logged)
	}
}
