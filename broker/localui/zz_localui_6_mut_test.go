package localui

// REQ: REC-4, DEV-7, DEV-10

import (
	"context"
	"errors"
	"fmt"
	"html"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/ghbmrk/agentos/broker/card"
	"github.com/ghbmrk/agentos/broker/card/words"
	"github.com/ghbmrk/agentos/broker/firstboot"
	"github.com/ghbmrk/agentos/broker/localapi"
)

// localui6Kills runs, as subtests of TestLostCardOnlyToItsSession, the
// checks that kill MUT-kill-localui-6's mutgate survivors in lostcard.go
// and cameras.go (#6770). They are subtests for the reason recoveryEdges
// gives: a new top-level test in localui changes the run list and makes
// every localui test a changed test.
func localui6Kills(t *testing.T) {
	t.Run("LostTextNamesEachRefusal", lostTextNamesEachRefusal)
	t.Run("LostWithdrawAndRestartRefusals", lostWithdrawAndRestartRefusals)
	t.Run("LostTapPageMethodAndHeaders", lostTapPageMethodAndHeaders)
	t.Run("LostCardPageNoSession", lostCardPageNoSession)
	t.Run("LostCardPageMethodsAndBounds", lostCardPageMethodsAndBounds)
	t.Run("LostCardPageHeaders", lostCardPageHeaders)
	t.Run("LostShowWipesTheBits", lostShowWipesTheBits)
	t.Run("LostShowRefusesAWrongID", lostShowRefusesAWrongID)
	t.Run("LostShowWithoutAGenerator", lostShowWithoutAGenerator)
	t.Run("LostShowWithoutAnAuthority", lostShowWithoutAnAuthority)
	t.Run("LostShowDiscardsTheOldDisplay", lostShowDiscardsTheOldDisplay)
	t.Run("LostConfirmUnlocks", lostConfirmUnlocks)
	t.Run("CameraTextNamesEachRefusal", cameraTextNamesEachRefusal)
	t.Run("CameraFormRetentionAndUnknownStep", cameraFormRetentionAndUnknownStep)
	t.Run("CamerasPagePathMethodsAndBounds", camerasPagePathMethodsAndBounds)
	t.Run("CamerasPageListRefused", camerasPageListRefused)
	t.Run("CamerasPageChangeRefusedShowsNoDone", camerasPageChangeRefusedShowsNoDone)
	t.Run("CamerasPageDoneRelists", camerasPageDoneRelists)
}

// keptLost is the lost-card ops with the card bytes it returned kept, so a
// test can read whether the page wiped them, and a scripted withdraw.
type keptLost struct {
	*fakeRecoveryOps
	kept        [][]byte
	withdrawErr error
}

func (k *keptLost) RecoveryLostCard(ctx context.Context, tok string, ad, cd, sig []byte) (localapi.RecoveryLostCard, error) {
	c, err := k.fakeRecoveryOps.RecoveryLostCard(ctx, tok, ad, cd, sig)
	k.kept = append(k.kept, c.Card)
	return c, err
}

func (k *keptLost) RecoveryLostWithdraw(ctx context.Context, tok string) error {
	if k.withdrawErr != nil {
		return k.withdrawErr
	}
	return k.fakeRecoveryOps.RecoveryLostWithdraw(ctx, tok)
}

// keptLostRig is a recovery rig, signed in, whose lost-card ops keep what
// they return.
func keptLostRig(t *testing.T) (*recoveryRig, *keptLost) {
	t.Helper()
	r := newRecoveryRig(t)
	k := &keptLost{fakeRecoveryOps: r.f}
	r.srv.cfg.Recovery = k
	r.signIn()
	return r, k
}

// lostBits is a made card's bytes, each different.
func lostBits() []byte {
	b := make([]byte, localapi.RecoveryCardLen)
	for i := range b {
		b[i] = byte(0x6b + 7*i)
	}
	return b
}

// pageCount is how many pages the body holds: a handler that renders
// twice writes two.
func pageCount(body string) int { return strings.Count(body, "<!doctype html>") }

// lostText and lostCardText (lostcard.go:148, :149, :151, :161): each
// refusal the route names has its own line, not recoveryText's.
func lostTextNamesEachRefusal(t *testing.T) {
	if got := lostText(Refused(localapi.ErrRecoveryNoCard)); got != lostNoCardText {
		t.Errorf("no card: %q", got)
	}
	stale := lostText(Refused(localapi.ErrRecoveryStale))
	if !strings.Contains(stale, "the request was withdrawn") || stale == recoveryText(Refused(localapi.ErrRecoveryStale)) {
		t.Errorf("stale: %q", stale)
	}
	if got, want := lostText(Refused(localapi.ErrRecoveryBusy)), recoveryText(Refused(localapi.ErrRecoveryBusy)); got != want {
		t.Errorf("busy: %q, want %q", got, want)
	}
	r := newRecoveryRig(t)
	err := fmt.Errorf("display: %w", card.ErrNoAuthority)
	if got := r.srv.lostCardText(context.Background(), "", err); got != firstboot.ErrNoAuthority.Error() || got == lostText(err) {
		t.Errorf("no authority: %q", got)
	}
}

// A refused withdraw or restart says why, never that it was done
// (lostcard.go:205, :210).
func lostWithdrawAndRestartRefusals(t *testing.T) {
	r, k := keptLostRig(t)
	r.f.lostState = localapi.RecoveryLostState{Filed: true}
	k.withdrawErr = Refused(localapi.ErrRecoveryStale)
	p := html.UnescapeString(r.post("/recovery/", url.Values{"step": {"withdraw"}}).Body.String())
	if strings.Contains(p, lostWithdrawText) || !strings.Contains(p, lostText(k.withdrawErr)) {
		t.Fatalf("a refused withdraw:\n%s", p)
	}
	r.f.lostErr = Refused(localapi.ErrRecoveryBusy)
	p = html.UnescapeString(r.post("/recovery/", url.Values{"step": {"restart"}}).Body.String())
	if strings.Contains(p, lostRestartText) || !strings.Contains(p, lostText(r.f.lostErr)) {
		t.Fatalf("a refused restart:\n%s", p)
	}
}

// /recovery/lost: GET only (lostcard.go:219); a refused begin shows its
// line under the vault page's policy with no tap step (:229), and the tap
// step is under the passkey page's (:235).
func lostTapPageMethodAndHeaders(t *testing.T) {
	r, _ := keptLostRig(t)
	if w := r.post("/recovery/lost", url.Values{"step": {"lost"}}); w.Code != http.StatusMethodNotAllowed || w.Header().Get("Allow") != "GET" {
		t.Fatalf("POST /recovery/lost: %d %v", w.Code, w.Header())
	}
	if len(r.f.lost) != 0 {
		t.Fatalf("a refused method called agentosd: %v", r.f.lost)
	}
	w := r.do("GET", "/recovery/lost", nil)
	if w.Code != http.StatusOK || w.Header().Get("Content-Security-Policy") != passkeyCSP || passkeyCSP == pageCSP {
		t.Fatalf("tap step: %d %v", w.Code, w.Header())
	}
	r.f.lostErr = Refused(localapi.ErrRecoveryBusy)
	w = r.do("GET", "/recovery/lost", nil)
	p := html.UnescapeString(w.Body.String())
	if w.Header().Get("Content-Security-Policy") != vaultCSP || vaultCSP == pageCSP || strings.Contains(p, `value="lost"`) ||
		strings.Contains(p, `id="pk-finish"`) || !strings.Contains(p, lostText(r.f.lostErr)) || pageCount(p) != 1 {
		t.Fatalf("a refused begin: %v\n%s", w.Header(), p)
	}
}

// lostCardPage with no session token sends the phone to the first step
// and reads nothing (lostcard.go:246). Mount's sign-in check keeps that
// case from the route, so the handler is called directly.
func lostCardPageNoSession(t *testing.T) {
	r, _ := keptLostRig(t)
	w := httptest.NewRecorder()
	r.srv.lostCardPage(w, httptest.NewRequest("GET", "http://10.42.0.1/new", nil), "")
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/recovery/" || len(r.f.lost) != 0 {
		t.Fatalf("no token: %d %q %v", w.Code, w.Header().Get("Location"), r.f.lost)
	}
}

// /recovery/new takes GET and POST only (lostcard.go:281), bounds a post's
// body and writes nothing more (:267, :270), and a refused begin renders
// once (:292).
func lostCardPageMethodsAndBounds(t *testing.T) {
	r, _ := keptLostRig(t)
	if w := r.do("PUT", "/recovery/new", nil); w.Code != http.StatusMethodNotAllowed || w.Header().Get("Allow") != "GET, POST" {
		t.Fatalf("PUT /recovery/new: %d %v", w.Code, w.Header())
	}
	if len(r.f.lost) != 0 {
		t.Fatalf("a refused method called agentosd: %v", r.f.lost)
	}
	big := url.Values{"step": {"show"}, "pad": {strings.Repeat("a", 17<<10)}}
	if w := r.post("/recovery/new", big); w.Code != http.StatusBadRequest || pageCount(w.Body.String()) != 0 {
		t.Fatalf("a post past 16 KiB: %d\n%s", w.Code, w.Body)
	}
	w := r.do("GET", "/recovery/new", nil)
	p := html.UnescapeString(w.Body.String())
	if w.Code != http.StatusOK || pageCount(p) != 1 || strings.Contains(p, `value="show"`) || !strings.Contains(p, lostNoCardText) {
		t.Fatalf("no card: %d\n%s", w.Code, p)
	}
}

// /recovery/new is under the vault page's policy until it shows the tap
// step, which is under the passkey page's (lostcard.go:260, :294).
func lostCardPageHeaders(t *testing.T) {
	r, _ := keptLostRig(t)
	if w := r.do("GET", "/recovery/new", nil); w.Header().Get("Content-Security-Policy") != vaultCSP || vaultCSP == pageCSP {
		t.Fatalf("no card: %v", w.Header())
	}
	r.f.lostCard = lostBits()
	if w := r.do("GET", "/recovery/new", nil); w.Header().Get("Content-Security-Policy") != passkeyCSP || !strings.Contains(w.Body.String(), `value="show"`) {
		t.Fatalf("the tap step: %v", w.Header())
	}
}

// The bits agentosd returned are wiped once the display holds the card
// (lostcard.go:328).
func lostShowWipesTheBits(t *testing.T) {
	r, k := keptLostRig(t)
	r.f.lostCard = lostBits()
	r.show()
	if len(k.kept) != 1 || len(k.kept[0]) != localapi.RecoveryCardLen {
		t.Fatalf("reads %d", len(k.kept))
	}
	for i, b := range k.kept[0] {
		if b != 0 {
			t.Fatalf("byte %d of the card agentosd returned is not wiped", i)
		}
	}
}

// A card whose ID is not its length is refused, and nothing is shown
// (lostcard.go:332).
func lostShowRefusesAWrongID(t *testing.T) {
	r, _ := keptLostRig(t)
	r.f.lostCard, r.f.lostID = lostBits(), testLostID[:localapi.RecoveryIDLen-2]
	w := r.post("/recovery/new", showTap)
	p := html.UnescapeString(w.Body.String())
	if w.Code != http.StatusOK || r.srv.lost.display != nil || !strings.Contains(p, recoveryText(Refused(localapi.ErrRecoveryUnavailable))) {
		t.Fatalf("a wrong ID: %d display %v\n%s", w.Code, r.srv.lost.display != nil, p)
	}
}

// With no RecoveryCard set, the display draws the card's other parts with
// card.Generate (lostcard.go:349), and prints the kernel's passphrase.
func lostShowWithoutAGenerator(t *testing.T) {
	r, _ := keptLostRig(t)
	r.srv.cfg.RecoveryCard = nil
	bits := lostBits()
	r.f.lostCard = bits
	pass, err := words.FromSeed(bits[localapi.RecoveryCardKeyLen:])
	if err != nil {
		t.Fatal(err)
	}
	if p := r.show(); !strings.Contains(p, string(pass)) || r.srv.lost.display == nil {
		t.Fatalf("no generator: the page lacks the passphrase\n%s", p)
	}
}

// With no page authority the display is refused, and the page says so
// and shows nothing (lostcard.go:363, :161).
func lostShowWithoutAnAuthority(t *testing.T) {
	r, _ := keptLostRig(t)
	r.srv.cfg.PageAuthority = nil
	r.f.lostCard = lostBits()
	w := r.post("/recovery/new", showTap)
	p := html.UnescapeString(w.Body.String())
	if w.Code != http.StatusOK || r.srv.lost.display != nil || !strings.Contains(p, firstboot.ErrNoAuthority.Error()) {
		t.Fatalf("no authority: %d display %v\n%s", w.Code, r.srv.lost.display != nil, p)
	}
}

// A second show discards the display it replaces (lostcard.go:370).
// lostDisplay drops another session's display before lostShow runs, so
// the overlap is two posts racing; lostShow is called directly for it.
func lostShowDiscardsTheOldDisplay(t *testing.T) {
	r, _ := keptLostRig(t)
	r.f.lostCard = lostBits()
	ctx := context.Background()
	if err := r.srv.lostShow(ctx, "tok-a", showTap); err != nil {
		t.Fatal(err)
	}
	old := r.srv.lost.display
	r.f.lostCard = lostBits()
	if err := r.srv.lostShow(ctx, "tok-b", showTap); err != nil {
		t.Fatal(err)
	}
	if r.srv.lost.display == old || old == nil {
		t.Fatal("the second show kept the first display")
	}
	if _, err := old.Page(); !errors.Is(err, card.ErrDisplayGone) {
		t.Fatalf("the replaced display still holds its card: %v", err)
	}
	r.srv.lost.display.Discard()
}

// The confirm leaves the lost-card lock free (lostcard.go:387).
func lostConfirmUnlocks(t *testing.T) {
	r, _ := keptLostRig(t)
	bits := lostBits()
	r.f.lostCard = bits
	r.show()
	text := card.RecoveryKeyText([localapi.RecoveryCardKeyLen]byte(bits[:localapi.RecoveryCardKeyLen]))
	pass, err := words.FromSeed(bits[localapi.RecoveryCardKeyLen:])
	if err != nil {
		t.Fatal(err)
	}
	wd, g := r.srv.lost.display.Asks()
	res := r.post("/recovery/new", url.Values{"word": {strings.Fields(string(pass))[wd-1]}, "group": {strings.Split(text, "-")[g-1]}}).Result()
	if res.StatusCode != http.StatusSeeOther || res.Header.Get("Location") != "/recovery/?lost=done" {
		t.Fatalf("confirm: %d %s", res.StatusCode, res.Header.Get("Location"))
	}
	if !r.srv.lost.mu.TryLock() {
		t.Fatal("the confirm left the lost-card lock held")
	}
	r.srv.lost.mu.Unlock()
}

// cameraText has its own line for each refusal (cameras.go:51 to :59).
func cameraTextNamesEachRefusal(t *testing.T) {
	other := cameraText(errors.New("down"))
	want := map[string]string{
		localapi.ErrCameraCode:    "That approval code didn't work.",
		localapi.ErrCameraRefused: "I can't connect that camera:",
		localapi.ErrCameraUnknown: "No camera has that name.",
		localapi.ErrBadArgs:       "Fill in every field, then try again.",
		localapi.ErrLimited:       "Too many tries.",
		localapi.ErrUnauthorized:  "Your sign-in ended.",
	}
	for code, w := range want {
		if got := cameraText(Refused(code)); !strings.HasPrefix(got, w) || got == other {
			t.Errorf("%s: %q", code, got)
		}
	}
}

// A retention step takes 0 to maxRetentionDays days, and an unknown step
// is refused even with a name (cameras.go:109, :126).
func cameraFormRetentionAndUnknownStep(t *testing.T) {
	var list localapi.CameraList
	form := func(step, days string) map[string][]string {
		return url.Values{"step": {step}, "id": {"porch"}, "days": {days}}
	}
	for _, d := range []int{0, 30, maxRetentionDays} {
		c, ok := formCameraChange(form(localapi.CameraRetention, fmt.Sprint(d)), list)
		if !ok || c.RetentionDays != d || c.Step != localapi.CameraRetention {
			t.Errorf("retention %d: %v %+v", d, ok, c)
		}
	}
	for _, d := range []string{"-1", fmt.Sprint(maxRetentionDays + 1), "x", ""} {
		if _, ok := formCameraChange(form(localapi.CameraRetention, d), list); ok {
			t.Errorf("retention %q taken", d)
		}
	}
	if _, ok := formCameraChange(form("format", "1"), list); ok {
		t.Error("an unknown step taken")
	}
}

// scriptedCameras is fakeCameras whose first lists fail and whose list
// changes once a change is taken.
type scriptedCameras struct {
	*fakeCameras
	listErrs int
	after    *localapi.CameraList
}

func (s *scriptedCameras) Cameras(ctx context.Context, tok string) (localapi.CameraList, error) {
	if s.listErrs > 0 {
		s.listErrs--
		return localapi.CameraList{}, errors.New("camera clerk down")
	}
	return s.fakeCameras.Cameras(ctx, tok)
}

func (s *scriptedCameras) CameraChange(ctx context.Context, c localapi.CameraChange) error {
	err := s.fakeCameras.CameraChange(ctx, c)
	if err == nil && s.after != nil {
		s.list = *s.after
	}
	return err
}

func scriptedCameraRig(t *testing.T) (*rig, *scriptedCameras) {
	t.Helper()
	r, fc := cameraRig(t)
	sc := &scriptedCameras{fakeCameras: fc}
	r.srv.cfg.Cameras = sc
	r.signIn()
	return r, sc
}

// /cameras/ serves its own path only, and a 404 writes nothing more
// (cameras.go:139, :141); a GET renders once (:157); methods other than GET
// and POST are refused (:159, :162); a post's body is bounded (:164, :167);
// and a bad step that is no connect or re-pin reads as a missing field
// (:171).
func camerasPagePathMethodsAndBounds(t *testing.T) {
	r, sc := scriptedCameraRig(t)
	if w := r.do("GET", "/cameras/porch", nil); w.Code != http.StatusNotFound || pageCount(w.Body.String()) != 0 {
		t.Fatalf("GET /cameras/porch: %d\n%s", w.Code, w.Body)
	}
	w := r.do("GET", "/cameras/", nil)
	if b := w.Body.String(); w.Code != http.StatusOK || pageCount(b) != 1 || strings.Contains(b, "Method not allowed") {
		t.Fatalf("GET /cameras/: %d\n%s", w.Code, b)
	}
	if w := r.do("PUT", "/cameras/", nil); w.Code != http.StatusMethodNotAllowed || w.Header().Get("Allow") != "GET, POST" || pageCount(w.Body.String()) != 0 {
		t.Fatalf("PUT /cameras/: %d %v", w.Code, w.Header())
	}
	big := url.Values{"step": {"disconnect"}, "id": {"porch"}, "confirm": {"1"}, "pad": {strings.Repeat("a", 17<<10)}}
	if w := r.post("/cameras/", big); w.Code != http.StatusBadRequest || len(sc.changes) != 0 || pageCount(w.Body.String()) != 0 {
		t.Fatalf("a post past 16 KiB: %d %v", w.Code, sc.changes)
	}
	p := html.UnescapeString(r.post("/cameras/", url.Values{"step": {"capture"}, "id": {"porch"}, "capture": {"sometimes"}}).Body.String())
	if !strings.Contains(p, cameraText(Refused(localapi.ErrBadArgs))) || len(sc.changes) != 0 {
		t.Fatalf("a bad capture mode:\n%s", p)
	}
}

// A list the clerk cannot give reads as the clerk not answering
// (cameras.go:149).
func camerasPageListRefused(t *testing.T) {
	r, sc := scriptedCameraRig(t)
	sc.listErrs = 1
	p := html.UnescapeString(r.get("/cameras/"))
	if !strings.Contains(p, cameraText(errors.New("down"))) || strings.Contains(p, "camera porch: capture off") {
		t.Fatalf("a refused list:\n%s", p)
	}
}

// A refused change says why, once, with no done line (cameras.go:192).
func camerasPageChangeRefusedShowsNoDone(t *testing.T) {
	r, sc := scriptedCameraRig(t)
	w := r.post("/cameras/", url.Values{"step": {"capture"}, "id": {"porch"}, "capture": {"continuous"}, "code": {"000000"}})
	p := html.UnescapeString(w.Body.String())
	if strings.Contains(p, "Done.") || pageCount(p) != 1 || !strings.Contains(p, cameraText(Refused(localapi.ErrCameraCode))) || len(sc.changes) != 0 {
		t.Fatalf("a refused code:\n%s", p)
	}
}

// A change taken clears an earlier list's error, lists again and says
// done (cameras.go:194 to :197).
func camerasPageDoneRelists(t *testing.T) {
	r, sc := scriptedCameraRig(t)
	sc.listErrs = 1
	sc.after = &localapi.CameraList{Lines: []string{"camera porch: capture continuous"},
		Cameras: []localapi.Camera{{ID: "porch", Addr: "192.168.1.60:8443", Capture: "continuous"}}}
	w := r.post("/cameras/", url.Values{"step": {"capture"}, "id": {"porch"}, "capture": {"continuous"}, "code": {"123456"}})
	p := html.UnescapeString(w.Body.String())
	if w.Code != http.StatusOK || pageCount(p) != 1 || !strings.Contains(p, "Done.") || !strings.Contains(p, "camera porch: capture continuous") ||
		strings.Contains(p, cameraText(errors.New("down"))) || len(sc.changes) != 1 {
		t.Fatalf("a taken change:\n%s", p)
	}
}
